#!/usr/bin/env python3
"""
test_gcmsiv_polyval.py - End-to-End AES-256-GCM-SIV + POLYVAL Integration Test

Tests the full C64 GCM-SIV encrypt/decrypt pipeline (including POLYVAL)
against OpenSSL AESGCMSIV, polyval_reference, and RFC 8452 test vectors.

Approach:
  - Encrypt on C64, compare against AESGCMSIV + polyval_reference
  - Decrypt on C64, verify roundtrip
  - RFC 8452 C.2 vectors (no-AAD)
  - Tag tamper detection

Usage:
    python3 tools/test_gcmsiv_polyval.py [--iterations N] [--seed S] [--workers N]

Requires: Python 3.10+, c64_test_harness, cryptography, VICE x64sc
"""

import json
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from polyval_reference import gcmsiv_encrypt as py_encrypt, gcmsiv_decrypt as py_decrypt

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceProcess,
    ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)
from c64_test_harness.backends.vice_manager import ViceInstanceManager
from c64_test_utils import robust_jsr, generate_random_bytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc8452_vectors.json")

DEFAULT_ITERATIONS = 15
DEFAULT_WORKERS = 1
PORT_RANGE_START = 6510
MAX_PT_LEN = 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def setup_key_and_expand(transport: ViceTransport, labels: Labels, key: bytes):
    write_bytes(transport, labels["key_data"], key)
    robust_jsr(transport, labels["aes_key_expansion"], timeout=10.0)


def c64_gcmsiv_encrypt(transport: ViceTransport, labels: Labels,
                       key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    setup_key_and_expand(transport, labels, key)
    write_bytes(transport, labels["gcmsiv_nonce"], nonce)
    write_bytes(transport, labels["gcmsiv_pt_buf"], plaintext)
    write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(plaintext)]))
    robust_jsr(transport, labels["gcmsiv_encrypt"], timeout=120.0)
    ct = read_bytes(transport, labels["gcmsiv_ct_buf"], len(plaintext))
    tag = read_bytes(transport, labels["gcmsiv_tag"], 16)
    return ct, tag


def c64_gcmsiv_decrypt(transport: ViceTransport, labels: Labels,
                       key: bytes, nonce: bytes, ciphertext: bytes,
                       tag: bytes) -> tuple[bytes, bool]:
    setup_key_and_expand(transport, labels, key)
    write_bytes(transport, labels["gcmsiv_nonce"], nonce)
    write_bytes(transport, labels["gcmsiv_ct_buf"], ciphertext)
    write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(ciphertext)]))
    write_bytes(transport, labels["gcmsiv_tag"], tag)
    robust_jsr(transport, labels["gcmsiv_decrypt"], timeout=120.0)
    pt = read_bytes(transport, labels["gcmsiv_dec_buf"], len(ciphertext))
    tag_valid = read_bytes(transport, labels["gcmsiv_tag_valid"], 1)[0]
    return pt, tag_valid == 1


def openssl_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    aead = AESGCMSIV(key)
    ct_tag = aead.encrypt(nonce, plaintext, None)
    return ct_tag[:-16], ct_tag[-16:]


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

def test_rfc_vector_encrypt(transport, labels, vector) -> bool:
    name = vector["name"]
    print(f"\n--- Encrypt: {name} ---")
    key = bytes.fromhex(vector["key"])
    nonce = bytes.fromhex(vector["nonce"])
    pt = bytes.fromhex(vector["plaintext"]) if vector["plaintext"] else b""
    expected_ct = bytes.fromhex(vector["ciphertext"]) if vector["ciphertext"] else b""
    expected_tag = bytes.fromhex(vector["tag"])

    if len(pt) == 0 or len(pt) > MAX_PT_LEN:
        print(f"  SKIP: plaintext length {len(pt)} not supported")
        return True
    if vector.get("aad", ""):
        print(f"  SKIP: C64 does not support AAD")
        return True

    ct, tag = c64_gcmsiv_encrypt(transport, labels, key, nonce, pt)
    if ct == expected_ct and tag == expected_tag:
        print(f"  PASS: ct={ct.hex() if ct else '(empty)'}, tag={tag.hex()}")
        return True
    else:
        print(f"  FAIL:")
        if ct != expected_ct:
            print(f"    CT expected: {expected_ct.hex()}")
            print(f"    CT got:      {ct.hex()}")
        if tag != expected_tag:
            print(f"    Tag expected: {expected_tag.hex()}")
            print(f"    Tag got:      {tag.hex()}")
        return False


def test_rfc_vector_decrypt(transport, labels, vector) -> bool:
    name = vector["name"]
    print(f"\n--- Decrypt: {name} ---")
    key = bytes.fromhex(vector["key"])
    nonce = bytes.fromhex(vector["nonce"])
    expected_pt = bytes.fromhex(vector["plaintext"]) if vector["plaintext"] else b""
    ct = bytes.fromhex(vector["ciphertext"]) if vector["ciphertext"] else b""
    tag = bytes.fromhex(vector["tag"])

    if len(ct) == 0 or len(ct) > MAX_PT_LEN:
        print(f"  SKIP: ciphertext length {len(ct)} not supported")
        return True
    if vector.get("aad", ""):
        print(f"  SKIP: C64 does not support AAD")
        return True

    pt, valid = c64_gcmsiv_decrypt(transport, labels, key, nonce, ct, tag)
    if pt == expected_pt and valid:
        print(f"  PASS: pt={pt.hex() if pt else '(empty)'}")
        return True
    else:
        print(f"  FAIL:")
        if pt != expected_pt:
            print(f"    PT expected: {expected_pt.hex()}")
            print(f"    PT got:      {pt.hex()}")
        if not valid:
            print(f"    Tag verification failed")
        return False


def test_random_roundtrip(transport, labels, pt_len, label) -> bool:
    print(f"\n--- {label} ---")
    key = generate_random_bytes(32)
    nonce = generate_random_bytes(12)
    pt = generate_random_bytes(pt_len) if pt_len > 0 else b""

    # Cross-check: OpenSSL and Python reference
    py_ct, py_tag = py_encrypt(key, nonce, pt)
    ossl_ct, ossl_tag = openssl_encrypt(key, nonce, pt)
    if py_ct != ossl_ct or py_tag != ossl_tag:
        print(f"  FAIL: Python vs OpenSSL mismatch (sanity)")
        return False

    # C64 encrypt
    c64_ct, c64_tag = c64_gcmsiv_encrypt(transport, labels, key, nonce, pt)
    if c64_ct != ossl_ct or c64_tag != ossl_tag:
        print(f"  FAIL: C64 encrypt doesn't match reference")
        print(f"    Key:   {key.hex()}")
        print(f"    Nonce: {nonce.hex()}")
        print(f"    PT:    {pt.hex() if pt else '(empty)'}")
        if c64_ct != ossl_ct:
            print(f"    CT expected: {ossl_ct.hex()}")
            print(f"    CT got:      {c64_ct.hex()}")
        if c64_tag != ossl_tag:
            print(f"    Tag expected: {ossl_tag.hex()}")
            print(f"    Tag got:      {c64_tag.hex()}")
        return False

    # C64 decrypt
    dec_pt, valid = c64_gcmsiv_decrypt(transport, labels, key, nonce, c64_ct, c64_tag)
    if dec_pt == pt and valid:
        print(f"  PASS: roundtrip OK ({pt_len} bytes)")
        return True
    else:
        print(f"  FAIL: decrypt mismatch or tag invalid")
        if dec_pt != pt:
            print(f"    PT expected: {pt.hex()}")
            print(f"    PT got:      {dec_pt.hex()}")
        if not valid:
            print(f"    Tag verification failed")
        return False


def test_tampered_tag(transport, labels) -> bool:
    print("\n--- Tampered tag detection ---")
    key = generate_random_bytes(32)
    nonce = generate_random_bytes(12)
    pt = generate_random_bytes(16)

    ct, tag = c64_gcmsiv_encrypt(transport, labels, key, nonce, pt)
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01

    _, valid = c64_gcmsiv_decrypt(transport, labels, key, nonce, ct, bytes(bad_tag))
    if not valid:
        print("  PASS: tampered tag correctly rejected")
        return True
    else:
        print("  FAIL: tampered tag was accepted!")
        return False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(transport, labels, iterations) -> tuple[int, int]:
    passed = 0
    failed = 0

    def record(ok):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1

    # Load RFC vectors
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)
    no_aad = [v for v in vectors["aes256_gcmsiv_vectors"] if not v.get("aad", "")]

    # RFC encrypt
    print("\n=== RFC 8452 C.2 Vector Encryption ===")
    for v in no_aad:
        record(test_rfc_vector_encrypt(transport, labels, v))

    # RFC decrypt
    print("\n=== RFC 8452 C.2 Vector Decryption ===")
    for v in no_aad:
        record(test_rfc_vector_decrypt(transport, labels, v))

    # Tampered tag
    print("\n=== Tampered Tag Detection ===")
    record(test_tampered_tag(transport, labels))

    # Random roundtrips
    print("\n=== Random Roundtrip Tests ===")
    fixed_count = len(no_aad) * 2 + 1
    random_count = max(0, iterations - fixed_count)

    boundary_lengths = [1, 15, 16, 17, 32, 48, 63, 64]
    for pt_len in boundary_lengths:
        if random_count <= 0:
            break
        record(test_random_roundtrip(transport, labels, pt_len, f"Roundtrip: {pt_len} bytes"))
        random_count -= 1

    for i in range(random_count):
        pt_len = random.randint(1, MAX_PT_LEN)
        record(test_random_roundtrip(transport, labels, pt_len, f"Random roundtrip {i+1}: {pt_len} bytes"))

    return passed, failed


# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------

def run_sequential(labels, iterations) -> tuple[int, int]:
    print("\n=== Starting VICE ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceProcess(config) as vice:
        if not vice.wait_for_monitor(timeout=30.0):
            print("FATAL: Could not connect to VICE monitor")
            sys.exit(1)
        print(f"  VICE started (PID {vice.pid})")

        transport = ViceTransport(port=config.port)
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        print(f"\n=== GCM-SIV + POLYVAL Integration Tests ({iterations} iterations) ===")
        return run_tests(transport, labels, iterations)


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def worker_run(worker_id, transport, labels, iterations):
    t0 = time.monotonic()
    print(f"  [Worker {worker_id}] Starting")
    passed, failed = run_tests(transport, labels, iterations)
    duration = time.monotonic() - t0
    print(f"  [Worker {worker_id}] Done: {passed} passed, {failed} failed ({duration:.1f}s)")
    return worker_id, passed, failed, duration


def run_parallel(labels, iterations, num_workers) -> tuple[int, int]:
    port_end = PORT_RANGE_START + num_workers
    print(f"\n=== Starting {num_workers} VICE instances (ports {PORT_RANGE_START}-{port_end - 1}) ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    # Each worker runs the full test suite independently
    per_worker = max(1, iterations // num_workers)

    with ViceInstanceManager(
        config=config,
        port_range_start=PORT_RANGE_START,
        port_range_end=port_end,
    ) as mgr:
        instances = []
        for i in range(num_workers):
            inst = mgr.acquire()
            pid = inst.process.pid if inst.process else "?"
            print(f"  Instance {i}: port {inst.port}, PID {pid}")
            instances.append(inst)

        print("\n=== Waiting for main menus ===")
        for i, inst in enumerate(instances):
            grid = wait_for_text(inst.transport, "Q=QUIT", timeout=60.0)
            if grid is None:
                print(f"  FATAL: Instance {i} (port {inst.port}) menu did not appear")
                sys.exit(1)
            print(f"  Instance {i}: menu ready")

        results = []
        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = {}
            for i, inst in enumerate(instances):
                fut = pool.submit(worker_run, i, inst.transport, labels, per_worker)
                futures[fut] = i

            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    wid = futures[fut]
                    print(f"  [Worker {wid}] EXCEPTION: {e}")
                    results.append((wid, 0, 1, 0.0))

        for inst in instances:
            mgr.release(inst)

    return sum(r[1] for r in results), sum(r[2] for r in results)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    iterations = DEFAULT_ITERATIONS
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        if idx + 1 < len(sys.argv):
            iterations = int(sys.argv[idx + 1])

    num_workers = DEFAULT_WORKERS
    if "--workers" in sys.argv:
        idx = sys.argv.index("--workers")
        if idx + 1 < len(sys.argv):
            num_workers = int(sys.argv[idx + 1])

    seed = random.randint(0, 2**32 - 1)
    if "--seed" in sys.argv:
        idx = sys.argv.index("--seed")
        if idx + 1 < len(sys.argv):
            seed = int(sys.argv[idx + 1])
    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")
    print(f"Workers: {num_workers}")

    # Build
    print("\n=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required_labels = [
        "key_data", "aes_key_expansion",
        "gcmsiv_nonce", "gcmsiv_pt_buf", "gcmsiv_pt_len",
        "gcmsiv_ct_buf", "gcmsiv_tag", "gcmsiv_tag_valid",
        "gcmsiv_dec_buf", "gcmsiv_encrypt", "gcmsiv_decrypt",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded")

    # Run tests
    if num_workers > 1:
        passed, failed = run_parallel(labels, iterations, num_workers)
    else:
        passed, failed = run_sequential(labels, iterations)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] GCM-SIV + POLYVAL: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] GCM-SIV + POLYVAL: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
