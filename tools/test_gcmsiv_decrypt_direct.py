#!/usr/bin/env python3
"""
test_gcmsiv_decrypt_direct.py - Direct-Memory AES-256-GCM-SIV Decrypt Test

Tests the C64 AES-256-GCM-SIV decrypt implementation (now using POLYVAL)
by calling gcmsiv_decrypt directly via jsr().

Dual validation: Uses AESGCMSIV (OpenSSL-backed) to encrypt, then C64 to
decrypt, verifying plaintext matches. Also cross-checks against
polyval_reference.

RFC 8452 C.2 vectors (no-AAD) are decrypted before random tests.

Usage:
    python3 tools/test_gcmsiv_decrypt_direct.py [--iterations N] [--seed S] [--workers N]

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
from polyval_reference import gcmsiv_encrypt as py_gcmsiv_encrypt

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from c64_test_harness import (
    Labels,
    ViceConfig,
    C64Transport as ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    wait_for_text,
    jsr,
)
from c64_test_harness.backends.vice_manager import ViceInstanceManager
from c64_test_utils import robust_jsr, generate_random_bytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
RFC_VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc8452_vectors.json")

MAX_PT_LEN = 64
DEFAULT_ITERATIONS = 50
DEFAULT_WORKERS = 1
PORT_RANGE_START = 6510


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def openssl_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with OpenSSL-backed AESGCMSIV. Returns (ciphertext, tag)."""
    aead = AESGCMSIV(key)
    ct_tag = aead.encrypt(nonce, plaintext, None)
    ct = ct_tag[:-16]
    tag = ct_tag[-16:]
    return ct, tag


def gcmsiv_decrypt_direct(
    transport: ViceTransport,
    labels: Labels,
    ciphertext: bytes,
    tag: bytes,
    nonce: bytes,
    key: bytes,
) -> tuple[bytes, bool]:
    """Decrypt via direct memory writes + jsr(). Returns (decrypted, tag_valid)."""
    write_bytes(transport, labels["key_data"], key)
    robust_jsr(transport, labels["aes_key_expansion"], timeout=5.0)
    write_bytes(transport, labels["gcmsiv_nonce"], nonce)
    write_bytes(transport, labels["gcmsiv_ct_buf"], ciphertext)
    write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(ciphertext)]))
    write_bytes(transport, labels["gcmsiv_tag"], tag)
    robust_jsr(transport, labels["gcmsiv_decrypt"], timeout=120.0)
    decrypted = read_bytes(transport, labels["gcmsiv_dec_buf"], len(ciphertext))
    tag_valid_byte = read_bytes(transport, labels["gcmsiv_tag_valid"], 1)
    return decrypted, tag_valid_byte[0] == 1


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

# (key, nonce, plaintext, label, is_tamper)
TestCase = tuple[bytes, bytes, bytes, str, bool]


def test_decrypt_valid(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    label: str,
) -> bool:
    """Encrypt with AESGCMSIV, decrypt on C64, verify."""
    pt_len = len(plaintext)
    print(f"\n--- {label}: {pt_len} bytes ---")

    # Encrypt with OpenSSL
    try:
        ciphertext, tag = openssl_encrypt(key, nonce, plaintext)
    except Exception as e:
        print(f"  FAIL: OpenSSL encrypt raised {e}")
        return False

    # Cross-check with Python reference
    py_ct, py_tag = py_gcmsiv_encrypt(key, nonce, plaintext)
    if ciphertext != py_ct or tag != py_tag:
        print(f"  FAIL: OpenSSL vs Python reference mismatch during encrypt")
        return False

    try:
        decrypted, tag_valid = gcmsiv_decrypt_direct(
            transport, labels, ciphertext, tag, nonce, key
        )
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, f"gcmsiv_decrypt_{pt_len}_error")
        return False

    if not tag_valid:
        print(f"  FAIL: tag_valid == 0 (expected 1)")
        print(f"    Key:   {key.hex()}")
        print(f"    Nonce: {nonce.hex()}")
        print(f"    PT:    {plaintext.hex()}")
        print(f"    CT:    {ciphertext.hex()}")
        print(f"    Tag:   {tag.hex()}")
        dump_screen(transport, f"gcmsiv_decrypt_{pt_len}_invalid")
        return False

    if decrypted == plaintext:
        print("  PASS")
        return True
    else:
        print(f"  FAIL: decrypted output mismatch")
        print(f"    Expected: {plaintext.hex()}")
        print(f"    Got:      {decrypted.hex()}")
        dump_screen(transport, f"gcmsiv_decrypt_{pt_len}_mismatch")
        return False


def test_decrypt_rfc_vector(
    transport: ViceTransport,
    labels: Labels,
    vector: dict,
) -> bool:
    """Decrypt an RFC 8452 C.2 vector on C64."""
    name = vector["name"]
    print(f"\n--- RFC Decrypt: {name} ---")

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

    try:
        decrypted, tag_valid = gcmsiv_decrypt_direct(
            transport, labels, ct, tag, nonce, key
        )
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if decrypted == expected_pt and tag_valid:
        print(f"  PASS: pt={decrypted.hex() if decrypted else '(empty)'}")
        return True
    else:
        print(f"  FAIL:")
        if decrypted != expected_pt:
            print(f"    PT expected: {expected_pt.hex()}")
            print(f"    PT got:      {decrypted.hex()}")
        if not tag_valid:
            print(f"    Tag verification failed")
        return False


def test_decrypt_tampered(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    label: str,
) -> bool:
    """Encrypt with AESGCMSIV, flip tag bit, verify C64 rejects."""
    pt_len = len(plaintext)
    print(f"\n--- {label}: {pt_len} bytes (tag tampered) ---")

    ciphertext, tag = openssl_encrypt(key, nonce, plaintext)
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01

    try:
        decrypted, tag_valid = gcmsiv_decrypt_direct(
            transport, labels, ciphertext, bytes(bad_tag), nonce, key
        )
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        return False

    if tag_valid:
        print(f"  FAIL: tag_valid == 1 (expected 0)")
        return False

    full_dec_buf = read_bytes(transport, labels["gcmsiv_dec_buf"], 64)
    if full_dec_buf != b'\x00' * 64:
        print(f"  FAIL: gcmsiv_dec_buf not zeroed on tag mismatch")
        return False

    print("  PASS (tag correctly rejected, dec_buf zeroed)")
    return True


# ---------------------------------------------------------------------------
# Test case generation
# ---------------------------------------------------------------------------

def generate_test_cases(
    iterations: int,
    rng: random.Random,
) -> list[TestCase]:
    cases: list[TestCase] = []

    # Boundary cases
    boundary_sizes = [1, 15, 16, 17, 32, 48, 63, 64]
    for size in boundary_sizes:
        key = generate_random_bytes(32, rng)
        nonce = generate_random_bytes(12, rng)
        plaintext = generate_random_bytes(size, rng)
        cases.append((key, nonce, plaintext, f"Boundary: {size} bytes", False))

    # Random valid decrypts
    tamper_count = 5
    random_count = max(0, iterations - len(boundary_sizes) - tamper_count)
    for i in range(random_count):
        pt_len = rng.randint(1, MAX_PT_LEN)
        key = generate_random_bytes(32, rng)
        nonce = generate_random_bytes(12, rng)
        plaintext = generate_random_bytes(pt_len, rng)
        cases.append((key, nonce, plaintext, f"Random {i+1}/{random_count}", False))

    # Tag tampering tests
    tamper_sizes = [1, 16, 32, 48, 64]
    for i, pt_len in enumerate(tamper_sizes):
        key = generate_random_bytes(32, rng)
        nonce = generate_random_bytes(12, rng)
        plaintext = generate_random_bytes(pt_len, rng)
        cases.append((key, nonce, plaintext, f"Tamper {i+1}/{len(tamper_sizes)}", True))

    return cases


def run_case(
    transport: ViceTransport,
    labels: Labels,
    case: TestCase,
) -> bool:
    key, nonce, plaintext, label, is_tamper = case
    if is_tamper:
        return test_decrypt_tampered(transport, labels, key, nonce, plaintext, label)
    else:
        return test_decrypt_valid(transport, labels, key, nonce, plaintext, label)


# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------

def run_sequential(labels: Labels, iterations: int) -> tuple[int, int]:
    print("\n=== Starting VICE ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"  VICE started (PID={inst.pid}, port={inst.port})")

        transport = inst.transport

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            mgr.release(inst)
            sys.exit(1)
        print("  Main menu ready")

        passed = 0
        failed = 0

        # RFC vector decrypt tests first
        if os.path.exists(RFC_VECTORS_PATH):
            with open(RFC_VECTORS_PATH) as f:
                data = json.load(f)
            no_aad_vectors = [v for v in data.get("aes256_gcmsiv_vectors", [])
                              if not v.get("aad", "")]
            print(f"\n=== RFC 8452 C.2 Vector Decrypt ({len(no_aad_vectors)} vectors) ===")
            for v in no_aad_vectors:
                if test_decrypt_rfc_vector(transport, labels, v):
                    passed += 1
                else:
                    failed += 1

        # Random tests
        rng = random.Random(random.getrandbits(64))
        cases = generate_test_cases(iterations, rng)

        print(f"\n=== AES-256-GCM-SIV Decrypt Tests ({len(cases)} tests) ===")

        tamper_started = False
        for case in cases:
            key, nonce, plaintext, label, is_tamper = case
            if is_tamper and not tamper_started:
                print("\n\n=== Tag Tampering Tests ===")
                tamper_started = True
            if run_case(transport, labels, case):
                passed += 1
            else:
                failed += 1

        mgr.release(inst)
        return passed, failed


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def worker(
    worker_id: int,
    transport: ViceTransport,
    labels: Labels,
    cases: list[TestCase],
) -> tuple[int, int, int, float]:
    t0 = time.monotonic()
    passed = 0
    failed = 0

    print(f"  [Worker {worker_id}] Starting ({len(cases)} tests)")

    for case in cases:
        key, nonce, plaintext, label, is_tamper = case
        tagged = (key, nonce, plaintext, f"[W{worker_id}] {label}", is_tamper)
        if run_case(transport, labels, tagged):
            passed += 1
        else:
            failed += 1

    duration = time.monotonic() - t0
    print(f"  [Worker {worker_id}] Done: {passed} passed, {failed} failed ({duration:.1f}s)")
    return worker_id, passed, failed, duration


def run_parallel(labels: Labels, iterations: int, num_workers: int) -> tuple[int, int]:
    rng = random.Random(random.getrandbits(64))
    all_cases = generate_test_cases(iterations, rng)

    # Also add RFC vector cases
    rfc_cases: list[TestCase] = []
    if os.path.exists(RFC_VECTORS_PATH):
        with open(RFC_VECTORS_PATH) as f:
            data = json.load(f)
        for v in data.get("aes256_gcmsiv_vectors", []):
            if v.get("aad", ""):
                continue
            key = bytes.fromhex(v["key"])
            nonce = bytes.fromhex(v["nonce"])
            pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
            if len(pt) == 0 or len(pt) > MAX_PT_LEN:
                continue  # C64 doesn't support empty PT; skip oversized
            rfc_cases.append((key, nonce, pt, f"RFC: {v['name']}", False))

    all_cases = rfc_cases + all_cases

    batches: list[list[TestCase]] = [[] for _ in range(num_workers)]
    for i, case in enumerate(all_cases):
        batches[i % num_workers].append(case)

    port_end = PORT_RANGE_START + num_workers
    print(f"\n=== Starting {num_workers} VICE instances (ports {PORT_RANGE_START}-{port_end - 1}) ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

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
                dump_screen(inst.transport, f"startup_{i}")
                sys.exit(1)
            print(f"  Instance {i}: menu ready")

        total_tests = len(all_cases)
        print(f"\n=== AES-256-GCM-SIV Decrypt Tests ({total_tests} tests x {num_workers} workers) ===")

        results: list[tuple[int, int, int, float]] = []

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = {}
            for i, inst in enumerate(instances):
                fut = pool.submit(worker, i, inst.transport, labels, batches[i])
                futures[fut] = i

            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    wid = futures[fut]
                    print(f"  [Worker {wid}] EXCEPTION: {e}")
                    results.append((wid, 0, len(batches[wid]), 0.0))

        for inst in instances:
            mgr.release(inst)

    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    return total_passed, total_failed


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
        "gcmsiv_nonce", "gcmsiv_ct_buf", "gcmsiv_pt_len",
        "gcmsiv_tag", "gcmsiv_dec_buf", "gcmsiv_tag_valid",
        "gcmsiv_decrypt",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded:")
    print(f"    gcmsiv_decrypt      @ ${labels['gcmsiv_decrypt']:04X}")
    print(f"    gcmsiv_dec_buf      @ ${labels['gcmsiv_dec_buf']:04X}")
    print(f"    gcmsiv_tag_valid    @ ${labels['gcmsiv_tag_valid']:04X}")

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
        print(f"\n  [+] AES-256-GCM-SIV Decrypt: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] AES-256-GCM-SIV Decrypt: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
