#!/usr/bin/env python3
"""
test_gcmsiv_encrypt_direct.py - Direct-Memory AES-256-GCM-SIV Encrypt Test

Tests the C64 AES-256-GCM-SIV implementation (now using POLYVAL) by calling
gcmsiv_encrypt directly via jsr().

Dual validation: C64 output is compared against BOTH:
  - cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV (OpenSSL-backed)
  - polyval_reference.gcmsiv_encrypt (pure-Python RFC 8452 reference)

Three-way consistency: AESGCMSIV must match polyval_reference (sanity check),
and C64 must match both.

RFC 8452 C.2 vectors (no-AAD) are run before random tests.

Usage:
    python3 tools/test_gcmsiv_encrypt_direct.py [--iterations N] [--seed S] [--workers N]

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
    ViceProcess,
    ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    wait_for_text,
    jsr,
)
from c64_test_harness.backends.vice_manager import ViceInstanceManager

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gcmsiv_test_vectors.json")
RFC_VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc8452_vectors.json")

MAX_PT_LEN = 64
DEFAULT_ITERATIONS = 50
DEFAULT_WORKERS = 1
PORT_RANGE_START = 6510

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randint(0, 255) for _ in range(length))


def openssl_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with OpenSSL-backed AESGCMSIV. Returns (ciphertext, tag)."""
    aead = AESGCMSIV(key)
    # AESGCMSIV.encrypt returns ciphertext || tag (16 bytes)
    ct_tag = aead.encrypt(nonce, plaintext, None)
    ct = ct_tag[:-16]
    tag = ct_tag[-16:]
    return ct, tag


def gcmsiv_encrypt_direct(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt via direct memory writes + jsr(). Returns (ciphertext, tag)."""
    write_bytes(transport, labels["key_data"], key)
    jsr(transport, labels["aes_key_expansion"], timeout=5.0)
    write_bytes(transport, labels["gcmsiv_nonce"], nonce)
    write_bytes(transport, labels["gcmsiv_pt_buf"], plaintext)
    write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(plaintext)]))
    jsr(transport, labels["gcmsiv_encrypt"], timeout=120.0)
    ciphertext = read_bytes(transport, labels["gcmsiv_ct_buf"], len(plaintext))
    tag = read_bytes(transport, labels["gcmsiv_tag"], 16)
    return ciphertext, tag


# ---------------------------------------------------------------------------
# Test case types
# ---------------------------------------------------------------------------

# (key, nonce, plaintext, label, expected_ct, expected_tag) - last two may be None for random
TestCase = tuple[bytes, bytes, bytes, str, bytes | None, bytes | None]


def test_encrypt_case(
    transport: ViceTransport,
    labels: Labels,
    case: TestCase,
) -> tuple[bool, dict]:
    """Test one encrypt case with three-way validation.

    Returns (pass_status, test_vector_dict).
    """
    key, nonce, plaintext, label, exp_ct, exp_tag = case
    pt_len = len(plaintext)
    print(f"\n--- {label}: {pt_len} bytes ---")

    # OpenSSL reference
    try:
        ossl_ct, ossl_tag = openssl_encrypt(key, nonce, plaintext)
    except Exception as e:
        print(f"  FAIL: OpenSSL raised {e}")
        return False, {}

    # Python reference
    try:
        py_ct, py_tag = py_gcmsiv_encrypt(key, nonce, plaintext)
    except Exception as e:
        print(f"  FAIL: Python reference raised {e}")
        return False, {}

    # Sanity: OpenSSL must match Python reference
    if ossl_ct != py_ct or ossl_tag != py_tag:
        print(f"  FAIL: OpenSSL vs Python reference mismatch!")
        print(f"    OpenSSL CT:  {ossl_ct.hex()}")
        print(f"    Python  CT:  {py_ct.hex()}")
        print(f"    OpenSSL Tag: {ossl_tag.hex()}")
        print(f"    Python  Tag: {py_tag.hex()}")
        return False, {}

    # If RFC vector, also check expected values
    if exp_ct is not None and exp_tag is not None:
        if ossl_ct != exp_ct or ossl_tag != exp_tag:
            print(f"  FAIL: OpenSSL doesn't match RFC expected!")
            return False, {}

    # C64 encrypt
    try:
        c64_ct, c64_tag = gcmsiv_encrypt_direct(transport, labels, key, nonce, plaintext)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, f"gcmsiv_encrypt_{pt_len}_error")
        return False, {}

    # Build test vector
    test_vector = {
        "key": key.hex(),
        "nonce": nonce.hex(),
        "plaintext": plaintext.hex(),
        "ciphertext": c64_ct.hex(),
        "tag": c64_tag.hex(),
    }

    if c64_ct == ossl_ct and c64_tag == ossl_tag:
        print(f"  PASS (ct={c64_ct[:4].hex()}..., tag={c64_tag[:4].hex()}...)")
        return True, test_vector
    else:
        print(f"  FAIL: C64 mismatch!")
        print(f"    Key:       {key.hex()}")
        print(f"    Nonce:     {nonce.hex()}")
        print(f"    Plaintext: {plaintext.hex()}")
        if c64_ct != ossl_ct:
            print(f"    Expected CT: {ossl_ct.hex()}")
            print(f"    Got CT:      {c64_ct.hex()}")
        if c64_tag != ossl_tag:
            print(f"    Expected Tag: {ossl_tag.hex()}")
            print(f"    Got Tag:      {c64_tag.hex()}")
        dump_screen(transport, f"gcmsiv_encrypt_{pt_len}_mismatch")
        return False, test_vector


# ---------------------------------------------------------------------------
# Test case generation
# ---------------------------------------------------------------------------

def load_rfc_vectors() -> list[TestCase]:
    """Load RFC 8452 C.2 vectors (no-AAD only)."""
    cases = []
    if not os.path.exists(RFC_VECTORS_PATH):
        print(f"  Warning: {RFC_VECTORS_PATH} not found, skipping RFC vectors")
        return cases

    with open(RFC_VECTORS_PATH) as f:
        data = json.load(f)

    for v in data.get("aes256_gcmsiv_vectors", []):
        if v.get("aad", ""):
            continue  # C64 doesn't support AAD
        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"])
        pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
        ct = bytes.fromhex(v["ciphertext"]) if v["ciphertext"] else b""
        tag = bytes.fromhex(v["tag"])
        if len(pt) == 0 or len(pt) > MAX_PT_LEN:
            continue  # C64 doesn't support empty PT; skip oversized
        cases.append((key, nonce, pt, f"RFC: {v['name']}", ct, tag))
    return cases


def generate_test_cases(
    iterations: int,
    rng: random.Random,
) -> list[TestCase]:
    """Generate all test cases (RFC vectors + boundary + random)."""
    cases: list[TestCase] = []

    # RFC vectors first
    cases.extend(load_rfc_vectors())

    # Boundary cases
    boundary_sizes = [1, 15, 16, 17, 32, 48, 63, 64]
    for size in boundary_sizes:
        key = generate_random_bytes(rng, 32)
        nonce = generate_random_bytes(rng, 12)
        plaintext = generate_random_bytes(rng, size)
        cases.append((key, nonce, plaintext, f"Boundary: {size} bytes", None, None))

    # Random tests
    fixed_count = len(cases)
    random_count = max(0, iterations - fixed_count)
    for i in range(random_count):
        pt_len = rng.randint(1, MAX_PT_LEN)
        key = generate_random_bytes(rng, 32)
        nonce = generate_random_bytes(rng, 12)
        plaintext = generate_random_bytes(rng, pt_len)
        cases.append((key, nonce, plaintext, f"Random {i+1}/{random_count} ({pt_len}B)", None, None))

    return cases


# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------

def run_sequential(labels: Labels, iterations: int) -> tuple[int, int, list[dict]]:
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

        rng = random.Random(random.getrandbits(64))
        cases = generate_test_cases(iterations, rng)

        print(f"\n=== AES-256-GCM-SIV Encrypt Tests ({len(cases)} tests) ===")

        passed = 0
        failed = 0
        vectors = []

        for case in cases:
            ok, vec = test_encrypt_case(transport, labels, case)
            if ok:
                passed += 1
                if vec:
                    vectors.append(vec)
            else:
                failed += 1

        return passed, failed, vectors


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def worker(
    worker_id: int,
    transport: ViceTransport,
    labels: Labels,
    cases: list[TestCase],
) -> tuple[int, int, int, float, list[dict]]:
    t0 = time.monotonic()
    passed = 0
    failed = 0
    vectors = []

    print(f"  [Worker {worker_id}] Starting ({len(cases)} tests)")

    for case in cases:
        key, nonce, pt, label, exp_ct, exp_tag = case
        tagged = (key, nonce, pt, f"[W{worker_id}] {label}", exp_ct, exp_tag)
        ok, vec = test_encrypt_case(transport, labels, tagged)
        if ok:
            passed += 1
            if vec:
                vectors.append(vec)
        else:
            failed += 1

    duration = time.monotonic() - t0
    print(f"  [Worker {worker_id}] Done: {passed} passed, {failed} failed ({duration:.1f}s)")
    return worker_id, passed, failed, duration, vectors


def run_parallel(labels: Labels, iterations: int, num_workers: int) -> tuple[int, int, list[dict]]:
    rng = random.Random(random.getrandbits(64))
    all_cases = generate_test_cases(iterations, rng)

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
        print(f"\n=== AES-256-GCM-SIV Encrypt Tests ({total_tests} tests x {num_workers} workers) ===")

        results: list[tuple[int, int, int, float, list[dict]]] = []

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
                    results.append((wid, 0, len(batches[wid]), 0.0, []))

        for inst in instances:
            mgr.release(inst)

    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    all_vectors: list[dict] = []
    for r in sorted(results):
        all_vectors.extend(r[4])

    return total_passed, total_failed, all_vectors


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
        "gcmsiv_ct_buf", "gcmsiv_tag", "gcmsiv_encrypt",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded:")
    print(f"    gcmsiv_encrypt  @ ${labels['gcmsiv_encrypt']:04X}")
    print(f"    gcmsiv_nonce    @ ${labels['gcmsiv_nonce']:04X}")
    print(f"    gcmsiv_pt_buf   @ ${labels['gcmsiv_pt_buf']:04X}")
    print(f"    gcmsiv_ct_buf   @ ${labels['gcmsiv_ct_buf']:04X}")
    print(f"    gcmsiv_tag      @ ${labels['gcmsiv_tag']:04X}")

    # Run tests
    if num_workers > 1:
        passed, failed, test_vectors = run_parallel(labels, iterations, num_workers)
    else:
        passed, failed, test_vectors = run_sequential(labels, iterations)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")

    if failed == 0:
        print(f"\n  [+] AES-256-GCM-SIV Encrypt: ALL {total} TESTS PASSED")

        # Save test vectors
        print(f"\n  Saving {len(test_vectors)} test vectors to {VECTORS_PATH}...")
        with open(VECTORS_PATH, "w") as f:
            json.dump(test_vectors, f, indent=2)
        print(f"  Test vectors saved successfully")
    else:
        print(f"\n  [-] AES-256-GCM-SIV Encrypt: {failed} TEST(S) FAILED")

    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
