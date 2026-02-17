#!/usr/bin/env python3
"""
test_gcmsiv_decrypt_direct.py - Direct-Memory AES-256-GCM-SIV Decrypt Test

Tests the C64 AES-256-GCM-SIV decrypt implementation by calling gcmsiv_decrypt
directly via jsr() — writing ciphertext/tag/nonce/key data and reading decrypted
output through memory, bypassing the menu UI entirely.

This is significantly faster per iteration than menu-driven tests.

IMPORTANT: gcmsiv_decrypt requires aes_key_expansion to be called first,
because gcmsiv_derive_keys calls aes_encrypt_block with the main key.

CRITICAL: Decrypted output is at gcmsiv_dec_buf ($4636), NOT gcmsiv_pt_buf.

CRITICAL: On tag mismatch, C64 zeros out gcmsiv_dec_buf (64 bytes) and sets
gcmsiv_tag_valid to 0.

Usage:
    # Standalone (single VICE instance, sequential):
    python3 tools/test_gcmsiv_decrypt_direct.py [--iterations N] [--seed S] [--vectors PATH]

    # Parallel (multiple VICE instances):
    python3 tools/test_gcmsiv_decrypt_direct.py --workers 3 [--iterations N] [--seed S] [--vectors PATH]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import json
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import gcmsiv_reference

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

MAX_PT_LEN = 64
DEFAULT_ITERATIONS = 50
DEFAULT_WORKERS = 1
PORT_RANGE_START = 6510


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_bytes(rng: random.Random, length: int) -> bytes:
    """Generate random bytes using the given RNG."""
    return bytes(rng.randint(0, 255) for _ in range(length))


def gcmsiv_decrypt_direct(
    transport: ViceTransport,
    labels: Labels,
    ciphertext: bytes,
    tag: bytes,
    nonce: bytes,
    key: bytes,
) -> tuple[bytes, bool]:
    """Decrypt via direct memory writes + jsr().

    Returns (decrypted_bytes, tag_valid).

    IMPORTANT: Must call aes_key_expansion before gcmsiv_decrypt.
    """
    # Write key and expand
    write_bytes(transport, labels["key_data"], key)
    jsr(transport, labels["aes_key_expansion"], timeout=5.0)

    # Write nonce
    write_bytes(transport, labels["gcmsiv_nonce"], nonce)

    # Write ciphertext
    write_bytes(transport, labels["gcmsiv_ct_buf"], ciphertext)
    write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(ciphertext)]))

    # Write tag
    write_bytes(transport, labels["gcmsiv_tag"], tag)

    # Decrypt
    jsr(transport, labels["gcmsiv_decrypt"], timeout=60.0)

    # Read results
    decrypted = read_bytes(transport, labels["gcmsiv_dec_buf"], len(ciphertext))
    tag_valid_byte = read_bytes(transport, labels["gcmsiv_tag_valid"], 1)
    tag_valid = tag_valid_byte[0] == 1

    return decrypted, tag_valid


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_gcmsiv_decrypt_valid(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    label: str,
) -> bool:
    """Test GCM-SIV decrypt with valid ciphertext/tag.

    1. Encrypt plaintext with Python reference to get (ciphertext, tag)
    2. Decrypt via direct memory on C64
    3. Verify tag_valid==1 and decrypted output matches plaintext

    Returns True on pass, False on fail.
    """
    pt_len = len(plaintext)

    # Encrypt with Python reference
    ciphertext, tag = gcmsiv_reference.encrypt(key, nonce, plaintext)
    ct_len = len(ciphertext)

    print(f"\n--- {label}: {pt_len} bytes PT -> {ct_len}-byte CT ---")

    # Safety check
    assert ct_len <= 64, f"BUG: ciphertext length {ct_len} exceeds buffer (64)"

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
        print(f"    Key:       {key.hex()}")
        print(f"    Nonce:     {nonce.hex()}")
        print(f"    Plaintext: {plaintext.hex()}")
        print(f"    CT:        {ciphertext.hex()}")
        print(f"    Tag:       {tag.hex()}")
        dump_screen(transport, f"gcmsiv_decrypt_{pt_len}_invalid")
        return False

    if decrypted == plaintext:
        print("  PASS")
        return True
    else:
        print(f"  FAIL: decrypted output mismatch")
        print(f"    Expected: {plaintext.hex()}")
        print(f"    Got:      {decrypted.hex()}")
        print(f"    Key:      {key.hex()}")
        print(f"    Nonce:    {nonce.hex()}")
        print(f"    CT:       {ciphertext.hex()}")
        print(f"    Tag:      {tag.hex()}")
        dump_screen(transport, f"gcmsiv_decrypt_{pt_len}_mismatch")
        return False


def test_gcmsiv_decrypt_tampered(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    label: str,
) -> bool:
    """Test GCM-SIV decrypt with tampered tag.

    1. Encrypt plaintext with Python reference
    2. Flip a bit in the tag
    3. Decrypt via C64
    4. Verify tag_valid==0 and gcmsiv_dec_buf is all zeros (64 bytes)

    Returns True on pass, False on fail.
    """
    pt_len = len(plaintext)

    # Encrypt with Python reference
    ciphertext, tag = gcmsiv_reference.encrypt(key, nonce, plaintext)

    # Tamper with tag
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01

    print(f"\n--- {label}: {pt_len} bytes PT (tag tampered) ---")

    try:
        decrypted, tag_valid = gcmsiv_decrypt_direct(
            transport, labels, ciphertext, bytes(bad_tag), nonce, key
        )
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, f"gcmsiv_tamper_{pt_len}_error")
        return False

    # Verify tag_valid == 0
    if tag_valid:
        print(f"  FAIL: tag_valid == 1 (expected 0)")
        dump_screen(transport, f"gcmsiv_tamper_{pt_len}_accepted")
        return False

    # Verify decrypted is all zeros (C64 clears dec_buf on tag mismatch)
    # Read full 64-byte buffer
    full_dec_buf = read_bytes(transport, labels["gcmsiv_dec_buf"], 64)
    if full_dec_buf != b'\x00' * 64:
        print(f"  FAIL: gcmsiv_dec_buf not zeroed on tag mismatch")
        print(f"    Expected: {(b'\\x00' * 64).hex()}")
        print(f"    Got:      {full_dec_buf.hex()}")
        dump_screen(transport, f"gcmsiv_tamper_{pt_len}_not_zeroed")
        return False

    print("  PASS (tag correctly rejected, dec_buf zeroed)")
    return True


# ---------------------------------------------------------------------------
# Test case generation
# ---------------------------------------------------------------------------

# Test case: (key, nonce, plaintext, label, is_tamper)
TestCase = tuple[bytes, bytes, bytes, str, bool]


def generate_test_cases(
    iterations: int,
    rng: random.Random,
    vectors: list[dict] | None,
) -> list[TestCase]:
    """Generate all test cases (vectors, boundary, random, tamper).

    Returns list of (key, nonce, plaintext, label, is_tamper) tuples.
    """
    cases: list[TestCase] = []

    if vectors:
        for i, vec in enumerate(vectors):
            key = bytes.fromhex(vec["key"])
            nonce = bytes.fromhex(vec["nonce"])
            plaintext = bytes.fromhex(vec["plaintext"])
            cases.append((key, nonce, plaintext, f"Vector {i + 1}/{len(vectors)}", False))
    else:
        # Boundary cases
        boundary_sizes = [
            (1, "Boundary: 1 byte"),
            (15, "Boundary: 15 bytes"),
            (16, "Boundary: 16 bytes (block boundary)"),
            (17, "Boundary: 17 bytes"),
            (32, "Boundary: 32 bytes (2 blocks)"),
            (48, "Boundary: 48 bytes (3 blocks)"),
            (63, "Boundary: 63 bytes"),
            (64, "Boundary: 64 bytes (max)"),
        ]

        for pt_len, label in boundary_sizes:
            key = generate_random_bytes(rng, 32)
            nonce = generate_random_bytes(rng, 12)
            plaintext = generate_random_bytes(rng, pt_len)
            cases.append((key, nonce, plaintext, label, False))

        # Random valid decrypts
        fixed_count = len(boundary_sizes)
        tamper_count = 5
        random_count = max(0, iterations - fixed_count - tamper_count)

        for i in range(random_count):
            pt_len = rng.randint(1, MAX_PT_LEN)
            key = generate_random_bytes(rng, 32)
            nonce = generate_random_bytes(rng, 12)
            plaintext = generate_random_bytes(rng, pt_len)
            cases.append((key, nonce, plaintext, f"Random test {i + 1}/{random_count}", False))

        # Tag tampering tests
        tamper_sizes = [1, 16, 32, 48, 64]
        for i, pt_len in enumerate(tamper_sizes):
            key = generate_random_bytes(rng, 32)
            nonce = generate_random_bytes(rng, 12)
            plaintext = generate_random_bytes(rng, pt_len)
            cases.append((key, nonce, plaintext, f"Tamper test {i + 1}/{len(tamper_sizes)}", True))

    return cases


def run_case(
    transport: ViceTransport,
    labels: Labels,
    case: TestCase,
) -> bool:
    """Run a single test case (valid or tampered)."""
    key, nonce, plaintext, label, is_tamper = case
    if is_tamper:
        return test_gcmsiv_decrypt_tampered(transport, labels, key, nonce, plaintext, label)
    else:
        return test_gcmsiv_decrypt_valid(transport, labels, key, nonce, plaintext, label)


# ---------------------------------------------------------------------------
# Sequential runner (standalone mode)
# ---------------------------------------------------------------------------

def run_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
    vectors: list[dict] | None,
) -> tuple[int, int]:
    """Run all GCM-SIV decrypt direct tests sequentially. Returns (passed, failed)."""
    passed = 0
    failed = 0

    rng = random.Random(random.getrandbits(64))
    cases = generate_test_cases(iterations, rng, vectors)

    # Print tamper section header at the right point
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

    return passed, failed


def run_sequential(
    labels: Labels,
    iterations: int,
    vectors: list[dict] | None,
) -> tuple[int, int]:
    """Standalone mode: single VICE instance, sequential execution."""
    print("\n=== Starting VICE ===")
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

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

        total_label = f"{iterations} iterations" if not vectors else f"{len(vectors)} vectors"
        print(f"\n=== AES-256-GCM-SIV Decrypt Direct Tests ({total_label}) ===")
        return run_tests(transport, labels, iterations, vectors)


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def worker(
    worker_id: int,
    transport: ViceTransport,
    labels: Labels,
    cases: list[TestCase],
) -> tuple[int, int, int, float]:
    """Run a batch of decrypt tests on one VICE instance.

    Returns (worker_id, passed, failed, duration).
    """
    t0 = time.monotonic()
    passed = 0
    failed = 0

    print(f"  [Worker {worker_id}] Starting ({len(cases)} tests)")

    for case in cases:
        key, nonce, plaintext, label, is_tamper = case
        tagged_label = f"[W{worker_id}] {label}"
        tagged_case = (key, nonce, plaintext, tagged_label, is_tamper)
        if run_case(transport, labels, tagged_case):
            passed += 1
        else:
            failed += 1

    duration = time.monotonic() - t0
    print(f"  [Worker {worker_id}] Done: {passed} passed, {failed} failed ({duration:.1f}s)")
    return worker_id, passed, failed, duration


def run_parallel(
    labels: Labels,
    iterations: int,
    num_workers: int,
    vectors: list[dict] | None,
) -> tuple[int, int]:
    """Parallel mode: multiple VICE instances, batched execution."""
    # Generate all test cases upfront (deterministic from seed)
    rng = random.Random(random.getrandbits(64))
    all_cases = generate_test_cases(iterations, rng, vectors)

    # Distribute cases across workers (round-robin for balance)
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
        # Acquire all instances
        instances = []
        for i in range(num_workers):
            inst = mgr.acquire()
            pid = inst.process.pid if inst.process else "?"
            print(f"  Instance {i}: port {inst.port}, PID {pid}")
            instances.append(inst)

        # Wait for each instance's main menu
        print("\n=== Waiting for main menus ===")
        for i, inst in enumerate(instances):
            grid = wait_for_text(inst.transport, "Q=QUIT", timeout=60.0)
            if grid is None:
                print(f"  FATAL: Instance {i} (port {inst.port}) menu did not appear")
                dump_screen(inst.transport, f"startup_{i}")
                sys.exit(1)
            print(f"  Instance {i}: menu ready")

        # Run tests in parallel
        total_tests = len(all_cases)
        print(f"\n=== AES-256-GCM-SIV Decrypt Direct Tests ({total_tests} tests x {num_workers} workers) ===")

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

        # Release instances
        for inst in instances:
            mgr.release(inst)

    # Aggregate results
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)

    return total_passed, total_failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    # Parse args
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

    vectors = None
    if "--vectors" in sys.argv:
        idx = sys.argv.index("--vectors")
        if idx + 1 < len(sys.argv):
            vectors_path = sys.argv[idx + 1]
            with open(vectors_path, "r") as f:
                vectors = json.load(f)
            print(f"Loaded {len(vectors)} test vectors from {vectors_path}")

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
    print(f"    key_data            @ ${labels['key_data']:04X}")
    print(f"    aes_key_expansion   @ ${labels['aes_key_expansion']:04X}")
    print(f"    gcmsiv_nonce        @ ${labels['gcmsiv_nonce']:04X}")
    print(f"    gcmsiv_ct_buf       @ ${labels['gcmsiv_ct_buf']:04X}")
    print(f"    gcmsiv_pt_len       @ ${labels['gcmsiv_pt_len']:04X}")
    print(f"    gcmsiv_tag          @ ${labels['gcmsiv_tag']:04X}")
    print(f"    gcmsiv_dec_buf      @ ${labels['gcmsiv_dec_buf']:04X}")
    print(f"    gcmsiv_tag_valid    @ ${labels['gcmsiv_tag_valid']:04X}")
    print(f"    gcmsiv_decrypt      @ ${labels['gcmsiv_decrypt']:04X}")

    # Run tests
    if num_workers > 1:
        passed, failed = run_parallel(labels, iterations, num_workers, vectors)
    else:
        passed, failed = run_sequential(labels, iterations, vectors)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] AES-256-GCM-SIV Decrypt Direct: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] AES-256-GCM-SIV Decrypt Direct: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
