#!/usr/bin/env python3
"""
test_gcmsiv_encrypt_direct.py - Direct-Memory AES-256-GCM-SIV Encrypt Test

Tests the C64 AES-256-GCM-SIV implementation by calling gcmsiv_encrypt directly
via jsr() — writing key/nonce/plaintext and reading ciphertext/tag through memory,
bypassing the menu UI entirely.

This enables comprehensive testing against the Python reference implementation.

Usage:
    # Standalone (single VICE instance, sequential):
    python3 tools/test_gcmsiv_encrypt_direct.py [--iterations N] [--seed S]

    # Parallel (multiple VICE instances):
    python3 tools/test_gcmsiv_encrypt_direct.py --workers 3 [--iterations N] [--seed S]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import json
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import GCM-SIV reference implementation
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
VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gcmsiv_test_vectors.json")

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


def gcmsiv_encrypt_direct(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes
) -> tuple[bytes, bytes]:
    """Encrypt via direct memory writes + jsr().

    Returns (ciphertext, tag).
    """
    # Write key and expand it (CRITICAL!)
    write_bytes(transport, labels["key_data"], key)
    jsr(transport, labels["aes_key_expansion"], timeout=5.0)

    # Write nonce
    write_bytes(transport, labels["gcmsiv_nonce"], nonce)

    # Write plaintext and length
    write_bytes(transport, labels["gcmsiv_pt_buf"], plaintext)
    write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(plaintext)]))

    # Call gcmsiv_encrypt (can be slow - up to 120s for 64 bytes!)
    jsr(transport, labels["gcmsiv_encrypt"], timeout=120.0)

    # Read results
    ciphertext = read_bytes(transport, labels["gcmsiv_ct_buf"], len(plaintext))
    tag = read_bytes(transport, labels["gcmsiv_tag"], 16)

    return ciphertext, tag


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_gcmsiv_encrypt_case(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    label: str,
) -> tuple[bool, dict]:
    """Test GCM-SIV encryption for given key/nonce/plaintext.

    Returns (pass_status, test_vector_dict).
    """
    pt_len = len(plaintext)
    print(f"\n--- {label}: {pt_len} bytes ---")

    # Compute reference ciphertext and tag
    try:
        ref_ct, ref_tag = gcmsiv_reference.encrypt(key, nonce, plaintext)
    except Exception as e:
        print(f"  FAIL: Python reference raised {e}")
        return False, {}

    # Compute C64 ciphertext and tag
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

    # Verify ciphertext and tag match reference
    if c64_ct == ref_ct and c64_tag == ref_tag:
        print(f"  PASS (ct={c64_ct[:4].hex()}..., tag={c64_tag[:4].hex()}...)")
        return True, test_vector
    else:
        print(f"  FAIL: mismatch!")
        print(f"    Key:       {key.hex()}")
        print(f"    Nonce:     {nonce.hex()}")
        print(f"    Plaintext: {plaintext.hex()}")
        if c64_ct != ref_ct:
            print(f"    Expected CT: {ref_ct.hex()}")
            print(f"    Got CT:      {c64_ct.hex()}")
        if c64_tag != ref_tag:
            print(f"    Expected Tag: {ref_tag.hex()}")
            print(f"    Got Tag:      {c64_tag.hex()}")
        dump_screen(transport, f"gcmsiv_encrypt_{pt_len}_mismatch")
        return False, test_vector


# ---------------------------------------------------------------------------
# Test case generation
# ---------------------------------------------------------------------------

def generate_test_cases(
    iterations: int,
    rng: random.Random,
) -> list[tuple[bytes, bytes, bytes, str]]:
    """Generate all test cases (boundary + random).

    Returns list of (key, nonce, plaintext, label) tuples.
    """
    cases: list[tuple[bytes, bytes, bytes, str]] = []

    # Boundary cases with known sizes
    boundary_sizes = [1, 15, 16, 17, 32, 48, 63, 64]
    for size in boundary_sizes:
        key = generate_random_bytes(rng, 32)
        nonce = generate_random_bytes(rng, 12)
        plaintext = generate_random_bytes(rng, size)
        cases.append((key, nonce, plaintext, f"Boundary: {size} bytes"))

    # Random tests — fill remaining iterations
    random_count = max(0, iterations - len(boundary_sizes))
    for i in range(random_count):
        pt_len = rng.randint(1, MAX_PT_LEN)
        key = generate_random_bytes(rng, 32)
        nonce = generate_random_bytes(rng, 12)
        plaintext = generate_random_bytes(rng, pt_len)
        cases.append((key, nonce, plaintext, f"Random test {i + 1}/{random_count} ({pt_len} bytes)"))

    return cases


# ---------------------------------------------------------------------------
# Sequential runner (standalone mode)
# ---------------------------------------------------------------------------

def run_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
) -> tuple[int, int, list[dict]]:
    """Run all GCM-SIV encrypt tests sequentially. Returns (passed, failed, test_vectors)."""
    passed = 0
    failed = 0
    test_vectors = []

    # Use the module-level RNG (seeded in main)
    cases = generate_test_cases(iterations, random.Random(random.getrandbits(64)))

    for key, nonce, plaintext, label in cases:
        ok, vector = test_gcmsiv_encrypt_case(transport, labels, key, nonce, plaintext, label)
        if ok:
            passed += 1
            test_vectors.append(vector)
        else:
            failed += 1

    return passed, failed, test_vectors


def run_sequential(labels: Labels, iterations: int) -> tuple[int, int, list[dict]]:
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

        print(f"\n=== AES-256-GCM-SIV Encrypt Direct Tests ({iterations} iterations) ===")
        return run_tests(transport, labels, iterations)


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def worker(
    worker_id: int,
    transport: ViceTransport,
    labels: Labels,
    cases: list[tuple[bytes, bytes, bytes, str]],
) -> tuple[int, int, int, float, list[dict]]:
    """Run a batch of encrypt tests on one VICE instance.

    Returns (worker_id, passed, failed, duration, test_vectors).
    """
    t0 = time.monotonic()
    passed = 0
    failed = 0
    test_vectors = []

    print(f"  [Worker {worker_id}] Starting ({len(cases)} tests)")

    for key, nonce, plaintext, label in cases:
        tagged_label = f"[W{worker_id}] {label}"
        ok, vector = test_gcmsiv_encrypt_case(transport, labels, key, nonce, plaintext, tagged_label)
        if ok:
            passed += 1
            test_vectors.append(vector)
        else:
            failed += 1

    duration = time.monotonic() - t0
    print(f"  [Worker {worker_id}] Done: {passed} passed, {failed} failed ({duration:.1f}s)")
    return worker_id, passed, failed, duration, test_vectors


def run_parallel(labels: Labels, iterations: int, num_workers: int) -> tuple[int, int, list[dict]]:
    """Parallel mode: multiple VICE instances, batched execution."""
    # Generate all test cases upfront (deterministic from seed)
    rng = random.Random(random.getrandbits(64))
    all_cases = generate_test_cases(iterations, rng)

    # Distribute cases across workers (round-robin for balance)
    batches: list[list[tuple[bytes, bytes, bytes, str]]] = [[] for _ in range(num_workers)]
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
        print(f"\n=== AES-256-GCM-SIV Encrypt Direct Tests ({total_tests} tests x {num_workers} workers) ===")

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

        # Release instances
        for inst in instances:
            mgr.release(inst)

    # Aggregate results
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
