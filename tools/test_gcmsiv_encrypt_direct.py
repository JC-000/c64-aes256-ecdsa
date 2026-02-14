#!/usr/bin/env python3
"""
test_gcmsiv_encrypt_direct.py - Direct-Memory AES-256-GCM-SIV Encrypt Test

Tests the C64 AES-256-GCM-SIV implementation by calling gcmsiv_encrypt directly
via jsr() — writing key/nonce/plaintext and reading ciphertext/tag through memory,
bypassing the menu UI entirely.

This enables comprehensive testing against the Python reference implementation.

Usage:
    python3 tools/test_gcmsiv_encrypt_direct.py [--iterations N] [--seed S]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import json
import os
import random
import subprocess
import sys
import time

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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gcmsiv_test_vectors.json")

MAX_PT_LEN = 64
DEFAULT_ITERATIONS = 50

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_bytes(length: int) -> bytes:
    """Generate random bytes."""
    return bytes(random.randint(0, 255) for _ in range(length))


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
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
) -> tuple[int, int, list[dict]]:
    """Run all GCM-SIV encrypt tests. Returns (passed, failed, test_vectors)."""
    passed = 0
    failed = 0
    test_vectors = []

    # Boundary cases with known sizes
    boundary_sizes = [1, 15, 16, 17, 32, 48, 63, 64]
    boundary_cases = []
    for size in boundary_sizes:
        key = generate_random_bytes(32)
        nonce = generate_random_bytes(12)
        plaintext = generate_random_bytes(size)
        boundary_cases.append((key, nonce, plaintext, f"Boundary: {size} bytes"))

    # Test boundary cases
    for key, nonce, plaintext, label in boundary_cases:
        ok, vector = test_gcmsiv_encrypt_case(transport, labels, key, nonce, plaintext, label)
        if ok:
            passed += 1
            test_vectors.append(vector)
        else:
            failed += 1

    # Random tests — fill remaining iterations
    fixed_count = len(boundary_cases)
    random_count = max(0, iterations - fixed_count)

    for i in range(random_count):
        # Random length from 1 to MAX_PT_LEN
        pt_len = random.randint(1, MAX_PT_LEN)
        key = generate_random_bytes(32)
        nonce = generate_random_bytes(12)
        plaintext = generate_random_bytes(pt_len)
        label = f"Random test {i + 1}/{random_count} ({pt_len} bytes)"

        ok, vector = test_gcmsiv_encrypt_case(transport, labels, key, nonce, plaintext, label)
        if ok:
            passed += 1
            test_vectors.append(vector)
        else:
            failed += 1

    return passed, failed, test_vectors


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

    seed = random.randint(0, 2**32 - 1)
    if "--seed" in sys.argv:
        idx = sys.argv.index("--seed")
        if idx + 1 < len(sys.argv):
            seed = int(sys.argv[idx + 1])
    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

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

    # Start VICE
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

        # Wait for main menu (needed for program to finish initialization)
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        print(f"\n=== AES-256-GCM-SIV Encrypt Direct Tests ({iterations} iterations) ===")

        passed, failed, test_vectors = run_tests(transport, labels, iterations)

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
