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
    python3 tools/test_gcmsiv_decrypt_direct.py [--iterations N] [--seed S] [--vectors PATH]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import json
import os
import random
import subprocess
import sys
import time

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

MAX_PT_LEN = 64
DEFAULT_ITERATIONS = 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

    print(f"\n--- {label}: {pt_len} bytes PT → {ct_len}-byte CT ---")

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
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
    vectors: list[dict] | None,
) -> tuple[int, int]:
    """Run all GCM-SIV decrypt direct tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    if vectors:
        # Load test vectors from file
        print(f"\n=== Using {len(vectors)} test vectors from file ===")
        for i, vec in enumerate(vectors):
            key = bytes.fromhex(vec["key"])
            nonce = bytes.fromhex(vec["nonce"])
            plaintext = bytes.fromhex(vec["plaintext"])
            # Note: vectors include ciphertext and tag, but we regenerate them
            # via Python reference for consistency
            label = f"Vector {i + 1}/{len(vectors)}"
            if test_gcmsiv_decrypt_valid(transport, labels, key, nonce, plaintext, label):
                passed += 1
            else:
                failed += 1
    else:
        # Boundary cases
        boundary_cases = [
            (1, "Boundary: 1 byte"),
            (15, "Boundary: 15 bytes"),
            (16, "Boundary: 16 bytes (block boundary)"),
            (17, "Boundary: 17 bytes"),
            (32, "Boundary: 32 bytes (2 blocks)"),
            (48, "Boundary: 48 bytes (3 blocks)"),
            (63, "Boundary: 63 bytes"),
            (64, "Boundary: 64 bytes (max)"),
        ]

        for pt_len, label in boundary_cases:
            key = bytes(random.getrandbits(8) for _ in range(32))
            nonce = bytes(random.getrandbits(8) for _ in range(12))
            plaintext = bytes(random.getrandbits(8) for _ in range(pt_len))

            if test_gcmsiv_decrypt_valid(transport, labels, key, nonce, plaintext, label):
                passed += 1
            else:
                failed += 1

        # Random pipeline tests — fill remaining iterations minus tag tamper tests
        fixed_count = len(boundary_cases)
        tamper_count = 5  # Reserve 5 tests for tag tampering
        random_count = max(0, iterations - fixed_count - tamper_count)

        for i in range(random_count):
            pt_len = random.randint(1, MAX_PT_LEN)
            key = bytes(random.getrandbits(8) for _ in range(32))
            nonce = bytes(random.getrandbits(8) for _ in range(12))
            plaintext = bytes(random.getrandbits(8) for _ in range(pt_len))

            label = f"Random test {i + 1}/{random_count}"
            if test_gcmsiv_decrypt_valid(transport, labels, key, nonce, plaintext, label):
                passed += 1
            else:
                failed += 1

        # Tag tampering tests
        print("\n\n=== Tag Tampering Tests ===")
        tamper_sizes = [1, 16, 32, 48, 64]
        for i, pt_len in enumerate(tamper_sizes):
            key = bytes(random.getrandbits(8) for _ in range(32))
            nonce = bytes(random.getrandbits(8) for _ in range(12))
            plaintext = bytes(random.getrandbits(8) for _ in range(pt_len))

            label = f"Tamper test {i + 1}/{len(tamper_sizes)}"
            if test_gcmsiv_decrypt_tampered(transport, labels, key, nonce, plaintext, label):
                passed += 1
            else:
                failed += 1

    return passed, failed


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
        total_label = f"{iterations} iterations" if not vectors else f"{len(vectors)} vectors"
        print(f"\n=== AES-256-GCM-SIV Decrypt Direct Tests ({total_label}) ===")

        passed, failed = run_tests(transport, labels, iterations, vectors)

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
