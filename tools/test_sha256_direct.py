#!/usr/bin/env python3
"""
test_sha256_direct.py - Direct-Memory SHA-256 Test

Tests the C64 SHA-256 implementation by calling sha256_init, sha256_update,
and sha256_final directly via jsr() — writing input data and reading hash
output through memory, bypassing the menu UI entirely.

This is ~20x faster per iteration than the menu-driven test_sha256.py,
enabling 50+ tests in less time than the original 10.

Usage:
    python3 tools/test_sha256_direct.py [--iterations N] [--seed S] [--cross-validate]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hashlib
import os
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceProcess,
    C64Transport as ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    send_key,
    send_text,
    wait_for_text,
    jsr,
)
from c64_test_utils import robust_jsr, generate_random_string

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

MAX_INPUT_LEN = 63
DEFAULT_ITERATIONS = 50

# SHA-256 initial hash values (FIPS 180-4, Section 5.3.3)
SHA256_IV = bytes.fromhex(
    "6a09e667" "bb67ae85" "3c6ef372" "a54ff53a"
    "510e527f" "9b05688c" "1f83d9ab" "5be0cd19"
)

# NIST "abc" test vector (SHA-256 of 0x61 0x62 0x63)
NIST_ABC_HASH = bytes.fromhex(
    "ba7816bf" "8f01cfea" "414140de" "5dae2223"
    "b00361a3" "96177a9c" "b410ff61" "f20015ad"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_direct(transport: ViceTransport, labels: Labels, message: bytes) -> bytes:
    """Hash message via direct memory writes + jsr() calls.

    Returns the 32-byte SHA-256 digest.
    """
    write_bytes(transport, labels["input_buffer"], message)
    write_bytes(transport, labels["input_length"], bytes([len(message)]))
    robust_jsr(transport, labels["sha256_init"], timeout=5.0)
    robust_jsr(transport, labels["sha256_update"], timeout=10.0)
    robust_jsr(transport, labels["sha256_final"], timeout=5.0)
    return read_bytes(transport, labels["sha256_hash"], 32)


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_sha256_init(transport: ViceTransport, labels: Labels) -> bool:
    """Verify sha256_init loads the standard IV into H0-H7."""
    print("\n--- Init Verification ---")

    try:
        robust_jsr(transport, labels["sha256_init"], timeout=5.0)
    except Exception as e:
        print(f"  FAIL: jsr(sha256_init) raised {e}")
        dump_screen(transport, "init_error")
        return False

    h_state = read_bytes(transport, labels["sha256_h0"], 32)

    if h_state == SHA256_IV:
        print("  PASS: H0-H7 match standard IV")
        return True
    else:
        print(f"  FAIL: H0-H7 mismatch")
        print(f"    Expected: {SHA256_IV.hex()}")
        print(f"    Got:      {h_state.hex()}")
        dump_screen(transport, "init_mismatch")
        return False


def test_sha256_process_block(transport: ViceTransport, labels: Labels) -> bool:
    """Test sha256_process_block in isolation with NIST "abc" vector.

    Manually prepares a padded 64-byte block for the 3-byte message "abc",
    writes it to sha256_block, calls sha256_init + sha256_process_block +
    sha256_final, and verifies against the known NIST hash.
    """
    print('\n--- Process Block: NIST "abc" ---')

    # Build the padded block for "abc" (3 bytes):
    # "abc" + 0x80 + 57 zero bytes + 8-byte big-endian bit length (24 = 0x18)
    msg = b"abc"
    block = bytearray(64)
    block[0:3] = msg
    block[3] = 0x80
    # Bit length = 3 * 8 = 24, stored as big-endian 64-bit at offset 56
    struct.pack_into(">Q", block, 56, len(msg) * 8)

    try:
        # Write padded block before init (sha256_init doesn't touch the block)
        write_bytes(transport, labels["sha256_block"], bytes(block))

        # Initialize hash state
        robust_jsr(transport, labels["sha256_init"], timeout=5.0)

        # Call process_block directly
        robust_jsr(transport, labels["sha256_process_block"], timeout=10.0)

        # Finalize (copy H0-H7 to sha256_hash)
        robust_jsr(transport, labels["sha256_final"], timeout=5.0)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, "process_block_error")
        return False

    c64_hash = read_bytes(transport, labels["sha256_hash"], 32)

    if c64_hash == NIST_ABC_HASH:
        print(f"  PASS: hash matches {NIST_ABC_HASH[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: hash mismatch")
        print(f"    Expected: {NIST_ABC_HASH.hex()}")
        print(f"    Got:      {c64_hash.hex()}")
        dump_screen(transport, "process_block_mismatch")
        return False


def test_sha256_empty(transport: ViceTransport, labels: Labels) -> bool:
    """Test SHA-256 of empty input (0 bytes)."""
    print("\n--- Empty input (0 bytes) ---")

    expected = hashlib.sha256(b"").digest()

    try:
        write_bytes(transport, labels["input_length"], bytes([0]))
        robust_jsr(transport, labels["sha256_init"], timeout=5.0)
        robust_jsr(transport, labels["sha256_update"], timeout=10.0)
        robust_jsr(transport, labels["sha256_final"], timeout=5.0)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, "empty_error")
        return False

    c64_hash = read_bytes(transport, labels["sha256_hash"], 32)

    if c64_hash == expected:
        print(f"  PASS: hash matches {expected[:4].hex()}...")
        return True
    else:
        print(f"  FAIL: hash mismatch")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {c64_hash.hex()}")
        dump_screen(transport, "empty_mismatch")
        return False


def test_sha256_pipeline(
    transport: ViceTransport,
    labels: Labels,
    message: str,
    label: str,
) -> bool:
    """Test full sha256_init/update/final pipeline for a given message.

    Returns True on pass, False on fail.
    """
    input_bytes = message.encode("ascii")
    input_len = len(input_bytes)
    block_type = "single-block" if input_len <= 55 else "two-block"
    print(f"\n--- {label}: {input_len} bytes ({block_type}) ---")

    expected = hashlib.sha256(input_bytes).digest()

    try:
        c64_hash = sha256_direct(transport, labels, input_bytes)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, f"pipeline_{input_len}_error")
        return False

    if c64_hash == expected:
        print("  PASS")
        return True
    else:
        print(f"  FAIL: hash mismatch")
        print(f"    Input:    \"{message}\"")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {c64_hash.hex()}")
        dump_screen(transport, f"pipeline_{input_len}_mismatch")
        return False


# ---------------------------------------------------------------------------
# Cross-validation (menu UI path)
# ---------------------------------------------------------------------------

def enter_text_and_hash(
    transport: ViceTransport, text: str, timeout: float = 30.0
) -> bool:
    """Enter text via option 2, then hash via option 9.

    Returns True if both operations completed successfully.
    """
    send_key(transport, "2")
    grid = wait_for_text(transport, "ENTER TEXT", timeout=timeout, verbose=False)
    if grid is None:
        print("    ERROR: 'ENTER TEXT' prompt did not appear")
        return False

    time.sleep(0.1)
    send_text(transport, text)
    time.sleep(0.1)
    send_key(transport, "\r")

    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after text entry")
        return False

    time.sleep(0.1)
    send_key(transport, "9")

    grid = wait_for_text(transport, "SHA-256 HASH", timeout=timeout, verbose=False)
    if grid is None:
        print("    ERROR: SHA-256 hash output did not appear")
        return False

    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after hashing")
        return False

    return True


def cross_validate(
    transport: ViceTransport,
    labels: Labels,
    test_cases: list[tuple[str, str]],
) -> tuple[int, int]:
    """Run boundary cases through both direct and menu paths, compare results.

    test_cases is a list of (message, label) tuples.
    Returns (passed, failed).
    """
    print("\n\n=== Cross-Validation (Direct vs Menu UI) ===")

    # After direct tests, the CPU is in BASIC (program state lost).
    # Restart the program by typing RUN + RETURN.
    print("  Restarting program from BASIC...")
    send_text(transport, "RUN")
    time.sleep(0.1)
    send_key(transport, "\r")
    grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
    if grid is None:
        print("  ERROR: Could not restart program for cross-validation")
        return 0, len(test_cases)

    passed = 0
    failed = 0

    for message, label in test_cases:
        input_bytes = message.encode("ascii")
        input_len = len(input_bytes)
        block_type = "single-block" if input_len <= 55 else "two-block"
        print(f"\n--- Cross-validate: {label} ({input_len} bytes, {block_type}) ---")

        # Get menu-driven hash first (we're at the menu)
        ok = enter_text_and_hash(transport, message)
        if not ok:
            print("  FAIL: menu-driven hash failed")
            failed += 1
            continue

        menu_hash = read_bytes(transport, labels["sha256_hash"], 32)

        # Get direct-memory hash
        try:
            direct_hash = sha256_direct(transport, labels, input_bytes)
        except Exception as e:
            print(f"  FAIL: direct jsr() raised {e}")
            failed += 1
            # Restart program for next iteration
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        reference = hashlib.sha256(input_bytes).digest()

        if direct_hash == menu_hash == reference:
            print(f"  PASS: direct == menu == OpenSSL ({reference[:4].hex()}...)")
            passed += 1
        else:
            print(f"  FAIL: mismatch!")
            print(f"    Direct:  {direct_hash.hex()}")
            print(f"    Menu:    {menu_hash.hex()}")
            print(f"    OpenSSL: {reference.hex()}")
            dump_screen(transport, f"crossval_{input_len}")
            failed += 1

        # Restart program for next iteration (direct test leaves CPU in BASIC)
        send_text(transport, "RUN")
        time.sleep(0.1)
        send_key(transport, "\r")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("  ERROR: Could not restart program, aborting cross-validation")
            failed += len(test_cases) - (passed + failed)
            break

    return passed, failed


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
    do_cross_validate: bool,
) -> tuple[int, int]:
    """Run all SHA-256 direct tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    # A. Init verification
    if test_sha256_init(transport, labels):
        passed += 1
    else:
        failed += 1

    # E. Process block isolation (NIST "abc")
    if test_sha256_process_block(transport, labels):
        passed += 1
    else:
        failed += 1

    # B. Empty input
    if test_sha256_empty(transport, labels):
        passed += 1
    else:
        failed += 1

    # C. Boundary cases
    boundary_cases = [
        (generate_random_string(1, 1), "Pipeline: 1 byte"),
        (generate_random_string(55, 55), "Pipeline: 55 bytes"),
        (generate_random_string(56, 56), "Pipeline: 56 bytes"),
        (generate_random_string(63, 63), "Pipeline: 63 bytes"),
    ]

    for message, label in boundary_cases:
        if test_sha256_pipeline(transport, labels, message, label):
            passed += 1
        else:
            failed += 1

    # D. Random pipeline tests — fill remaining iterations
    fixed_count = 3 + len(boundary_cases)  # init + process_block + empty + boundaries
    random_count = max(0, iterations - fixed_count)

    for i in range(random_count):
        message = generate_random_string(1, MAX_INPUT_LEN)
        label = f"Random test {i + 1}/{random_count}"
        if test_sha256_pipeline(transport, labels, message, label):
            passed += 1
        else:
            failed += 1

    # F. Cross-validation (optional)
    if do_cross_validate:
        cv_passed, cv_failed = cross_validate(
            transport, labels, boundary_cases,
        )
        passed += cv_passed
        failed += cv_failed

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

    do_cross_validate = "--cross-validate" in sys.argv

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
        "sha256_hash", "sha256_init", "sha256_update", "sha256_final",
        "sha256_h0", "sha256_block", "sha256_process_block",
        "input_buffer", "input_length",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded, sha256_hash at ${labels['sha256_hash']:04X}")

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
        total_label = f"{iterations} iterations"
        if do_cross_validate:
            total_label += " + cross-validation"
        print(f"\n=== SHA-256 Direct Tests ({total_label}) ===")

        passed, failed = run_tests(transport, labels, iterations, do_cross_validate)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] SHA-256 Direct: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] SHA-256 Direct: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
