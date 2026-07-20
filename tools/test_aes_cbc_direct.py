#!/usr/bin/env python3
"""
test_aes_cbc_direct.py - Direct-Memory AES-256-CBC Test

Tests the C64 AES-256-CBC implementation by calling encrypt_input directly
via jsr() — writing plaintext/key/IV and reading ciphertext through memory,
bypassing the menu UI entirely.

This is significantly faster per iteration than the menu-driven test_aes_cbc.py,
enabling 50+ tests in less time than the original 10.

Usage:
    python3 tools/test_aes_cbc_direct.py [--iterations N] [--seed S] [--cross-validate]

Requires: Python 3.10+, c64_test_harness, cryptography, VICE x64sc
"""

import os
import random
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    C64Transport as ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    send_key,
    send_text,
    wait_for_text,
    jsr,
)
from c64_test_utils import robust_jsr, generate_random_string, generate_random_bytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

MAX_INPUT_LEN = 63
DEFAULT_ITERATIONS = 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def compute_reference_ciphertext(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Compute AES-256-CBC ciphertext with PKCS#7 padding."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_cbc_encrypt_direct(
    transport: ViceTransport,
    labels: Labels,
    plaintext: bytes,
    key: bytes,
    iv: bytes
) -> tuple[bytes, int]:
    """Encrypt via direct memory writes + jsr().

    Returns (ciphertext, ciphertext_length).
    """
    # Write plaintext to input_buffer
    write_bytes(transport, labels["input_buffer"], plaintext)
    write_bytes(transport, labels["input_length"], bytes([len(plaintext)]))

    # Write key and IV
    write_bytes(transport, labels["key_data"], key)
    write_bytes(transport, labels["iv_data"], iv)

    # Key expansion + encrypt (encrypt_input does NOT call aes_key_expansion)
    robust_jsr(transport, labels["aes_key_expansion"], timeout=5.0)
    robust_jsr(transport, labels["encrypt_input"], timeout=15.0)

    # Read results
    ct_len_byte = read_bytes(transport, labels["encrypt_length"], 1)
    ct_len = ct_len_byte[0]
    ciphertext = read_bytes(transport, labels["encrypt_buffer"], ct_len)

    return ciphertext, ct_len


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_aes_cbc_pipeline(
    transport: ViceTransport,
    labels: Labels,
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    label: str,
) -> bool:
    """Test full AES-256-CBC encryption pipeline for given plaintext/key/IV.

    Returns True on pass, False on fail.
    """
    input_len = len(plaintext)
    expected_ct_len = ((input_len // 16) + 1) * 16
    print(f"\n--- {label}: {input_len} bytes → {expected_ct_len}-byte CT ---")

    # Compute reference ciphertext
    reference_ct = compute_reference_ciphertext(plaintext, key, iv)

    try:
        c64_ct, c64_ct_len = aes_cbc_encrypt_direct(transport, labels, plaintext, key, iv)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, f"aes_cbc_direct_{input_len}_error")
        return False

    # Verify ciphertext length
    if c64_ct_len != expected_ct_len:
        print(f"  FAIL: ciphertext length mismatch")
        print(f"    Expected: {expected_ct_len}")
        print(f"    Got:      {c64_ct_len}")
        return False

    # Verify ciphertext content
    if c64_ct == reference_ct:
        print("  PASS")
        return True
    else:
        print(f"  FAIL: ciphertext mismatch")
        print(f"    Plaintext: {plaintext.hex()}")
        print(f"    Key:       {key.hex()}")
        print(f"    IV:        {iv.hex()}")
        print(f"    Expected:  {reference_ct.hex()}")
        print(f"    Got:       {c64_ct.hex()}")
        dump_screen(transport, f"aes_cbc_direct_{input_len}_mismatch")
        return False


# ---------------------------------------------------------------------------
# Cross-validation (menu UI path)
# ---------------------------------------------------------------------------

def encrypt_text_on_c64(
    transport: ViceTransport, text: str, timeout: float = 30.0
) -> bool:
    """Enter text via option 2 (encrypt), wait for completion.

    Returns True if the operation completed successfully.
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
        print("    ERROR: Did not return to menu after encryption")
        return False

    return True


def cross_validate(
    transport: ViceTransport,
    labels: Labels,
    test_cases: list[tuple[bytes, str]],
) -> tuple[int, int]:
    """Run boundary cases through both direct and menu paths, compare results.

    test_cases is a list of (plaintext_bytes, label) tuples.
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

    for plaintext_bytes, label in test_cases:
        input_len = len(plaintext_bytes)
        expected_ct_len = ((input_len // 16) + 1) * 16
        print(f"\n--- Cross-validate: {label} ({input_len} bytes → {expected_ct_len}-byte CT) ---")

        # Decode plaintext to string for UI input
        try:
            plaintext_str = plaintext_bytes.decode("ascii")
        except UnicodeDecodeError:
            print(f"  SKIP: Cannot decode plaintext as ASCII for UI input")
            continue

        # Get menu-driven encryption first (we're at the menu)
        ok = encrypt_text_on_c64(transport, plaintext_str)
        if not ok:
            print("  FAIL: menu-driven encryption failed")
            failed += 1
            continue

        # Read the key/IV/ciphertext that the UI generated
        ui_key = read_bytes(transport, labels["key_data"], 32)
        ui_iv = read_bytes(transport, labels["iv_data"], 16)
        ui_ct_len_byte = read_bytes(transport, labels["encrypt_length"], 1)
        ui_ct_len = ui_ct_len_byte[0]
        ui_ct = read_bytes(transport, labels["encrypt_buffer"], ui_ct_len)

        # Get direct-memory encryption with SAME key/IV
        try:
            direct_ct, direct_ct_len = aes_cbc_encrypt_direct(
                transport, labels, plaintext_bytes, ui_key, ui_iv
            )
        except Exception as e:
            print(f"  FAIL: direct jsr() raised {e}")
            failed += 1
            # Restart program for next iteration
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        # Compute Python reference with same key/IV
        reference_ct = compute_reference_ciphertext(plaintext_bytes, ui_key, ui_iv)

        # All three must match
        if direct_ct == ui_ct == reference_ct:
            print(f"  PASS: direct == menu == Python reference ({reference_ct[:4].hex()}...)")
            passed += 1
        else:
            print(f"  FAIL: mismatch!")
            print(f"    Direct:  {direct_ct.hex()}")
            print(f"    Menu:    {ui_ct.hex()}")
            print(f"    Python:  {reference_ct.hex()}")
            print(f"    Key:     {ui_key.hex()}")
            print(f"    IV:      {ui_iv.hex()}")
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
    """Run all AES-256-CBC direct tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    # Boundary cases with known inputs
    boundary_cases = [
        (generate_random_string(1, 1).encode("ascii"), "Pipeline: 1 byte"),
        (generate_random_string(16, 16).encode("ascii"), "Pipeline: 16 bytes (block boundary)"),
        (generate_random_string(48, 48).encode("ascii"), "Pipeline: 48 bytes (3 blocks)"),
        (generate_random_string(63, 63).encode("ascii"), "Pipeline: 63 bytes (max)"),
    ]

    # Store test cases for cross-validation
    test_cases_for_crossval = []

    for plaintext, label in boundary_cases:
        key = generate_random_bytes(32)
        iv = generate_random_bytes(16)

        if test_aes_cbc_pipeline(transport, labels, plaintext, key, iv, label):
            passed += 1
        else:
            failed += 1

        # Save for cross-validation
        test_cases_for_crossval.append((plaintext, label))

    # Random pipeline tests — fill remaining iterations
    fixed_count = len(boundary_cases)
    random_count = max(0, iterations - fixed_count)

    for i in range(random_count):
        plaintext = generate_random_string(1, MAX_INPUT_LEN).encode("ascii")
        key = generate_random_bytes(32)
        iv = generate_random_bytes(16)
        label = f"Random test {i + 1}/{random_count}"

        if test_aes_cbc_pipeline(transport, labels, plaintext, key, iv, label):
            passed += 1
        else:
            failed += 1

    # Cross-validation (optional)
    if do_cross_validate:
        cv_passed, cv_failed = cross_validate(
            transport, labels, test_cases_for_crossval,
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
        "encrypt_input", "aes_key_expansion", "input_buffer", "input_length",
        "encrypt_buffer", "encrypt_length", "key_data", "iv_data",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded:")
    print(f"    encrypt_input   @ ${labels['encrypt_input']:04X}")
    print(f"    input_buffer    @ ${labels['input_buffer']:04X}")
    print(f"    encrypt_buffer  @ ${labels['encrypt_buffer']:04X}")
    print(f"    key_data        @ ${labels['key_data']:04X}")
    print(f"    iv_data         @ ${labels['iv_data']:04X}")

    # Start VICE
    print("\n=== Starting VICE ===")
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"  VICE started (PID={inst.pid}, port={inst.port})")

        transport = inst.transport

        # Wait for main menu (needed for program to finish initialization)
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            mgr.release(inst)
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        total_label = f"{iterations} iterations"
        if do_cross_validate:
            total_label += " + cross-validation"
        print(f"\n=== AES-256-CBC Direct Tests ({total_label}) ===")

        passed, failed = run_tests(transport, labels, iterations, do_cross_validate)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] AES-256-CBC Direct: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] AES-256-CBC Direct: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
