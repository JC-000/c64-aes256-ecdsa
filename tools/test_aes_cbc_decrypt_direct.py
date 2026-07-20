#!/usr/bin/env python3
"""
test_aes_cbc_decrypt_direct.py - Direct-Memory AES-256-CBC Decrypt Test

Tests the C64 AES-256-CBC decrypt implementation by calling decrypt_buffer
directly via jsr() — writing ciphertext/key/IV data and reading decrypted
output through memory, bypassing the menu UI entirely.

This is significantly faster per iteration than the menu-driven
test_aes_cbc_decrypt.py, enabling 50+ tests in less time than the original 10.

IMPORTANT: decrypt_buffer does NOT call aes_key_expansion internally, so we
must call aes_key_expansion before decrypt_buffer for each test.

Usage:
    python3 tools/test_aes_cbc_decrypt_direct.py [--iterations N] [--seed S] [--cross-validate]

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
from c64_test_utils import robust_jsr, generate_random_string

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

def pkcs7_pad(plaintext: bytes) -> bytes:
    """Apply PKCS#7 padding (128-bit block)."""
    padder = padding.PKCS7(128).padder()
    return padder.update(plaintext) + padder.finalize()


def pkcs7_unpad(padded: bytes) -> bytes:
    """Remove PKCS#7 padding (128-bit block)."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def python_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encrypt with PKCS#7 padding."""
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_cbc_decrypt_direct(
    transport: ViceTransport, labels: Labels, ciphertext: bytes, key: bytes, iv: bytes
) -> bytes:
    """Decrypt via direct memory writes + jsr().

    Returns the decrypted bytes (with PKCS#7 padding still present).

    IMPORTANT: decrypt_buffer does NOT call aes_key_expansion, so we must
    call it explicitly before decrypt_buffer.
    """
    # Write ciphertext to encrypt_buffer (that's the input for decrypt)
    write_bytes(transport, labels["encrypt_buffer"], ciphertext)
    write_bytes(transport, labels["encrypt_length"], bytes([len(ciphertext)]))
    # Write key and IV
    write_bytes(transport, labels["key_data"], key)
    write_bytes(transport, labels["iv_data"], iv)
    # Key expansion + decrypt
    robust_jsr(transport, labels["aes_key_expansion"], timeout=5.0)
    robust_jsr(transport, labels["decrypt_buffer"], timeout=15.0)
    # Read decrypted output (same length as ciphertext)
    return read_bytes(transport, labels["decrypt_data"], len(ciphertext))


# ---------------------------------------------------------------------------
# Individual test functions
# ---------------------------------------------------------------------------

def test_aes_cbc_decrypt_pipeline(
    transport: ViceTransport,
    labels: Labels,
    plaintext: str,
    label: str,
) -> bool:
    """Test full AES-256-CBC decrypt pipeline for a given plaintext.

    1. Generate random key and IV
    2. Encrypt plaintext in Python to get ciphertext
    3. Decrypt via direct memory on C64
    4. Verify decrypted output matches PKCS#7-padded plaintext

    Returns True on pass, False on fail.
    """
    plaintext_bytes = plaintext.encode("ascii")
    pt_len = len(plaintext_bytes)
    padded = pkcs7_pad(plaintext_bytes)
    padded_len = len(padded)

    # Generate random key and IV
    key = bytes(random.getrandbits(8) for _ in range(32))
    iv = bytes(random.getrandbits(8) for _ in range(16))

    # Encrypt in Python
    ciphertext = python_encrypt(plaintext_bytes, key, iv)
    ct_len = len(ciphertext)

    print(f"\n--- {label}: {pt_len} bytes PT → {padded_len} bytes padded → {ct_len}-byte CT ---")

    # Safety check: ciphertext must fit in decrypt_data (64 bytes)
    assert ct_len <= 64, (
        f"BUG: ciphertext length {ct_len} exceeds decrypt_data buffer (64)"
    )

    try:
        decrypted = aes_cbc_decrypt_direct(transport, labels, ciphertext, key, iv)
    except Exception as e:
        print(f"  FAIL: jsr() raised {e}")
        dump_screen(transport, f"decrypt_{pt_len}_error")
        return False

    if decrypted == padded:
        # Also verify unpadded plaintext prefix
        if decrypted[:pt_len] == plaintext_bytes:
            print("  PASS")
            return True
        else:
            print(f"  FAIL: padded match but plaintext prefix mismatch!")
            print(f"  PT bytes:  {plaintext_bytes.hex()}")
            print(f"  Got:       {decrypted[:pt_len].hex()}")
            dump_screen(transport, f"decrypt_{pt_len}_prefix")
            return False
    else:
        print(f"  FAIL: decrypted output mismatch")
        print(f"    Plaintext:    \"{plaintext}\"")
        print(f"    Expected pad: {padded.hex()}")
        print(f"    Got:          {decrypted.hex()}")
        print(f"    Key:          {key.hex()}")
        print(f"    IV:           {iv.hex()}")
        print(f"    Ciphertext:   {ciphertext.hex()}")
        dump_screen(transport, f"decrypt_{pt_len}_mismatch")
        return False


# ---------------------------------------------------------------------------
# Cross-validation (menu UI path)
# ---------------------------------------------------------------------------

def encrypt_text_on_c64(
    transport: ViceTransport, text: str, timeout: float = 30.0
) -> bool:
    """Enter text via option 2 (encrypt), wait for completion."""
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


def decrypt_on_c64_ui(transport: ViceTransport, timeout: float = 30.0) -> bool:
    """Press 4 to decrypt via UI, wait for completion."""
    send_key(transport, "4")
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after decrypt")
        return False
    return True


def cross_validate(
    transport: ViceTransport,
    labels: Labels,
    test_cases: list[tuple[str, str]],
) -> tuple[int, int]:
    """Run boundary cases through both direct and menu paths, compare results.

    For each test case:
    1. Restart program and wait for menu
    2. Encrypt via UI (option 2) to populate encrypt_buffer with ciphertext
    3. Read key, IV, ciphertext from memory
    4. Decrypt via UI (option 4) and read decrypt_data (UI result)
    5. Direct decrypt same ciphertext with same key/IV
    6. Compare UI-decrypted vs direct-decrypted

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
        plaintext_bytes = message.encode("ascii")
        pt_len = len(plaintext_bytes)
        padded_len = len(pkcs7_pad(plaintext_bytes))
        print(f"\n--- Cross-validate: {label} ({pt_len} bytes PT, {padded_len} bytes padded) ---")

        # First, encrypt via UI to populate encrypt_buffer with ciphertext
        ok = encrypt_text_on_c64(transport, message)
        if not ok:
            print("  FAIL: menu-driven encrypt failed")
            failed += 1
            # Restart program for next iteration
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        # Read key, IV, ciphertext from memory
        key = read_bytes(transport, labels["key_data"], 32)
        iv = read_bytes(transport, labels["iv_data"], 16)
        ct_len_byte = read_bytes(transport, labels["encrypt_length"], 1)
        if key is None or iv is None or ct_len_byte is None:
            print("  FAIL: Could not read key/IV/length from memory")
            failed += 1
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        ct_len = ct_len_byte[0]
        ciphertext = read_bytes(transport, labels["encrypt_buffer"], ct_len)
        if ciphertext is None:
            print("  FAIL: Could not read ciphertext from memory")
            failed += 1
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        # Decrypt via UI (option 4)
        ok = decrypt_on_c64_ui(transport)
        if not ok:
            print("  FAIL: menu-driven decrypt failed")
            failed += 1
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        # Read UI-decrypted result
        ui_decrypted = read_bytes(transport, labels["decrypt_data"], ct_len)
        if ui_decrypted is None:
            print("  FAIL: Could not read UI decrypt_data from memory")
            failed += 1
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        # Get direct-memory decrypt
        try:
            direct_decrypted = aes_cbc_decrypt_direct(transport, labels, ciphertext, key, iv)
        except Exception as e:
            print(f"  FAIL: direct jsr() raised {e}")
            failed += 1
            # Restart program for next iteration
            send_text(transport, "RUN")
            time.sleep(0.1)
            send_key(transport, "\r")
            wait_for_text(transport, "Q=QUIT", timeout=60.0)
            continue

        # Verify both match the expected padded plaintext
        expected_padded = pkcs7_pad(plaintext_bytes)

        if direct_decrypted == ui_decrypted == expected_padded:
            print(f"  PASS: direct == UI == expected ({expected_padded[:4].hex()}...)")
            passed += 1
        else:
            print(f"  FAIL: mismatch!")
            print(f"    Direct:   {direct_decrypted.hex()}")
            print(f"    UI:       {ui_decrypted.hex()}")
            print(f"    Expected: {expected_padded.hex()}")
            dump_screen(transport, f"crossval_{pt_len}")
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
    """Run all AES-256-CBC decrypt direct tests. Returns (passed, failed)."""
    passed = 0
    failed = 0

    # Boundary cases
    boundary_cases = [
        (generate_random_string(1, 1), "Boundary: 1 byte (15 bytes pad)"),
        (generate_random_string(16, 16), "Boundary: 16 bytes (full padding block)"),
        (generate_random_string(48, 48), "Boundary: 48 bytes (3 blocks + pad)"),
        (generate_random_string(63, 63), "Boundary: 63 bytes (max, 1 byte pad)"),
    ]

    for message, label in boundary_cases:
        if test_aes_cbc_decrypt_pipeline(transport, labels, message, label):
            passed += 1
        else:
            failed += 1

    # Random pipeline tests — fill remaining iterations
    fixed_count = len(boundary_cases)
    random_count = max(0, iterations - fixed_count)

    for i in range(random_count):
        message = generate_random_string(1, MAX_INPUT_LEN)
        label = f"Random test {i + 1}/{random_count}"
        if test_aes_cbc_decrypt_pipeline(transport, labels, message, label):
            passed += 1
        else:
            failed += 1

    # Cross-validation (optional)
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
        "decrypt_buffer", "aes_key_expansion",
        "encrypt_buffer", "encrypt_length",
        "decrypt_data", "key_data", "iv_data",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found")
            sys.exit(1)
    print(f"  Labels loaded:")
    print(f"    decrypt_buffer      @ ${labels['decrypt_buffer']:04X}")
    print(f"    aes_key_expansion   @ ${labels['aes_key_expansion']:04X}")
    print(f"    encrypt_buffer      @ ${labels['encrypt_buffer']:04X}")
    print(f"    encrypt_length      @ ${labels['encrypt_length']:04X}")
    print(f"    decrypt_data        @ ${labels['decrypt_data']:04X}")
    print(f"    key_data            @ ${labels['key_data']:04X}")
    print(f"    iv_data             @ ${labels['iv_data']:04X}")

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
        print(f"\n=== AES-256-CBC Decrypt Direct Tests ({total_label}) ===")

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
        print(f"\n  [+] AES-256-CBC Decrypt Direct: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] AES-256-CBC Decrypt Direct: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
