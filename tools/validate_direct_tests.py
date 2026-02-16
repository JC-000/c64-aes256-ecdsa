#!/usr/bin/env python3
"""
validate_direct_tests.py - Cross-Validation of UI-driven vs Direct-Memory Tests

Runs both the UI-driven and direct-memory AES-256-CBC tests with identical inputs
(same random seed) on a single VICE instance, comparing outputs byte-for-byte.

This validates that the direct-memory tests produce exactly the same results as
the original UI-driven tests.

Usage:
    python3 tools/validate_direct_tests.py [--seed S] [--iterations N]

Requires: Python 3.10+, c64_test_harness, cryptography, VICE x64sc
"""

import os
import random
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceProcess,
    ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    send_key,
    send_text,
    wait_for_text,
    jsr,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

MAX_INPUT_LEN = 63
SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_ITERATIONS = 5  # kept small since cross-validation is slow (UI path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_string(min_len: int = 1, max_len: int = MAX_INPUT_LEN) -> str:
    length = random.randint(min_len, max_len)
    return "".join(random.choice(SAFE_CHARS) for _ in range(length))


def compute_reference_ciphertext(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def python_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return compute_reference_ciphertext(plaintext, key, iv)


def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def recover_to_menu(transport: ViceTransport, timeout: float = 30.0) -> bool:
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout, verbose=False)
    if grid is not None:
        return True
    send_key(transport, "\r")
    time.sleep(0.5)
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    return grid is not None


def restart_program(transport: ViceTransport, timeout: float = 60.0) -> bool:
    send_text(transport, "RUN")
    time.sleep(0.1)
    send_key(transport, "\r")
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    return grid is not None


# ---------------------------------------------------------------------------
# UI-driven encrypt (from test_aes_cbc.py)
# ---------------------------------------------------------------------------

def ui_encrypt(transport: ViceTransport, text: str, timeout: float = 30.0) -> bool:
    send_key(transport, "2")
    grid = wait_for_text(transport, "ENTER TEXT", timeout=timeout, verbose=False)
    if grid is None:
        return False
    time.sleep(0.1)
    send_text(transport, text)
    time.sleep(0.1)
    send_key(transport, "\r")
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    return grid is not None


def ui_decrypt(transport: ViceTransport, timeout: float = 30.0) -> bool:
    send_key(transport, "4")
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    return grid is not None


# ---------------------------------------------------------------------------
# Direct-memory operations
# ---------------------------------------------------------------------------

def direct_encrypt(
    transport: ViceTransport, labels: Labels,
    plaintext: bytes, key: bytes, iv: bytes,
) -> tuple[bytes, int] | None:
    try:
        write_bytes(transport, labels["input_buffer"], plaintext)
        write_bytes(transport, labels["input_length"], bytes([len(plaintext)]))
        write_bytes(transport, labels["key_data"], key)
        write_bytes(transport, labels["iv_data"], iv)
        jsr(transport, labels["aes_key_expansion"], timeout=5.0)
        jsr(transport, labels["encrypt_input"], timeout=15.0)
        ct_len = read_bytes(transport, labels["encrypt_length"], 1)[0]
        ct = read_bytes(transport, labels["encrypt_buffer"], ct_len)
        return ct, ct_len
    except Exception as e:
        print(f"    direct_encrypt error: {e}")
        return None


def direct_decrypt(
    transport: ViceTransport, labels: Labels,
    ciphertext: bytes, key: bytes, iv: bytes,
) -> bytes | None:
    try:
        write_bytes(transport, labels["encrypt_buffer"], ciphertext)
        write_bytes(transport, labels["encrypt_length"], bytes([len(ciphertext)]))
        write_bytes(transport, labels["key_data"], key)
        write_bytes(transport, labels["iv_data"], iv)
        jsr(transport, labels["aes_key_expansion"], timeout=5.0)
        jsr(transport, labels["decrypt_buffer"], timeout=15.0)
        return read_bytes(transport, labels["decrypt_data"], len(ciphertext))
    except Exception as e:
        print(f"    direct_decrypt error: {e}")
        return None


# ---------------------------------------------------------------------------
# Cross-Validation: Encrypt
# ---------------------------------------------------------------------------

def validate_encrypt(
    transport: ViceTransport, labels: Labels, iterations: int,
) -> tuple[int, int]:
    print("\n\n=== Cross-Validation: AES-256-CBC Encrypt ===")
    print("  (UI-driven vs Direct-memory vs Python reference)\n")

    passed = 0
    failed = 0

    # Boundary cases + random
    test_strings = []
    test_strings.append(generate_random_string(1, 1))
    test_strings.append(generate_random_string(16, 16))
    test_strings.append(generate_random_string(48, 48))
    test_strings.append(generate_random_string(63, 63))
    for _ in range(max(0, iterations - len(test_strings))):
        test_strings.append(generate_random_string(1, MAX_INPUT_LEN))
    test_strings = test_strings[:iterations]

    for i, text in enumerate(test_strings):
        pt_len = len(text)
        expected_ct_len = ((pt_len // 16) + 1) * 16
        print(f"--- Encrypt Validate {i+1}/{iterations}: {pt_len} bytes → {expected_ct_len}-byte CT ---")

        # 1. UI encrypt: uses C64-generated key/IV
        ok = ui_encrypt(transport, text)
        if not ok:
            print("  FAIL: UI encrypt did not complete")
            failed += 1
            if not recover_to_menu(transport):
                print("  FATAL: Cannot recover")
                return passed, failed + (iterations - i - 1)
            continue

        # Read what the C64 produced (key, IV, ciphertext)
        ui_key = read_bytes(transport, labels["key_data"], 32)
        ui_iv = read_bytes(transport, labels["iv_data"], 16)
        ui_ct_len = read_bytes(transport, labels["encrypt_length"], 1)[0]
        ui_ct = read_bytes(transport, labels["encrypt_buffer"], ui_ct_len)

        # 2. Direct encrypt: same text, same key, same IV
        direct_result = direct_encrypt(
            transport, labels, text.encode("ascii"), ui_key, ui_iv,
        )
        if direct_result is None:
            print("  FAIL: direct encrypt error")
            failed += 1
            if not restart_program(transport):
                print("  FATAL: Cannot restart")
                return passed, failed + (iterations - i - 1)
            continue

        direct_ct, direct_ct_len = direct_result

        # 3. Python reference
        ref_ct = compute_reference_ciphertext(text.encode("ascii"), ui_key, ui_iv)

        # Compare all three
        if ui_ct == direct_ct == ref_ct:
            print(f"  PASS: UI == Direct == Python ({ref_ct[:4].hex()}...)")
            passed += 1
        else:
            print("  FAIL: mismatch!")
            print(f"    UI:     {ui_ct.hex()}")
            print(f"    Direct: {direct_ct.hex()}")
            print(f"    Python: {ref_ct.hex()}")
            dump_screen(transport, f"encrypt_validate_{i+1}")
            failed += 1

        # Restart program for next UI encrypt (direct test leaves CPU state dirty)
        if i < iterations - 1:
            if not restart_program(transport):
                print("  FATAL: Cannot restart for next iteration")
                return passed, failed + (iterations - i - 1)

    return passed, failed


# ---------------------------------------------------------------------------
# Cross-Validation: Decrypt
# ---------------------------------------------------------------------------

def validate_decrypt(
    transport: ViceTransport, labels: Labels, iterations: int,
) -> tuple[int, int]:
    print("\n\n=== Cross-Validation: AES-256-CBC Decrypt ===")
    print("  (UI-driven vs Direct-memory vs Python reference)\n")

    passed = 0
    failed = 0

    # First, do a UI encrypt to prime key expansion and get the boot key
    if not restart_program(transport):
        print("  FATAL: Cannot start program")
        return 0, iterations

    ok = ui_encrypt(transport, "A")
    if not ok:
        print("  FATAL: Could not prime key expansion")
        return 0, iterations

    boot_key = read_bytes(transport, labels["key_data"], 32)
    print(f"  Boot key: {boot_key.hex()}")

    # Boundary + random test cases
    test_cases: list[tuple[int, str]] = []
    test_cases.append((1, "1-byte plaintext"))
    test_cases.append((16, "Block boundary"))
    test_cases.append((48, "3 blocks + pad"))
    test_cases.append((63, "Max input"))
    for _ in range(max(0, iterations - len(test_cases))):
        test_cases.append((random.randint(1, MAX_INPUT_LEN), "Random"))
    test_cases = test_cases[:iterations]

    for i, (pt_len, desc) in enumerate(test_cases):
        plaintext_str = generate_random_string(pt_len, pt_len)
        plaintext_bytes = plaintext_str.encode("ascii")
        padded = pkcs7_pad(plaintext_bytes)
        iv = bytes(random.getrandbits(8) for _ in range(16))
        ciphertext = python_encrypt(plaintext_bytes, boot_key, iv)
        ct_len = len(ciphertext)

        print(f"\n--- Decrypt Validate {i+1}/{iterations}: {pt_len} bytes PT → {ct_len}-byte CT ({desc}) ---")

        # 1. UI decrypt: inject ciphertext + IV into memory, press '4'
        write_bytes(transport, labels["iv_data"], iv)
        write_bytes(transport, labels["encrypt_buffer"], ciphertext)
        write_bytes(transport, labels["encrypt_length"], bytes([ct_len]))

        ok = ui_decrypt(transport)
        if not ok:
            print("  FAIL: UI decrypt timed out")
            failed += 1
            if not recover_to_menu(transport):
                return passed, failed + (iterations - i - 1)
            continue

        ui_decrypted = read_bytes(transport, labels["decrypt_data"], ct_len)

        # 2. Direct decrypt: same ciphertext, same key, same IV
        direct_decrypted = direct_decrypt(
            transport, labels, ciphertext, boot_key, iv,
        )
        if direct_decrypted is None:
            print("  FAIL: direct decrypt error")
            failed += 1
            if not restart_program(transport):
                return passed, failed + (iterations - i - 1)
            continue

        # Compare
        if ui_decrypted == direct_decrypted == padded:
            print(f"  PASS: UI == Direct == Python-padded")
            passed += 1
        else:
            print("  FAIL: mismatch!")
            print(f"    UI:      {ui_decrypted.hex()}")
            print(f"    Direct:  {direct_decrypted.hex()}")
            print(f"    Padded:  {padded.hex()}")
            dump_screen(transport, f"decrypt_validate_{i+1}")
            failed += 1

        # Restart for next UI decrypt (direct jsr leaves CPU dirty)
        if i < iterations - 1:
            if not restart_program(transport):
                print("  FATAL: Cannot restart for next iteration")
                return passed, failed + (iterations - i - 1)
            # Re-prime key expansion
            ok = ui_encrypt(transport, "A")
            if not ok:
                print("  FATAL: Could not re-prime key expansion")
                return passed, failed + (iterations - i - 1)
            # Re-read boot key (restart generates a new random key)
            boot_key = read_bytes(transport, labels["key_data"], 32)

    return passed, failed


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
        "key_data", "iv_data", "encrypt_length", "encrypt_buffer",
        "decrypt_data", "input_buffer", "input_length",
        "encrypt_input", "decrypt_buffer", "aes_key_expansion",
    ]
    for lbl in required_labels:
        if labels.address(lbl) is None:
            print(f"FATAL: '{lbl}' label not found")
            sys.exit(1)
    print("  Labels loaded")

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

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        # Run encrypt cross-validation
        enc_passed, enc_failed = validate_encrypt(transport, labels, iterations)

        # Run decrypt cross-validation
        dec_passed, dec_failed = validate_decrypt(transport, labels, iterations)

    # Summary
    total_passed = enc_passed + dec_passed
    total_failed = enc_failed + dec_failed
    total = total_passed + total_failed

    print("\n" + "=" * 60)
    print("CROSS-VALIDATION RESULTS")
    print("=" * 60)
    print(f"  Encrypt: {enc_passed}/{enc_passed + enc_failed} passed")
    print(f"  Decrypt: {dec_passed}/{dec_passed + dec_failed} passed")
    print(f"  Total:   {total_passed}/{total} passed")
    if total_failed == 0:
        print(f"\n  [+] ALL {total} CROSS-VALIDATION TESTS PASSED")
        print("  Direct-memory tests produce identical results to UI-driven tests.")
    else:
        print(f"\n  [-] {total_failed} CROSS-VALIDATION TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
