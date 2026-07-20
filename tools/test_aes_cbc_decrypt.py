#!/usr/bin/env python3
"""
test_aes_cbc_decrypt.py - AES-256-CBC Decrypt Functional Test

Encrypts random plaintext in Python, injects ciphertext into VICE memory,
triggers C64 AES-256-CBC decrypt (menu option 4), and verifies the decrypted
output matches the original padded plaintext.

For each iteration:
  1. Generate random plaintext (1–63 bytes) and random IV
  2. PKCS#7 pad and AES-256-CBC encrypt in Python using the C64's key
  3. Write IV, ciphertext, and length into VICE memory
  4. Press 4 (decrypt) → wait for "Q=QUIT"
  5. Read decrypt_data from memory
  6. Verify decrypted bytes == PKCS#7-padded plaintext

The C64 does NOT strip PKCS#7 padding, so the comparison is against the
padded plaintext.

A dummy encrypt (option 2) is performed once at startup to prime the
expanded_key, which is only computed during encrypt.

Usage:
    python3 tools/test_aes_cbc_decrypt.py [--iterations N] [--seed S]

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
    ScreenGrid,
    ViceConfig,
    ViceInstanceManager,
    C64Transport as ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    send_key,
    send_text,
    wait_for_text,
    wait_for_stable,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

MAX_INPUT_LEN = 63
SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_ITERATIONS = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_string(min_len: int = 1, max_len: int = MAX_INPUT_LEN) -> str:
    """Generate a random string of safe characters with random length."""
    length = random.randint(min_len, max_len)
    return "".join(random.choice(SAFE_CHARS) for _ in range(length))


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

    # Wait for the encryption to actually complete. "Q=QUIT" is part of the
    # always-visible static menu footer (instructions_msg), so it is already
    # on screen before the keypress above is even processed and is NOT a
    # valid "operation finished" signal. "ENCRYPTION COMPLETE" is printed by
    # encrypt_done_msg only after encrypt_input actually runs.
    grid = wait_for_text(transport, "ENCRYPTION COMPLETE", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after encryption")
        return False

    return True


def python_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encrypt with PKCS#7 padding."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def pkcs7_pad(plaintext: bytes) -> bytes:
    """Apply PKCS#7 padding (128-bit block)."""
    padder = padding.PKCS7(128).padder()
    return padder.update(plaintext) + padder.finalize()


def decrypt_on_c64(
    transport: ViceTransport,
    labels: Labels,
    iv: bytes,
    ciphertext: bytes,
    timeout: float = 30.0,
) -> bytes | None:
    """Inject ciphertext into VICE memory and trigger C64 decrypt.

    Returns the decrypted bytes or None on error.
    """
    iv_addr = labels.address("iv_data")
    enc_buf_addr = labels.address("encrypt_buffer")
    enc_len_addr = labels.address("encrypt_length")
    dec_data_addr = labels.address("decrypt_data")

    # Write IV, ciphertext, and length
    write_bytes(transport, iv_addr, iv)
    write_bytes(transport, enc_buf_addr, ciphertext)
    write_bytes(transport, enc_len_addr, bytes([len(ciphertext)]))

    # Blank the text screen before triggering the decrypt. "DECRYPTED (HEX)"
    # is a valid one-shot completion marker for a single decrypt, but this
    # helper is called once per test iteration and the marker text from the
    # PREVIOUS iteration's output stays on screen (it is not cleared, only
    # scrolled/appended to) until the next decrypt actually redraws it. That
    # means wait_for_text() below would otherwise match the stale marker on
    # its very first (level-triggered) poll, before the CPU has even been
    # resumed to run this iteration's decrypt - the exact same class of bug
    # as the "Q=QUIT" static-footer issue, just recurring across iterations.
    # Clearing screen RAM directly guarantees the marker is genuinely absent
    # until this iteration's decrypt prints it fresh.
    write_bytes(transport, 0x0400, bytes([0x20]) * 1000)

    # Press 4 to decrypt
    send_key(transport, "4")

    # Wait for the decrypt to actually complete. "Q=QUIT" is part of the
    # always-visible static menu footer (instructions_msg), so it is already
    # on screen before the keypress above is even processed and is NOT a
    # valid "operation finished" signal. "DECRYPTED (HEX)" is printed by
    # decrypted_header_msg only after decrypt_input actually runs.
    grid = wait_for_text(transport, "DECRYPTED (HEX)", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after decrypt")
        return None

    # Read decrypted output (length = encrypt_length, since C64 sets
    # decrypt_length = encrypt_length)
    decrypted = read_bytes(transport, dec_data_addr, len(ciphertext))
    if decrypted is None:
        print("    ERROR: Could not read decrypt_data from memory")
        return None

    return decrypted


def recover_to_menu(transport: ViceTransport, timeout: float = 15.0) -> bool:
    """Try to get back to main menu from any state."""
    for _ in range(5):
        send_key(transport, "\r")
        time.sleep(0.15)
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    return grid is not None


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def run_aes_cbc_decrypt_tests(
    transport: ViceTransport,
    labels: Labels,
    key: bytes,
    iterations: int,
) -> tuple[int, int]:
    """Run AES-256-CBC decrypt tests, return (passed, failed)."""
    passed = 0
    failed = 0

    # Build test cases with boundary cases first
    test_cases: list[tuple[int, str]] = []
    test_cases.append((1, "Minimum input, 15 bytes PKCS#7 padding"))
    test_cases.append((16, "Exact block boundary, full padding block"))
    test_cases.append((48, "3 blocks + full padding block = max 4 blocks"))
    test_cases.append((63, "Maximum input, 1 byte padding"))

    # Fill remaining with random lengths
    for _ in range(max(0, iterations - len(test_cases))):
        test_cases.append((random.randint(1, MAX_INPUT_LEN), "Random length"))

    # Trim to requested count
    test_cases = test_cases[:iterations]

    for i, (pt_len, description) in enumerate(test_cases):
        plaintext_str = generate_random_string(pt_len, pt_len)
        plaintext_bytes = plaintext_str.encode("ascii")
        padded = pkcs7_pad(plaintext_bytes)
        iv = bytes(random.getrandbits(8) for _ in range(16))
        ciphertext = python_encrypt(plaintext_bytes, key, iv)

        ct_len = len(ciphertext)
        print(f"\n--- Test {i + 1}/{iterations}: {pt_len} bytes PT → {ct_len}-byte CT ({description}) ---")
        print(f"  Plaintext: \"{plaintext_str}\"")

        # Safety check: ciphertext must fit in decrypt_data (64 bytes)
        assert ct_len <= 64, (
            f"BUG: ciphertext length {ct_len} exceeds decrypt_data buffer (64)"
        )

        # Decrypt on C64
        decrypted = decrypt_on_c64(transport, labels, iv, ciphertext)
        if decrypted is None:
            print("  FAIL: C64 interaction error")
            failed += 1
            dump_screen(transport, f"aes_cbc_dec_test_{i+1}_error")
            if not recover_to_menu(transport):
                print("  FATAL: Could not recover to main menu")
                return passed, failed + (iterations - i)
            continue

        # Display results
        print(f"  C64 decrypted: {decrypted.hex()}")
        print(f"  Expected:      {padded.hex()}")

        if decrypted == padded:
            # Also verify unpadded plaintext prefix
            if decrypted[:pt_len] == plaintext_bytes:
                print(f"  PASS")
                passed += 1
            else:
                print(f"  FAIL: padded match but plaintext prefix mismatch!")
                print(f"  PT bytes:  {plaintext_bytes.hex()}")
                print(f"  Got:       {decrypted[:pt_len].hex()}")
                failed += 1
                dump_screen(transport, f"aes_cbc_dec_test_{i+1}_prefix")
        else:
            print(f"  FAIL: decrypted output mismatch!")
            print(f"  Key: {key.hex()}")
            print(f"  IV:  {iv.hex()}")
            print(f"  CT:  {ciphertext.hex()}")
            failed += 1
            dump_screen(transport, f"aes_cbc_dec_test_{i+1}_mismatch")

    return passed, failed


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
        "key_data", "iv_data", "encrypt_length", "encrypt_buffer",
        "decrypt_data", "decrypt_length",
    ]
    for lbl in required_labels:
        if labels.address(lbl) is None:
            print(f"FATAL: '{lbl}' label not found")
            sys.exit(1)
    print(f"  Labels loaded:")
    print(f"    key_data         @ ${labels['key_data']:04X}")
    print(f"    iv_data          @ ${labels['iv_data']:04X}")
    print(f"    encrypt_length   @ ${labels['encrypt_length']:04X}")
    print(f"    encrypt_buffer   @ ${labels['encrypt_buffer']:04X}")
    print(f"    decrypt_data     @ ${labels['decrypt_data']:04X}")
    print(f"    decrypt_length   @ ${labels['decrypt_length']:04X}")

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
        print(f"  VICE started (PID {inst.pid}, port {inst.port})")

        transport = inst.transport

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        # Prime key expansion: encrypt a dummy string via option 2
        print("\n=== Priming key expansion ===")
        ok = encrypt_text_on_c64(transport, "A")
        if not ok:
            print("FATAL: Could not prime key expansion")
            dump_screen(transport, "prime_error")
            sys.exit(1)

        # Read the AES-256 key (generated at boot, now expanded)
        key_addr = labels.address("key_data")
        key = read_bytes(transport, key_addr, 32)
        if key is None:
            print("FATAL: Could not read key_data")
            sys.exit(1)
        print(f"  Key: {key.hex()}")
        print("  Key expansion primed")

        # Run tests
        print(f"\n=== AES-256-CBC Decrypt Functional Test ({iterations} iterations) ===")
        passed, failed = run_aes_cbc_decrypt_tests(
            transport, labels, key, iterations
        )

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] AES-256-CBC DECRYPT: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] AES-256-CBC DECRYPT: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
