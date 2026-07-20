#!/usr/bin/env python3
"""
test_aes_cbc.py - AES-256-CBC Encrypt Functional Test

Iteratively feeds random strings through the C64 AES-256-CBC encrypt menu option
(key 2) and validates each ciphertext against Python's cryptography library with
PKCS#7 padding.

For each iteration:
  1. Press 2 → wait for "ENTER TEXT" prompt
  2. Send random string (1–63 chars, uppercase A-Z + digits 0-9) + RETURN
  3. Wait for "Q=QUIT" (menu returns after encryption)
  4. Read key_data (32), iv_data (16), encrypt_length (1), encrypt_buffer from memory
  5. Compute reference AES-256-CBC with PKCS#7 padding using same key/IV
  6. Compare ciphertexts

Input constraints:
  - input_buf_size = 64, do_encrypt_text caps at 63 chars
  - PKCS#7 padding always adds 1–16 bytes
  - Max ciphertext: 63 + 1 = 64 bytes (fits encrypt_buf_size = 80)

Usage:
    python3 tools/test_aes_cbc.py [--iterations N] [--seed S]

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

# C64 input_buf_size = 64, but do_encrypt_text limits to input_buf_size-1 = 63
MAX_INPUT_LEN = 63

# Safe character set: PETSCII codes identical to ASCII
SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

DEFAULT_ITERATIONS = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_string(min_len: int = 1, max_len: int = MAX_INPUT_LEN) -> str:
    """Generate a random string of safe characters with random length."""
    length = random.randint(min_len, max_len)
    return "".join(random.choice(SAFE_CHARS) for _ in range(length))


def force_cpu_execution(transport: ViceTransport, duration: float = 1.0, poll_interval: float = 0.25) -> None:
    """Unconditionally resume the CPU and let it run for *duration* seconds.

    The C64 screen is never cleared between menu operations, so the text
    a caller is about to wait for (e.g. "ENTER TEXT" or "ENCRYPTION
    COMPLETE") is typically still visible on screen already, left over
    from a *previous* iteration's output. wait_for_text() is level-
    triggered: it checks the screen BEFORE ever calling resume(), so if
    the needle already happens to be present it returns immediately
    without giving the CPU any chance to run the operation just triggered
    by the preceding keypress(es) -- the bug this whole file was hit by
    when it used to wait on the always-visible "Q=QUIT" footer, and which
    resurfaces against any needle once the test loops past its first
    iteration and that needle's prior occurrence is still on screen.

    Calling this (which calls resume() unconditionally, on every cycle,
    regardless of screen content) BEFORE a wait_for_text() check closes
    that gap: by the time the check runs, the CPU has genuinely executed
    for *duration* seconds of wall-clock time. AES-256-CBC over <=64
    bytes is a few thousand 6502 cycles -- effectively instantaneous next
    to a 1s budget, even without VICE's warp mode -- so this reliably
    covers real completion, not just "the CPU ran for a bit."
    """
    elapsed = 0.0
    while elapsed < duration:
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(poll_interval)
        elapsed += poll_interval


def encrypt_text_on_c64(
    transport: ViceTransport, text: str, timeout: float = 30.0
) -> bool:
    """Enter text via option 2 (encrypt), wait for completion.

    Returns True if the operation completed successfully.
    """
    # Press 2 to enter text / encrypt
    send_key(transport, "2")
    # Force real CPU execution before checking for the prompt -- see
    # force_cpu_execution() docstring for why this is required even
    # though "ENTER TEXT" (unlike "Q=QUIT") is a legitimate per-operation
    # completion marker in principle.
    force_cpu_execution(transport, duration=0.5)
    grid = wait_for_text(transport, "ENTER TEXT", timeout=timeout, verbose=False)
    if grid is None:
        print("    ERROR: 'ENTER TEXT' prompt did not appear")
        return False

    time.sleep(0.1)

    # Type the text and press RETURN
    send_text(transport, text)
    time.sleep(0.1)
    send_key(transport, "\r")

    # Wait for the encryption to actually complete. "Q=QUIT" is part of the
    # always-visible static menu footer (instructions_msg), so it is already
    # on screen before the keypress above is even processed and is NOT a
    # valid "operation finished" signal. "ENCRYPTION COMPLETE" is printed by
    # encrypt_done_msg only after encrypt_input actually runs. Force real
    # execution time first (see force_cpu_execution) so this check can't
    # short-circuit on a prior iteration's leftover "ENCRYPTION COMPLETE".
    force_cpu_execution(transport, duration=1.0)
    grid = wait_for_text(transport, "ENCRYPTION COMPLETE", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after encryption")
        return False

    return True


def read_c64_ciphertext(
    transport: ViceTransport, labels: Labels
) -> tuple[bytes, bytes, bytes] | None:
    """Read key, IV, and ciphertext from C64 memory.

    Returns (key, iv, ciphertext) or None on error.
    """
    key_addr = labels.address("key_data")
    iv_addr = labels.address("iv_data")
    len_addr = labels.address("encrypt_length")
    buf_addr = labels.address("encrypt_buffer")

    if any(a is None for a in (key_addr, iv_addr, len_addr, buf_addr)):
        print("    ERROR: Required label(s) not found")
        return None

    key = read_bytes(transport, key_addr, 32)
    iv = read_bytes(transport, iv_addr, 16)
    ct_len_byte = read_bytes(transport, len_addr, 1)

    if key is None or iv is None or ct_len_byte is None:
        print("    ERROR: Could not read key/IV/length from memory")
        return None

    ct_len = ct_len_byte[0]
    if ct_len == 0 or ct_len > 80:
        print(f"    ERROR: Invalid encrypt_length: {ct_len}")
        return None

    ct = read_bytes(transport, buf_addr, ct_len)
    if ct is None:
        print("    ERROR: Could not read ciphertext from memory")
        return None

    return key, iv, ct


def compute_reference_ciphertext(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Compute AES-256-CBC ciphertext with PKCS#7 padding."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def recover_to_menu(transport: ViceTransport, timeout: float = 15.0) -> bool:
    """Try to get back to main menu from any state."""
    for _ in range(5):
        send_key(transport, "\r")
        time.sleep(0.15)
    # "Q=QUIT" is the correct target here (we genuinely want to detect the
    # idle main menu), but it is also part of the always-visible footer, so
    # wait_for_text() would match it instantly on its first check without
    # ever calling resume() -- meaning the RETURN keypresses just queued
    # above would never actually get processed by the CPU. Explicitly
    # resume so they run before we check.
    transport.resume()
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    return grid is not None


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def run_aes_cbc_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
) -> tuple[int, int]:
    """Run AES-256-CBC tests, return (passed, failed)."""
    passed = 0
    failed = 0

    # Build test strings with boundary cases first
    test_strings = []
    test_strings.append(generate_random_string(1, 1))       # 1 byte: 15 pad → 16-byte CT
    test_strings.append(generate_random_string(16, 16))      # 16 bytes: block boundary → 32-byte CT
    test_strings.append(generate_random_string(48, 48))      # 48 bytes: 3 blocks + pad → 64-byte CT
    test_strings.append(generate_random_string(63, 63))      # 63 bytes: max input → 64-byte CT

    # Fill remaining with random lengths
    for _ in range(max(0, iterations - len(test_strings))):
        test_strings.append(generate_random_string(1, MAX_INPUT_LEN))

    # Trim to requested count
    test_strings = test_strings[:iterations]

    for i, test_input in enumerate(test_strings):
        input_len = len(test_input)
        expected_ct_len = ((input_len // 16) + 1) * 16
        print(f"\n--- Test {i + 1}/{iterations}: {input_len} bytes → {expected_ct_len}-byte CT ---")
        print(f"  Input: \"{test_input}\"")

        assert input_len <= MAX_INPUT_LEN, (
            f"BUG: generated string length {input_len} exceeds "
            f"C64 input_buf_size-1 ({MAX_INPUT_LEN})"
        )

        # Encrypt on C64
        ok = encrypt_text_on_c64(transport, test_input)
        if not ok:
            print("  FAIL: C64 interaction error")
            failed += 1
            dump_screen(transport, f"aes_cbc_test_{i+1}_error")
            if not recover_to_menu(transport):
                print("  FATAL: Could not recover to main menu")
                return passed, failed + (iterations - i)
            continue

        # Read C64 results from memory
        result = read_c64_ciphertext(transport, labels)
        if result is None:
            print("  FAIL: Could not read ciphertext from memory")
            failed += 1
            continue

        c64_key, c64_iv, c64_ct = result

        # Compute reference ciphertext with same key/IV
        plaintext_bytes = test_input.encode("ascii")
        reference_ct = compute_reference_ciphertext(plaintext_bytes, c64_key, c64_iv)

        # Display results
        print(f"  C64 ciphertext:    {c64_ct.hex()}")
        print(f"  Reference CT:      {reference_ct.hex()}")

        if c64_ct == reference_ct:
            print(f"  PASS")
            passed += 1
        else:
            print(f"  FAIL: ciphertext mismatch!")
            print(f"  Key: {c64_key.hex()}")
            print(f"  IV:  {c64_iv.hex()}")
            failed += 1
            dump_screen(transport, f"aes_cbc_test_{i+1}_mismatch")

    return passed, failed


def main():
    os.chdir(PROJECT_ROOT)

    # Parse args
    iterations = DEFAULT_ITERATIONS
    if "--iterations" in sys.argv:
        idx = sys.argv.index("--iterations")
        if idx + 1 < len(sys.argv):
            iterations = int(sys.argv[idx + 1])

    # Seed RNG for reproducibility (optional override)
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
    required_labels = ["key_data", "iv_data", "encrypt_length", "encrypt_buffer"]
    for lbl in required_labels:
        if labels.address(lbl) is None:
            print(f"FATAL: '{lbl}' label not found")
            sys.exit(1)
    print(f"  Labels loaded:")
    print(f"    key_data        @ ${labels['key_data']:04X}")
    print(f"    iv_data         @ ${labels['iv_data']:04X}")
    print(f"    encrypt_length  @ ${labels['encrypt_length']:04X}")
    print(f"    encrypt_buffer  @ ${labels['encrypt_buffer']:04X}")

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

        # Run tests
        print(f"\n=== AES-256-CBC Functional Test ({iterations} iterations) ===")
        passed, failed = run_aes_cbc_tests(transport, labels, iterations)

        mgr.release(inst)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] AES-256-CBC: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] AES-256-CBC: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
