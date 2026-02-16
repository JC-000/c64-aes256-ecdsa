#!/usr/bin/env python3
"""
test_sha256.py - SHA-256 Menu Option Functional Test

Iteratively feeds random strings through the C64 SHA-256 menu option (key 9)
and validates each result against Python hashlib (OpenSSL-backed).

For each iteration:
  1. Enter text via menu option 2 (Encrypt Text — populates input_buffer)
  2. Hash via menu option 9 (SHA-256)
  3. Read sha256_hash from C64 memory
  4. Display C64 result above the OpenSSL result
  5. Compare

Input constraints:
  - input_buf_size = 64, but do_encrypt_text caps at input_buf_size-1 = 63 chars
  - sha256_update handles single-block (≤55 bytes) and two-block (56-63 bytes)
  - Characters limited to uppercase A-Z + digits 0-9 (PETSCII $41-$5A, $30-$39
    = ASCII, so byte-identical for hashing)

Usage:
    python3 tools/test_sha256.py [--iterations N]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hashlib
import os
import random
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ScreenGrid,
    ViceConfig,
    ViceProcess,
    ViceTransport,
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
    """Generate a random string of safe characters with random length.

    Ensures coverage of:
      - Short strings (1-10 bytes): single SHA-256 block, short padding
      - Medium strings (11-55 bytes): single block, longer data
      - Long strings (56-63 bytes): triggers two-block SHA-256 path
    """
    length = random.randint(min_len, max_len)
    return "".join(random.choice(SAFE_CHARS) for _ in range(length))


def enter_text_and_hash(
    transport: ViceTransport, text: str, timeout: float = 30.0
) -> bool:
    """Enter text via option 2, then hash via option 9.

    Returns True if both operations completed successfully.
    """
    # Press 2 to enter text
    send_key(transport, "2")
    grid = wait_for_text(transport, "ENTER TEXT", timeout=timeout, verbose=False)
    if grid is None:
        print("    ERROR: 'ENTER TEXT' prompt did not appear")
        return False

    time.sleep(0.1)

    # Type the text and press RETURN
    send_text(transport, text)
    time.sleep(0.1)
    send_key(transport, "\r")

    # Wait for encryption to complete and return to menu
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after text entry")
        return False

    time.sleep(0.1)

    # Press 9 to hash
    send_key(transport, "9")

    # Wait for hash display — look for "SHA-256 HASH"
    grid = wait_for_text(transport, "SHA-256 HASH", timeout=timeout, verbose=False)
    if grid is None:
        print("    ERROR: SHA-256 hash output did not appear")
        return False

    # Wait for menu to reappear (hash display complete)
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        print("    ERROR: Did not return to menu after hashing")
        return False

    return True


def read_c64_hash(transport: ViceTransport, labels: Labels) -> bytes | None:
    """Read 32-byte sha256_hash from C64 memory."""
    addr = labels.address("sha256_hash")
    if addr is None:
        print("    ERROR: sha256_hash label not found")
        return None
    return read_bytes(transport, addr, 32)


def parse_hash_from_screen(transport: ViceTransport) -> str | None:
    """Parse the hex hash from screen output as a display string.

    The C64 displays 4 lines of 8 hex bytes each:
        6A 09 E6 67 BB 67 AE 85
        3C 6E F3 72 A5 4F F5 3A
        ...
    """
    grid = ScreenGrid.from_transport(transport)
    text = grid.continuous_text().upper()

    idx = text.find("SHA-256 HASH")
    if idx < 0:
        return None

    # Extract hex characters after the header
    after = text[idx + 13:]  # skip past "SHA-256 HASH:"
    hex_chars = []
    for ch in after:
        if ch in "0123456789ABCDEF":
            hex_chars.append(ch)
        elif ch in (" ", "\n"):
            continue
        elif len(hex_chars) >= 64:
            break
    if len(hex_chars) >= 64:
        return "".join(hex_chars[:64]).lower()
    return None


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

def run_sha256_tests(
    transport: ViceTransport,
    labels: Labels,
    iterations: int,
) -> tuple[int, int]:
    """Run SHA-256 tests, return (passed, failed)."""
    passed = 0
    failed = 0

    # Ensure we have a spread of lengths including the two-block boundary
    test_strings = []

    # Fixed boundary cases
    test_strings.append(generate_random_string(1, 1))       # 1 byte (minimum)
    test_strings.append(generate_random_string(55, 55))     # 55 bytes (last single-block)
    test_strings.append(generate_random_string(56, 56))     # 56 bytes (first two-block)
    test_strings.append(generate_random_string(63, 63))     # 63 bytes (maximum)

    # Fill remaining with random lengths
    for _ in range(max(0, iterations - len(test_strings))):
        test_strings.append(generate_random_string(1, MAX_INPUT_LEN))

    # Trim to requested count
    test_strings = test_strings[:iterations]

    for i, test_input in enumerate(test_strings):
        input_len = len(test_input)
        block_type = "single-block" if input_len <= 55 else "two-block"
        print(f"\n--- Test {i + 1}/{iterations}: {input_len} bytes ({block_type}) ---")
        print(f"  Input: \"{test_input}\"")

        # Validate length constraint
        assert input_len <= MAX_INPUT_LEN, (
            f"BUG: generated string length {input_len} exceeds "
            f"C64 input_buf_size-1 ({MAX_INPUT_LEN})"
        )

        # Enter text and hash on C64
        ok = enter_text_and_hash(transport, test_input)
        if not ok:
            print("  FAIL: C64 interaction error")
            failed += 1
            dump_screen(transport, f"sha256_test_{i+1}_error")
            if not recover_to_menu(transport):
                print("  FATAL: Could not recover to main menu")
                return passed, failed + (iterations - i)
            continue

        # Read C64 hash from memory
        c64_hash = read_c64_hash(transport, labels)
        if c64_hash is None:
            print("  FAIL: Could not read sha256_hash from memory")
            failed += 1
            continue

        # Compute reference hash with Python/OpenSSL
        # PETSCII uppercase A-Z = $41-$5A, digits 0-9 = $30-$39
        # These are identical to ASCII, so encode as ASCII
        reference_hash = hashlib.sha256(test_input.encode("ascii")).digest()

        # Display results
        c64_hex = c64_hash.hex()
        ref_hex = reference_hash.hex()

        print(f"  C64 SHA-256:    {c64_hex}")
        print(f"  OpenSSL SHA-256: {ref_hex}")

        if c64_hash == reference_hash:
            print(f"  PASS")
            passed += 1
        else:
            print(f"  FAIL: hash mismatch!")
            failed += 1
            dump_screen(transport, f"sha256_test_{i+1}_mismatch")

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
    if labels.address("sha256_hash") is None:
        print("FATAL: 'sha256_hash' label not found")
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

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        # Run tests
        print(f"\n=== SHA-256 Functional Test ({iterations} iterations) ===")
        passed, failed = run_sha256_tests(transport, labels, iterations)

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] SHA-256: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] SHA-256: {failed} TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
