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


def test_aes_cbc_encrypt_overflow(
    transport: ViceTransport,
    labels: Labels,
) -> bool:
    """Guard test: encrypt_input must reject an out-of-range input_length.

    encrypt_input bounds input_length against input_buf_size (64) before it
    touches any buffer (HANDOFF.md Bug 9, fixed). 64 is the largest accepted
    length: PKCS#7 turns it into exactly 5 blocks = 80 bytes, which is exactly
    encrypt_buf_size. Longer inputs previously over-read input_buffer, overran
    encrypt_buffer into decrypt_data, and from ~200 corrupted the
    block_count/current_block loop control itself (making the iteration count
    non-deterministic, sometimes hanging).

    A rejected call must be a complete no-op: no ciphertext written, adjacent
    decrypt_data untouched, and encrypt_length/block_count zeroed so no stale
    output length is left behind for a caller to trust. The UI text-entry loop
    clamps at 63, but this direct jsr() path bypasses it entirely — which is
    precisely the path the guard exists to protect.

    Returns True if the guard holds at every probed length.
    """
    print("\n\n=== Guard: out-of-range input_length rejected (encrypt) ===")

    enc_buf = labels["encrypt_buffer"]
    dec_buf = labels["decrypt_data"]
    in_buf = labels["input_buffer"]
    MAX_INPUT = 64  # input_buf_size in src/constants.s

    key = bytes(random.getrandbits(8) for _ in range(32))
    iv = bytes(random.getrandbits(8) for _ in range(16))
    write_bytes(transport, labels["key_data"], key)
    write_bytes(transport, labels["iv_data"], iv)
    robust_jsr(transport, labels["aes_key_expansion"], timeout=5.0)

    DEC_SENTINEL = b"\xEE" * 64
    ENC_SENTINEL = b"\xDD" * 80
    ok = True

    def probe(length: int) -> dict:
        should_accept = length <= MAX_INPUT

        # Sentinel both the output buffer and the buffer immediately after it,
        # so a rejected call is provably a no-op and an accepted one provably
        # stays inside its own buffer.
        write_bytes(transport, in_buf, bytes((i * 7) & 0xFF for i in range(64)))
        write_bytes(transport, enc_buf, ENC_SENTINEL)
        write_bytes(transport, dec_buf, DEC_SENTINEL)
        write_bytes(transport, labels["input_length"], bytes([length]))

        obs = {"length": length, "should_accept": should_accept,
               "timed_out": False}
        try:
            # A working guard cannot hang. Keep the bounded budget so a
            # regression that reintroduces loop-control corruption fails here
            # instead of stalling the suite.
            robust_jsr(transport, labels["encrypt_input"],
                       timeout=30.0, retries=1)
        except Exception as e:
            obs["timed_out"] = True
            obs["error"] = str(e)
            print(f"  len={length:3d}: jsr did not return within budget ({e}) "
                  f"— the guard should make this impossible")
            return obs

        obs["enc_len"] = read_bytes(transport, labels["encrypt_length"], 1)[0]
        obs["blocks"] = read_bytes(transport, labels["block_count"], 1)[0]
        obs["dec_clobbered"] = read_bytes(transport, dec_buf, 64) != DEC_SENTINEL
        obs["enc_written"] = read_bytes(transport, enc_buf, 80) != ENC_SENTINEL

        print(f"  len={length:3d}: {'accept' if should_accept else 'REJECT':6s} "
              f"encrypt_length={obs['enc_len']:3d} block_count={obs['blocks']:2d} "
              f"encrypt_buffer {'written' if obs['enc_written'] else 'untouched'} "
              f"decrypt_data {'CLOBBERED' if obs['dec_clobbered'] else 'intact'}")
        return obs

    # 64 is the boundary — the largest length that still fits (5 blocks / 80
    # bytes). 65 is the first rejection. 128/200/255 are the lengths that used
    # to clobber decrypt_data, the loop control, and (at 255) wrap
    # encrypt_length to 0x00.
    for length in (64, 65, 128, 200, 255):
        o = probe(length)
        if o["timed_out"]:
            ok = False
            continue
        if o["should_accept"]:
            if o["enc_len"] != 80 or o["blocks"] != 5:
                print(f"  FAIL: len={length} should produce 5 blocks / 80 bytes, "
                      f"got block_count={o['blocks']} encrypt_length={o['enc_len']}")
                ok = False
            if o["dec_clobbered"]:
                print(f"  FAIL: len={length} is in range but clobbered decrypt_data")
                ok = False
            if not o["enc_written"]:
                print(f"  FAIL: len={length} is in range but wrote no ciphertext")
                ok = False
        else:
            if o["dec_clobbered"]:
                print(f"  FAIL: len={length} was not rejected — decrypt_data "
                      f"clobbered (Bug 9 has regressed)")
                ok = False
            if o["enc_written"]:
                print(f"  FAIL: len={length} was rejected but still wrote to "
                      f"encrypt_buffer")
                ok = False
            if o["enc_len"] != 0 or o["blocks"] != 0:
                print(f"  FAIL: len={length} was rejected but left "
                      f"encrypt_length={o['enc_len']} block_count={o['blocks']} "
                      f"(expected 0/0 — no stale output length)")
                ok = False

    if ok:
        print("  PASS (every out-of-range length rejected, adjacent memory intact)")
    else:
        print("  FAIL: encrypt_input's length guard did not hold")
    return ok


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

    # Depth: out-of-range length fault injection (leaves memory corrupted,
    # so run it after the correctness cases)
    if test_aes_cbc_encrypt_overflow(transport, labels):
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
        "decrypt_data",
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
