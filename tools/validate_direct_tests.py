#!/usr/bin/env python3
"""
validate_direct_tests.py - Cross-Validation of UI-driven vs Direct-Memory Tests

Runs both the UI-driven and direct-memory AES-256-CBC tests with identical inputs
(same random seed) on a single VICE instance, comparing outputs byte-for-byte.
Also validates AES-256-GCM-SIV direct-memory output against OpenSSL AESGCMSIV.

This validates that the direct-memory tests produce exactly the same results as
the original UI-driven tests (CBC) and the OpenSSL reference (GCM-SIV).

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
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from polyval_reference import gcmsiv_encrypt as py_gcmsiv_encrypt

from c64_test_harness import (
    Labels,
    ViceConfig,
    C64Transport as ViceTransport,
    ScreenGrid,
    dump_screen,
    read_bytes,
    write_bytes,
    send_key,
    send_text,
    wait_for_text,
    jsr,
)
from c64_test_harness.backends.vice_manager import ViceInstanceManager

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


def current_screen_text(transport: ViceTransport) -> str:
    """Snapshot the current screen as continuous text, without resuming."""
    return ScreenGrid.from_transport(transport).continuous_text()


def wait_for_operation(
    transport: ViceTransport,
    needle: str,
    baseline: str,
    timeout: float = 30.0,
    poll_interval: float = 0.5,
) -> ScreenGrid | None:
    """Wait for *needle* to appear on screen as a result of an operation
    that was just triggered by a keypress, WITHOUT falsely matching text
    that was already sitting on screen (in *baseline*, captured right
    before the triggering keypress) from a previous operation.

    This C64 program's screen is a plain scrolling text console that is
    never cleared between operations, and menu selections/results (e.g.
    the "Q=QUIT" footer, or a completion banner like "ENCRYPTION COMPLETE")
    routinely stay within the visible 25-row window across several
    subsequent operations -- especially in this script, which interleaves
    silent direct-memory jsr() calls and program restarts that add no (or
    stale-matching) visible output of their own. Plain wait_for_text()
    only calls transport.resume() when the needle is ABSENT, so it matches
    such leftover text on its very first (non-resuming) check, before the
    CPU ever runs the operation that was just triggered. Requiring the
    screen text to differ from the pre-keypress baseline guarantees at
    least one real resume()+poll cycle happens before a match can be
    accepted, so a match here reflects real, new output.
    """
    start = time.monotonic()
    needle_upper = needle.upper()
    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            return None
        try:
            grid = ScreenGrid.from_transport(transport)
            text = grid.continuous_text()
            if text != baseline and needle_upper in text.upper():
                return grid
        except Exception:
            pass
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(poll_interval)


def recover_to_menu(transport: ViceTransport, timeout: float = 30.0) -> bool:
    baseline = current_screen_text(transport)
    send_key(transport, "\r")
    grid = wait_for_operation(transport, "Q=QUIT", baseline, timeout=timeout)
    if grid is not None:
        return True
    # Already at a quiescent "Q=QUIT" menu screen (no change from one more
    # RETURN) -- treat as recovered rather than looping forever.
    return "Q=QUIT" in baseline.upper()


def restart_program(transport: ViceTransport, timeout: float = 60.0) -> bool:
    baseline = current_screen_text(transport)
    send_text(transport, "RUN")
    time.sleep(0.1)
    send_key(transport, "\r")
    # See wait_for_operation() docstring: "Q=QUIT" is genuinely the right
    # needle here (we want the fresh main menu after the restart), but the
    # *previous* run's menu footer (which also contains "Q=QUIT") is still
    # sitting on screen from before RUN was typed, so we must confirm the
    # screen actually changed before trusting the match.
    grid = wait_for_operation(transport, "Q=QUIT", baseline, timeout=timeout)
    return grid is not None


# ---------------------------------------------------------------------------
# UI-driven encrypt (from test_aes_cbc.py)
# ---------------------------------------------------------------------------

def ui_encrypt(transport: ViceTransport, text: str, timeout: float = 30.0) -> bool:
    baseline = current_screen_text(transport)
    send_key(transport, "2")
    # "ENTER TEXT" is not part of the static footer, but on this
    # never-cleared scrolling screen it (and everything printed after it,
    # including a previous "ENCRYPTION COMPLETE") can still be sitting in
    # the visible 25-row window from a prior iteration -- see
    # wait_for_operation() docstring.
    grid = wait_for_operation(transport, "ENTER TEXT", baseline, timeout=timeout)
    if grid is None:
        return False
    baseline = grid.continuous_text()
    time.sleep(0.1)
    send_text(transport, text)
    time.sleep(0.1)
    send_key(transport, "\r")
    # NOTE: "Q=QUIT" is part of the always-visible main-menu footer (printed
    # by instructions_msg in src/strings.s) and stays on screen WHILE the
    # encrypt operation runs, so it is present on the stale pre-keypress
    # screen too. Wait for the operation's own completion message instead
    # (encrypt_done_msg in src/aes_encrypt.s) -- itself subject to the same
    # staleness risk, hence wait_for_operation() rather than wait_for_text().
    grid = wait_for_operation(transport, "ENCRYPTION COMPLETE", baseline, timeout=timeout)
    return grid is not None


def ui_decrypt(transport: ViceTransport, timeout: float = 30.0) -> bool:
    baseline = current_screen_text(transport)
    send_key(transport, "4")
    # Same stale-match issue as ui_encrypt() above, both for "Q=QUIT" and for
    # the "DECRYPTED (HEX)" completion message itself (decrypted_header_msg
    # in src/aes_decrypt.s, printed as "*** DECRYPTED (HEX) ***").
    grid = wait_for_operation(transport, "DECRYPTED (HEX)", baseline, timeout=timeout)
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
# GCM-SIV Direct-memory helpers
# ---------------------------------------------------------------------------

def gcmsiv_direct_encrypt(
    transport: ViceTransport, labels: Labels,
    key: bytes, nonce: bytes, plaintext: bytes,
) -> tuple[bytes, bytes] | None:
    """Encrypt via C64 GCM-SIV, return (ciphertext, tag) or None."""
    try:
        write_bytes(transport, labels["key_data"], key)
        jsr(transport, labels["aes_key_expansion"], timeout=10.0)
        write_bytes(transport, labels["gcmsiv_nonce"], nonce)
        write_bytes(transport, labels["gcmsiv_pt_buf"], plaintext)
        write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(plaintext)]))
        jsr(transport, labels["gcmsiv_encrypt"], timeout=120.0)
        ct = read_bytes(transport, labels["gcmsiv_ct_buf"], len(plaintext))
        tag = read_bytes(transport, labels["gcmsiv_tag"], 16)
        return ct, tag
    except Exception as e:
        print(f"    gcmsiv_direct_encrypt error: {e}")
        return None


def gcmsiv_direct_decrypt(
    transport: ViceTransport, labels: Labels,
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
) -> tuple[bytes, int] | None:
    """Decrypt via C64 GCM-SIV, return (plaintext, tag_valid) or None."""
    try:
        write_bytes(transport, labels["key_data"], key)
        jsr(transport, labels["aes_key_expansion"], timeout=10.0)
        write_bytes(transport, labels["gcmsiv_nonce"], nonce)
        write_bytes(transport, labels["gcmsiv_ct_buf"], ciphertext)
        # NOTE: there is no separate "gcmsiv_ct_len" label in the 6502 source
        # (grep -rn gcmsiv_ct_len src/ returns nothing) - gcmsiv_pt_len is
        # reused for both the encrypt-plaintext-length and the
        # decrypt-ciphertext-length (see src/gcm_siv.s), exactly as
        # tools/test_gcmsiv_polyval.py already does.
        write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(ciphertext)]))
        write_bytes(transport, labels["gcmsiv_tag"], tag)
        jsr(transport, labels["gcmsiv_decrypt"], timeout=120.0)
        pt = read_bytes(transport, labels["gcmsiv_dec_buf"], len(ciphertext))
        tag_valid = read_bytes(transport, labels["gcmsiv_tag_valid"], 1)[0]
        return pt, tag_valid
    except Exception as e:
        print(f"    gcmsiv_direct_decrypt error: {e}")
        return None


# ---------------------------------------------------------------------------
# Cross-Validation: GCM-SIV (C64 vs AESGCMSIV vs polyval_reference)
# ---------------------------------------------------------------------------

def validate_gcmsiv(
    transport: ViceTransport, labels: Labels, iterations: int,
) -> tuple[int, int]:
    print("\n\n=== Cross-Validation: AES-256-GCM-SIV ===")
    print("  (C64 direct-memory vs OpenSSL AESGCMSIV vs polyval_reference)\n")

    passed = 0
    failed = 0

    test_sizes = [1, 15, 16, 17, 32, 48, 63, 64]
    test_cases = []
    for sz in test_sizes:
        key = bytes(random.getrandbits(8) for _ in range(32))
        nonce = bytes(random.getrandbits(8) for _ in range(12))
        pt = bytes(random.getrandbits(8) for _ in range(sz))
        test_cases.append((key, nonce, pt, f"{sz}-byte boundary"))
    for _ in range(max(0, iterations - len(test_cases))):
        sz = random.randint(1, 64)
        key = bytes(random.getrandbits(8) for _ in range(32))
        nonce = bytes(random.getrandbits(8) for _ in range(12))
        pt = bytes(random.getrandbits(8) for _ in range(sz))
        test_cases.append((key, nonce, pt, f"{sz}-byte random"))
    test_cases = test_cases[:iterations]

    for i, (key, nonce, pt, desc) in enumerate(test_cases):
        print(f"\n--- GCM-SIV Validate {i+1}/{len(test_cases)}: {desc} ---")

        # 1. OpenSSL AESGCMSIV reference
        aesgcmsiv = AESGCMSIV(key)
        openssl_out = aesgcmsiv.encrypt(nonce, pt, None)
        openssl_ct = openssl_out[:-16]
        openssl_tag = openssl_out[-16:]

        # 2. Python polyval_reference
        py_ct, py_tag = py_gcmsiv_encrypt(key, nonce, pt)

        # 3. Sanity: OpenSSL must match Python reference
        if openssl_ct != py_ct or openssl_tag != py_tag:
            print("  FAIL: OpenSSL != polyval_reference (sanity check)")
            print(f"    OpenSSL CT:  {openssl_ct.hex()}")
            print(f"    Python  CT:  {py_ct.hex()}")
            print(f"    OpenSSL tag: {openssl_tag.hex()}")
            print(f"    Python  tag: {py_tag.hex()}")
            failed += 1
            continue

        # 4. C64 encrypt
        c64_result = gcmsiv_direct_encrypt(transport, labels, key, nonce, pt)
        if c64_result is None:
            print("  FAIL: C64 encrypt error")
            failed += 1
            continue
        c64_ct, c64_tag = c64_result

        if c64_ct != openssl_ct or c64_tag != openssl_tag:
            print("  FAIL: C64 encrypt mismatch vs OpenSSL/Python")
            print(f"    OpenSSL CT:  {openssl_ct.hex()}")
            print(f"    C64     CT:  {c64_ct.hex()}")
            print(f"    OpenSSL tag: {openssl_tag.hex()}")
            print(f"    C64     tag: {c64_tag.hex()}")
            failed += 1
            continue

        # 5. C64 decrypt (round-trip)
        dec_result = gcmsiv_direct_decrypt(transport, labels, key, nonce, c64_ct, c64_tag)
        if dec_result is None:
            print("  FAIL: C64 decrypt error")
            failed += 1
            continue
        c64_pt, tag_valid = dec_result

        if tag_valid != 1:
            print(f"  FAIL: C64 decrypt tag_valid={tag_valid} (expected 1)")
            failed += 1
            continue

        if c64_pt != pt:
            print("  FAIL: C64 decrypt plaintext mismatch")
            print(f"    Expected: {pt.hex()}")
            print(f"    Got:      {c64_pt.hex()}")
            failed += 1
            continue

        print(f"  PASS: C64 == OpenSSL == Python, roundtrip OK (tag={c64_tag[:4].hex()}...)")
        passed += 1

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
        # GCM-SIV labels (gcmsiv_pt_len is reused for both plaintext length
        # on encrypt and ciphertext length on decrypt - there is no separate
        # gcmsiv_ct_len label in the 6502 source)
        "gcmsiv_nonce", "gcmsiv_pt_buf", "gcmsiv_pt_len",
        "gcmsiv_ct_buf", "gcmsiv_tag",
        "gcmsiv_dec_buf", "gcmsiv_tag_valid",
        "gcmsiv_encrypt", "gcmsiv_decrypt",
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

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"  VICE started (PID={inst.pid}, port={inst.port})")

        transport = inst.transport

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        # Run AES-CBC encrypt cross-validation
        enc_passed, enc_failed = validate_encrypt(transport, labels, iterations)

        # Run AES-CBC decrypt cross-validation
        dec_passed, dec_failed = validate_decrypt(transport, labels, iterations)

        # Run GCM-SIV cross-validation (C64 vs OpenSSL vs polyval_reference)
        gcmsiv_passed, gcmsiv_failed = validate_gcmsiv(transport, labels, iterations)

        mgr.release(inst)

    # Summary
    total_passed = enc_passed + dec_passed + gcmsiv_passed
    total_failed = enc_failed + dec_failed + gcmsiv_failed
    total = total_passed + total_failed

    print("\n" + "=" * 60)
    print("CROSS-VALIDATION RESULTS")
    print("=" * 60)
    print(f"  CBC Encrypt:  {enc_passed}/{enc_passed + enc_failed} passed")
    print(f"  CBC Decrypt:  {dec_passed}/{dec_passed + dec_failed} passed")
    print(f"  GCM-SIV:      {gcmsiv_passed}/{gcmsiv_passed + gcmsiv_failed} passed")
    print(f"  Total:        {total_passed}/{total} passed")
    if total_failed == 0:
        print(f"\n  [+] ALL {total} CROSS-VALIDATION TESTS PASSED")
        print("  Direct-memory tests produce identical results to UI-driven and OpenSSL references.")
    else:
        print(f"\n  [-] {total_failed} CROSS-VALIDATION TEST(S) FAILED")
    print("=" * 60)

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
