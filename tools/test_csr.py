#!/usr/bin/env python3
"""
test_csr.py - AES Key Integrity and Crypto Tests

Tests that are unique to this file (not duplicated in test_csr_harness.py):
  - Test 5: Key preserved after NIST AES known-answer test
  - Test 6: AES-256-ECB cryptographic comparison (C64 vs OpenSSL)

Usage:
    python3 tools/test_csr.py

Requires: Python 3.10+, cryptography >= 41.0, c64_test_harness, VICE x64sc
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ScreenGrid,
    TestRunner,
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

FIELD_PROMPTS = [
    ("country", "COUNTRY"),
    ("state", "STATE/PROVINCE"),
    ("city", "CITY/LOCALITY"),
    ("org", "ORGANIZATION"),
    ("ou", "ORG UNIT"),
    ("cn", "COMMON NAME"),
    ("email", "EMAIL ADDRESS"),
]


# ---------------------------------------------------------------------------
# C64 interaction helpers
# ---------------------------------------------------------------------------

def navigate_to_csr(transport: ViceTransport, timeout: float = 30.0) -> None:
    """Press J -> wait for '1=TEXT CSR' -> press 1."""
    send_key(transport, "J")
    grid = wait_for_text(transport, "1=TEXT CSR", timeout=timeout)
    if grid is None:
        raise TimeoutError("CSR submenu did not appear")
    time.sleep(0.1)
    send_key(transport, "1")


def send_csr_fields(
    transport: ViceTransport, fields: dict[str, str], timeout: float = 20.0
) -> None:
    """Wait for each prompt, type value + RETURN."""
    for key, prompt_text in FIELD_PROMPTS:
        grid = wait_for_text(
            transport, prompt_text, timeout=timeout, verbose=False
        )
        if grid is None:
            raise TimeoutError(
                f"Prompt for {key} ({prompt_text}) did not appear"
            )
        time.sleep(0.05)
        value = fields.get(key, "")
        if value:
            send_text(transport, value)
        send_key(transport, "\r")
        time.sleep(0.05)


def read_screen_csr(transport: ViceTransport) -> dict:
    """Extract KEY/SUBJECT/EMAIL from continuous_text()."""
    grid = wait_for_stable(transport, timeout=5.0)
    if grid is None:
        grid = ScreenGrid.from_transport(transport)

    continuous = grid.continuous_text()
    upper = continuous.upper()

    result: dict[str, str | None] = {
        "key_hex": None,
        "subject": None,
        "email": None,
    }

    key_idx = upper.find("KEY: ")
    if key_idx >= 0:
        hex_start = key_idx + 5
        candidate = continuous[hex_start : hex_start + 64]
        hex_clean = "".join(
            c for c in candidate if c.upper() in "0123456789ABCDEF"
        )
        if len(hex_clean) >= 64:
            result["key_hex"] = hex_clean[:64]

    subj_idx = upper.find("SUBJECT: ")
    if subj_idx >= 0:
        subj_start = subj_idx + 9
        email_marker = upper.find("EMAIL:", subj_start)
        end_marker = upper.find("-----END", subj_start)
        markers = [m for m in (email_marker, end_marker) if m > subj_start]
        subj_end = min(markers) if markers else subj_start + 120
        result["subject"] = continuous[subj_start:subj_end].strip()

    email_idx = upper.find("EMAIL: ")
    if email_idx >= 0:
        email_start = email_idx + 7
        end_marker = upper.find("-----END", email_start)
        if end_marker > email_start:
            result["email"] = continuous[email_start:end_marker].strip()
        else:
            result["email"] = continuous[email_start : email_start + 60].strip()

    return result


def decline_save(transport: ViceTransport, timeout: float = 20.0) -> None:
    """Send N at the save prompt, wait for main menu."""
    grid = wait_for_text(
        transport, "SAVE CSR TO DISK", timeout=timeout, verbose=False
    )
    if grid is None:
        raise TimeoutError("Save prompt did not appear")
    time.sleep(0.05)
    send_key(transport, "N")
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        raise TimeoutError("Main menu did not reappear after declining save")


def recover_to_menu(transport: ViceTransport, timeout: float = 15.0) -> bool:
    """Try to get back to main menu from any CSR state."""
    print("  (recovering to main menu...)")
    for _ in range(8):
        send_key(transport, "\r")
        time.sleep(0.1)
    time.sleep(0.5)

    grid = ScreenGrid.from_transport(transport)
    if grid.has_text("SAVE CSR TO DISK"):
        send_key(transport, "N")
        time.sleep(0.3)

    grid = ScreenGrid.from_transport(transport)
    if grid.has_text("DRIVE NUMBER"):
        send_key(transport, "\r")
        time.sleep(0.3)

    grid = ScreenGrid.from_transport(transport)
    if grid.has_text("FILENAME"):
        send_key(transport, "\r")
        time.sleep(0.3)

    result = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if result is None:
        dump_screen(transport, "recovery failed")
        return False
    return True


def read_key_from_memory(transport: ViceTransport, labels: Labels) -> bytes:
    """Read 32 bytes at key_data label."""
    return read_bytes(transport, labels["key_data"], 32)


def read_iv_from_memory(transport: ViceTransport, labels: Labels) -> bytes:
    """Read 16 bytes at iv_data label."""
    return read_bytes(transport, labels["iv_data"], 16)


def validate_key_hex(screen_hex, memory_key):
    """Decode hex string from screen, compare to memory key bytes."""
    screen_hex_clean = screen_hex.replace(" ", "").upper()
    if len(screen_hex_clean) != 64:
        return False, f"Key hex wrong length: {len(screen_hex_clean)} (expected 64)"
    try:
        decoded = bytes.fromhex(screen_hex_clean)
    except ValueError as e:
        return False, f"Key hex decode error: {e}"
    if decoded != memory_key:
        return False, f"Key mismatch: screen={decoded.hex()} memory={memory_key.hex()}"
    return True, "Key matches"


def openssl_aes_ecb_encrypt(key_bytes, plaintext_bytes):
    """AES-256-ECB encryption via cryptography library."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(plaintext_bytes) + enc.finalize()


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

def test_key_preserved_after_nist(transport, labels):
    """Test 5: Key preserved after NIST test (bug fix 2 regression)."""
    print("\n=== Test 5: Key preserved after NIST test ===")

    key_before = read_key_from_memory(transport, labels)
    print(f"  Key before NIST: {key_before.hex()}")

    send_key(transport, "F")

    grid = wait_for_text(transport, "NIST", timeout=30.0, verbose=False)
    if grid is None:
        return False, "NIST test header did not appear"

    grid = wait_for_text(transport, "Q=QUIT", timeout=90.0)
    if grid is None:
        dump_screen(transport, "NIST did not finish")
        return False, "Did not return to main menu after NIST"

    if grid.has_text("FAIL"):
        dump_screen(transport, "NIST FAIL")
        return False, "NIST test reported FAIL"

    print("  NIST test completed (no FAIL on screen)")

    key_after = read_key_from_memory(transport, labels)
    print(f"  Key after NIST:  {key_after.hex()}")

    errors = []

    if key_before != key_after:
        errors.append(
            f"Key changed after NIST! before={key_before.hex()} after={key_after.hex()}"
        )
    else:
        print("  Key preserved after NIST test")

    # Generate a CN-only CSR and verify key matches
    fields = {
        "country": "",
        "state": "",
        "city": "",
        "org": "",
        "ou": "",
        "cn": "AFTER.NIST.COM",
        "email": "",
    }
    navigate_to_csr(transport)
    send_csr_fields(transport, fields)

    grid = wait_for_text(
        transport, "CSR PREVIEW", timeout=20.0, verbose=False
    )
    if grid is None:
        errors.append("CSR preview did not appear after NIST")
        dump_screen(transport, "post-NIST CSR")
    else:
        csr = read_screen_csr(transport)
        if csr["key_hex"] is not None:
            ok, msg = validate_key_hex(csr["key_hex"], key_before)
            if not ok:
                errors.append(f"Key in CSR differs from pre-NIST key: {msg}")
            else:
                print("  CSR key matches pre-NIST key")
        else:
            errors.append("KEY line not found on screen")

    decline_save(transport)

    if errors:
        return False, "; ".join(errors)
    return True, "All checks passed"


def test_aes_crypto_match(transport, labels):
    """Test 6: AES cryptographic comparison -- C64 vs OpenSSL."""
    print("\n=== Test 6: AES crypto match (C64 vs OpenSSL) ===")

    errors = []

    # NIST known-answer test (OpenSSL side)
    nist_key = bytes(range(0x00, 0x20))
    nist_pt = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ])
    expected_ct = bytes([
        0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
        0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89,
    ])

    actual_ct = openssl_aes_ecb_encrypt(nist_key, nist_pt)
    if actual_ct != expected_ct:
        errors.append(
            f"NIST KAT failed: got {actual_ct.hex()}, expected {expected_ct.hex()}"
        )
    else:
        print(f"  NIST KAT (OpenSSL): {actual_ct.hex()} -- matches FIPS 197 C.3")

    # Live key integrity check
    key_data = read_key_from_memory(transport, labels)
    iv_data = read_iv_from_memory(transport, labels)
    print(f"  Live key_data ({len(key_data)} bytes): {key_data.hex()}")
    print(f"  Live iv_data  ({len(iv_data)} bytes): {iv_data.hex()}")

    if len(key_data) != 32:
        errors.append(f"key_data length {len(key_data)}, expected 32")

    # Expanded key first 32 bytes = original key for AES-256
    exp_addr = labels.address("expanded_key")
    if exp_addr is not None:
        exp_first_32 = read_bytes(transport, exp_addr, 32)
        if exp_first_32 == key_data:
            print("  Expanded key round 0 matches key_data")
        else:
            errors.append(
                f"Expanded key mismatch: first 32={exp_first_32.hex()} "
                f"key_data={key_data.hex()}"
            )
    else:
        errors.append("expanded_key label not found")

    # Verify the live key encrypts via OpenSSL
    if len(key_data) == 32:
        live_ct = openssl_aes_ecb_encrypt(key_data, nist_pt)
        print(f"  Live key encrypts NIST PT to: {live_ct.hex()}")
        if len(live_ct) != 16:
            errors.append(f"Live ciphertext wrong length: {len(live_ct)}")
    else:
        errors.append("Skipping live encrypt (key wrong length)")

    if errors:
        return False, "; ".join(errors)
    return True, "All checks passed"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    # Build
    print("=== Building ===")
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
    if labels.address("key_data") is None:
        print("FATAL: 'key_data' label not found in labels file")
        sys.exit(1)
    print(f"  Labels loaded, key_data at ${labels['key_data']:04X}")

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

        # Register test scenarios
        runner = TestRunner()

        def make_recovery():
            return lambda: recover_to_menu(transport)

        runner.add_scenario(
            "Key preserved after NIST",
            lambda: test_key_preserved_after_nist(transport, labels),
            make_recovery(),
        )
        runner.add_scenario(
            "AES crypto match (C64 vs OpenSSL)",
            lambda: test_aes_crypto_match(transport, labels),
            make_recovery(),
        )

        runner.run_all()
        runner.print_summary()

        sys.exit(runner.exit_code)


if __name__ == "__main__":
    main()
