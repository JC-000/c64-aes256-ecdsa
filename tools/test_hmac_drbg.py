#!/usr/bin/env python3
"""
test_hmac_drbg.py - HMAC-DRBG / RFC 6979 integration test

Drives the C64 through the PKCS#10 CSR generation path (menu J->3),
then reads the private key, message hash, and signing nonce k from
VICE memory. Verifies that k matches the deterministic HMAC-DRBG
output computed by the Python reference implementation.

This implicitly tests:
  - HMAC-SHA256 (used internally by DRBG)
  - HMAC-DRBG instantiate (K/V initialization + update with seed)
  - HMAC-DRBG generate (output + post-generate update)
  - RFC 6979 nonce derivation (seed = privkey || hash, reduce mod n)

Usage:
    python3 tools/test_hmac_drbg.py

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import hmac
import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    C64Transport as ViceTransport,
    dump_screen,
    read_bytes,
    read_word_le,
    send_key,
    send_text,
    wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# P-256 curve order
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

FIELD_PROMPTS = [
    ("country", "COUNTRY"),
    ("state", "STATE/PROVINCE"),
    ("city", "CITY/LOCALITY"),
    ("org", "ORGANIZATION"),
    ("ou", "ORG UNIT"),
    ("cn", "COMMON NAME"),
    ("email", "EMAIL ADDRESS"),
]


def python_hmac_drbg(seed: bytes):
    """Reference HMAC-DRBG: instantiate + generate.
    Returns (output, K_after, V_after)."""
    K = b"\x00" * 32
    V = b"\x01" * 32
    # update(seed)
    K = hmac.new(K, V + b"\x00" + seed, "sha256").digest()
    V = hmac.new(K, V, "sha256").digest()
    K = hmac.new(K, V + b"\x01" + seed, "sha256").digest()
    V = hmac.new(K, V, "sha256").digest()
    # generate
    V = hmac.new(K, V, "sha256").digest()
    output = V
    # update("") after generate
    K = hmac.new(K, V + b"\x00", "sha256").digest()
    V = hmac.new(K, V, "sha256").digest()
    return output, K, V


def test_rfc6979_via_pkcs10(transport, labels, timeout=600):
    """Drive PKCS#10 CSR generation and verify deterministic k."""
    print("\n=== HMAC-DRBG / RFC 6979 Integration Test ===")
    errors = []

    # --- Step 1: Navigate to PKCS#10 CSR ---
    print("  Step 1: Navigate to J -> 3 (PKCS#10 CSR)")
    send_key(transport, "J")
    grid = wait_for_text(transport, "1=TEXT CSR", timeout=30.0)
    if grid is None:
        dump_screen(transport, "no submenu")
        return False, "CSR submenu did not appear"
    time.sleep(0.2)
    send_key(transport, "3")

    # --- Step 2: Enter CSR fields (CN only, minimal) ---
    print("  Step 2: Enter CSR fields (CN only)")
    fields = {
        "country": "",
        "state": "",
        "city": "",
        "org": "",
        "ou": "",
        "cn": "TEST.C64.DEV",
        "email": "",
    }

    for key, prompt_text in FIELD_PROMPTS:
        grid = wait_for_text(transport, prompt_text, timeout=30.0, verbose=False)
        if grid is None:
            dump_screen(transport, f"missing prompt: {prompt_text}")
            return False, f"Prompt for {key} ({prompt_text}) did not appear"
        time.sleep(0.1)
        value = fields.get(key, "")
        if value:
            send_text(transport, value)
        send_key(transport, "\r")
        time.sleep(0.1)

    # --- Step 3: Wait for key generation ---
    print("  Step 3: Waiting for ECDSA key generation...")
    grid = wait_for_text(
        transport, "PUBLIC KEY", timeout=timeout, poll_interval=5
    )
    if grid is None:
        dump_screen(transport, "keygen timeout")
        return False, "ECDSA key generation timed out"
    print("    Key generation complete")

    # --- Step 4: Wait for CSR ready (includes hashing + signing) ---
    print("  Step 4: Waiting for CSR building + hashing + signing...")
    grid = wait_for_text(
        transport, "CSR READY", timeout=timeout, poll_interval=5
    )
    if grid is None:
        dump_screen(transport, "csr build timeout")
        return False, "CSR build/sign timed out"
    print("    CSR generation complete")

    # --- Step 5: Read key material and nonce from memory ---
    print("  Step 5: Reading key material from VICE memory...")
    time.sleep(1)

    privkey_addr = labels.address("pkcs10_privkey")
    hash_addr = labels.address("sha256_hash")
    k_buf_addr = labels.address("pkcs10_k_buf")
    hmac_key_addr = labels.address("hmac_key")
    hmac_val_addr = labels.address("hmac_val")
    drbg_output_addr = labels.address("drbg_output")

    if not all([privkey_addr, hash_addr, k_buf_addr]):
        return False, "Required labels not found"

    privkey = read_bytes(transport, privkey_addr, 32)
    msg_hash = read_bytes(transport, hash_addr, 32)
    c64_k = read_bytes(transport, k_buf_addr, 32)

    print(f"    Private key:  {privkey.hex()}")
    print(f"    Message hash: {msg_hash.hex()}")
    print(f"    C64 k:        {c64_k.hex()}")

    # Read DRBG internal state (K, V after generate)
    if hmac_key_addr and hmac_val_addr:
        c64_K = read_bytes(transport, hmac_key_addr, 32)
        c64_V = read_bytes(transport, hmac_val_addr, 32)
        print(f"    C64 DRBG K:   {c64_K.hex()}")
        print(f"    C64 DRBG V:   {c64_V.hex()}")

    if drbg_output_addr:
        c64_raw = read_bytes(transport, drbg_output_addr, 32)
        print(f"    C64 raw DRBG: {c64_raw.hex()}")

    # --- Step 6: Decline save ---
    print("  Step 6: Declining save...")
    grid = wait_for_text(transport, "SAVE CSR TO DISK", timeout=30.0, verbose=False)
    if grid is None:
        send_key(transport, "\r")
        time.sleep(1)
    send_key(transport, "N")
    time.sleep(1)

    # --- Step 7: Verify HMAC-DRBG output ---
    print("\n  Step 7: Verifying HMAC-DRBG deterministic nonce...")

    seed = privkey + msg_hash
    expected_raw, expected_K, expected_V = python_hmac_drbg(seed)

    # Reduce raw output mod n
    k_int = int.from_bytes(expected_raw, "big") % P256_N
    if k_int == 0:
        k_int = 1
    expected_k = k_int.to_bytes(32, "big")

    print(f"    Python raw DRBG: {expected_raw.hex()}")
    print(f"    Python k (mod n): {expected_k.hex()}")

    # Test A: Raw DRBG output matches
    if drbg_output_addr:
        if c64_raw == expected_raw:
            print("    [+] Raw DRBG output: MATCH")
        else:
            print("    [-] Raw DRBG output: MISMATCH")
            errors.append("Raw DRBG output mismatch")

    # Test B: Final k (after mod n reduction) matches
    if c64_k == expected_k:
        print("    [+] k (mod n): MATCH")
    else:
        print("    [-] k (mod n): MISMATCH")
        errors.append(f"k mismatch: expected {expected_k.hex()}, got {c64_k.hex()}")

    # Test C: DRBG internal state (K, V) after generate matches
    if hmac_key_addr and hmac_val_addr:
        if c64_K == expected_K:
            print("    [+] DRBG K after generate: MATCH")
        else:
            print("    [-] DRBG K after generate: MISMATCH")
            print(f"         Expected: {expected_K.hex()}")
            errors.append("DRBG K state mismatch")

        if c64_V == expected_V:
            print("    [+] DRBG V after generate: MATCH")
        else:
            print("    [-] DRBG V after generate: MISMATCH")
            print(f"         Expected: {expected_V.hex()}")
            errors.append("DRBG V state mismatch")

    # --- Step 8: Also verify the CSR signature is valid ---
    print("\n  Step 8: Verifying CSR signature...")
    der_len_addr = labels.address("pkcs10_der_len")
    der_buf_addr = labels.address("der_buf")

    if der_len_addr and der_buf_addr:
        der_len = read_word_le(transport, der_len_addr)
        if 100 <= der_len <= 512:
            from c64_test_harness import read_bytes_chunked
            der_data = read_bytes_chunked(transport, der_buf_addr, der_len)

            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
                f.write(der_data)
                der_path = f.name

            try:
                result = subprocess.run(
                    ["openssl", "req", "-inform", "DER", "-in", der_path,
                     "-verify", "-noout"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    print("    [+] OpenSSL signature verify: OK")
                else:
                    sig_err = (result.stderr + result.stdout).strip()
                    print(f"    [-] OpenSSL signature verify: FAILED ({sig_err})")
                    errors.append(f"Signature verification failed: {sig_err[:200]}")
            finally:
                os.unlink(der_path)
        else:
            print(f"    DER length out of range: {der_len}")
            errors.append(f"DER length {der_len} out of range")

    if errors:
        return False, "; ".join(errors)
    return True, "All HMAC-DRBG / RFC 6979 checks passed"


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
    print(f"  Labels loaded")

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
            mgr.release(inst)
            sys.exit(1)
        print("  Main menu ready")

        # Run the test
        ok, msg = test_rfc6979_via_pkcs10(transport, labels)

        print("\n" + "=" * 60)
        print("RESULTS")
        print("=" * 60)
        icon = "+" if ok else "-"
        status = "PASS" if ok else "FAIL"
        print(f'  [{icon}] HMAC-DRBG / RFC 6979: {status}')
        if not ok:
            print(f"      {msg}")
        print("=" * 60)

        mgr.release(inst)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
