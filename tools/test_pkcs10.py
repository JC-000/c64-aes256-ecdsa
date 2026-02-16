#!/usr/bin/env python3
"""
test_pkcs10.py - PKCS#10 CSR Generation Integration Test

Drives the C64 through the PKCS#10 CSR generation path (menu J->3),
waits for ECDSA key generation and signing to complete, then reads the
DER-encoded CSR from VICE memory and verifies it with OpenSSL.

This test exercises the full PKCS#10 pipeline:
  - Field collection
  - ECDSA P-256 key pair generation (ec_scalar_mul)
  - DER/ASN.1 encoding of TBS CertificationRequest
  - Multi-block SHA-256 hash of TBS
  - ECDSA signing
  - DER encoding of outer CSR with signature
  - Base64/PEM encoding

Usage:
    python3 tools/test_pkcs10.py

Requires: Python 3.10+, cryptography >= 41.0, c64_test_harness, VICE x64sc
"""

import os
import subprocess
import sys
import tempfile
import time

from c64_test_harness import (
    Labels,
    PrgFile,
    ScreenGrid,
    ViceConfig,
    ViceProcess,
    ViceTransport,
    dump_screen,
    read_bytes,
    read_bytes_chunked,
    read_word_le,
    send_key,
    send_text,
    wait_for_text,
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
# PKCS#10 CSR test
# ---------------------------------------------------------------------------

def test_pkcs10_csr(transport, labels, prg_path, timeout=600):
    """Drive PKCS#10 CSR generation and verify the output."""
    print("\n=== PKCS#10 CSR Generation Test ===")
    errors = []

    # Step 1: Navigate to CSR submenu, select option 3
    print("  Step 1: Navigate to J -> 3 (PKCS#10 CSR)")
    send_key(transport, "J")
    grid = wait_for_text(transport, "1=TEXT CSR", timeout=30.0)
    if grid is None:
        dump_screen(transport, "no submenu")
        return False, "CSR submenu did not appear"
    time.sleep(0.2)
    send_key(transport, "3")

    # Step 2: Wait for field prompts and enter a CN-only CSR (minimal for speed)
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
        grid = wait_for_text(
            transport, prompt_text, timeout=30.0, verbose=False
        )
        if grid is None:
            dump_screen(transport, f"missing prompt: {prompt_text}")
            return False, f"Prompt for {key} ({prompt_text}) did not appear"
        time.sleep(0.1)
        value = fields.get(key, "")
        if value:
            send_text(transport, value)
        send_key(transport, "\r")
        time.sleep(0.1)

    # Step 3: Wait for key generation (LONG - ec_scalar_mul is slow)
    print("  Step 3: Waiting for ECDSA key generation...")
    grid = wait_for_text(
        transport, "PUBLIC KEY", timeout=timeout, poll_interval=5
    )
    if grid is None:
        dump_screen(transport, "keygen timeout")
        return False, "ECDSA key generation timed out"
    print("  Key generation complete")

    # Step 4: Wait for CSR ready
    print("  Step 4: Waiting for CSR building + hashing + signing...")
    grid = wait_for_text(
        transport, "CSR READY", timeout=timeout, poll_interval=5
    )
    if grid is None:
        dump_screen(transport, "csr build timeout")
        return False, "CSR build/sign timed out"
    print("  CSR generation complete")

    # Step 5: Read DER from memory
    print("  Step 5: Reading DER from VICE memory...")
    time.sleep(1)  # let screen settle

    der_len_addr = labels.address("pkcs10_der_len")
    der_buf_addr = labels.address("der_buf")
    privkey_addr = labels.address("pkcs10_privkey")
    pubkey_x_addr = labels.address("pkcs10_pubkey_x")
    pubkey_y_addr = labels.address("pkcs10_pubkey_y")

    if der_len_addr is None or der_buf_addr is None:
        return False, "Required labels not found (pkcs10_der_len / der_buf)"

    # Read DER length (2 bytes, little-endian)
    der_len = read_word_le(transport, der_len_addr)
    print(f"  DER length: {der_len} bytes")

    if der_len < 100 or der_len > 512:
        errors.append(f"DER length out of range: {der_len}")
        dump_screen(transport, "bad der_len")
        return False, f"DER length {der_len} out of expected range (100-512)"

    # Read DER data
    der_data = read_bytes_chunked(transport, der_buf_addr, der_len)
    print(f"  Read {len(der_data)} DER bytes from ${der_buf_addr:04X}")

    if len(der_data) != der_len:
        errors.append(f"Read {len(der_data)} bytes but expected {der_len}")

    # Read private key
    privkey_data = read_bytes(transport, privkey_addr, 32)
    print(f"  Private key: {privkey_data.hex()}")

    # Read public key
    pubkey_x = read_bytes(transport, pubkey_x_addr, 32)
    pubkey_y = read_bytes(transport, pubkey_y_addr, 32)
    print(f"  Public key X: {pubkey_x.hex()}")
    print(f"  Public key Y: {pubkey_y.hex()}")

    # Step 6: Decline save, return to menu
    print("  Step 6: Declining save...")
    grid = wait_for_text(
        transport, "SAVE CSR TO DISK", timeout=30.0, verbose=False
    )
    if grid is None:
        # Might need to scroll past PEM display
        dump_screen(transport, "no save prompt")
        send_key(transport, "\r")
        time.sleep(1)

    send_key(transport, "N")
    time.sleep(1)

    # Step 7: Verify DER with OpenSSL
    print("\n  Step 7: Verifying DER with OpenSSL...")

    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
        f.write(der_data)
        der_path = f.name

    try:
        # Parse DER with openssl
        result = subprocess.run(
            ["openssl", "req", "-inform", "DER", "-in", der_path, "-text", "-noout"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"  openssl req -text FAILED: {result.stderr.strip()}")
            print(f"  DER hex (first 64): {der_data[:64].hex()}")
            errors.append(f"openssl req -text failed: {result.stderr.strip()[:200]}")
        else:
            print("  openssl req -text: OK")
            for line in result.stdout.strip().split("\n"):
                print(f"    {line}")

        # Verify signature
        result = subprocess.run(
            ["openssl", "req", "-inform", "DER", "-in", der_path, "-verify", "-noout"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            sig_err = (result.stderr + result.stdout).strip()
            print(f"  openssl req -verify FAILED: {sig_err}")
            errors.append(f"Signature verification failed: {sig_err[:200]}")
        else:
            sig_ok = (result.stdout + result.stderr).strip()
            print(f"  openssl req -verify: {sig_ok}")

    finally:
        os.unlink(der_path)

    # Step 7b: Deep SHA-256 and signature diagnostics
    print("\n  Step 7b: SHA-256 and signature diagnostics...")
    try:
        import hashlib

        # Read TBS data that was hashed by the C64
        tbs_tlv_len_addr = labels.address("pkcs10_tbs_tlv_len")
        tbs_copy_addr = labels.address("pkcs10_tbs_copy")
        sha256_hash_addr = labels.address("sha256_hash")
        bitlen_addr = labels.address("pkcs10_bitlen")

        if tbs_tlv_len_addr and tbs_copy_addr and sha256_hash_addr:
            tbs_len = read_word_le(transport, tbs_tlv_len_addr)
            print(f"  TBS TLV length (from C64 memory): {tbs_len} bytes")

            tbs_data = read_bytes_chunked(transport, tbs_copy_addr, tbs_len)
            print(f"  TBS first 32 bytes: {tbs_data[:32].hex()}")
            print(f"  TBS last  16 bytes: {tbs_data[-16:].hex()}")

            # Read pkcs10_bitlen (4 bytes, big-endian)
            if bitlen_addr:
                bitlen_bytes = read_bytes(transport, bitlen_addr, 4)
                bitlen_val = (
                    (bitlen_bytes[0] << 24)
                    | (bitlen_bytes[1] << 16)
                    | (bitlen_bytes[2] << 8)
                    | bitlen_bytes[3]
                )
                print(
                    f"  pkcs10_bitlen: {bitlen_bytes[0]:02x} {bitlen_bytes[1]:02x} "
                    f"{bitlen_bytes[2]:02x} {bitlen_bytes[3]:02x} = "
                    f"{bitlen_val} bits ({bitlen_val // 8} bytes)"
                )
                expected_bitlen = tbs_len * 8
                if bitlen_val != expected_bitlen:
                    print(f"  WARNING: expected bitlen {expected_bitlen}, got {bitlen_val}")

            # Compute SHA-256 independently
            python_hash = hashlib.sha256(tbs_data).digest()
            print(f"  Python SHA-256(TBS): {python_hash.hex()}")

            # Read C64's SHA-256 hash
            c64_hash = read_bytes(transport, sha256_hash_addr, 32)
            print(f"  C64    SHA-256     : {c64_hash.hex()}")

            if python_hash == c64_hash:
                print("  SHA-256 MATCH")
            else:
                print("  SHA-256 MISMATCH - investigating...")
                errors.append("SHA-256 hash mismatch between C64 and Python")

                # Read sha256_block to see what was in it last
                sha256_block_addr = labels.address("sha256_block")
                if sha256_block_addr:
                    last_block = read_bytes(transport, sha256_block_addr, 64)
                    print(f"  Last sha256_block: {last_block.hex()}")
                    print(f"    Pos 56-63: {last_block[56:64].hex()}")

                # Read sha256 hash state (h0-h7)
                h_addrs = [labels.address(f"sha256_h{i}") for i in range(8)]
                if all(h_addrs):
                    h_vals = []
                    for addr in h_addrs:
                        hb = read_bytes(transport, addr, 4)
                        h_vals.append(hb.hex())
                    print(f"  sha256 h0-h7: {' '.join(h_vals)}")

                # Check if C64 might be hashing more or fewer bytes
                for extra in [-1, 1, 2, -2]:
                    test_len = tbs_len + extra
                    if 0 < test_len <= tbs_len + 16:
                        if test_len > tbs_len:
                            test_data = read_bytes_chunked(
                                transport, tbs_copy_addr, test_len
                            )
                        else:
                            test_data = tbs_data[:test_len]
                        test_hash = hashlib.sha256(test_data).digest()
                        if test_hash == c64_hash:
                            print(
                                f"    Hash of {test_len} bytes: "
                                f"{test_hash.hex()} <<MATCH>>"
                            )

                # Check SHA-256 constants integrity via PRG file
                prg = PrgFile.from_file(prg_path)

                sha256_h0_init_addr = labels.address("sha256_h0_init")
                sha256_k_addr = labels.address("sha256_k")
                if sha256_h0_init_addr:
                    expected_h_init = bytes([
                        0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
                        0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
                        0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C,
                        0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19,
                    ])
                    h_init_mem = read_bytes(transport, sha256_h0_init_addr, 32)
                    if h_init_mem == expected_h_init:
                        print(
                            f"  SHA-256 H init constants at "
                            f"${sha256_h0_init_addr:04X}: OK"
                        )
                    else:
                        print(
                            f"  SHA-256 H init constants at "
                            f"${sha256_h0_init_addr:04X}: CORRUPTED!"
                        )
                        print(f"    Got:      {h_init_mem.hex()}")
                        print(f"    Expected: {expected_h_init.hex()}")
                        errors.append("SHA-256 H init constants are corrupted!")

                if sha256_k_addr:
                    match, diff_count = prg.verify_region(
                        transport, sha256_k_addr, 256
                    )
                    if match:
                        print("  SHA-256 K constants (256 bytes): OK")
                    else:
                        print(f"  SHA-256 K constants: {diff_count} bytes CORRUPTED!")
                        first = prg.first_diff(transport, sha256_k_addr, 256)
                        if first:
                            offset, expected_byte, actual_byte = first
                            print(
                                f"    First diff at K+{offset}: "
                                f"mem={actual_byte:02x} prg={expected_byte:02x}"
                            )
                        errors.append("SHA-256 K constants are corrupted!")

                # Check sha256_process_block code integrity
                pb_addr = labels.address("sha256_process_block")
                ath_addr = labels.address("sha256_add_to_hash")
                if pb_addr and ath_addr:
                    code_len = ath_addr - pb_addr + 200
                    match, diff_count = prg.verify_region(
                        transport, pb_addr, code_len
                    )
                    if match:
                        print(
                            f"  sha256_process_block code ({code_len} bytes): intact"
                        )
                    else:
                        print(
                            f"  sha256_process_block code: "
                            f"{diff_count} bytes CORRUPTED!"
                        )
                        first = prg.first_diff(transport, pb_addr, code_len)
                        if first:
                            offset, expected_byte, actual_byte = first
                            code_addr_diff = pb_addr + offset
                            print(
                                f"    First diff at ${code_addr_diff:04X}: "
                                f"mem={actual_byte:02x} prg={expected_byte:02x}"
                            )
                        errors.append("SHA-256 process_block code is corrupted!")

                # Read more bytes from tbs_copy to check for corruption
                extra_tbs = read_bytes_chunked(
                    transport, tbs_copy_addr, tbs_len + 16
                )
                print(
                    f"  Bytes after TBS copy (positions {tbs_len}..{tbs_len + 15}): "
                    f"{extra_tbs[tbs_len:].hex()}"
                )

            # Extract TBS from the output DER and compare
            outer_tag = der_data[0]
            if outer_tag == 0x30:
                if der_data[1] & 0x80:
                    n_len_bytes = der_data[1] & 0x7F
                    outer_content_start = 2 + n_len_bytes
                else:
                    outer_content_start = 2
                tbs_in_der = der_data[outer_content_start:]
                if tbs_in_der[1] & 0x80:
                    n = tbs_in_der[1] & 0x7F
                    tbs_body_len = int.from_bytes(tbs_in_der[2 : 2 + n], "big")
                    tbs_total = 2 + n + tbs_body_len
                else:
                    tbs_body_len = tbs_in_der[1]
                    tbs_total = 2 + tbs_body_len
                tbs_from_der = der_data[
                    outer_content_start : outer_content_start + tbs_total
                ]
                print(f"  TBS from output DER: {len(tbs_from_der)} bytes")

                if tbs_from_der == tbs_data:
                    print("  TBS in DER matches TBS copy: OK")
                else:
                    print("  TBS in DER DIFFERS from TBS copy!")
                    errors.append(
                        "TBS in output DER differs from hashed TBS copy"
                    )
                    for i in range(min(len(tbs_from_der), len(tbs_data))):
                        if tbs_from_der[i] != tbs_data[i]:
                            print(
                                f"    First diff at byte {i}: "
                                f"DER={tbs_from_der[i]:02x} copy={tbs_data[i]:02x}"
                            )
                            break

            # Independently verify signature
            from cryptography.hazmat.primitives.asymmetric import ec, utils
            from cryptography.hazmat.primitives import hashes

            sig_r_addr = labels.address("ecdsa_sig_r")
            sig_s_addr = labels.address("ecdsa_sig_s")
            if sig_r_addr and sig_s_addr:
                sig_r = read_bytes(transport, sig_r_addr, 32)
                sig_s = read_bytes(transport, sig_s_addr, 32)
                print(f"  Sig R: {sig_r.hex()}")
                print(f"  Sig S: {sig_s.hex()}")

                r_int = int.from_bytes(sig_r, "big")
                s_int = int.from_bytes(sig_s, "big")
                sig_der_manual = utils.encode_dss_signature(r_int, s_int)

                pub_nums = ec.EllipticCurvePublicNumbers(
                    x=int.from_bytes(pubkey_x, "big"),
                    y=int.from_bytes(pubkey_y, "big"),
                    curve=ec.SECP256R1(),
                )
                pub_key = pub_nums.public_key()

                from cryptography.hazmat.primitives.asymmetric.utils import (
                    Prehashed,
                )

                try:
                    pub_key.verify(
                        sig_der_manual,
                        c64_hash,
                        ec.ECDSA(Prehashed(hashes.SHA256())),
                    )
                    print("  Sig verify with C64 hash (prehashed): VALID")
                except Exception as e2:
                    print(
                        f"  Sig verify with C64 hash (prehashed): INVALID ({e2})"
                    )

        else:
            print(
                "  Missing labels for diagnostic "
                "(tbs_tlv_len/tbs_copy/sha256_hash)"
            )

    except Exception as e:
        print(f"  Diagnostic error: {e}")
        import traceback

        traceback.print_exc()

    # Step 8: Verify subject field
    print("\n  Step 8: Cross-checking subject fields...")
    try:
        from cryptography.x509 import load_der_x509_csr
        from cryptography.x509.oid import NameOID

        csr = load_der_x509_csr(der_data)

        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            cn_val = cn_attrs[0].value
            if cn_val == "TEST.C64.DEV":
                print(f"  CN matches: {cn_val}")
            else:
                errors.append(f"CN mismatch: expected TEST.C64.DEV, got {cn_val}")
                print(f"  CN MISMATCH: expected TEST.C64.DEV, got {cn_val}")
        else:
            errors.append("CN not found in parsed CSR subject")
            print("  CN not found in CSR subject")

        from cryptography.hazmat.primitives.asymmetric import ec

        pub = csr.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            nums = pub.public_numbers()
            openssl_x = nums.x.to_bytes(32, "big")
            openssl_y = nums.y.to_bytes(32, "big")
            if openssl_x == pubkey_x and openssl_y == pubkey_y:
                print("  Public key in CSR matches memory")
            else:
                errors.append("Public key in CSR does not match memory")
                print(f"  PubX CSR: {openssl_x.hex()}")
                print(f"  PubX mem: {pubkey_x.hex()}")
        else:
            errors.append("CSR public key is not EC")

    except Exception as e:
        errors.append(f"Python verification error: {e}")
        print(f"  Python verification error: {e}")

    # Step 9: Verify public key derivation (Q = d*G)
    print("\n  Step 9: Verifying Q = d*G...")
    try:
        from cryptography.hazmat.primitives.asymmetric import ec

        d_int = int.from_bytes(privkey_data, "big")
        priv = ec.derive_private_key(d_int, ec.SECP256R1())
        derived_pub = priv.public_key().public_numbers()
        derived_x = derived_pub.x.to_bytes(32, "big")
        derived_y = derived_pub.y.to_bytes(32, "big")
        if derived_x == pubkey_x and derived_y == pubkey_y:
            print("  Q = d*G: verified")
        else:
            errors.append("Q != d*G: public key does not match private key")
            print("  Q = d*G: MISMATCH")
            print(f"    Derived X: {derived_x.hex()}")
            print(f"    Memory  X: {pubkey_x.hex()}")
    except Exception as e:
        errors.append(f"Q=d*G check error: {e}")
        print(f"  Q=d*G check error: {e}")

    # Step 10: Display PEM comparison (C64 vs OpenSSL)
    print("\n  Step 10: PEM comparison...")
    try:
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        # C64-generated PEM
        b64_data = base64.b64encode(der_data).decode("ascii")
        c64_pem_lines = ["-----BEGIN CERTIFICATE REQUEST-----"]
        for i in range(0, len(b64_data), 64):
            c64_pem_lines.append(b64_data[i : i + 64])
        c64_pem_lines.append("-----END CERTIFICATE REQUEST-----")
        c64_pem = "\n".join(c64_pem_lines)

        # OpenSSL-generated PEM using same private key and subject
        d_int = int.from_bytes(privkey_data, "big")
        priv = ec.derive_private_key(d_int, ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST.C64.DEV")])
        )
        openssl_csr = builder.sign(priv, hashes.SHA256())
        openssl_pem = (
            openssl_csr.public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
            .strip()
        )

        print("\n" + "=" * 72)
        print("  COMMODORE 64 PKCS#10 CSR")
        print("=" * 72)
        print(c64_pem)
        print("\n" + "=" * 72)
        print("  OPENSSL PKCS#10 CSR (same private key, same subject)")
        print("=" * 72)
        print(openssl_pem)
        print("=" * 72)

        # Also show parsed fields of C64 CSR
        result = subprocess.run(
            ["openssl", "req", "-inform", "PEM", "-text", "-noout"],
            input=c64_pem,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            print("\n  C64 CSR parsed by OpenSSL:")
            for line in result.stdout.strip().split("\n"):
                print(f"    {line}")
    except Exception as e:
        print(f"  PEM comparison error: {e}")

    if errors:
        return False, "; ".join(errors)
    return True, "All PKCS#10 checks passed"


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
    print(f"  Labels loaded")

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

        # Run the PKCS#10 test
        ok, msg = test_pkcs10_csr(transport, labels, PRG_PATH)

        print("\n" + "=" * 60)
        print("RESULT")
        print("=" * 60)
        icon = "+" if ok else "-"
        print(f'  [{icon}] PKCS#10 CSR: {"PASS" if ok else "FAIL"}')
        if not ok:
            print(f"      {msg}")
        print("=" * 60)

        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
