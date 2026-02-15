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
    python3 tools/test_pkcs10.py [--timeout SECONDS] [--port PORT]

Requires: Python 3.10+, cryptography >= 41.0, VICE x64sc on PATH
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vicemon import ViceMon, ASCII_TO_PETSCII

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYBUF_ADDR = 0x0277
KEYBUF_COUNT = 0x00C6
KEYBUF_MAX = 10

EXTRA_PETSCII = {
    '@': 0x40, '<': 0x3C, '>': 0x3E,
    '[': 0x5B, ']': 0x5D, '_': 0xA4,
}

VICE_PROC = None


def char_to_petscii(ch):
    if ch in ASCII_TO_PETSCII:
        return ASCII_TO_PETSCII[ch]
    if ch in EXTRA_PETSCII:
        return EXTRA_PETSCII[ch]
    raise ValueError(f'No PETSCII mapping for {ch!r}')


# ---------------------------------------------------------------------------
# Screen helpers
# ---------------------------------------------------------------------------

def screen_continuous(mon):
    return mon.screen_text().replace('\n', '')


def screen_has_text(mon, text):
    return text.upper() in screen_continuous(mon).upper()


def wait_for_screen_text(mon, text, timeout=60, poll_interval=2, verbose=True):
    text_upper = text.upper()
    start = time.time()
    while time.time() - start < timeout:
        try:
            continuous = screen_continuous(mon)
            if text_upper in continuous.upper():
                return True
            if verbose:
                elapsed = int(time.time() - start)
                chunks = [continuous[i:i+40] for i in range(0, 1000, 40)]
                last = [c for c in chunks if c.strip()]
                tail = last[-1].strip()[:60] if last else ''
                print(f'  [{elapsed:3d}s] {tail}', flush=True)
        except Exception as e:
            if verbose:
                print(f'  [monitor error: {e}]', flush=True)
        time.sleep(poll_interval)
    return False


def dump_screen(mon, label=''):
    prefix = f' [{label}]' if label else ''
    print(f'  --- Screen dump{prefix} ---')
    try:
        for i, line in enumerate(mon.screen_text().split('\n')):
            print(f'  {i:2d}| {line}')
    except Exception as e:
        print(f'  (screen read failed: {e})')
    print('  ---')


# ---------------------------------------------------------------------------
# VICE lifecycle
# ---------------------------------------------------------------------------

def start_vice(prg_path, port=6510, vice_path='x64sc'):
    global VICE_PROC
    subprocess.run(['pkill', '-f', f'remotemonitoraddress.*{port}'],
                   capture_output=True)
    time.sleep(0.5)
    proc = subprocess.Popen(
        [vice_path, '-autostart', prg_path, '-warp', '-ntsc',
         '-remotemonitor', '-remotemonitoraddress',
         f'ip4://127.0.0.1:{port}', '+sound'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    VICE_PROC = proc
    print(f'  VICE started (PID {proc.pid}, NTSC, warp)')
    return proc


def stop_vice():
    global VICE_PROC
    if VICE_PROC is not None:
        try:
            VICE_PROC.terminate()
            VICE_PROC.wait(timeout=5)
        except Exception:
            try:
                VICE_PROC.kill()
            except Exception:
                pass
        VICE_PROC = None


def wait_for_monitor(port=6510, timeout=30):
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(('127.0.0.1', port))
            s.close()
            return True
        except Exception:
            time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Fast keyboard input
# ---------------------------------------------------------------------------

def send_keys_fast(mon, text):
    petscii_codes = [char_to_petscii(ch) for ch in text]
    for i in range(0, len(petscii_codes), KEYBUF_MAX):
        batch = petscii_codes[i:i + KEYBUF_MAX]
        mon.write_mem(KEYBUF_ADDR, batch)
        mon.write_mem(KEYBUF_COUNT, [len(batch)])


def send_key_fast(mon, ch):
    petscii = char_to_petscii(ch) if isinstance(ch, str) else ch
    mon.write_mem(KEYBUF_ADDR, [petscii])
    mon.write_mem(KEYBUF_COUNT, [1])


# ---------------------------------------------------------------------------
# Reliable memory reads
# ---------------------------------------------------------------------------

import re

def read_mem_reliable(mon, addr, length):
    """Read memory with robust parsing (handles VICE prompt prepended to data)."""
    end = addr + length - 1
    resp = mon.command(f'm {addr:04x} {end:04x}')
    result = []
    for line in resp.split('\n'):
        m = re.search(r'>C:[0-9a-fA-F]{4}\s{2}(.*)', line)
        if not m:
            continue
        hex_section = m.group(1)
        parts = hex_section.split('  ')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens and all(
                len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t)
                for t in tokens
            ):
                for t in tokens:
                    result.append(int(t, 16))
    return result[:length]


def read_mem_chunked(mon, addr, length, chunk_size=128):
    """Read memory in small chunks for reliability on large reads."""
    result = []
    offset = 0
    while offset < length:
        n = min(chunk_size, length - offset)
        chunk = read_mem_reliable(mon, addr + offset, n)
        result.extend(chunk)
        offset += n
    return result[:length]


# ---------------------------------------------------------------------------
# PKCS#10 CSR test
# ---------------------------------------------------------------------------

def test_pkcs10_csr(mon, timeout=600):
    """Drive PKCS#10 CSR generation and verify the output."""
    print('\n=== PKCS#10 CSR Generation Test ===')
    errors = []

    # Step 1: Navigate to CSR submenu, select option 3
    print('  Step 1: Navigate to J -> 3 (PKCS#10 CSR)')
    send_key_fast(mon, 'J')
    if not wait_for_screen_text(mon, '1=TEXT CSR', timeout=30):
        dump_screen(mon, 'no submenu')
        return False, 'CSR submenu did not appear'
    time.sleep(0.2)
    send_key_fast(mon, '3')

    # Step 2: Wait for field prompts and enter a CN-only CSR (minimal for speed)
    print('  Step 2: Enter CSR fields (CN only)')
    fields = {
        'country': '',
        'state': '',
        'city': '',
        'org': '',
        'ou': '',
        'cn': 'TEST.C64.DEV',
        'email': '',
    }

    prompts = [
        ('country', 'COUNTRY'),
        ('state', 'STATE/PROVINCE'),
        ('city', 'CITY/LOCALITY'),
        ('org', 'ORGANIZATION'),
        ('ou', 'ORG UNIT'),
        ('cn', 'COMMON NAME'),
        ('email', 'EMAIL ADDRESS'),
    ]

    for key, prompt_text in prompts:
        if not wait_for_screen_text(mon, prompt_text, timeout=30, verbose=False):
            dump_screen(mon, f'missing prompt: {prompt_text}')
            return False, f'Prompt for {key} ({prompt_text}) did not appear'
        time.sleep(0.1)
        value = fields.get(key, '')
        if value:
            send_keys_fast(mon, value)
        send_key_fast(mon, '\r')
        time.sleep(0.1)

    # Step 3: Wait for key generation (LONG - ec_scalar_mul is slow)
    print('  Step 3: Waiting for ECDSA key generation...')
    if not wait_for_screen_text(mon, 'PUBLIC KEY', timeout=timeout, poll_interval=5):
        dump_screen(mon, 'keygen timeout')
        return False, 'ECDSA key generation timed out'
    print('  Key generation complete')

    # Step 4: Wait for CSR ready
    print('  Step 4: Waiting for CSR building + hashing + signing...')
    if not wait_for_screen_text(mon, 'CSR READY', timeout=timeout, poll_interval=5):
        dump_screen(mon, 'csr build timeout')
        return False, 'CSR build/sign timed out'
    print('  CSR generation complete')

    # Step 5: Read DER from memory
    print('  Step 5: Reading DER from VICE memory...')
    time.sleep(1)  # let screen settle

    der_len_addr = mon.label_addr('pkcs10_der_len')
    der_buf_addr = mon.label_addr('der_buf')
    privkey_addr = mon.label_addr('pkcs10_privkey')
    pubkey_x_addr = mon.label_addr('pkcs10_pubkey_x')
    pubkey_y_addr = mon.label_addr('pkcs10_pubkey_y')

    if der_len_addr is None or der_buf_addr is None:
        return False, 'Required labels not found (pkcs10_der_len / der_buf)'

    # Read DER length (2 bytes, little-endian)
    der_len_bytes = read_mem_reliable(mon, der_len_addr, 2)
    der_len = der_len_bytes[0] + (der_len_bytes[1] << 8)
    print(f'  DER length: {der_len} bytes')

    if der_len < 100 or der_len > 512:
        errors.append(f'DER length out of range: {der_len}')
        dump_screen(mon, 'bad der_len')
        return False, f'DER length {der_len} out of expected range (100-512)'

    # Read DER data
    der_data = bytes(read_mem_chunked(mon, der_buf_addr, der_len))
    print(f'  Read {len(der_data)} DER bytes from ${ der_buf_addr:04X}')

    if len(der_data) != der_len:
        errors.append(f'Read {len(der_data)} bytes but expected {der_len}')

    # Read private key
    privkey_data = bytes(read_mem_reliable(mon, privkey_addr, 32))
    print(f'  Private key: {privkey_data.hex()}')

    # Read public key
    pubkey_x = bytes(read_mem_reliable(mon, pubkey_x_addr, 32))
    pubkey_y = bytes(read_mem_reliable(mon, pubkey_y_addr, 32))
    print(f'  Public key X: {pubkey_x.hex()}')
    print(f'  Public key Y: {pubkey_y.hex()}')

    # Step 6: Decline save, return to menu
    print('  Step 6: Declining save...')
    if not wait_for_screen_text(mon, 'SAVE CSR TO DISK', timeout=30, verbose=False):
        # Might need to scroll past PEM display
        dump_screen(mon, 'no save prompt')
        # Try pressing a key to advance
        send_key_fast(mon, '\r')
        time.sleep(1)

    send_key_fast(mon, 'N')
    time.sleep(1)

    # Step 7: Verify DER with OpenSSL
    print('\n  Step 7: Verifying DER with OpenSSL...')

    # Write DER to temp file
    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as f:
        f.write(der_data)
        der_path = f.name

    try:
        # Parse DER with openssl
        result = subprocess.run(
            ['openssl', 'req', '-inform', 'DER', '-in', der_path, '-text', '-noout'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            print(f'  openssl req -text FAILED: {result.stderr.strip()}')
            # Hex dump first 64 bytes for debugging
            print(f'  DER hex (first 64): {der_data[:64].hex()}')
            errors.append(f'openssl req -text failed: {result.stderr.strip()[:200]}')
        else:
            print(f'  openssl req -text: OK')
            # Show parsed output
            for line in result.stdout.strip().split('\n'):
                print(f'    {line}')

        # Verify signature
        result = subprocess.run(
            ['openssl', 'req', '-inform', 'DER', '-in', der_path, '-verify', '-noout'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            sig_err = (result.stderr + result.stdout).strip()
            print(f'  openssl req -verify FAILED: {sig_err}')
            errors.append(f'Signature verification failed: {sig_err[:200]}')
        else:
            sig_ok = (result.stdout + result.stderr).strip()
            print(f'  openssl req -verify: {sig_ok}')

    finally:
        os.unlink(der_path)

    # Step 7b: Deep SHA-256 and signature diagnostics
    print('\n  Step 7b: SHA-256 and signature diagnostics...')
    try:
        import hashlib
        import struct

        # Read TBS data that was hashed by the C64
        tbs_tlv_len_addr = mon.label_addr('pkcs10_tbs_tlv_len')
        tbs_copy_addr = mon.label_addr('pkcs10_tbs_copy')
        sha256_hash_addr = mon.label_addr('sha256_hash')
        bitlen_addr = mon.label_addr('pkcs10_bitlen')

        if tbs_tlv_len_addr and tbs_copy_addr and sha256_hash_addr:
            tbs_len_bytes = read_mem_reliable(mon, tbs_tlv_len_addr, 2)
            tbs_len = tbs_len_bytes[0] + (tbs_len_bytes[1] << 8)
            print(f'  TBS TLV length (from C64 memory): {tbs_len} bytes')

            tbs_data = bytes(read_mem_chunked(mon, tbs_copy_addr, tbs_len))
            print(f'  TBS first 32 bytes: {tbs_data[:32].hex()}')
            print(f'  TBS last  16 bytes: {tbs_data[-16:].hex()}')

            # Read pkcs10_bitlen (4 bytes, big-endian)
            if bitlen_addr:
                bitlen_bytes = read_mem_reliable(mon, bitlen_addr, 4)
                bitlen_val = (bitlen_bytes[0] << 24) | (bitlen_bytes[1] << 16) | (bitlen_bytes[2] << 8) | bitlen_bytes[3]
                print(f'  pkcs10_bitlen: {bitlen_bytes[0]:02x} {bitlen_bytes[1]:02x} {bitlen_bytes[2]:02x} {bitlen_bytes[3]:02x} = {bitlen_val} bits ({bitlen_val//8} bytes)')
                expected_bitlen = tbs_len * 8
                if bitlen_val != expected_bitlen:
                    print(f'  WARNING: expected bitlen {expected_bitlen}, got {bitlen_val}')

            # Compute SHA-256 independently
            python_hash = hashlib.sha256(tbs_data).digest()
            print(f'  Python SHA-256(TBS): {python_hash.hex()}')

            # Read C64's SHA-256 hash
            c64_hash = bytes(read_mem_reliable(mon, sha256_hash_addr, 32))
            print(f'  C64    SHA-256     : {c64_hash.hex()}')

            if python_hash == c64_hash:
                print('  SHA-256 MATCH')
            else:
                print('  SHA-256 MISMATCH - investigating...')
                errors.append('SHA-256 hash mismatch between C64 and Python')

                # Read sha256_block to see what was in it last
                sha256_block_addr = mon.label_addr('sha256_block')
                if sha256_block_addr:
                    last_block = bytes(read_mem_reliable(mon, sha256_block_addr, 64))
                    print(f'  Last sha256_block: {last_block.hex()}')
                    print(f'    Pos 56-63: {last_block[56:64].hex()}')

                # Read sha256 hash state (h0-h7) to see intermediate state
                h_addrs = [mon.label_addr(f'sha256_h{i}') for i in range(8)]
                if all(h_addrs):
                    h_vals = []
                    for addr in h_addrs:
                        hb = read_mem_reliable(mon, addr, 4)
                        h_vals.append(bytes(hb).hex())
                    print(f'  sha256 h0-h7: {" ".join(h_vals)}')

                # Try various broken SHA-256 scenarios to find what C64 computed
                print('\n  Trying alternative padding scenarios:')

                # Scenario 1: Correct (already computed above)
                print(f'    Correct padding: {python_hash.hex()}')

                # Scenario 2: Manual multi-block to match C64 code
                # For 123 bytes: block0 = data[0:64], block1 = data[64:123]+0x80+zeros, block2 = zeros+length
                def sha256_blocks_manual(data_bytes, bitlen_at_60=True):
                    """Compute SHA-256 by manually constructing blocks as C64 does."""
                    import struct

                    # SHA-256 initial hash values
                    h = [
                        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                    ]

                    # SHA-256 round constants
                    k = [
                        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
                    ]

                    def rotr(x, n):
                        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

                    def process_block(block, h):
                        w = list(struct.unpack('>16I', block))
                        for i in range(16, 64):
                            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
                            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
                            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

                        a, b, c, d, e, f, g, hh = h

                        for i in range(64):
                            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
                            ch = (e & f) ^ ((~e) & g)
                            temp1 = (hh + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
                            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
                            maj = (a & b) ^ (a & c) ^ (b & c)
                            temp2 = (S0 + maj) & 0xFFFFFFFF

                            hh = g
                            g = f
                            f = e
                            e = (d + temp1) & 0xFFFFFFFF
                            d = c
                            c = b
                            b = a
                            a = (temp1 + temp2) & 0xFFFFFFFF

                        return [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

                    n = len(data_bytes)
                    pos = 0

                    # Process full blocks
                    while n - pos >= 64:
                        h = process_block(data_bytes[pos:pos+64], h)
                        pos += 64

                    remain = n - pos

                    # Build final block with remaining data + 0x80 + zeros
                    block = bytearray(64)
                    block[:remain] = data_bytes[pos:pos+remain]
                    block[remain] = 0x80

                    bitlen = n * 8

                    if remain < 56:
                        # Length fits in this block
                        if bitlen_at_60:
                            block[60] = (bitlen >> 24) & 0xFF
                            block[61] = (bitlen >> 16) & 0xFF
                            block[62] = (bitlen >> 8) & 0xFF
                            block[63] = bitlen & 0xFF
                        else:
                            block[56] = (bitlen >> 24) & 0xFF
                            block[57] = (bitlen >> 16) & 0xFF
                            block[58] = (bitlen >> 8) & 0xFF
                            block[59] = bitlen & 0xFF
                        h = process_block(bytes(block), h)
                    else:
                        # Need extra block
                        h = process_block(bytes(block), h)
                        block2 = bytearray(64)
                        if bitlen_at_60:
                            block2[60] = (bitlen >> 24) & 0xFF
                            block2[61] = (bitlen >> 16) & 0xFF
                            block2[62] = (bitlen >> 8) & 0xFF
                            block2[63] = bitlen & 0xFF
                        else:
                            block2[56] = (bitlen >> 24) & 0xFF
                            block2[57] = (bitlen >> 16) & 0xFF
                            block2[58] = (bitlen >> 8) & 0xFF
                            block2[59] = bitlen & 0xFF
                        h = process_block(bytes(block2), h)

                    return b''.join(struct.pack('>I', x) for x in h)

                # Test: manual multi-block with length at position 60
                manual_60 = sha256_blocks_manual(tbs_data, bitlen_at_60=True)
                match_60 = '<<MATCH>>' if manual_60 == c64_hash else ''
                print(f'    Manual (len@60): {manual_60.hex()} {match_60}')

                # Test: manual multi-block with length at position 56
                manual_56 = sha256_blocks_manual(tbs_data, bitlen_at_60=False)
                match_56 = '<<MATCH>>' if manual_56 == c64_hash else ''
                print(f'    Manual (len@56): {manual_56.hex()} {match_56}')

                # Also verify: correct SHA-256 manual implementation
                manual_correct = sha256_blocks_manual(tbs_data, bitlen_at_60=True)
                ref_check = '<<MATCH ref>>' if manual_correct == python_hash else ''
                print(f'    Manual vs hashlib: {ref_check or "MISMATCH (bug in manual impl)"}')

                # Wait - maybe the correct SHA-256 puts length at 56-63 (8 byte big-endian)
                # where positions 56-59 are upper 32 bits (zero) and 60-63 are lower 32 bits
                # This is EXACTLY what "length at 60" does for a 32-bit value
                # So if manual_60 != python_hash, there's a bug in my manual implementation

                # Check if C64 might be hashing more or fewer bytes
                for extra in [-1, 1, 2, -2]:
                    test_len = tbs_len + extra
                    if 0 < test_len <= len(tbs_data) + 16:
                        test_data = bytes(read_mem_chunked(mon, tbs_copy_addr, test_len)) if test_len > len(tbs_data) else tbs_data[:test_len]
                        test_hash = hashlib.sha256(test_data).digest()
                        match_str = '<<MATCH>>' if test_hash == c64_hash else ''
                        if match_str:
                            print(f'    Hash of {test_len} bytes: {test_hash.hex()} {match_str}')

                # Check SHA-256 constants integrity
                sha256_h0_init_addr = mon.label_addr('sha256_h0_init')
                sha256_k_addr = mon.label_addr('sha256_k')
                if sha256_h0_init_addr:
                    h_init_mem = bytes(read_mem_reliable(mon, sha256_h0_init_addr, 32))
                    expected_h_init = bytes([
                        0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
                        0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
                        0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
                        0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
                    ])
                    if h_init_mem == expected_h_init:
                        print(f'  SHA-256 H init constants at ${sha256_h0_init_addr:04X}: OK')
                    else:
                        print(f'  SHA-256 H init constants at ${sha256_h0_init_addr:04X}: CORRUPTED!')
                        print(f'    Got:      {h_init_mem.hex()}')
                        print(f'    Expected: {expected_h_init.hex()}')
                        errors.append('SHA-256 H init constants are corrupted!')

                if sha256_k_addr:
                    k_all = bytes(read_mem_chunked(mon, sha256_k_addr, 256))
                    # Load expected K from the PRG file
                    with open('build/aes256keygen.prg', 'rb') as pf:
                        prg = pf.read()
                    prg_load = prg[0] + (prg[1] << 8)
                    k_offset = sha256_k_addr - prg_load + 2
                    k_expected = prg[k_offset:k_offset+256]
                    if k_all == k_expected:
                        print(f'  SHA-256 K constants (256 bytes): OK')
                    else:
                        diffs = sum(1 for a, b in zip(k_all, k_expected) if a != b)
                        print(f'  SHA-256 K constants: {diffs} bytes CORRUPTED!')
                        for i in range(256):
                            if k_all[i] != k_expected[i]:
                                print(f'    First diff at K+{i}: mem={k_all[i]:02x} prg={k_expected[i]:02x}')
                                break
                        errors.append('SHA-256 K constants are corrupted!')

                # Check sha256_process_block code integrity
                pb_addr = mon.label_addr('sha256_process_block')
                ath_addr = mon.label_addr('sha256_add_to_hash')
                if pb_addr and ath_addr:
                    code_len = ath_addr - pb_addr + 200  # include add_to_hash + a bit more
                    code_mem = bytes(read_mem_chunked(mon, pb_addr, code_len))
                    code_offset = pb_addr - prg_load + 2
                    code_expected = prg[code_offset:code_offset+code_len]
                    if code_mem == code_expected:
                        print(f'  sha256_process_block code ({code_len} bytes): intact')
                    else:
                        diffs = sum(1 for a, b in zip(code_mem, code_expected) if a != b)
                        print(f'  sha256_process_block code: {diffs} bytes CORRUPTED!')
                        for i in range(code_len):
                            if code_mem[i] != code_expected[i]:
                                code_addr_diff = pb_addr + i
                                print(f'    First diff at ${code_addr_diff:04X}: mem={code_mem[i]:02x} prg={code_expected[i]:02x}')
                                break
                        errors.append('SHA-256 process_block code is corrupted!')

                # Read more bytes from tbs_copy to check for corruption
                extra_tbs = bytes(read_mem_chunked(mon, tbs_copy_addr, tbs_len + 16))
                print(f'  Bytes after TBS copy (positions {tbs_len}..{tbs_len+15}): {extra_tbs[tbs_len:].hex()}')

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
                    tbs_body_len = int.from_bytes(tbs_in_der[2:2+n], 'big')
                    tbs_total = 2 + n + tbs_body_len
                else:
                    tbs_body_len = tbs_in_der[1]
                    tbs_total = 2 + tbs_body_len
                tbs_from_der = der_data[outer_content_start:outer_content_start + tbs_total]
                print(f'  TBS from output DER: {len(tbs_from_der)} bytes')

                if tbs_from_der == tbs_data:
                    print('  TBS in DER matches TBS copy: OK')
                else:
                    print('  TBS in DER DIFFERS from TBS copy!')
                    errors.append('TBS in output DER differs from hashed TBS copy')
                    for i in range(min(len(tbs_from_der), len(tbs_data))):
                        if tbs_from_der[i] != tbs_data[i]:
                            print(f'    First diff at byte {i}: DER={tbs_from_der[i]:02x} copy={tbs_data[i]:02x}')
                            break

            # Now independently verify signature
            from cryptography.hazmat.primitives.asymmetric import ec, utils
            from cryptography.hazmat.primitives import hashes
            sig_r_addr = mon.label_addr('ecdsa_sig_r')
            sig_s_addr = mon.label_addr('ecdsa_sig_s')
            if sig_r_addr and sig_s_addr:
                sig_r = bytes(read_mem_reliable(mon, sig_r_addr, 32))
                sig_s = bytes(read_mem_reliable(mon, sig_s_addr, 32))
                print(f'  Sig R: {sig_r.hex()}')
                print(f'  Sig S: {sig_s.hex()}')

                r_int = int.from_bytes(sig_r, 'big')
                s_int = int.from_bytes(sig_s, 'big')
                sig_der_manual = utils.encode_dss_signature(r_int, s_int)

                pub_nums = ec.EllipticCurvePublicNumbers(
                    x=int.from_bytes(pubkey_x, 'big'),
                    y=int.from_bytes(pubkey_y, 'big'),
                    curve=ec.SECP256R1()
                )
                pub_key = pub_nums.public_key()

                # Verify using pre-hashed (C64's hash)
                from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
                try:
                    pub_key.verify(sig_der_manual, c64_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
                    print('  Sig verify with C64 hash (prehashed): VALID')
                except Exception as e2:
                    print(f'  Sig verify with C64 hash (prehashed): INVALID ({e2})')

        else:
            print('  Missing labels for diagnostic (tbs_tlv_len/tbs_copy/sha256_hash)')

    except Exception as e:
        print(f'  Diagnostic error: {e}')
        import traceback
        traceback.print_exc()

    # Step 8: Verify subject field
    print('\n  Step 8: Cross-checking subject fields...')
    try:
        from cryptography.x509 import load_der_x509_csr
        csr = load_der_x509_csr(der_data)

        # Check subject
        from cryptography.x509.oid import NameOID
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            cn_val = cn_attrs[0].value
            if cn_val == 'TEST.C64.DEV':
                print(f'  CN matches: {cn_val}')
            else:
                errors.append(f'CN mismatch: expected TEST.C64.DEV, got {cn_val}')
                print(f'  CN MISMATCH: expected TEST.C64.DEV, got {cn_val}')
        else:
            errors.append('CN not found in parsed CSR subject')
            print('  CN not found in CSR subject')

        # Check public key
        from cryptography.hazmat.primitives.asymmetric import ec
        pub = csr.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            nums = pub.public_numbers()
            openssl_x = nums.x.to_bytes(32, 'big')
            openssl_y = nums.y.to_bytes(32, 'big')
            if openssl_x == pubkey_x and openssl_y == pubkey_y:
                print('  Public key in CSR matches memory')
            else:
                errors.append('Public key in CSR does not match memory')
                print(f'  PubX CSR: {openssl_x.hex()}')
                print(f'  PubX mem: {pubkey_x.hex()}')
        else:
            errors.append('CSR public key is not EC')

    except Exception as e:
        errors.append(f'Python verification error: {e}')
        print(f'  Python verification error: {e}')

    # Step 9: Verify public key derivation (Q = d*G)
    print('\n  Step 9: Verifying Q = d*G...')
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        d_int = int.from_bytes(privkey_data, 'big')
        priv = ec.derive_private_key(d_int, ec.SECP256R1())
        derived_pub = priv.public_key().public_numbers()
        derived_x = derived_pub.x.to_bytes(32, 'big')
        derived_y = derived_pub.y.to_bytes(32, 'big')
        if derived_x == pubkey_x and derived_y == pubkey_y:
            print('  Q = d*G: verified')
        else:
            errors.append('Q != d*G: public key does not match private key')
            print('  Q = d*G: MISMATCH')
            print(f'    Derived X: {derived_x.hex()}')
            print(f'    Memory  X: {pubkey_x.hex()}')
    except Exception as e:
        errors.append(f'Q=d*G check error: {e}')
        print(f'  Q=d*G check error: {e}')

    # Step 10: Display PEM comparison (C64 vs OpenSSL)
    print('\n  Step 10: PEM comparison...')
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # C64-generated PEM
        b64_data = base64.b64encode(der_data).decode('ascii')
        c64_pem_lines = ['-----BEGIN CERTIFICATE REQUEST-----']
        for i in range(0, len(b64_data), 64):
            c64_pem_lines.append(b64_data[i:i+64])
        c64_pem_lines.append('-----END CERTIFICATE REQUEST-----')
        c64_pem = '\n'.join(c64_pem_lines)

        # OpenSSL-generated PEM using same private key and subject
        d_int = int.from_bytes(privkey_data, 'big')
        priv = ec.derive_private_key(d_int, ec.SECP256R1())
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'TEST.C64.DEV'),
        ]))
        openssl_csr = builder.sign(priv, hashes.SHA256())
        openssl_pem = openssl_csr.public_bytes(serialization.Encoding.PEM).decode('ascii').strip()

        print('\n' + '=' * 72)
        print('  COMMODORE 64 PKCS#10 CSR')
        print('=' * 72)
        print(c64_pem)
        print('\n' + '=' * 72)
        print('  OPENSSL PKCS#10 CSR (same private key, same subject)')
        print('=' * 72)
        print(openssl_pem)
        print('=' * 72)

        # Also show parsed fields of C64 CSR for completeness
        result = subprocess.run(
            ['openssl', 'req', '-inform', 'PEM', '-text', '-noout'],
            input=c64_pem, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print('\n  C64 CSR parsed by OpenSSL:')
            for line in result.stdout.strip().split('\n'):
                print(f'    {line}')
    except Exception as e:
        print(f'  PEM comparison error: {e}')

    if errors:
        return False, '; '.join(errors)
    return True, 'All PKCS#10 checks passed'


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='PKCS#10 CSR Integration Test')
    parser.add_argument('--timeout', type=int, default=600,
                        help='Timeout for ECDSA operations in seconds (default: 600)')
    parser.add_argument('--port', type=int, default=6510,
                        help='VICE monitor port (default: 6510)')
    parser.add_argument('--vice-path', default='x64sc',
                        help='Path to VICE executable')
    args = parser.parse_args()

    project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    os.chdir(project_root)

    prg_path = 'build/aes256keygen.prg'
    labels_path = 'build/labels.txt'

    # Build
    print('=== Building ===')
    subprocess.run(['make', 'clean'], capture_output=True)
    result = subprocess.run(['make'], capture_output=True, text=True)
    if result.returncode != 0:
        print(f'Build failed:\n{result.stderr}')
        sys.exit(1)
    print('  Build OK')

    if not os.path.exists(prg_path):
        print(f'FATAL: {prg_path} not found')
        sys.exit(1)

    # Start VICE
    print('\n=== Starting VICE ===')
    start_vice(prg_path, port=args.port, vice_path=args.vice_path)

    try:
        print('  Waiting for monitor...')
        if not wait_for_monitor(port=args.port, timeout=30):
            print('FATAL: Could not connect to VICE monitor')
            sys.exit(1)
        print('  Monitor connected')

        mon = ViceMon(port=args.port)
        n = mon.load_labels(labels_path)
        print(f'  Loaded {n} labels')

        print('  Waiting for main menu...')
        if not wait_for_screen_text(mon, 'Q=QUIT', timeout=60):
            print('FATAL: Main menu did not appear')
            dump_screen(mon, 'startup')
            sys.exit(1)
        print('  Main menu ready')

        # Run the PKCS#10 test
        ok, msg = test_pkcs10_csr(mon, timeout=args.timeout)

        print('\n' + '=' * 60)
        print('RESULT')
        print('=' * 60)
        icon = '+' if ok else '-'
        print(f'  [{icon}] PKCS#10 CSR: {"PASS" if ok else "FAIL"}')
        if not ok:
            print(f'      {msg}')
        print('=' * 60)

        return 0 if ok else 1

    finally:
        print('\n=== Stopping VICE ===')
        stop_vice()


if __name__ == '__main__':
    sys.exit(main())
