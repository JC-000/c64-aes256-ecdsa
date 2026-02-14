#!/usr/bin/env python3
"""
gcmsiv_reference.py - Python reference implementation of the C64's AES-256-GCM-SIV algorithm.

IMPORTANT: The C64 implementation uses AES-CBC-MAC instead of POLYVAL for tag
computation. This means standard AES-256-GCM-SIV libraries (e.g. cryptography.hazmat)
will NOT produce matching results. This module replicates the C64's exact algorithm.

Algorithm steps:
  1. Key Derivation (RFC 8452 standard):
     - 6 AES-256-ECB encryptions of LE32(counter) || nonce (12 bytes)
     - Take first 8 bytes of each output:
       counter=0 -> auth_key[0:8], counter=1 -> auth_key[8:16]
       counter=2 -> enc_key[0:8], counter=3 -> enc_key[8:16]
       counter=4 -> enc_key[16:24], counter=5 -> enc_key[24:32]

  2. Tag Base via CBC-MAC (C64-specific, NOT standard POLYVAL):
     - Key = auth_key (16 bytes) padded to 32 bytes with zeros -> AES-256
     - CBC-MAC over plaintext blocks (zero-padded last block if needed)
     - Final block: [0x00*8 || LE64(pt_len_bits)] XOR'd with accumulator, encrypted

  3. Tag Finalize:
     - tag_acc XOR nonce (first 12 bytes)
     - Clear MSB of byte 15 (byte 15 &= 0x7F)
     - AES-256-ECB encrypt with enc_key

  4. CTR Encrypt:
     - Copy tag to counter, set MSB of byte 15 (byte 15 |= 0x80)
     - AES-CTR with LE32 increment on bytes 0-3
     - Ciphertext is exactly pt_len bytes (no padding)

  5. Decrypt:
     - Derive keys (step 1)
     - CTR decrypt (step 4 is symmetric)
     - Recompute tag (steps 2-3) over decrypted plaintext
     - Compare with received tag
"""

import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _aes256_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-256-ECB."""
    assert len(key) == 32
    assert len(block) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def derive_keys(main_key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Derive auth_key (16 bytes) and enc_key (32 bytes) per RFC 8452.

    Uses the main AES-256 key to encrypt 6 blocks of (LE32(counter) || nonce),
    taking the first 8 bytes of each output.
    """
    assert len(main_key) == 32
    assert len(nonce) == 12

    derived = bytearray()
    for counter in range(6):
        block = struct.pack("<I", counter) + nonce
        assert len(block) == 16
        encrypted = _aes256_ecb_encrypt_block(main_key, block)
        derived.extend(encrypted[:8])

    auth_key = bytes(derived[0:16])
    enc_key = bytes(derived[16:48])
    return auth_key, enc_key


def compute_tag_base(auth_key: bytes, plaintext: bytes) -> bytes:
    """Compute tag base using AES-CBC-MAC (C64's POLYVAL approximation).

    Uses auth_key padded to 32 bytes with zeros as an AES-256 key.
    Processes plaintext in 16-byte blocks (zero-padded last block),
    then a length block [0x00*8 || LE64(pt_bits)].
    """
    assert len(auth_key) == 16

    # Pad auth_key to 32 bytes for AES-256
    mac_key = auth_key + b'\x00' * 16

    # Initialize accumulator to zeros
    acc = bytearray(16)

    # Process plaintext in 16-byte blocks
    pt_len = len(plaintext)
    offset = 0
    while offset < pt_len:
        # Get up to 16 bytes, zero-pad if needed
        chunk = plaintext[offset:offset + 16]
        block = bytearray(16)
        block[:len(chunk)] = chunk

        # XOR with accumulator
        for i in range(16):
            block[i] ^= acc[i]

        # Encrypt with auth key
        acc = bytearray(_aes256_ecb_encrypt_block(mac_key, bytes(block)))
        offset += 16

    # Process length block: [0x00*8 || LE64(pt_bits)]
    pt_bits = pt_len * 8
    len_block = bytearray(16)
    # Store pt_bits at bytes 8-15 as little-endian 64-bit
    struct.pack_into("<Q", len_block, 8, pt_bits)

    # XOR with accumulator
    for i in range(16):
        len_block[i] ^= acc[i]

    # Encrypt
    acc = bytearray(_aes256_ecb_encrypt_block(mac_key, bytes(len_block)))

    return bytes(acc)


def finalize_tag(tag_base: bytes, nonce: bytes, enc_key: bytes) -> bytes:
    """Finalize the authentication tag.

    XOR tag_base with nonce (first 12 bytes), clear MSB of byte 15,
    then AES-256-ECB encrypt with enc_key.
    """
    assert len(tag_base) == 16
    assert len(nonce) == 12
    assert len(enc_key) == 32

    state = bytearray(tag_base)

    # XOR with nonce (first 12 bytes)
    for i in range(12):
        state[i] ^= nonce[i]

    # Clear MSB of byte 15
    state[15] &= 0x7F

    # Encrypt with enc_key
    tag = _aes256_ecb_encrypt_block(enc_key, bytes(state))
    return tag


def ctr_process(enc_key: bytes, tag: bytes, data: bytes) -> bytes:
    """AES-CTR encrypt/decrypt (symmetric operation).

    Uses tag as counter base with MSB of byte 15 set.
    LE32 increment on bytes 0-3.
    """
    assert len(enc_key) == 32
    assert len(tag) == 16

    # Set up counter from tag
    counter = bytearray(tag)
    counter[15] |= 0x80

    result = bytearray()
    offset = 0
    data_len = len(data)

    while offset < data_len:
        # Generate keystream block
        keystream = _aes256_ecb_encrypt_block(enc_key, bytes(counter))

        # XOR data with keystream
        block_size = min(16, data_len - offset)
        for i in range(block_size):
            result.append(data[offset + i] ^ keystream[i])

        offset += block_size

        # Increment counter (LE32 on bytes 0-3)
        ctr_val = struct.unpack_from("<I", counter, 0)[0]
        ctr_val = (ctr_val + 1) & 0xFFFFFFFF
        struct.pack_into("<I", counter, 0, ctr_val)

    return bytes(result)


def encrypt(main_key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM-SIV encrypt (C64 variant with CBC-MAC).

    Args:
        main_key: 32-byte AES-256 key
        nonce: 12-byte nonce
        plaintext: up to 64 bytes

    Returns:
        (ciphertext, tag) where ciphertext is len(plaintext) bytes and tag is 16 bytes
    """
    assert len(main_key) == 32
    assert len(nonce) == 12
    assert len(plaintext) <= 64

    # Step 1: Derive keys
    auth_key, enc_key = derive_keys(main_key, nonce)

    # Step 2: Compute tag base via CBC-MAC
    tag_base = compute_tag_base(auth_key, plaintext)

    # Step 3: Finalize tag
    tag = finalize_tag(tag_base, nonce, enc_key)

    # Step 4: CTR encrypt
    ciphertext = ctr_process(enc_key, tag, plaintext)

    return ciphertext, tag


def decrypt(main_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> tuple[bytes, bool]:
    """AES-256-GCM-SIV decrypt (C64 variant with CBC-MAC).

    Args:
        main_key: 32-byte AES-256 key
        nonce: 12-byte nonce
        ciphertext: encrypted data (up to 64 bytes)
        tag: 16-byte authentication tag

    Returns:
        (plaintext, tag_valid) where tag_valid is True if authentication passed.
        If tag_valid is False, plaintext is all zeros (matching C64 behavior).
    """
    assert len(main_key) == 32
    assert len(nonce) == 12
    assert len(tag) == 16
    assert len(ciphertext) <= 64

    # Step 1: Derive keys
    auth_key, enc_key = derive_keys(main_key, nonce)

    # Step 2: CTR decrypt (symmetric operation)
    plaintext = ctr_process(enc_key, tag, ciphertext)

    # Step 3: Recompute tag over decrypted plaintext
    tag_base = compute_tag_base(auth_key, plaintext)
    recomputed_tag = finalize_tag(tag_base, nonce, enc_key)

    # Step 4: Verify tag
    if recomputed_tag == tag:
        return plaintext, True
    else:
        # Tag mismatch - clear plaintext (C64 zeros dec_buf on failure)
        return b'\x00' * len(ciphertext), False


def self_test() -> bool:
    """Run encrypt -> decrypt roundtrip verification."""
    import os

    print("=== GCM-SIV Reference Self-Test ===")
    test_cases = [
        (1, "1 byte"),
        (15, "15 bytes"),
        (16, "16 bytes (block boundary)"),
        (17, "17 bytes"),
        (32, "32 bytes (2 blocks)"),
        (48, "48 bytes (3 blocks)"),
        (63, "63 bytes"),
        (64, "64 bytes (max)"),
    ]

    all_passed = True
    for pt_len, label in test_cases:
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = os.urandom(pt_len)

        ct, tag = encrypt(key, nonce, plaintext)

        # Verify ciphertext length
        assert len(ct) == pt_len, f"CT length mismatch: {len(ct)} != {pt_len}"

        # Decrypt and verify
        decrypted, valid = decrypt(key, nonce, ct, tag)
        if valid and decrypted == plaintext:
            print(f"  PASS: {label}")
        else:
            print(f"  FAIL: {label} (valid={valid}, match={decrypted == plaintext})")
            all_passed = False

        # Test tag tampering
        bad_tag = bytearray(tag)
        bad_tag[0] ^= 0x01
        _, tamper_valid = decrypt(key, nonce, ct, bytes(bad_tag))
        if not tamper_valid:
            print(f"  PASS: {label} (tag tamper correctly rejected)")
        else:
            print(f"  FAIL: {label} (tag tamper NOT rejected!)")
            all_passed = False

    if all_passed:
        print("\n  [+] All self-tests passed")
    else:
        print("\n  [-] Some self-tests FAILED")

    return all_passed


if __name__ == "__main__":
    import sys
    ok = self_test()
    sys.exit(0 if ok else 1)
