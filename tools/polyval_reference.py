#!/usr/bin/env python3
"""
polyval_reference.py - Pure-Python POLYVAL (RFC 8452) + AES-256-GCM-SIV reference

Provides:
  - GF(2^128) multiplication with POLYVAL polynomial (x^128 + x^127 + x^126 + x^121 + 1)
  - POLYVAL universal hash
  - AES-256-GCM-SIV key derivation, encryption, decryption

All values are little-endian 128-bit integers stored as 16-byte bytes objects,
consistent with RFC 8452 wire format and the C64 implementation.

Usage as library:
    from polyval_reference import polyval, gcmsiv_encrypt, gcmsiv_decrypt

Usage standalone (runs self-test against RFC 8452 Appendix A + C.2 vectors):
    python3 tools/polyval_reference.py
"""

import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# GF(2^128) arithmetic for POLYVAL
# ---------------------------------------------------------------------------

# POLYVAL uses GF(2^128) with polynomial x^128 + x^127 + x^126 + x^121 + 1.
# The dot product dot(a, b) is defined via the GHASH relationship in RFC 8452
# Appendix A, and corresponds to a * b * x^{-128} in the polynomial ring.
#
# Right-shift reduction constant: x^{-1} mod p = 0xe1000000...0 (same value
# as GHASH's reduction constant, but in POLYVAL's little-endian representation).
# When the LSB falls off during right-shift, XOR with this value.
POLYVAL_RIGHT_REDUCE = 0xe1 << 120  # 0xe1000000000000000000000000000000

# Left-shift reduction constant (for table precomputation doubling):
# x^128 mod p = x^127 + x^126 + x^121 + 1
POLYVAL_LEFT_REDUCE = (1 << 127) | (1 << 126) | (1 << 121) | 1

MASK128 = (1 << 128) - 1


def bytes_to_int(b: bytes) -> int:
    """Convert 16 little-endian bytes to a 128-bit integer."""
    return int.from_bytes(b, "little")


def int_to_bytes(n: int) -> bytes:
    """Convert a 128-bit integer to 16 little-endian bytes."""
    return (n & MASK128).to_bytes(16, "little")


def polyval_dot(a: int, b: int) -> int:
    """POLYVAL dot product: multiply two field elements per RFC 8452.

    Processes bits of b from MSB to LSB using right-shift with reduction.
    This computes a * b * x^{-128} mod p, which is the correct POLYVAL
    dot product (equivalent to GHASH-style multiplication in POLYVAL's field).
    """
    result = 0
    v = a
    for i in range(127, -1, -1):
        # Shift first (multiply v by x^{-1})
        carry = v & 1
        v >>= 1
        if carry:
            v ^= POLYVAL_RIGHT_REDUCE
        # Then conditionally XOR
        if (b >> i) & 1:
            result ^= v
    return result


def polyval(h_bytes: bytes, *blocks: bytes) -> bytes:
    """Compute POLYVAL(H, X_1, ..., X_n) per RFC 8452.

    S_0 = 0
    S_i = (S_{i-1} XOR X_i) * H   in GF(2^128)

    Args:
        h_bytes: 16-byte hash key H
        *blocks: one or more 16-byte blocks X_1 .. X_n

    Returns:
        16-byte POLYVAL result
    """
    h = bytes_to_int(h_bytes)
    s = 0
    for block in blocks:
        assert len(block) == 16, f"block must be 16 bytes, got {len(block)}"
        x = bytes_to_int(block)
        s = polyval_dot(s ^ x, h)
    return int_to_bytes(s)


def polyval_double(val: int) -> int:
    """Left-shift a 128-bit field element by 1, with reduction.

    Used during table precomputation (htable[2i] = double(htable[i])).
    This is multiplication by x using the POLYVAL polynomial.
    """
    carry = (val >> 127) & 1
    val = (val << 1) & MASK128
    if carry:
        val ^= POLYVAL_LEFT_REDUCE
    return val


def polyval_right_shift_1(val: int) -> int:
    """Right-shift a 128-bit field element by 1, with reduction.

    When the LSB falls off, XOR with x^{-1} mod p = 0xe1<<120.
    """
    carry = val & 1
    val >>= 1
    if carry:
        val ^= POLYVAL_RIGHT_REDUCE
    return val


def polyval_precompute_table(h: int) -> list:
    """Build the 4-bit multiplication table htable[0..15] from H.

    First computes H' = H * x^{-128} by right-shifting H 128 times.
    Then builds htable using left-shift doubling from H':
    htable[0] = 0, htable[1] = H', htable[2i] = double(htable[i]),
    htable[2i+1] = htable[2i] XOR H'.

    The multiplication algorithm uses left-shift-by-4 to produce the
    correct POLYVAL dot product (a * b * x^{-128}).

    Returns list of 16 integers.
    """
    # Compute H' = H * x^{-128}
    h_prime = h
    for _ in range(128):
        h_prime = polyval_right_shift_1(h_prime)

    htable = [0] * 16
    htable[1] = h_prime
    htable[2] = polyval_double(h_prime)
    for i in range(3, 16):
        if i % 2 == 0:
            htable[i] = polyval_double(htable[i // 2])
        else:
            htable[i] = htable[i - 1] ^ htable[1]
    return htable


def polyval_multiply_table(acc: int, htable: list) -> int:
    """Multiply acc by H using the 4-bit nibble table.

    Matches the C64 implementation algorithm:
    Process bytes from MSB (byte 15) to LSB (byte 0), each as two nibbles.
    For each nibble: left-shift result by 4 bits (with reduction),
    then XOR with htable[nibble].

    The table was built from H' = H * x^{-128}, so this computes
    acc * H' = acc * H * x^{-128} = dot(acc, H).
    """
    result = 0
    for byte_idx in range(15, -1, -1):
        byte_val = (acc >> (byte_idx * 8)) & 0xFF
        high_nibble = byte_val >> 4
        low_nibble = byte_val & 0x0F

        # Process high nibble: left-shift 4, XOR table entry
        for _ in range(4):
            result = polyval_double(result)
        result ^= htable[high_nibble]

        # Process low nibble: left-shift 4, XOR table entry
        for _ in range(4):
            result = polyval_double(result)
        result ^= htable[low_nibble]

    return result


# ---------------------------------------------------------------------------
# AES-256-GCM-SIV
# ---------------------------------------------------------------------------

def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Single AES-ECB block encryption."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def gcmsiv_derive_keys(key: bytes, nonce: bytes) -> tuple:
    """Derive authentication key (16 bytes) and encryption key (32 bytes).

    Per RFC 8452 Section 4: for AES-256, uses counters 0..5.
    Each counter produces 8 bytes from first half of AES output.
    """
    auth_key = b""
    enc_key = b""

    for ctr in range(6):
        block = struct.pack("<I", ctr) + nonce
        assert len(block) == 16
        out = aes_encrypt_block(key, block)
        eight = out[:8]

        if ctr < 2:
            auth_key += eight
        else:
            enc_key += eight

    assert len(auth_key) == 16
    assert len(enc_key) == 32
    return auth_key, enc_key


def gcmsiv_compute_tag(auth_key: bytes, enc_key: bytes, nonce: bytes,
                       plaintext: bytes, aad: bytes = b"") -> bytes:
    """Compute the GCM-SIV authentication tag.

    1. POLYVAL over [AAD blocks] [plaintext blocks] [length block]
    2. XOR with nonce
    3. Clear MSB of byte 15
    4. AES-encrypt with derived encryption key
    """
    # Build POLYVAL blocks
    blocks = []

    # AAD blocks (padded)
    if aad:
        for i in range(0, len(aad), 16):
            chunk = aad[i:i+16]
            if len(chunk) < 16:
                chunk = chunk + b'\x00' * (16 - len(chunk))
            blocks.append(chunk)

    # Plaintext blocks (padded)
    if plaintext:
        for i in range(0, len(plaintext), 16):
            chunk = plaintext[i:i+16]
            if len(chunk) < 16:
                chunk = chunk + b'\x00' * (16 - len(chunk))
            blocks.append(chunk)

    # Length block: 64-bit AAD bit length || 64-bit plaintext bit length (LE)
    len_block = struct.pack("<QQ", len(aad) * 8, len(plaintext) * 8)
    blocks.append(len_block)

    # Compute POLYVAL
    pv_result = polyval(auth_key, *blocks)

    # XOR with nonce (first 12 bytes)
    pv_arr = bytearray(pv_result)
    for i in range(12):
        pv_arr[i] ^= nonce[i]

    # Clear MSB of byte 15
    pv_arr[15] &= 0x7F

    # AES-encrypt to get tag
    tag = aes_encrypt_block(enc_key, bytes(pv_arr))
    return tag


def gcmsiv_ctr_encrypt(enc_key: bytes, tag: bytes, plaintext: bytes) -> bytes:
    """AES-CTR encryption using tag as IV, per RFC 8452."""
    if not plaintext:
        return b""

    # Counter = tag with MSB of byte 15 set
    counter = bytearray(tag)
    counter[15] |= 0x80

    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        # Encrypt counter block
        keystream = aes_encrypt_block(enc_key, bytes(counter))

        # XOR plaintext chunk
        chunk = plaintext[i:i+16]
        for j in range(len(chunk)):
            ciphertext.append(chunk[j] ^ keystream[j])

        # Increment 32-bit LE counter (bytes 0-3)
        c = struct.unpack_from("<I", counter, 0)[0]
        c = (c + 1) & 0xFFFFFFFF
        struct.pack_into("<I", counter, 0, c)

    return bytes(ciphertext)


def gcmsiv_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                   aad: bytes = b"") -> tuple:
    """Full AES-256-GCM-SIV encryption.

    Returns (ciphertext, tag) tuple.
    """
    auth_key, enc_key = gcmsiv_derive_keys(key, nonce)
    tag = gcmsiv_compute_tag(auth_key, enc_key, nonce, plaintext, aad)
    ciphertext = gcmsiv_ctr_encrypt(enc_key, tag, plaintext)
    return ciphertext, tag


def gcmsiv_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                   tag: bytes, aad: bytes = b"") -> tuple:
    """Full AES-256-GCM-SIV decryption with tag verification.

    Returns (plaintext, tag_valid) tuple.
    """
    auth_key, enc_key = gcmsiv_derive_keys(key, nonce)

    # Decrypt ciphertext (CTR mode is symmetric)
    plaintext = gcmsiv_ctr_encrypt(enc_key, tag, ciphertext)

    # Recompute tag over decrypted plaintext
    expected_tag = gcmsiv_compute_tag(auth_key, enc_key, nonce, plaintext, aad)

    tag_valid = (tag == expected_tag)
    return plaintext, tag_valid


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _test():
    """Run self-tests against RFC 8452 test vectors."""
    passed = 0
    failed = 0

    # --- Appendix A: POLYVAL worked example ---
    print("=== Appendix A: POLYVAL worked example ===")
    h = bytes.fromhex("25629347589242761d31f826ba4b757b")
    x1 = bytes.fromhex("4f4f95668c83dfb6401762bb2d01a262")
    x2 = bytes.fromhex("d1a24ddd2721d006bbe45f20d3c9f362")
    expected = bytes.fromhex("f7a3b47b846119fae5b7866cf5e5b77e")

    result = polyval(h, x1, x2)
    if result == expected:
        print(f"  PASS: POLYVAL matches {expected.hex()}")
        passed += 1
    else:
        print(f"  FAIL: expected {expected.hex()}")
        print(f"        got      {result.hex()}")
        failed += 1

    # --- Appendix A: POLYVAL table-based multiply verification ---
    print("\n=== Table-based multiplication ===")
    h_int = bytes_to_int(h)
    htable = polyval_precompute_table(h_int)
    s_tbl = 0
    s_tbl = polyval_multiply_table(s_tbl ^ bytes_to_int(x1), htable)
    s_tbl = polyval_multiply_table(s_tbl ^ bytes_to_int(x2), htable)
    tbl_result = int_to_bytes(s_tbl)
    if tbl_result == expected:
        print(f"  PASS: table-based matches {expected.hex()}")
        passed += 1
    else:
        print(f"  FAIL: expected {expected.hex()}")
        print(f"        got      {tbl_result.hex()}")
        failed += 1

    # --- Appendix C.2: AES-256-GCM-SIV vectors ---
    print("\n=== Appendix C.2: AES-256-GCM-SIV vectors ===")

    vectors = [
        {
            "name": "C.2 Test 1: empty PT, empty AAD",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "",
            "plaintext": "",
            "ct_tag": "07f5f4169bbf55a8400cd47ea6fd400f",
        },
        {
            "name": "C.2 Test 2: 8-byte PT",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "",
            "plaintext": "0100000000000000",
            "ct_tag": "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
        },
        {
            "name": "C.2 Test 3: 12-byte PT",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "",
            "plaintext": "010000000000000000000000",
            "ct_tag": "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e",
        },
        {
            "name": "C.2 Test 4: 32-byte PT (2 blocks)",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "",
            "plaintext": "01000000000000000000000000000000"
                         "02000000000000000000000000000000",
            "ct_tag": "4a6a9db4c8c6549201b9edb53006cba8"
                      "21ec9cf850948a7c86c68ac7539d027f"
                      "e819e63abcd020b006a976397632eb5d",
        },
        {
            "name": "C.2 Test 5: 48-byte PT (3 blocks)",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "",
            "plaintext": "01000000000000000000000000000000"
                         "02000000000000000000000000000000"
                         "03000000000000000000000000000000",
            "ct_tag": "c00d121893a9fa603f48ccc1ca3c57ce"
                      "7499245ea0046db16c53c7c66fe717e3"
                      "9cf6c748837b61f6ee3adcee17534ed5"
                      "790bc96880a99ba804bd12c0e6a22cc4",
        },
        {
            "name": "C.2 Test 6: 64-byte PT (4 blocks)",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "",
            "plaintext": "01000000000000000000000000000000"
                         "02000000000000000000000000000000"
                         "03000000000000000000000000000000"
                         "04000000000000000000000000000000",
            "ct_tag": "c2d5160a1f8683834910acdafc41fbb1"
                      "632d4a353e8b905ec9a5499ac34f96c7"
                      "e1049eb080883891a4db8caaa1f99dd0"
                      "04d80487540735234e3744512c6f90ce"
                      "112864c269fc0d9d88c61fa47e39aa08",
        },
        {
            "name": "C.2 Test 7: 1-byte AAD + 8-byte PT",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "01",
            "plaintext": "0200000000000000",
            "ct_tag": "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
        },
        {
            "name": "C.2 Test 8: 1-byte AAD + 12-byte PT",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "01",
            "plaintext": "020000000000000000000000",
            "ct_tag": "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f",
        },
        {
            "name": "C.2 Test 9: 1-byte AAD + 16-byte PT",
            "key": "0100000000000000000000000000000000000000000000000000000000000000",
            "nonce": "030000000000000000000000",
            "aad": "01",
            "plaintext": "02000000000000000000000000000000",
            "ct_tag": "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7",
        },
    ]

    for v in vectors:
        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"])
        aad = bytes.fromhex(v["aad"]) if v["aad"] else b""
        pt = bytes.fromhex(v["plaintext"]) if v["plaintext"] else b""
        expected_ct_tag = bytes.fromhex(v["ct_tag"])

        ct, tag = gcmsiv_encrypt(key, nonce, pt, aad)
        result = ct + tag

        if result == expected_ct_tag:
            print(f"  PASS: {v['name']}")
            passed += 1

            # Also verify decryption
            dec_pt, valid = gcmsiv_decrypt(key, nonce, ct, tag, aad)
            if dec_pt == pt and valid:
                passed += 1
            else:
                print(f"  FAIL: decrypt mismatch for {v['name']}")
                failed += 1
        else:
            print(f"  FAIL: {v['name']}")
            print(f"    Expected: {expected_ct_tag.hex()}")
            print(f"    Got:      {result.hex()}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    import sys
    ok = _test()
    sys.exit(0 if ok else 1)
