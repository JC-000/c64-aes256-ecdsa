# ECDSA P-256 Implementation Plan for C64

## Overview

Implement ECDSA signing on the NIST P-256 (secp256r1) curve to enable
proper PKCS#10 CSR generation. The implementation is built as a set of
reusable 256-bit modular arithmetic primitives.

## Curve P-256 Parameters (all big-endian, 32 bytes)

### Prime p (field modulus)
```
FFFFFFFF 00000001 00000000 00000000
00000000 FFFFFFFF FFFFFFFF FFFFFFFF
```

### Order n (group order, for scalar arithmetic)
```
FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
BCE6FAAD A7179E84 F3B9CAC2 FC632551
```

### Coefficient a = -3 (mod p)
```
FFFFFFFF 00000001 00000000 00000000
00000000 FFFFFFFF FFFFFFFF FFFFFFFC
```

### Coefficient b
```
5AC635D8 AA3A93E7 B3EBBD55 769886BC
651D06B0 CC53B0F6 3BCE3C3E 27D2604B
```

### Generator G.x
```
6B17D1F2 E12C4247 F8BCE6E5 63A440F2
77037D81 2DEB33A0 F4A13945 D898C296
```

### Generator G.y
```
4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16
2BCE3357 6B315ECE CBB64068 37BF51F5
```

## NIST ECDSA Test Vector (from FIPS 186-4 / RFC 6979)

For verification against OpenSSL, use this deterministic test:

### Private key d:
```
C9AFA9D8 45BA75166B 5C215767 B1D6934E
50C3DB36 E89B127B 8A622B12 0F6721
```
Wait -- let me use a simpler, well-documented test vector.

### Test Vector: RFC 6979 A.2.5 (ECDSA with P-256 and SHA-256)

Private key (x):
```
C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
```

Message: "sample" (ASCII, 6 bytes: 73 61 6D 70 6C 65)

SHA-256("sample") = 
```
AF2BDBE1 AA9B6EC1 E2ADE1D6 94F41FC7
1A831D02 68E98915 62113D8A 62ADD1BF
```

k (deterministic per RFC 6979):
```
A6E3C57D D01ABE90 086538398 355DD4C3
B17AA873 82B0F24D 6189172 4BA7FB1C
```

Resulting signature:
  r = EFD48B2A ACA0A6D0 F9B5571B 7E34A5E1
      42B8DA07 14FB5F00 882DCEDB 5849B832
  s = F7CB1C94 2D657C41 D436C7A1 B6E29F65
      F3E900DB B9AFF406 4DC4AB2F 843ACDA8

## Implementation Layers (bottom up)

### Layer 1: 256-bit Unsigned Integer Arithmetic
Storage: 32 bytes, big-endian (MSB at offset 0)

Routines:
- `fp_load(src, dst)` — copy 32 bytes
- `fp_zero(dst)` — clear 32 bytes
- `fp_cmp(a, b)` — compare, return flags (carry/zero)
- `fp_add(a, b, dst)` — add, return carry
- `fp_sub(a, b, dst)` — subtract, return borrow
- `fp_lshift(a)` — left shift 1 bit in place
- `fp_rshift(a)` — right shift 1 bit in place
- `fp_is_zero(a)` — test if zero
- `fp_is_even(a)` — test LSB
- `fp_mul(a, b, dst)` — full 256x256->512 multiply
  Uses quarter-square lookup table (512 bytes in RAM)

Working registers: fp_a, fp_b, fp_r (32 bytes each) + fp_tmp (64 bytes)

### Layer 2: Modular Arithmetic (mod p and mod n)

Routines:
- `fp_mod_add(a, b, mod, dst)` — (a + b) mod m
- `fp_mod_sub(a, b, mod, dst)` — (a - b) mod m 
- `fp_mod_mul(a, b, mod, dst)` — (a * b) mod m
  Method: multiply to 512-bit result, then Barrett reduction
- `fp_mod_inv(a, mod, dst)` — modular inverse via binary extended GCD
  (Avoids modular exponentiation; faster for single inversions)
- `fp_mod_reduce(wide, mod, dst)` — reduce 512-bit value mod m

### Layer 3: Elliptic Curve Point Operations

Point storage: Jacobian coordinates (X, Y, Z), 96 bytes per point
  Avoids modular inversions during intermediate calculations.
  Convert to affine (x, y) only at the end.

Routines:
- `ec_point_double(P, R)` — R = 2P
- `ec_point_add(P, Q, R)` — R = P + Q
- `ec_point_is_inf(P)` — test if P is point at infinity
- `ec_point_set_inf(P)` — set P to point at infinity
- `ec_scalar_mul(k, P, R)` — R = kP via double-and-add
- `ec_jacobian_to_affine(P, x, y)` — convert to affine coords

### Layer 4: ECDSA Sign

Routine: `ecdsa_sign(hash, privkey, k, r_out, s_out)`

Algorithm:
1. Compute (x1, y1) = k * G
2. r = x1 mod n  (if r == 0, need new k)
3. s = k^(-1) * (hash + r * d) mod n  (if s == 0, need new k)
4. Signature is (r, s)

### Layer 5: ECDSA Test & CSR Integration

- `ecdsa_test` — run RFC 6979 test vector and verify r,s match
- CSR generation with proper ASN.1 DER encoding
- PKCS#10 structure with ECDSA-with-SHA256 OID

## Memory Layout

The 8-bit multiply lookup table (quarter squares) occupies 512 bytes.
Curve parameters: 7 × 32 = 224 bytes
Working point storage: 3 points × 96 bytes = 288 bytes  
Working big-number registers: ~320 bytes (10 × 32)
Wide multiply buffer: 64 bytes
Total data: ~1.4 KB

Code estimate:
- Layer 1 (bignum): ~800 bytes
- Layer 2 (modular): ~600 bytes
- Layer 3 (EC point): ~800 bytes
- Layer 4 (ECDSA sign): ~300 bytes
- Layer 5 (test + CSR): ~500 bytes
- Strings/tables: ~500 bytes
Total code: ~3.5 KB

Grand total: ~5 KB additional. Well within the 15.6KB free.

## 8-bit Multiply Table

For the quarter-square method:
  a*b = sq[(a+b)/2] - sq[(a-b)/2]  (for even sums)

Actually, easier to use: a*b = f(a+b) - f(a-b) where f(x) = floor(x²/4)

Table: 512 entries of floor(n²/4) for n = 0..511
Each entry is 16 bits (values up to 65,025)
Table size: 1024 bytes

This replaces the ~40-cycle shift-and-add multiply with
a ~20-cycle table lookup, roughly doubling multiply speed.

## Implementation Order

1. **fp_* base routines** — test with known vectors
2. **fp_mod_* routines** — test with field operations  
3. **Multiply table + fp_mul** — test with known products
4. **fp_mod_reduce / fp_mod_mul** — test mod p
5. **ec_point_double, ec_point_add** — test with known points
6. **ec_scalar_mul** — test: k*G should give known public key
7. **ec_jacobian_to_affine** — test with above
8. **ecdsa_sign** — test with RFC 6979 vector
9. **CSR generation** — integrate with existing CSR code

## OpenSSL Verification Commands

```bash
# Verify the test vector signature
# Create private key file from raw hex:
echo "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721" | xxd -r -p > privkey.bin

# Create EC private key PEM
openssl ec -inform DER ... (needs proper ASN.1 wrapping)

# Or use openssl dgst to verify:
# 1. Construct the public key from private key
# 2. Hash the message
# 3. Verify (r, s) against the hash and public key
```
