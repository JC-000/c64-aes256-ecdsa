# c64-aes256-ecdsa

A cryptography suite for the Commodore 64 in 6502 assembly. Implements AES-256 (CBC and GCM-SIV modes), SHA-256, ECDSA P-256 digital signatures, and SID-based random number generation, all running on a 1 MHz 8-bit processor.

**For demonstration and educational purposes only - not cryptographically secure.**

## Features

- **AES-256-CBC** encryption and decryption with PKCS#7 padding
- **AES-256-GCM-SIV** nonce-misuse resistant authenticated encryption (AEAD)
- **SHA-256** hashing (FIPS 180-4)
- **ECDSA P-256** digital signature generation (FIPS 186-4, RFC 6979 test vectors)
- **HMAC-DRBG** cryptographic random number generation (HMAC-SHA256 based, 256-bit internal state) seeded from SID+CIA hardware entropy, also used for RFC 6979 deterministic ECDSA nonces
- **PKCS#10 CSR generation** with DER/ASN.1 encoding, SHA-256 hashing, and PEM output
- **CSR generation** with X.509 subject fields in text format
- **REU support** with auto-detection (up to 16 MB)
- **NIST test vector verification** and CIA timer benchmarking
- **Disk I/O** for saving/loading keys and ciphertext (IEC bus / SD2IEC)
- **Multi-SID** configuration for enhanced entropy collection

## Building

**Requirements:** [ACME cross-assembler](https://sourceforge.net/projects/acme-crossass/), GNU Make

```bash
make            # Build build/aes256keygen.prg
make run        # Build and launch in VICE (x64sc)
make clean      # Remove build artifacts
```

Or build manually:

```bash
cd src && acme -f cbm -o ../build/aes256keygen.prg --vicelabels ../build/labels.txt main.asm
```

## Running

Load the `.prg` file in [VICE](https://vice-emu.sourceforge.io/) or transfer to real hardware:

```bash
x64sc -autostart build/aes256keygen.prg
```

On startup the program seeds the HMAC-DRBG from SID+CIA hardware entropy, generates a random IV and AES-256 key, expands the key schedule, and presents the main menu.

## Menu

| Key | Function | Key | Function |
|-----|----------|-----|----------|
| 1 | Display encryption key | A | Encrypt (GCM-SIV) |
| 2 | Encrypt text (CBC) | B | Decrypt (GCM-SIV) |
| 3 | Show ciphertext | C | Save GCM-SIV to disk |
| 4 | Decrypt (CBC) | D | Load GCM-SIV from disk |
| 5 | Save key to disk | E | Benchmark (CBC vs GCM-SIV) |
| 6 | Load key from disk | F | NIST test vector verify |
| 7 | Save ciphertext to disk | G | Show REU status |
| 8 | Load ciphertext from disk | H | Random hex stream |
| 9 | SHA-256 hash | I | Configure SID chips |
| | | J | CSR / ECDSA test |
| | | Q | Quit |

**J submenu:** `1` = Generate CSR (collects X.509 fields, outputs PEM-like text file), `2` = Run ECDSA P-256 test (RFC 6979 A.2.5 test vector, verifies r and s components), `3` = Generate PKCS#10 CSR (DER-encoded, ECDSA P-256 signed, PEM output with deterministic HMAC-DRBG nonce).

## Source Structure

The codebase is split into 31 focused modules included via `src/main.asm`:

| Module | Lines | Description |
|--------|------:|-------------|
| `main.asm` | 45 | Top-level includes and origin setup |
| `constants.asm` | 104 | System equates, zero page, hardware addresses |
| `boot.asm` | 101 | BASIC stub, startup and initialization |
| `main_loop.asm` | 195 | Menu dispatcher and cleanup |
| `aes_encrypt.asm` | 688 | AES-256 key expansion and CBC encryption |
| `aes_decrypt.asm` | 634 | AES-256 inverse operations and CBC decryption |
| `gcm_siv.asm` | 1,652 | GCM-SIV AEAD: key derivation, CTR mode, tagging |
| `sha256.asm` | 1,107 | SHA-256 with H and K constants |
| `hmac_drbg.asm` | 400 | HMAC-SHA256, HMAC-DRBG, entropy-seeded PRNG |
| `ecdsa_fp.asm` | 310 | Big-number primitives: add, sub, mul, shift |
| `ecdsa_mod.asm` | 514 | Modular arithmetic: mod_add, mod_sub, mod_mul, mod_inv |
| `ecdsa_curve.asm` | 149 | P-256 curve parameters, test vectors, point storage |
| `ecdsa_points.asm` | 899 | Point operations: double, add, scalar_mul, J-to-affine |
| `ecdsa_sign.asm` | 125 | ECDSA signing routine |
| `ecdsa_test.asm` | 318 | ECDSA test harness and UI |
| `csr.asm` | 724 | CSR field collection, formatting, and file output |
| `der_encode.asm` | — | DER/ASN.1 encoding for PKCS#10 |
| `base64.asm` | — | Base64/PEM encoding |
| `pkcs10_build.asm` | — | PKCS#10 TBS structure builder |
| `pkcs10.asm` | — | PKCS#10 CSR orchestrator (keygen, hash, sign, save) |
| `prng.asm` | 60 | SID hardware initialization (voice 3 noise setup) |
| `sid_config.asm` | 780 | Multi-SID UI, address parsing, random stream |
| `disk_io.asm` | 1,802 | Kernal file I/O, filenames, hex conversion |
| `reu_core.asm` | 282 | REU detection, stash/fetch |
| `reu_advanced.asm` | 1,361 | REU status, fill, save-to-disk |
| `benchmark.asm` | 547 | CIA timer benchmarks, NIST vector loading |
| `display.asm` | 153 | Hex display, print routines |
| `data.asm` | 237 | Shared mutable buffers (key, IV, state, I/O, HMAC-DRBG) |
| `tables.asm` | 52 | AES S-box, inverse S-box, round constants |
| `strings.asm` | 744 | UI message strings |
| `debug_strings.asm` | 63 | Debug output messages |

**Total:** ~13,900 lines of 6502 assembly, producing a 28 KB `.prg` binary.

## ECDSA P-256 Implementation

The ECDSA module implements full elliptic curve arithmetic over the NIST P-256 prime field:

- **Field arithmetic:** add, subtract, multiply (quarter-square lookup tables at $7800), modular reduction via binary long division, modular inverse via binary extended GCD
- **Point operations:** Jacobian coordinates, point doubling, point addition, scalar multiplication
- **Signing:** RFC 6979 deterministic nonce via HMAC-DRBG, produces (r, s) signature pair

The built-in test (`J` then `2`) runs the RFC 6979 A.2.5 test vector (SHA-256, message "sample") and verifies the computed r and s against known-good values.

## Test Automation

Tests use the [`c64-test-harness`](../c64-test-harness) package to drive VICE via its remote text monitor. Install the harness first (`pip install -e ../c64-test-harness`).

```bash
# Run all test suites:
python3 tools/test_csr_harness.py    # 4 tests: CSR field parsing and formatting
python3 tools/test_csr.py            # 2 tests: AES key integrity + NIST KAT crypto match
python3 tools/test_pkcs10.py         # 1 test:  PKCS#10 CSR generation + SHA-256 + ECDSA verification
python3 tools/test_hmac_drbg.py      # 1 test:  HMAC-DRBG / RFC 6979 deterministic nonce verification
python3 tools/test_sha256.py         # 10 tests: SHA-256 hash vs OpenSSL (random inputs, boundary cases)
```

Each test script builds the project, launches VICE in warp mode, drives the C64 through keyboard injection and screen polling, then verifies results against Python/OpenSSL references.

### Automated Test Suites

Tests use the [`c64-test-harness`](../c64-test-harness) package to drive VICE via its remote text monitor. Install the harness first (`pip install -e ../c64-test-harness`).

```bash
python3 tools/test_aes_cbc.py            # 10 tests: AES-256-CBC encrypt vs Python cryptography (PKCS#7, boundary cases)
python3 tools/test_aes_cbc_decrypt.py    # 10 tests: AES-256-CBC decrypt (Python encrypts, C64 decrypts, verify plaintext)
```

## Technical Notes

- **HMAC-DRBG PRNG:** All random byte generation (AES keys, IVs, GCM-SIV nonces, REU random fill) uses HMAC-DRBG with 256-bit internal state, seeded from SID voice 3 noise oscillator + CIA timer XOR hardware entropy. Single-byte requests are served from a 32-byte buffer to amortize the cost of SHA-256 computation. For ECDSA signing, the same DRBG is re-instantiated deterministically per RFC 6979 (`privkey || message_hash`), then reseeded from hardware entropy after CSR generation.
- **GCM-SIV:** Nonce-misuse resistant AEAD. Safe to reuse nonces with the same key (unlike standard GCM). Structure: `nonce(12) || ciphertext || tag(16)`.
- **Quarter-square multiplication:** ECDSA uses precomputed tables at $7800-$7BFF for 8x8 multiply via the identity `a*b = f(a+b) - f(a-b)` where `f(x) = floor(x^2/4)`.
- **Memory footprint:** The binary occupies $0801 through ~$78xx (pre-$7C00 region) plus $7C00+ for PKCS#10/HMAC-DRBG modules. Quarter-square tables use $7800-$7BFF (1 KB, runtime-generated). New code modules must be placed after `* = $7C00` to avoid overlapping the table region.
- **Module ordering matters:** The `!source` include order in `main.asm` defines the binary layout. Do not reorder. Modules requiring >~1 KB of code should go after `* = $7C00` to avoid pushing ECDSA code into the $7800-$7BFF quarter-square table region.

## License

See repository for license terms.
