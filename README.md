# c64-aes256-ecdsa

A cryptography suite for the Commodore 64 in 6502 assembly. Implements AES-256 (CBC and GCM-SIV modes), SHA-256, ECDSA P-256 digital signatures, and SID-based random number generation, all running on a 1 MHz 8-bit processor.

**For demonstration and educational purposes only - not cryptographically secure.**

## Features

- **AES-256-CBC** encryption and decryption with PKCS#7 padding
- **AES-256-GCM-SIV** nonce-misuse resistant authenticated encryption (AEAD) with RFC 8452 POLYVAL
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

**Requirements:** [cc65](https://cc65.github.io/) (ca65 assembler + ld65 linker), GNU Make

```bash
make            # Build build/aes256keygen.prg
make run        # Build and launch in VICE (x64sc)
make clean      # Remove build artifacts
```

Source lives in `src/*.s` (ca65 syntax), one real object file per module — the `Makefile`'s `MODULES` list assembles each with `ca65` and links them together in one `ld65` invocation (`build/%.o: src/%.s` pattern rule). `build_ca65/linker.cfg` defines the memory layout (BASIC-stub load at `$0801`, the `$7800-$7BFF` quarter-square table reservation, and the `$7C00` high-memory overflow area for the PKCS#10/ECDSA modules) that reproduces the project's historical layout.

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

The codebase is split into 32 focused modules included via `src/main.s`:

| Module | Lines | Description |
|--------|------:|-------------|
| `main.s` | 45 | Top-level includes and origin setup |
| `constants.s` | 107 | System equates, zero page, hardware addresses |
| `boot.s` | 101 | BASIC stub, startup and initialization |
| `main_loop.s` | 195 | Menu dispatcher and cleanup |
| `aes_encrypt.s` | 688 | AES-256 key expansion and CBC encryption |
| `aes_decrypt.s` | 634 | AES-256 inverse operations and CBC decryption |
| `gcm_siv.s` | 1,652 | GCM-SIV AEAD: key derivation, CTR mode, POLYVAL tagging |
| `polyval.s` | 411 | POLYVAL GF(2^128) universal hash (RFC 8452, 4-bit nibble table) |
| `sha256.s` | 1,069 | SHA-256 with H and K constants (optimized rotations) |
| `hmac_drbg.s` | 400 | HMAC-SHA256, HMAC-DRBG, entropy-seeded PRNG |
| `ecdsa_fp.s` | 310 | Big-number primitives: add, sub, mul, shift |
| `ecdsa_mod.s` | 514 | Modular arithmetic: mod_add, mod_sub, mod_mul, mod_inv |
| `ecdsa_curve.s` | 149 | P-256 curve parameters, test vectors, point storage |
| `ecdsa_points.s` | 899 | Point operations: double, add, scalar_mul, J-to-affine |
| `ecdsa_sign.s` | 125 | ECDSA signing routine |
| `ecdsa_test.s` | 318 | ECDSA test harness and UI |
| `csr.s` | 724 | CSR field collection, formatting, and file output |
| `der_encode.s` | — | DER/ASN.1 encoding for PKCS#10 |
| `base64.s` | — | Base64/PEM encoding |
| `pkcs10_build.s` | — | PKCS#10 TBS structure builder |
| `pkcs10.s` | — | PKCS#10 CSR orchestrator (keygen, hash, sign, save) |
| `prng.s` | 60 | SID hardware initialization (voice 3 noise setup) |
| `sid_config.s` | 780 | Multi-SID UI, address parsing, random stream |
| `disk_io.s` | 1,802 | Kernal file I/O, filenames, hex conversion |
| `reu_core.s` | 282 | REU detection, stash/fetch |
| `reu_advanced.s` | 1,361 | REU status, fill, save-to-disk |
| `benchmark.s` | 547 | CIA timer benchmarks, NIST vector loading |
| `display.s` | 153 | Hex display, print routines |
| `data.s` | 237 | Shared mutable buffers (key, IV, state, I/O, HMAC-DRBG) |
| `tables.s` | 52 | AES S-box, inverse S-box, round constants |
| `strings.s` | 744 | UI message strings |
| `debug_strings.s` | 63 | Debug output messages |

**Total:** ~13,900 lines of 6502 assembly, producing a ~35 KB `.prg` binary.

## ECDSA P-256 Implementation

The ECDSA module implements full elliptic curve arithmetic over the NIST P-256 prime field:

- **Field arithmetic:** add, subtract, multiply (quarter-square lookup tables at $7800), modular reduction via binary long division, modular inverse via binary extended GCD
- **Point operations:** Jacobian coordinates, point doubling, point addition, scalar multiplication
- **Signing:** RFC 6979 deterministic nonce via HMAC-DRBG, produces (r, s) signature pair

The built-in test (`J` then `2`) runs the RFC 6979 A.2.5 test vector (SHA-256, message "sample") and verifies the computed r and s against known-good values.

## Test Automation

Tests use the [`c64-test-harness`](../c64-test-harness) package to drive VICE via its remote text monitor. Install the harness first (`pip install -e ../c64-test-harness`).

### Unified Test Runner

Run all direct-memory test suites in parallel with a shared VICE worker pool:

```bash
python3 tools/run_all_tests.py                             # Auto-detect workers, 50 iterations
python3 tools/run_all_tests.py --workers 2 --iterations 10 # Conservative (2 VICE instances, 10 iters)
python3 tools/run_all_tests.py --workers 3 --fail-fast     # Stop on first failure
python3 tools/run_all_tests.py --seed 42 --verbose         # Reproducible seed, verbose output
python3 tools/run_all_tests.py --smoke-test                # Quick write/read verification only
```

The unified runner manages a pool of VICE instances (`ViceInstanceManager`), builds the project, loads labels, boots all instances, then runs 7 direct-memory test suites across workers followed by 2 UI-driven suites:

| Suite | Tests | Description |
|-------|------:|-------------|
| SHA-256 | 7/worker | Init IV, NIST "abc", empty input, boundary 1/55/56/63 bytes |
| AES-CBC Encrypt | 5/worker | Boundary 1/16/48/63 bytes + random sizes vs Python `cryptography` |
| AES-CBC Decrypt | 5/worker | Boundary 1/16/48/63 bytes + random sizes (Python encrypts, C64 decrypts) |
| POLYVAL | 153 total | All routines: init, double, shift, table, multiply, update, pipeline |
| GCM-SIV Encrypt | 13 total | RFC 8452 C.2 vectors + boundary sizes vs OpenSSL AESGCMSIV |
| GCM-SIV Decrypt | 13 total | Boundary sizes + tag tampering detection |
| GCM-SIV Roundtrip | 13/worker | RFC 8452 vectors + tamper detection + random encrypt/decrypt |
| CSR (PKCS#10) | 4 total | UI-driven: full CSR, CN-only, no-CN, all-empty rejection |
| HMAC-DRBG (RFC 6979) | 1 total | UI-driven: deterministic nonce via PKCS#10 CSR flow |

All `jsr()` calls use a `robust_jsr()` retry wrapper (3 attempts, 0.3s delay) for resilience against transient VICE TCP failures. Each VICE instance in warp mode uses ~1 CPU core and ~170 MB RAM. The default worker count is `min(cpu_count - 2, 10)`.

### Individual Test Scripts

```bash
# UI-driven tests (single VICE instance):
python3 tools/test_csr_harness.py              # 4 tests: CSR field parsing and formatting
python3 tools/test_csr.py                      # 2 tests: AES key integrity + NIST KAT crypto match
python3 tools/test_pkcs10.py                   # 1 test:  PKCS#10 CSR generation + SHA-256 + ECDSA verification
python3 tools/test_hmac_drbg.py                # 1 test:  HMAC-DRBG / RFC 6979 deterministic nonce verification
python3 tools/test_sha256.py                   # 10 tests: SHA-256 hash via menu UI vs OpenSSL
python3 tools/test_aes_cbc.py                  # 10 tests: AES-256-CBC encrypt via menu UI
python3 tools/test_aes_cbc_decrypt.py          # 10 tests: AES-256-CBC decrypt via menu UI

# Direct-memory tests (faster, support --workers N for parallel execution):
python3 tools/test_sha256_direct.py            # 50 tests: SHA-256 via direct jsr() + memory (~20x faster)
python3 tools/test_aes_cbc_direct.py           # 50 tests: AES-256-CBC encrypt via direct jsr() + memory
python3 tools/test_aes_cbc_decrypt_direct.py   # 50 tests: AES-256-CBC decrypt via direct jsr() + memory
python3 tools/test_polyval_direct.py            # 153 tests: POLYVAL GF(2^128) unit tests via direct jsr() + memory
python3 tools/test_gcmsiv_encrypt_direct.py    # 50 tests: AES-256-GCM-SIV encrypt vs OpenSSL AESGCMSIV + polyval_reference
python3 tools/test_gcmsiv_decrypt_direct.py    # 50 tests: AES-256-GCM-SIV decrypt vs OpenSSL AESGCMSIV (includes tag tampering)
python3 tools/test_gcmsiv_polyval.py           # 15 tests: GCM-SIV full roundtrip + RFC 8452 C.2 vectors
python3 tools/validate_direct_tests.py         # Cross-validation: CBC (UI vs direct) + GCM-SIV (C64 vs OpenSSL)
```

The `*_direct.py` scripts use `jsr()` from the test harness to call assembly routines directly via the VICE monitor, writing input and reading output through memory. This bypasses the menu UI, enabling ~20x faster iterations. Use `--cross-validate` (where supported) to also run boundary cases through the menu UI for comparison. Shared test helpers (`robust_jsr`, `generate_random_string`, `generate_random_bytes`) live in `tools/c64_test_utils.py`.

Individual direct-memory tests support parallel execution via `--workers N`, which launches N concurrent VICE instances on separate monitor ports using `ViceInstanceManager` from the test harness. Test cases are distributed round-robin across workers for balanced load. The default (`--workers 1`) runs sequentially on a single instance.

The GCM-SIV tests validate against both OpenSSL's `AESGCMSIV` (from the `cryptography` library) and a pure-Python reference (`tools/polyval_reference.py`) implementing RFC 8452 POLYVAL. Three-way consistency checks ensure C64, OpenSSL, and the Python reference all produce identical output. RFC 8452 Appendix A and C.2 test vectors (`test/rfc8452_vectors.json`) are run before random tests.

Each test script builds the project, launches VICE in warp mode, drives the C64 through keyboard injection/screen polling or direct memory access, then verifies results against Python/OpenSSL references.

## Technical Notes

- **HMAC-DRBG PRNG:** All random byte generation (AES keys, IVs, GCM-SIV nonces, REU random fill) uses HMAC-DRBG with 256-bit internal state, seeded from SID voice 3 noise oscillator + CIA timer XOR hardware entropy. Single-byte requests are served from a 32-byte buffer to amortize the cost of SHA-256 computation. For ECDSA signing, the same DRBG is re-instantiated deterministically per RFC 6979 (`privkey || message_hash`), then reseeded from hardware entropy after CSR generation.
- **GCM-SIV:** Nonce-misuse resistant AEAD per RFC 8452. Uses POLYVAL (GF(2^128) universal hash with 4-bit nibble table lookup) for tag computation. Safe to reuse nonces with the same key (unlike standard GCM). Structure: `nonce(12) || ciphertext || tag(16)`.
- **SHA-256 performance:** Optimized from ~800 ms/block to ~683 ms/block (~15% faster) via four techniques: (1) sha_temp1/sha_temp2/sha256_round moved to zero page for automatic 2-byte addressing, (2) bit-by-bit rotation loops replaced with byte-swap + small-bit-rotate decomposition (e.g., ROTR22 = 3x ROTR8 + 2x ROTL1), (3) T2 recalculation eliminated by saving Sig0(a)+Maj(a,b,c) before the working variable update, (4) six individual 4-byte copy loops replaced with a single 28-byte backward memcpy for the h=g,g=f,...,b=a shift. Benchmark: 82 jiffies/call (2 blocks) vs 97 baseline.
- **Quarter-square multiplication:** ECDSA uses precomputed tables at $7800-$7BFF for 8x8 multiply via the identity `a*b = f(a+b) - f(a-b)` where `f(x) = floor(x^2/4)`.
- **Memory footprint:** The binary occupies $0801 through ~$78xx (pre-$7C00 region) plus $7C00+ for PKCS#10/HMAC-DRBG modules. Quarter-square tables use $7800-$7BFF (1 KB, runtime-generated). New code modules must be placed after `* = $7C00` to avoid overlapping the table region.
- **Module ordering matters:** every `src/*.s` module is a real, separately-assembled ca65 object (see `Makefile`'s `MODULES` list); `src/boot.s` must stay the first object linked after `main.o`, since its BASIC stub hardcodes `SYS 2064` as a literal byte string rather than a symbolic reference — it only lands correctly if `boot.o`'s code is the very first thing placed after the 2-byte LOADADDR header. Modules requiring >~1 KB of code should go in the `HICODE` segment (`.segment "HICODE"` in the module's own source; see `build_ca65/linker.cfg`), which is placed at $7C00 to avoid pushing ECDSA code into the $7800-$7BFF quarter-square table region.

## License

See repository for license terms.
