# c64-aes256-ecdsa

A cryptography suite for the Commodore 64 in 6502 assembly. Implements AES-256 (CBC and GCM-SIV modes), SHA-256, ECDSA P-256 digital signatures, and SID-based random number generation, all running on a 1 MHz 8-bit processor.

**For demonstration and educational purposes only - not cryptographically secure.**

## Features

- **AES-256-CBC** encryption and decryption with PKCS#7 padding
- **AES-256-GCM-SIV** nonce-misuse resistant authenticated encryption (AEAD)
- **SHA-256** hashing (FIPS 180-4)
- **ECDSA P-256** digital signature generation (FIPS 186-4, RFC 6979 test vectors)
- **CSR generation** with X.509 subject fields in text format
- **SID-based PRNG** using voice 3 noise oscillator + CIA timer entropy
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

On startup the program generates a random IV and AES-256 key using the SID chip, expands the key schedule, and presents the main menu.

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

**J submenu:** `1` = Generate CSR (collects X.509 fields, outputs PEM-like text file), `2` = Run ECDSA P-256 test (RFC 6979 A.2.5 test vector, verifies r and s components).

## Source Structure

The codebase is split into 21 focused modules included via `src/main.asm`:

| Module | Lines | Description |
|--------|------:|-------------|
| `main.asm` | 39 | Top-level includes and origin setup |
| `constants.asm` | 104 | System equates, zero page, hardware addresses |
| `boot.asm` | 101 | BASIC stub, startup and initialization |
| `main_loop.asm` | 195 | Menu dispatcher and cleanup |
| `aes_encrypt.asm` | 688 | AES-256 key expansion and CBC encryption |
| `aes_decrypt.asm` | 634 | AES-256 inverse operations and CBC decryption |
| `gcm_siv.asm` | 1,652 | GCM-SIV AEAD: key derivation, CTR mode, tagging |
| `sha256.asm` | 1,107 | SHA-256 with H and K constants |
| `ecdsa_p256.asm` | 2,306 | P-256 field/curve arithmetic, ECDSA signing |
| `csr.asm` | 715 | CSR field collection, formatting, and file output |
| `prng.asm` | 295 | SID init, LFSR seeding, byte generation |
| `sid_config.asm` | 817 | Multi-SID UI, address parsing, random stream |
| `disk_io.asm` | 1,802 | Kernal file I/O, filenames, hex conversion |
| `reu_core.asm` | 282 | REU detection, stash/fetch |
| `reu_advanced.asm` | 1,361 | REU status, fill, save-to-disk |
| `benchmark.asm` | 513 | CIA timer benchmarks, NIST vector loading |
| `display.asm` | 153 | Hex display, print routines |
| `data.asm` | 223 | Shared mutable buffers (key, IV, state, I/O) |
| `tables.asm` | 52 | AES S-box, inverse S-box, round constants |
| `strings.asm` | 744 | UI message strings |
| `debug_strings.asm` | 63 | Debug output messages |

**Total:** ~13,800 lines of 6502 assembly, producing a 28 KB `.prg` binary.

## ECDSA P-256 Implementation

The ECDSA module implements full elliptic curve arithmetic over the NIST P-256 prime field:

- **Field arithmetic:** add, subtract, multiply (quarter-square lookup tables at $7800), modular reduction via binary long division, modular inverse via binary extended GCD
- **Point operations:** Jacobian coordinates, point doubling, point addition, scalar multiplication
- **Signing:** RFC 6979 deterministic nonce support, produces (r, s) signature pair

The built-in test (`J` then `2`) runs the RFC 6979 A.2.5 test vector (SHA-256, message "sample") and verifies the computed r and s against known-good values.

## Test Automation

`tools/vicemon.py` is a Python client for VICE's remote text monitor, usable as both a library and CLI tool:

```bash
# Start VICE with remote monitor enabled
x64sc -autostart build/aes256keygen.prg -remotemonitor

# In another terminal:
python3 tools/vicemon.py screen              # Read screen as text
python3 tools/vicemon.py send J              # Send keypress
python3 tools/vicemon.py wait "PASS" 300     # Wait for text (timeout 300s)
python3 tools/vicemon.py mem 0x6668 32       # Hex dump memory
python3 tools/vicemon.py regs                # Show CPU registers
```

As a library:

```python
from vicemon import ViceMon
mon = ViceMon()                              # Connect to localhost:6510
print(mon.screen_text())                     # Decode screen memory
mon.send_key('2')                            # Inject keypress
mon.wait_for_text('PASS', timeout=300)       # Poll screen for result
print(mon.hex_dump(0x66E8, 32))              # Dump fp_r0 register
```

### Automated Test Suites

Tests use the [`c64-test-harness`](../c64-test-harness) package to drive VICE via its remote text monitor. Install the harness first (`pip install -e ../c64-test-harness`).

```bash
python3 tools/test_aes_cbc.py            # 10 tests: AES-256-CBC encrypt vs Python cryptography (PKCS#7, boundary cases)
python3 tools/test_aes_cbc_decrypt.py    # 10 tests: AES-256-CBC decrypt (Python encrypts, C64 decrypts, verify plaintext)
```

## Technical Notes

- **SID entropy:** Voice 3 oscillator noise + CIA timer XOR provides the entropy source. Non-deterministic even under emulation, though not cryptographically strong.
- **GCM-SIV:** Nonce-misuse resistant AEAD. Safe to reuse nonces with the same key (unlike standard GCM). Structure: `nonce(12) || ciphertext || tag(16)`.
- **Quarter-square multiplication:** ECDSA uses precomputed tables at $7800-$7BFF for 8x8 multiply via the identity `a*b = f(a+b) - f(a-b)` where `f(x) = floor(x^2/4)`.
- **Memory footprint:** The binary occupies $0801-$75EC (~28 KB). Quarter-square tables use $7800-$7BFF (1 KB). Remaining RAM is available for data buffers.
- **Module ordering matters:** The `!source` include order in `main.asm` defines the binary layout. Do not reorder.

## License

See repository for license terms.
