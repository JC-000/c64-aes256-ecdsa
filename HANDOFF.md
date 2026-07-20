# Claude Code Handoff Prompt

Use this prompt when starting work in Claude Code. Submit it alongside the extracted bundle files.

---

## PROMPT TO SUBMIT:

I'm handing off a Commodore 64 assembly project for continued development. The bundle is a tarball (`c64-aes256-bundle.tar.gz`) containing the complete project. Please:

1. Extract the tarball to a new directory
2. Create a GitHub repo called `c64-aes256-ecdsa` and push the initial commit
3. Read this entire briefing before making any code changes

## PROJECT OVERVIEW

This is a ~11,400-line 6502 assembly program for the Commodore 64 that implements:
- AES-256-CBC encryption/decryption (fully working)
- AES-256-GCM-SIV authenticated encryption (fully working)
- SHA-256 hashing (fully working)
- HMAC-DRBG PRNG seeded from SID+CIA hardware entropy (fully working)
- REU (Ram Expansion Unit) support for large data (working, 2 known non-critical bugs)
- REU-to-disk save with multi-pass refill (working)
- CSR text-format generation via menu key J→1 (working)
- **ECDSA P-256 digital signature (IN PROGRESS — has a blocking bug)**

The program loads at $0801 and runs via `RUN` from BASIC. Menu-driven UI. Key J opens CSR/ECDSA sub-menu: option 1 = CSR generation, option 2 = ECDSA test vector.

## BUILD

NOTE: this project has since been cut over from ACME to the cc65 suite
(ca65/ld65) as its build toolchain; source now lives under `src/*.s`. The
build command below is kept for historical context only — see README.md
for the current build instructions.

```
ca65 -I src -o build/aes256keygen.o -l build/aes256keygen.lst src/main.s
ld65 -C build_ca65/linker.cfg -o build/aes256keygen.prg -Ln build/labels.txt -m build/aes256keygen.map build/aes256keygen.o
```

Or just `make`. Run with `make run` (launches VICE x64sc). Requires cc65 (ca65/ld65) and VICE emulator.

## FILE STRUCTURE

- `src/aes256keygen.asm` — Main program. Line 11416 includes ecdsa_p256.asm via `!source`
- `src/ecdsa_p256.asm` — ECDSA P-256 module (~2300 lines). Layers 1-5.
- `build/aes256keygen.prg` — Last compiled binary (28,141 bytes, loads $0801, ends $75EC)
- `build/labels.txt` — VICE-format label dump from last compile
- `test/` — OpenSSL verification files for RFC 6979 test vector
- `docs/ecdsa_plan.md` — Original implementation plan

## MEMORY LAYOUT

```
$0801-$75EC  Program code + data (28,141 bytes)
$75ED-$77FF  Gap (532 bytes free)
$7800-$79FF  Quarter-square multiply table low bytes (runtime-generated)
$7A00-$7BFF  Quarter-square multiply table high bytes (runtime-generated)
$7C00-$9FFF  Free RAM (9,215 bytes)
```

Quarter-square tables MUST stay at $7800. They are page-aligned for performance. `fp_init_sqtab` builds them at runtime before any ECDSA operations.

## ZERO-PAGE USAGE

See `src/zp_config.s` for the authoritative, single-source-of-truth
zero-page map.

All 256-bit values are BIG-ENDIAN (MSB at byte 0, LSB at byte 31).

## ECDSA ARCHITECTURE (5 layers)

### Layer 1 — 256-bit unsigned integer arithmetic (WORKING)
- `fp_init_sqtab` — Build quarter-square lookup table at $7800
- `fp_copy` — Copy 32 bytes via (fp_src1)→(fp_dst)
- `fp_zero` — Zero 32 bytes at (fp_dst)
- `fp_cmp` — Compare (fp_src1) vs (fp_src2). Carry set if src1≥src2
- `fp_add` — 256-bit add. Carry out in fp_carry
- `fp_sub` — 256-bit subtract. Borrow in fp_carry (1=borrow)
- `fp_is_zero` — Test if (fp_src1)==0. Z flag set if zero
- `fp_rshift1` — Right-shift (fp_src1) by 1 bit in place
- `fp_mul` — 256×256→512 multiply using quarter-square lookup. Result in fp_wide (64 bytes)
- `fp_chk_one` — Test if (fp_src1)==1. Z flag set if one

### Layer 2 — Modular arithmetic (WORKING except fp_mod_inv — see BUG)
- `fp_mod_add` — Modular addition mod (fp_misc)
- `fp_mod_sub` — Modular subtraction mod (fp_misc)
- `fp_mod_reduce` — Reduce 512-bit fp_wide mod (fp_misc) → fp_r0. Binary long division.
- `fp_mod_mul` — Modular multiply = fp_mul + fp_mod_reduce
- `fp_mod_inv` — Modular inverse via binary extended GCD. **HAS A BUG — SEE BELOW**

### Layer 3 — EC point operations (IMPLEMENTED, UNTESTED due to Layer 2 bug)
- `ec_point_double` — Jacobian doubling with a=-3 optimization (8 field multiplies)
- `ec_point_add` — Mixed Jacobian+affine addition (11 field multiplies)
- `ec_scalar_mul` — Double-and-add, 256 bits. Result in ec_p3 (Jacobian)
- `ec_jacobian_to_affine` — Convert via Z⁻¹ (calls fp_mod_inv)

### Layer 4 — ECDSA signing (IMPLEMENTED, UNTESTED)
- `ecdsa_sign` — Full ECDSA: k·G → (r,s)

### Layer 5 — Test runner (IMPLEMENTED, BLOCKED by bug)
- `do_ecdsa_test` — Runs RFC 6979 A.2.5 test vector with staged diagnostics

## THE BLOCKING BUG: fp_mod_inv infinite loop

### Symptoms
The ECDSA test (menu J→2) runs staged diagnostics:
- T1 (3×5 multiply) — **should work** (tests fp_mul)
- T2 (15 mod p) — **should work** (tests fp_mod_reduce)
- T3 (7⁻¹ mod p) — **HANGS** after printing 3 dots (~48 main-loop iterations)
- T4 (verification multiply) — never reached

### What we know
- The binary extended GCD algorithm is correct (Python simulation converges in 76 iterations for inv(7) mod p)
- A carry-loss bug was found and fixed: when computing `x += modulus; x >>= 1`, the carry from the addition must be shifted into bit 255 of the result. The fix uses inline ROR with fp_carry instead of calling fp_rshift1.
- Despite the fix, the function still hangs around iteration 48
- The current build has per-section debug characters: H (halving u), V (halving v), C (compare/subtract). The expected output is ~334 characters of mostly C's and V's. The actual output from the user's last test has not been reported yet.

### Key addresses (from build/labels.txt)
```
fp_mod_inv:  $6465
fp_inv_u:    $6656
fp_inv_v:    $6676
fp_inv_x1:   $6696
fp_inv_x2:   $66B6
fp_r0:       $66D6
fp_r1:       $66F6
fp_chk_one:  $6643
fp_rshift1:  $6229
fp_add:      $61F3
fp_sub:      $6206
fp_cmp:      $61E5
fp_mod_sub:  $6387
ec_p:        $6756
```

### Debugging approach for Claude Code
The most productive next step is to write a **bit-exact Python simulator** of fp_mod_inv that operates on 32-byte arrays with the same byte ordering, using the same sequence of operations as the 6502 code. Run it with input=7, modulus=ec_p. If the Python sim converges but the 6502 hangs, the bug is a subtle addressing/encoding error in the binary. If the Python sim also hangs, the bug is in the algorithm logic.

Specifically simulate:
1. `fp_rshift1` — shift 32 bytes right by 1 via (indirect),Y from byte 0→31 with CLC/ROR
2. The inline `@x1sh` shift — shift 32 bytes right by 1 via absolute,Y with carry from fp_carry
3. `fp_add` with aliased src1=dst — verify read-before-write safety
4. `fp_sub` — verify borrow/carry flag logic (result inverted via EOR #1)
5. `fp_mod_sub` — verify conditional add-back uses correct modulus from fp_misc
6. The full `@mainlp` loop with halfu/halfv/comp

Compare iteration-by-iteration u, v, x1, x2 values between Python and the known-good infinite-precision version.

## RFC 6979 A.2.5 TEST VECTOR (P-256/SHA-256, message="sample")

```
Private key d: C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
Nonce k:       A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
Message hash:  AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF
Expected r:    EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
Expected s:    F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
Public key Qx: 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
Public key Qy: 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
Known 2G.x:   7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
Known 2G.y:   07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1
```

Verified with OpenSSL: `openssl dgst -sha256 -verify test_pubkey.pem -signature test/test_sig.der test/test_msg.txt → Verified OK`

## P-256 CURVE PARAMETERS

```
p  (field prime): FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
n  (group order): FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
a  (coefficient):  FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC  (= p-3)
b  (coefficient):  5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx (generator):   6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy (generator):   4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
```

## EXISTING KNOWN BUGS (non-blocking)

(Bug 4 and Bug 5, formerly listed here, are fixed — see COMPLETED SINCE HANDOFF below.)

**Bug 6 — CSR field-selection/validation (discovered 2026-07-18):** `tools/run_all_tests.py`'s CSR (PKCS#10) suite fails 2 of 4 scenarios: a subject-field-selection issue and a missing "AT LEAST ONE FIELD REQUIRED"-style validation message on the all-empty-fields rejection path (menu J→1). Confirmed **pre-existing** — reproduced identically against the untouched pre-restructure binary (`build/aes256keygen.prg.original`), so it predates and is unrelated to the modular-restructure effort (`docs/modular_restructure_plan.md`). Not investigated further; root cause is in `src/csr.s`'s field-collection/validation logic, out of scope for a structural refactor. Logged here per that plan's own "no behavior changes" constraint.

**Bug 7 — HMAC-DRBG/ECDSA keygen timeout via PKCS#10 (discovered 2026-07-18):** `tools/run_all_tests.py`'s HMAC-DRBG (RFC 6979) suite (menu J→3, PKCS#10 CSR generation, which drives full ECDSA P-256 key generation) times out (~10 min via VICE warp). Also confirmed **pre-existing** by the same original-binary reproduction. Not investigated further — may be a genuine hang, or the harness's timeout may simply be too tight for this known-slow path (see "PERFORMANCE EXPECTATIONS" below); needs a maintainer decision on which.

**Bug 8 — possible dropped keypress on first `J` after the NIST self-test returns to the main menu (discovered 2026-07-20, during a c64-test-harness compatibility fix pass on `tools/test_csr.py`):** after running the on-device NIST self-test (menu `F`) and returning to the `Q=QUIT` main menu, a single `"J"` keypress is silently dropped — the screen does not change at all, even after a 5s settle delay — while the identical `"J"` keypress works instantly and reliably from a freshly-booted main menu. Sending an extra `"\r"` before `"J"` reliably "unsticks" it. Reproduced consistently across multiple runs with two independent transport implementations (both `ViceProcess`- and `ViceInstanceManager`-based), ruling out a test-harness-version artifact. **Not yet determined whether this is a genuine C64-side keyboard-buffer/timing issue in `main_loop.s`'s key-read loop after the NIST-test return path, or a VICE-emulation-specific quirk** — needs investigation before it can be classified as a real product bug or dismissed as environmental. Not investigated further as part of the harness-compat fix (out of scope for that task). See `docs/test_suite_audit.md` for the broader test-infrastructure findings from the same pass. Filed upstream as [c64-test-harness#138](https://github.com/JC-000/c64-test-harness/issues/138) since it's not yet known whether root cause lies in this project, VICE emulation, or the harness's transport timing — pending triage there.

## PERFORMANCE EXPECTATIONS

Once fp_mod_inv is fixed, the full ECDSA test vector signing will take approximately:
- **37-52 minutes on real hardware** (1 MHz 6502)
- **60-120 minutes in VICE** without warp mode
- **3-8 minutes in VICE with warp mode** (Alt+W)

The scalar multiply (256 point doubles + ~120 point adds) dominates runtime. Each point operation requires 8-11 modular multiplies. Each modular multiply does a 256×256→512 schoolbook multiply followed by 512-bit binary long division.

Future optimization: replace generic `fp_mod_reduce` with P-256-specific fast reduction (Solinas prime structure) for ~100× speedup on that routine alone. This would bring total signing time to ~3 minutes on real hardware.

## DO NOT MODIFY

- Any code in aes256keygen.asm above line 11416 (the `!source` directive). This is the stable AES/SHA/GCM/REU/CSR code.
- The quarter-square table address ($7800) or the big-endian byte ordering convention.
- The test vector data — these are from the RFC and verified against OpenSSL.

## COMPLETED SINCE HANDOFF

The following items have been implemented and are fully working:

1. **fp_mod_inv bug fixed** — carry-loss in binary extended GCD resolved
2. **ECDSA P-256 signing works** — RFC 6979 A.2.5 test vector passes (menu J→2)
3. **PKCS#10 CSR generation** (menu J→3) — DER/ASN.1 encoding, multi-block SHA-256, ECDSA signing, Base64/PEM output, disk save. New files: `der_encode.asm`, `base64.asm`, `pkcs10_build.asm`, `pkcs10.asm`
4. **HMAC-DRBG (RFC 6979)** — Deterministic nonce generation replaces SID+CIA random nonce for ECDSA signing. New file: `hmac_drbg.asm`. HMAC-DRBG data buffers added to `data.asm`.
5. **Test automation** — 9 unified suites (227 tests) via `run_all_tests.py`: SHA-256, AES-CBC encrypt/decrypt, POLYVAL, GCM-SIV encrypt/decrypt/roundtrip, CSR (PKCS#10), and HMAC-DRBG (RFC 6979). All direct-memory tests use `robust_jsr()` retry wrapper for VICE TCP resilience. Plus standalone scripts: `test_csr.py` (2 tests), `test_pkcs10.py` (1 test), `test_sha256.py` (10 tests), `test_aes_cbc.py` (10 tests), `test_aes_cbc_decrypt.py` (10 tests)
6. **LFSR→HMAC-DRBG migration** — Replaced 16-bit Galois LFSR PRNG with HMAC-DRBG (256-bit internal state, HMAC-SHA256) for all random byte generation. New routines in `hmac_drbg.asm`: `drbg_init_entropy` (SID+CIA entropy collection), `drbg_random_byte` (buffered single byte), `drbg_fill_bytes` (multi-byte fill). Removed `seed_lfsr`, `lfsr_random`, `generate_bytes`, `check_prng_reseed` from `prng.asm`; removed `multi_sid_random` from `sid_config.asm`; removed `lfsr_lo`/`lfsr_hi` from `data.asm`. After PKCS#10 CSR save, DRBG is reseeded from hardware entropy to restore non-deterministic state.
7. **Bug 4 fixed (REU fill progress counter stuck at 0)** — two independent root causes in `reu_advanced.asm`. (a) Cosmetic: `show_fill_progress` did a bare carriage return before reprinting, and CR always advances to a new screen row, so repeated updates scrolled a stack of progress lines instead of overwriting in place — fixed with a `reu_progress_row_set` flag that returns the cursor to the same row (CR + cursor-up `$91`) after the first update. (b) Real performance bug, the dominant cause of the "stuck" symptom: the random-fill path generated data via the full HMAC-DRBG (3 `hmac_sha256` calls = 12 SHA-256 block compressions, ~683 ms/block) every 32 bytes — about 256 ms/byte, meaning the KB counter would not visibly advance for minutes on a small REU and effectively never on a real one (~9+ hours projected for a 128 KB fill). Fixed by adding a cheap 16-bit Galois LFSR (`fast_random_byte`), seeded once per fill from the real HMAC-DRBG (`seed_fast_prng`), for REU bulk fill/wipe data — this is not key material, so a fast non-cryptographic generator is appropriate once cryptographically seeded. **Note for reviewers**: this reintroduces an LFSR after commit `338661e` deliberately removed the project's LFSR PRNG for cryptographic weakness in random *number generation for keys/nonces*; the reintroduction here is scoped strictly to REU bulk-fill wipe data, not key material, but merits explicit sign-off given that history.
8. **Bug 5 fixed (disk write silently succeeds on IEC write-timeout)** — `write_block_to_file` in `reu_advanced.asm` checked KERNAL STATUS ($90) once per 254-byte block via `AND #$80`, treating only "device not present" (bit 7) as fatal. Real KERNAL STATUS bit semantics (verified against C64-Wiki/sta.c64.org, not assumed) show bit 1 is the actual IEC write-timeout error bit — bit 6 is EOF (already used correctly elsewhere in this same file for directory reads). The in-source comment claiming "KERNAL chrout handles retries internally" was verified false. Fixed by widening the fatal mask to `AND #$82` (bits 7 and 1) and checking status after every byte instead of once per block. **Not verified against real 1541 hardware** (the U64E target used for hardware testing was unreachable in this environment) — only via VICE and KERNAL-bit-semantics reasoning; real-hardware validation of the actual "real 1541 vs. faster/more tolerant drive" scenario this bug describes is recommended before considering it fully closed.

## REMAINING FUTURE WORK

1. Consider P-256-specific fast reduction optimization (Solinas prime structure)
2. Strip debug output from ecdsa_test.asm if desired
3. **SHA-256 further optimization** — current ~683 ms/block vs Bumbershoot's ~360 ms. Remaining gap requires deeper changes: inlining JSR calls, unrolling 4-byte loops, self-modifying code. Circular W buffer (Step 5 in optimization plan) deferred — saves 192 bytes RAM but no speed benefit.
4. **Real-hardware validation of the Bug 5 fix** against an actual 1541 drive (not just VICE/emulated 1541) — see item 8 above.
5. **Committed regression tests for Bugs 4/5** — both fixes were verified via ad-hoc, uncommitted VICE scripts during development; neither has a permanent test in `tools/`.
