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

(Bug 4 and Bug 5, formerly listed here, are fixed — see COMPLETED SINCE HANDOFF below. Bugs 9 and 10 are also fixed but their entries are retained in place below, marked FIXED, because the buffer/channel detail they record is still worth reading; Bugs 6, 7, 8 and 11 remain open.)

**Bug 6 — CSR field-selection/validation (discovered 2026-07-18):** `tools/run_all_tests.py`'s CSR (PKCS#10) suite fails 2 of 4 scenarios: a subject-field-selection issue and a missing "AT LEAST ONE FIELD REQUIRED"-style validation message on the all-empty-fields rejection path (menu J→1). Confirmed **pre-existing** — reproduced identically against the untouched pre-restructure binary (`build/aes256keygen.prg.original`), so it predates and is unrelated to the modular-restructure effort (`docs/modular_restructure_plan.md`). Not investigated further; root cause is in `src/csr.s`'s field-collection/validation logic, out of scope for a structural refactor. Logged here per that plan's own "no behavior changes" constraint.

**Bug 7 — HMAC-DRBG/ECDSA keygen timeout via PKCS#10 (discovered 2026-07-18):** `tools/run_all_tests.py`'s HMAC-DRBG (RFC 6979) suite (menu J→3, PKCS#10 CSR generation, which drives full ECDSA P-256 key generation) times out (~10 min via VICE warp). Also confirmed **pre-existing** by the same original-binary reproduction. Not investigated further — may be a genuine hang, or the harness's timeout may simply be too tight for this known-slow path (see "PERFORMANCE EXPECTATIONS" below); needs a maintainer decision on which.

**Bug 8 — possible dropped keypress on first `J` after the NIST self-test returns to the main menu (discovered 2026-07-20, during a c64-test-harness compatibility fix pass on `tools/test_csr.py`):** after running the on-device NIST self-test (menu `F`) and returning to the `Q=QUIT` main menu, a single `"J"` keypress is silently dropped — the screen does not change at all, even after a 5s settle delay — while the identical `"J"` keypress works instantly and reliably from a freshly-booted main menu. Sending an extra `"\r"` before `"J"` reliably "unsticks" it. Reproduced consistently across multiple runs with two independent transport implementations (both `ViceProcess`- and `ViceInstanceManager`-based), ruling out a test-harness-version artifact. **Not yet determined whether this is a genuine C64-side keyboard-buffer/timing issue in `main_loop.s`'s key-read loop after the NIST-test return path, or a VICE-emulation-specific quirk** — needs investigation before it can be classified as a real product bug or dismissed as environmental. Not investigated further as part of the harness-compat fix (out of scope for that task). See `docs/test_suite_audit.md` for the broader test-infrastructure findings from the same pass. Filed upstream as [c64-test-harness#138](https://github.com/JC-000/c64-test-harness/issues/138) since it's not yet known whether root cause lies in this project, VICE emulation, or the harness's transport timing — pending triage there.

**Bug 9 — no upper-bound check on input length in either encryption path (discovered 2026-07-28, during the test-suite hardening round; FIXED 2026-07-28, verified live on VICE):** neither `encrypt_input` (`src/aes_encrypt.s:149`, AES-CBC) nor `gcmsiv_ctr_encrypt` (`src/gcm_siv.s:603`, GCM-SIV) validated its length byte against the capacity of its output buffer. The only length clamp lived in the interactive text-entry loops — `do_encrypt_text` (`src/aes_encrypt.s`, caps `input_index` at `input_buf_size-1` = 63) and `get_gcmsiv_input` (`src/gcm_siv.s`, caps `gcmsiv_pt_len` at 63) — so the UI path masked the problem completely. The direct-memory `jsr()` path used by the test harness (and by any future library consumer, per the `c64-lib-contract` work in `docs/`) writes `input_length` / `gcmsiv_pt_len` straight into the data segment and bypasses the clamp entirely; the encryption routines then overran into whatever `src/data.s` happens to place next. What used to happen:

- **AES-CBC** (`encrypt_buffer` = 80 bytes @ `$0A03`, `decrypt_data` = 64 bytes @ `$0A53`): output length is `block_count * 16` where `block_count = (input_length / 16) + 1` (PKCS#7), so overflow began at `input_length` ≥ 80. `len=64` produces exactly 80 bytes and fits the buffer exactly. `len=128` produced 144 bytes and deterministically clobbered all 64 bytes of `decrypt_data`. `len=200` (208 bytes) and `len=255` (16 blocks; note `encrypt_length` itself wraps to `$00`) additionally overwrote the loop-control bytes `block_count` (`$0A96`) and `current_block` (`$0A97`) while the block loop was still running, making the iteration count non-deterministic — it could terminate early, run long, or hang. `copy_block_to_state` also read past the 64-byte `input_buffer` for the same lengths.
- **GCM-SIV** (`gcmsiv_ct_buf` = 64 bytes @ `$0EF3`): the CTR loop writes `gcmsiv_ct_buf,x` for `x` in `0..gcmsiv_pt_len-1`, formerly with no cap. `pt_len=64` fills `gcmsiv_ct_buf` exactly. `pt_len` ≥ 65 clobbered `gcmsiv_dec_buf` (`$0F33`); ≥ 129 also clobbered `gcmsiv_tag` (`$0F73`); ≥ 209 walked through `gcmsiv_counter` and `gcmsiv_keystream`, corrupting the keystream mid-generation; and `pt_len=255` reached `gcmsiv_ct_idx` (`$0FE4`, = `gcmsiv_ct_buf+241`), corrupting the loop counter itself. Plaintext reads spilled out of `gcmsiv_pt_buf` past `gcmsiv_pt_len` into the ciphertext buffer being written.

**Status: FIXED — guards implemented in the routines themselves, so direct-memory callers cannot bypass them.** `src/constants.s` gained `gcmsiv_buf_size = 64` (exported alongside `input_buf_size`). The accepted maximum is now **64 for both paths**; anything longer is rejected up front, before any buffer is touched, with carry SET and nothing written (the success paths return carry CLEAR). Four guard sites:

- `encrypt_input` (`src/aes_encrypt.s:159`) rejects `input_length > input_buf_size`, and zeroes `block_count` and `encrypt_length` so no stale output length is left behind.
- `gcmsiv_encrypt` (`src/gcm_siv.s:234`) rejects `gcmsiv_pt_len > gcmsiv_buf_size` before key derivation, which also closes the POLYVAL over-read of the plaintext buffer.
- `gcmsiv_ctr_encrypt` (`src/gcm_siv.s:608`) repeats the same check rather than trusting its caller, because it is exported and called directly from `src/benchmark.s`.
- `gcmsiv_decrypt` (`src/gcm_siv.s:874`) guards the symmetric path (`gcmsiv_ctr_decrypt` plus the tag-recompute copy back into `gcmsiv_pt_buf`); rejected input leaves `gcmsiv_tag_valid = 0`, so a caller that only inspects the tag flag still sees a failed decrypt. **Note:** this decrypt guard was added defensively from code reading, *not* from an independently reproduced fault.

Verified on VICE: `tools/test_aes_cbc_direct.py` 51/51 and `tools/test_gcmsiv_encrypt_direct.py` 50/50. The boundary probes show `len`/`pt_len=64` accepted with full normal output (AES: `block_count=5`, `encrypt_length=80`), and 65/128/200/255 all rejected with the output buffer untouched, the adjacent buffer intact and the counters zeroed. No probe timed out, so the loop-control corruption and its hang path are gone. All five RFC 8452 C.2 vectors and the AES boundary cases (1/16/48/63) remain exact, so the guards caused no correctness regression. Both fault-injection tests were **rewritten to assert the guard** — they now fail if it regresses, replacing the earlier arrangement where they deliberately passed against the unguarded behavior. No assertion-flipping remains to be done.

**Bug 10 — REU save-to-disk writes screen status text into the open disk file (discovered 2026-07-28, by the first real run of `tools/test_reu.py` against VICE; FIXED 2026-07-28, verified on VICE):** the REU save path left logical file 2 — the open disk file — selected as the CHROUT output channel and never restored the screen channel before printing progress, so status messages were written *into the file*. `open_new_file` (`src/reu_advanced.s:987-988`) and `open_append_file` (`src/reu_advanced.s:1064-1065`) both end with `ldx #2 / jsr chkout` and return with that channel active, and no `clrchn` or screen-directed `chkout` used to sit between them and the print sites in the main write loop. Three things consequently went to disk instead of the screen: `reu_writing_msg` "WRITING TO DISK..." + CR (19 bytes); the every-16-blocks "PROGRESS: n OF m BLOCKS" line (~30 bytes per occurrence); and `rng_refilling_msg` "REFILLING REU (PASS n)..." (~27 bytes), which is printed *before* the branch's `close_save_file`.

Two consequences, and the second was fatal. (1) The saved RNG data was interleaved with ASCII status text, so the file was corrupt even where it was written. (2) The write loop stops after exactly `disk_free_lo`/`disk_free_hi` blocks, which by design fills the disk exactly — so the stray status bytes had nowhere to go. The drive returned error 72 DISK FULL on the final block, CHROUT timed out, `readst` reported ST(`$90`)=`$83` (bits 7, 1 and 0), `write_block_to_file`'s `AND #$82` fatal mask caught it and returned carry set, "WRITE ERROR!" was printed, and the file was never closed — so no directory entry landed and the save was lost entirely. This failed 100% of the time regardless of disk size. The visible tell was that "WRITING TO DISK..." never appeared on screen during a save.

Original evidence (reproduced identically across runs): `strings(1)` on the resulting D64 recovered both "WRITING TO DISK..." and "REFILLING REU (PASS 2)..."; the BAM showed 0 free blocks after every failed run; ST=`$83` confirmed at the failure point under a monitor breakpoint; reproduced in 4 configurations (512 KB / 128 KB REU × 73-free / 664-free empty disk); and VICE drive configuration was ruled out (identical failure under harness defaults, `-drive8truedrive`, and `+trapdevice8`). The IEC path itself was healthy — the free-block check reported correctly, and a 128 KB run wrote 516 blocks before its first refill — so only the channel accounting was broken.

**Status: FIXED.** Three `jsr clrchn` calls now precede the status-print sites in `src/reu_advanced.s`'s save loop: before `reu_writing_msg` (`:619`), before the refill message (`:650`), and before the progress block (`:708`). This is safe because `write_block_to_file` re-issues its own `ldx #2 / jsr chkout` at the top of every block (`src/reu_advanced.s:1318-1319`), so clearing the channel between blocks cannot break the write. Verified on VICE: "WRITING TO DISK", "PROGRESS", "REFILLING" and "PASS" are all **absent** from the saved D64 across 4 runs — their presence was the original smoking gun — while "WRITING TO DISK..." and "PROGRESS: n OF 73 BLOCKS" now render correctly on the C64 screen. The refill-branch site was verified separately by forcing that branch with a 128 KB REU on an empty 664-block disk, since scenario 3's 73-block budget never reaches it. `tools/test_reu.py` went from 29/31 to 31/32; the denominator grew because "save reports a block count" is nested inside the SAVE COMPLETE branch and only became reachable once the save succeeded.

**Nuance:** scenario 3 still fails one assertion, `saved file present on D64`. That is **Bug 11 below, not a Bug 10 regression** — the channel fix is complete and independently verified by the D64 string checks above, which no longer depend on the save succeeding end-to-end. Scenario 3 going fully green is now the signal that Bug 11 is closed, not Bug 10.

**Bug 11 — REU save off-by-one at the disk-full boundary, and a false "SAVE COMPLETE" report (discovered 2026-07-28 while verifying the Bug 10 fix, which had been masking it):** the write loop's bound is `blocks_written < disk_free` (`src/reu_advanced.s:632-640`), so it writes exactly `disk_free` full blocks. That is one too many. A 1541 allocates the *next* block whenever a buffer fills, because the current sector's link field has to point somewhere — so writing the 73rd block into 73 free blocks demands a 74th. The drive returns error 72 DISK FULL, abandons the file, and never finalizes the directory entry, leaving the D64 with an unclosed "splat" entry (type `$01`, bit 7 clear, name `REUSAVE`, blocks 0) that persists across a clean drive detach and a clean VICE exit. The BAM confirms free 73 → 0 with a 73-block data chain, and reading the drive error channel from BASIC after the save returns `72 DISK FULL 0 0`. Control experiment: aborting with SPACE at 28 blocks, short of the boundary, closed the file perfectly (type `$81` CLOSED, blocks 28, listed correctly), so `close_save_file` and the CHROUT path are healthy — only the boundary case breaks.

**The second half of this bug is arguably worse than the first.** `write_block_to_file` only tests ST bits `$82` — device-not-present and IEC timeout (`src/reu_advanced.s:1328`). Error 72 never appears in ST at all; it exists only on the drive's error channel, which the save path never reads. So the program printed "SAVE COMPLETE. 73 BLOCKS WRITTEN." for a save that had in fact **failed**. This false success is timing-dependent rather than universal: in a 664-block run the same boundary happened to trip ST and did print "WRITE ERROR!". A correct fix therefore needs *both* halves — bound the loop at `disk_free - 1`, **and** read the drive error channel before claiming success. Fixing only the off-by-one would leave the program still able to report success for an unrelated drive-side failure.

**Status: OPEN.** Regression coverage is `tools/test_reu.py` scenario 3's `saved file present on D64` assertion, which fails on this today. Same polarity as Bug 10: it asserts the correct behavior and will go green when the bug is fixed, so no assertion-flipping is needed.

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
6. **Fix the six benign "Didn't use zeropage addressing" ca65 warnings** — file-local `sym = zp_...` equates in `src/base64.s` (`b64_ws_ptr`) and `src/csr.s` (`csr_ws_lo/hi`, `csr_wf_lo/hi`, `csr_field_ptr`) are defined after their first use, so ca65 emits absolute addressing (harmless: same byte reached, 1 extra byte + 1 cycle per site). Move each equate above its first use. NOTE: this is a real binary change (instructions shrink, addresses shift), so it needs a full test-suite run — until then these six exact warnings are allowlisted in `tools/run_all_tests.py`'s `build()` warning gate; remove the allowlist in the same change. (This was item 8 before Bugs 9 and 10 were fixed and their items removed; `tools/run_all_tests.py`'s `build()` comment still refers to it as "future work item 8" and needs updating to item 6.)
7. **Fix Bug 11 (REU save disk-full boundary)** — bound the write loop at `disk_free - 1` instead of `disk_free`, *and* read the drive error channel before reporting "SAVE COMPLETE", since error 72 never reaches ST and the program can otherwise claim success for a failed save. Both halves are needed. Verification is `tools/test_reu.py` scenario 3 going fully green; no test changes required.
8. **Make `tools/test_aes_cbc_direct.py` and `tools/test_gcmsiv_encrypt_direct.py` honour `C64_SKIP_BUILD` and `C64_PORT_RANGE_START`** — today both unconditionally run `make clean && make` (`test_aes_cbc_direct.py:493-494`, `test_gcmsiv_encrypt_direct.py:532-533`) and hard-code the default port range, so running either standalone destroys build artifacts other tests are using and collides with concurrent runs. Follow the existing patterns: `C64_SKIP_BUILD=1` is handled by `tools/run_all_tests.py:153`, and `C64_PORT_RANGE_START` by `tools/test_disk_io.py:59` and `tools/test_reu.py:63` (note those two never build at all, so neither is a complete template on its own).
