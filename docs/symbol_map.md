# Symbol Map — Phase 0 Deliverable for Modular Restructure

**Superseded by `src/exports.inc` as of Phase 4 — see that file for the
current, authoritative module dependency map.** This file is kept for its
narrative anomaly writeups (sections A-D below) which `exports.inc`
summarizes but doesn't reproduce in full. The per-file EXPORTS/IMPORTS
listings, the zero-page equate inventory, and the suggested Phase 5
conversion order that used to live in this file have all been superseded
by `src/exports.inc` (which also corrects the zero-page entries for
Phase 1's move of every ZP equate into `src/zp_config.s`, and adds entries
for `src/zp_config.s` and `src/lib_version.s` — two modules that didn't
exist when this file was written) — do not use this file for those.

---

## Cross-check anomalies

**Result: zero dangling `imports_from_modules` references.** Every symbol
named in every file's `imports_from_modules` block was found, verbatim, in
the claimed target module's own `exports` list. There are no typos, no
symbols that don't exist, and no agent that missed adding a genuinely-used
symbol to its own exports list. This is a clean bill of health for the
"does the claimed edge actually exist" check.

That said, three related categories of finding surfaced during
verification and are flagged here because they affect what `.export`/
`.import` statements Phase 5 actually needs to write:

### A. Harness-only exports (not inter-module edges — do not drop them)

These symbols carry (or need) an `.export` purely because
`tools/run_all_tests.py`'s `ALL_REQUIRED_LABELS` / direct `jsr(labels[...])`
calls the Python test harness make reach into them directly. No other
`src/*.s` file references them, so they are correctly *excluded* from the
per-file exports lists below (per the strict "only export if another `.s`
file references it" rule), but a naive Phase 5 pass that drops "unused"
`.export` lines will silently break the test harness:

- `aes_decrypt.s`: `decrypt_buffer`
- `aes_encrypt.s`: `encrypt_input`
- `gcm_siv.s`: `gcmsiv_encrypt`, `gcmsiv_decrypt`
- `sha256.s`: `sha256_update`
- `pkcs10.s`: `pkcs10_privkey`, `pkcs10_k_buf`
- `polyval.s`: `polyval_double`, `polyval_right_shift_1`,
  `polyval_shift_left_4`, `polyval_multiply`, `polyval_xor_table_entry`,
  `pv_mul_nibble`

**Action for Phase 5:** keep `.export` on all of these in their home module
regardless of in-repo importer count; do not treat "no `src/*.s` caller" as
grounds for removal.

### B. Layering smells that *are* the root cause of the big circular group

Two low-level print helpers are homed in `sid_config.s` (a SID/audio-config
module) instead of `display.s`/`disk_io.s`, and this single placement
decision is what turns the dependency graph in section 3 below into an
8-module strongly-connected component:

- `print_hex_digit` — called by `display.s`'s `print_hex_byte`, but defined
  in `sid_config.s`. Creates `display.s → sid_config.s`.
- `print_decimal_word` — called by `reu_core.s` and `reu_advanced.s`, but
  defined in `sid_config.s`. Creates `reu_core.s → sid_config.s` and
  `reu_advanced.s → sid_config.s`.

Combined with `sid_config.s`'s own genuine need for `disk_io.s::get_input_line`
and `hmac_drbg.s::drbg_random_byte`, and `disk_io.s`/`hmac_drbg.s` (via
`sha256.s`) each needing `display.s` back, these two misplaced routines are
sufficient to close a cycle across `{display.s, sid_config.s, disk_io.s,
reu_advanced.s, reu_core.s, hmac_drbg.s, sha256.s, aes_encrypt.s}` — see
section 3. **Relocating `print_hex_digit` and `print_decimal_word` into
`display.s` before Phase 5 would break this cycle entirely** and is the
single highest-leverage cleanup available before the module split.

### C. Cross-file dependencies filed under `imports_data` instead of `imports_from_modules`

These are genuine, verified-correct cross-module data dependencies (the
target symbol does exist in the named file), but the originating agent
classified them as plain data imports rather than routine imports, so they
don't show up in the `imports_from_modules` grouping used for the dependency
graph. Confirmed all resolve correctly; listed here so Phase 5's `.import`
generation doesn't miss them by only scanning `imports_from_modules` blocks:

- `ecdsa_test.s` imports `fp_r0`/`fp_r1`/`fp_r2` from `ecdsa_mod.s`;
  `ecdsa_hash_ptr`/`ecdsa_privkey_ptr`/`ecdsa_k_ptr`/`ecdsa_sig_r`/`ecdsa_sig_s`
  from `ecdsa_sign.s`; `ecdsa_test_hash`/`ecdsa_test_privkey`/`ecdsa_test_k`/
  `ecdsa_test_r`/`ecdsa_test_s` from `ecdsa_curve.s`; `fp_wide` from
  `ecdsa_fp.s`.
- `pkcs10_build.s` imports `pkcs10_pubkey_x`/`pkcs10_pubkey_y` from
  `pkcs10.s`; `ecdsa_sig_r`/`ecdsa_sig_s` from `ecdsa_sign.s`.
- `reu_advanced.s` imports `reu_banks` from `reu_core.s`.

### D. Same-content duplicate strings (not a broken link, a consolidation opportunity)

`debug_strings.s` defines two label pairs with identical text consumed by
different files: `debug_blk_msg`/`dbg_blocks_msg` (both `"BLOCKS: "`, consumed
by `aes_decrypt.s` and `aes_encrypt.s` respectively) and
`debug_len_msg`/`dbg_enclen_msg` (both `"ENC LEN: "`, same split). Not a
build-breakage risk, just worth collapsing into one shared export during the
split.

**Anomaly tally: 0 dangling/mismatched imports_from_modules edges; 6 harness-only export groups to preserve; 2 layering smells causing the circular group; 3 miscategorized-but-valid import groups; 1 duplicate-string pair.**
