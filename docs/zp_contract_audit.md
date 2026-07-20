# `src/zp_config.s` — c64-lib-contract SPEC §2 compliance audit

**Scope:** §2 "Zero-page contract" workstream of
`docs/lib_contract_alignment_plan.md`. Audit only — no rewrite. Reference
adopter compared against: `c64-nist-curves/src/zp_config.s` (SPEC-compliant
per that project's `adopters.md` row). SPEC version audited against:
`c64-lib-contract` SPEC.md v0.4.1, §2.

**Result: fully compliant. No gaps found, no code changes made to
`src/zp_config.s`.**

## Check 1 — every slot has both a `.ifndef` guard and an `.exportzp` entry

`grep`-derived authoritative slot list from the current file (23 slots,
`.ifndef`-guard names vs. `.exportzp`'d names, sorted and diffed):

```
kbd_buffer, zp_ptr, zp_temp, zp_count, zp_ptr2,
zp_round, zp_col, zp_tmp1, zp_tmp2, zp_tmp3, zp_tmp4,
sha_temp1, sha_temp2, sha256_round,
fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j,
ec_scalar_ptr
```

23 `.ifndef` guards, 23 `.exportzp` names — the two sets are identical
(byte-for-byte name match, no extras on either side). One apparent 24th
`.ifndef` hit from a naive `grep -oE '\.ifndef [a-zA-Z0-9_]+'` was a false
positive from the prose comment on line 12 ("Every slot is wrapped in
`.ifndef` so a future consumer...") — confirmed by re-grepping only actual
`.ifndef` statement lines (line-anchored), which returns exactly 23.

Each slot also follows the exact SPEC §2 pattern shape:

```asm
.ifndef <name>
  <name> = $<addr>
.endif
```

with the `.exportzp` lines grouped at the bottom of the file (four lines,
compliant with the "MUST publish them as `.exportzp`-ed equates" wording —
SPEC does not require one `.exportzp` per line).

**PASS** — no gap.

## Check 2 — naming convention (bare-role vs. project-specific prefix)

SPEC §2 states the convention as `<lib_prefix>_<role>`, lower-case, citing
`fp_src1`, `cc20_state`, `x25519_w_lo` as examples.

Read literally, `<lib_prefix>` might suggest each adopter should prefix
with its own project name (e.g. `aes256ecdsa_fp_src1`). Checked what the
reference adopter (`c64-nist-curves/src/zp_config.s`) actually does:

```
proc_port, zp_tmp1, zp_tmp2, zp_ptr1, zp_ptr2,
fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j,
ec_scalar_ptr,
sha_src, sha_len, sha_w_ptr, sha_w_ptr2,
poly_i, poly_j, poly_carry, poly_tmp
```

`c64-nist-curves` does **not** prefix with its own project name
("nistcurves_"). Its "`<lib_prefix>`" is read as the *role-family* prefix
(`fp_`, `sha_`, `poly_`, `zp_`, `ec_`) — i.e. the prefix disambiguates by
subsystem/role within a library, not by which library/project it came
from. The worked example in the SPEC text itself (`fp_src1`) is exactly
this project's `fp_src1` name, unprefixed by project.

`c64-aes256-ecdsa`'s `zp_config.s` uses the identical convention:
`fp_src1`/`fp_src2`/`fp_dst`/`fp_misc`/`fp_carry`/`fp_loop`/`fp_mul_i`/
`fp_mul_j` (role prefix `fp_`), `zp_ptr`/`zp_temp`/`zp_count`/`zp_ptr2`/
`zp_round`/`zp_col`/`zp_tmp1..4` (role prefix `zp_`), `sha_temp1`/
`sha_temp2`/`sha256_round` (role prefix `sha`), `ec_scalar_ptr` (role
prefix `ec_`), `kbd_buffer` (hardware-fixed, documented as such).

Since the reference adopter itself does not apply project-specific ZP-name
prefixes, this project matching that same bare-role convention **is**
correct compliance, not a gap.

**No rename performed** — renaming would break every already-linked
module's working symbol references across the recently-completed modular
restructure (34 modules), which is out of scope and high-risk for an audit
task, and per the above is not actually required by the SPEC as the
reference adopter interprets/implements it.

**PASS** — no gap; convention matches reference adopter exactly.

## Check 3 — `build_ca65/linker.cfg` ZP2/ZP3/ZP4 free-pool consistency

Re-confirmed (not re-derived from scratch — this was already verified once
during the modular restructure) that the three free-pool zero-page regions
`linker.cfg` exposes for consumer/future use are still an exact
complement of the 23 addresses `zp_config.s` claims, with no overlap
either way:

| Pool | Range | Size | Adjacent claimed slots |
|---|---|---|---|
| ZP2 | `$13`–`$21` | 15 B | preceded by `sha256_round` ($12), followed by `fp_src1` ($22) |
| ZP3 | `$2C`–`$38` | 13 B | preceded by `fp_loop` ($2B), followed by `fp_mul_i` ($39) |
| ZP4 | `$3D`–`$8F` | 83 B | preceded by `ec_scalar_ptr` ($3B), followed (far above) by `kbd_buffer` ($C6) |

Walked every claimed slot's address range (`zp_ptr2` $02–03 through
`kbd_buffer` $C6 and `zp_ptr`/`zp_temp`/`zp_count` $FB–$FE) against the
three pool ranges: no overlap in either direction. Pool boundaries land
exactly on the byte before/after the nearest claimed slot in all three
cases, matching `linker.cfg`'s own header comment
("$13-$21, $2C-$38, $3D-$8F"), which itself matches `zp_config.s`'s header
comment verbatim.

**PASS** — still consistent, no drift since the modular restructure.

## Build verification

```
cd /Users/someone/Documents/c64-aes256-ecdsa && make clean && make
```

Links cleanly (`ld65` completes with no errors; only pre-existing,
unrelated "Didn't use zeropage addressing" warnings from `base64.s` and
`csr.s`, not touched by this audit). No changes were made to
`src/zp_config.s`, so this run is a confirmation, not a regression check.

## Conclusion

`src/zp_config.s` is already fully compliant with SPEC §2 as implemented
by the reference adopter. No code changes required.
