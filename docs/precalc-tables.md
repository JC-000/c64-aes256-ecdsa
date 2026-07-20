# Precalculated tables — c64-aes256-ecdsa

This document enumerates every precalculated table shipped by
`c64-aes256-ecdsa` that meets the c64-lib-contract SPEC §8.0
("Catch loop: enumeration at adopter intake") floor:

- size ≥ 256 B, AND
- one of: REU-resident, hot-loop-read, or page-aligned.

The list below is **authoritative against the `LIB_PRECALC_TABLE` macro
invocations in `src/precalc_manifest.s`**. The two forms (this doc and
the macro invocations) MUST remain in lock-step — an asymmetry between
them blocks adopter PRs per the intake-reviewer rule in
c64-lib-contract `adopters.md` step 6. To re-audit:

```
od65 --dump-exports build/precalc_manifest.o | grep LIB_PRECALC
grep -n LIB_PRECALC_TABLE src/precalc_manifest.s
```

Both forms must enumerate the same set of `(name, size, region, shared)`
tuples. The doc captures the **rationale** field — which the macro
cannot — so a future audit run can mechanically judge whether each
classification still holds.

## Tables

| Name | Size (B) | Region | Source file | Classification | Rationale |
|---|---:|---|---|---|---|
| `sqtab` | 1024 | RAM | `src/ecdsa_fp.s` | Shareable (§8.1 normative) | Two 512-byte tables (`sqtab_lo` at `$7800`, `sqtab_hi` at `$7a00`) implementing the quarter-square identity `a*b = floor((a+b)^2/4) - floor((a-b)^2/4)`, built at runtime by `fp_init_sqtab` and read in `fp_mul`'s 32×32 inner byte-multiply loop — the hottest loop in this project's ECDSA field arithmetic. Page-aligned (`$7800`/`$7a00`) matching §8.1's page-alignment requirement, and shape-identical to the canonical `sqtab_lo`/`sqtab_hi` pair (512 B + 512 B, `floor(n^2/4)` recurrence, index 511 unused). This project does not yet implement the §8.1 placement contract (`LIB_SHARED_SQTAB_BASE`, the `.assert`s, or `mul_tables_init`) — that migration is out of scope for this round per `docs/lib_contract_alignment_plan.md`'s "Out of scope" section — but the table's *shape* already matches §8.1 exactly. It is named `"sqtab"` (not a project-prefixed variant) per SPEC §8.1's normative naming requirement, and is flagged a concrete future §8.1 promotion candidate: if `c64-nist-curves`' field-arithmetic modules are ever vendored in to replace this project's own `ecdsa_fp.s`, this table folds directly into that shared primitive with no shape change. |
| `aes_sbox` | 256 | RODATA | `src/tables.s` | Algorithm-specific (AES) | The FIPS-197 AES S-box, a static 256-byte literal table (16 rows of 16 `.byte`s) compiled into the PRG image (never written at runtime). Read per-byte inside SubBytes (`src/aes_encrypt.s`, e.g. line 396) on every AES round of every block encrypted, and again during key expansion (`SubWord`) — a genuine per-byte hot loop, called on every AES-256 block. Not shareable under any current §8.x clause: AES's S-box is a different primitive from `sqtab`/`reu_mul`/`ct_mul_8x8` (which are all quarter-square-multiply-family), and no c64-lib-contract adopter has yet had its AES S-box duplication confirmed across two or more sibling libraries. Speculatively marking it shared without a matching §8.x clause would violate the SPEC's own audit-trigger process (only listed here per the §8.0 catch-loop; not proposed for promotion). |
| `aes_inv_sbox` | 256 | RODATA | `src/tables.s` | Algorithm-specific (AES) | The FIPS-197 AES inverse S-box, same shape and provenance as `aes_sbox` above. Read per-byte inside InvSubBytes (`src/aes_decrypt.s` line 440) on every AES round of every block decrypted. Same non-shareable rationale as `aes_sbox`: distinct primitive family from the §8.x quarter-square-multiply primitives, no cross-adopter duplication evidence yet. |
| `sha256_k` | 256 | RODATA | `src/sha256.s` | Algorithm-specific (SHA-256) | FIPS 180-4 §4.2.2 K[64] round constants for the SHA-256 compression function — the first 32 bits of the fractional parts of the cube roots of the first 64 primes. 64 × 4 B, static literal table compiled into the PRG image. Read 4 bytes at a time inside `sha256_process_block`'s 64-round main compression loop (`@add_k`), once per round on every 64-byte block hashed — a genuine hot loop, since SHA-256 is used throughout this project's HMAC-DRBG, ECDSA signing, and CSR/PKCS#10 code paths. Could in principle be shared with a future SHA-256 sibling library (mirrors `c64-nist-curves`' `sha384_k` entry, which notes the identical situation for SHA-384/512's K table), but no second adopter with a byte-identical SHA-256 K table exists in this stack today. Promotion to a §8.x clause would require a second adopter and an audit-confirmed bit-identical table; not pursued in this round. |
| `polyval_htable` | 256 | RAM | `src/data.s` (buffer), `src/polyval.s` (`polyval_precompute_table` builds it, `polyval_xor_table_entry` reads it) | Algorithm-specific (POLYVAL / GCM-SIV) | RFC 8452 POLYVAL 4-bit nibble multiplication table: 16 entries × 16 bytes, built at runtime from the derived hash key `H` by `polyval_precompute_table`. Read inside `polyval_xor_table_entry`, called twice per input byte (once per nibble) from `polyval_multiply`'s 16-byte accumulator loop — 32 table reads per 128-bit POLYVAL block, the hot path of every GCM-SIV authentication/encryption operation. Not shareable under any current §8.x clause: no c64-lib-contract adopter in this stack implements GCM-SIV/POLYVAL, so there is no sibling library to have confirmed duplication against. Unlike `sqtab`, this table is keyed per-message (rebuilt whenever the GCM-SIV authentication key changes), which is itself a data point against a §8.1-style single-shape promotion — a future audit would need to confirm both the table *shape* and the *key-dependent rebuild semantics* match before treating it as a `sqtab`-style shared primitive. |

## Excluded (below floor or exempt by kind)

Noted here per SPEC §8.0's own example ("ChaCha20 quarter-round
constants... are correctly never §8.0-eligible") — these were
considered and excluded, not overlooked:

- **`aes_rcon`** (`src/tables.s`, 10 bytes) — AES key-schedule round
  constants. Fails the size floor outright (10 B ≪ 256 B); excluded
  regardless of its hot-loop read pattern during key expansion.
- **`expanded_key`** (`src/data.s`, 240 bytes — 15 round keys × 16
  bytes) — the live AES-256 round-key schedule, read per-byte every
  AES round. Fails the size floor by 16 bytes (240 B < 256 B). Also
  per-key derived state rather than a constant table, which would have
  been a second reason to exclude it even had it cleared the floor.
- **`gcmsiv_exp_enc_key`** / **`gcmsiv_saved_exp`** (`src/data.s`, 256
  bytes each) — save/restore scratch copies of `expanded_key` used by
  GCM-SIV's key-derivation flow (`src/gcm_siv.s`, `gcmsiv_install_enc_key`
  and friends) to swap the active AES key schedule in and out. These
  clear the 256 B size floor and are touched in AES's per-byte hot
  loop once installed into `expanded_key`, but they hold no
  precalculated *content* of their own — they are per-message,
  per-derived-key save/restore buffers, rebuilt from scratch on every
  GCM-SIV operation. This is exactly the "per-message scratch" category
  the SPEC's own floor commentary calls out as exempt regardless of
  size; enumerating them would dilute the catalog with duplicate-content
  copies of `expanded_key` rather than a genuine independent table.
- **`reu_zero_buffer`** (`src/reu_advanced.s`, 256 bytes) — an
  all-zeros staging buffer used as the DMA source for REU
  fill/wipe/benchmark operations. Clears the size floor and is
  REU-adjacent, but carries no precalculated content (it is simply
  zeroed once and reused); this project's REU usage is generic
  end-user fill/detect/save rather than a precompute cache (see
  `docs/lib_contract_alignment_plan.md` §3 status), so this buffer is
  exempt on the same "not actually a table" grounds as the GCM-SIV
  save/restore buffers above.

## Cross-reference

- `sqtab` is the only table here flagged `PRECALC_SHARED_YES`. This
  project does not yet export a `LIB_AES256ECDSA_SHARED_PRIMITIVES`
  manifest equate (SPEC §5) — that is deferred until the §8.1 placement
  contract itself is adopted (out of scope for this round; see
  `docs/lib_contract_alignment_plan.md`). When that migration happens,
  `LIB_AES256ECDSA_SHARED_PRIMITIVES` will OR in `LIB_SHARED_PRIMITIVES_SQTAB`
  (`$0001`) subject to the conditional `SHARED_SQTAB_INIT` mask
  construction required by SPEC §8.0.
- Tables flagged `PRECALC_SHARED_YES` here are the ones whose
  `LIB_PRECALC_<name>_*` exports cross-adopters can audit via
  `od65 --dump-exports build/precalc_manifest.o | grep LIB_PRECALC_<name>`.
  A byte-identical match across two or more adopters is a §8.x
  promotion candidate per the SPEC §8.0 audit triggers.
