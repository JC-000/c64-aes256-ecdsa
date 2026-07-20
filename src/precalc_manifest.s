.setcpu "6502"

; =============================================================================
; precalc_manifest.s - c64-aes256-ecdsa precalc-table enumeration
;                      (c64-lib-contract SPEC §8.0 catch-loop)
;
; SPEC §8.0 step-6 requires every adopter to enumerate its precalculated
; tables (size >= 256 B AND one of: REU-resident / hot-loop-read /
; page-aligned) in two forms:
;
;   1. Doc-level in `docs/precalc-tables.md` -- name, size, region,
;      source file, classification, rationale. The rationale field is
;      load-bearing for the cross-adopter audit.
;   2. Assembler-level via the `LIB_PRECALC_TABLE` ca65 macro, which
;      emits three exported equates per invocation
;      (`LIB_PRECALC_<name>_{SIZE,REGION,SHARED}`). Build-time discovery
;      via `od65 --dump-exports build/precalc_manifest.o | grep LIB_PRECALC`.
;
; Both forms are required; asymmetry between them blocks adopter PRs per
; the intake-reviewer-MUST rule in c64-lib-contract `adopters.md` step 6.
;
; Canonical-name discipline: the `name` argument is preserved verbatim by
; the macro (ca65 has no built-in toupper), and §8.1 makes one name
; normative -- "sqtab" MUST appear unprefixed so the cross-adopter audit
; `grep LIB_PRECALC_sqtab_SIZE` resolves the same symbol family across
; every adopter's archives. This project's `sqtab_lo`/`sqtab_hi` pair
; (src/ecdsa_fp.s) already matches §8.1's canonical shape (two 512-byte
; tables, floor(n^2/4) recurrence, page-aligned at $7800/$7a00), so it is
; enumerated as "sqtab" here rather than a project-prefixed variant, even
; though this project has not yet adopted the full §8.1 placement contract
; (LIB_SHARED_SQTAB_BASE / mul_tables_init) -- that migration is out of
; scope for this round per docs/lib_contract_alignment_plan.md.
;
; The remaining tables (`aes_sbox`, `aes_inv_sbox`, `sha256_k`,
; `polyval_htable`) are not §8.x-normative; their names follow
; lower_snake_case for grep-consistency with the normative entry but are
; otherwise local to this library. See docs/precalc-tables.md for the
; full rationale behind each classification, plus the excluded
; candidates (aes_rcon, expanded_key, gcmsiv_exp_enc_key/saved_exp,
; reu_zero_buffer) that were considered and did not qualify.
; =============================================================================

.segment "LIB_AES256ECDSA_CODE"

.include "precalc_table.inc"

LIB_PRECALC_TABLE "sqtab",          1024, PRECALC_REGION_RAM,    PRECALC_SHARED_YES
LIB_PRECALC_TABLE "aes_sbox",       256,  PRECALC_REGION_RODATA, PRECALC_SHARED_NO
LIB_PRECALC_TABLE "aes_inv_sbox",   256,  PRECALC_REGION_RODATA, PRECALC_SHARED_NO
LIB_PRECALC_TABLE "sha256_k",       256,  PRECALC_REGION_RODATA, PRECALC_SHARED_NO
LIB_PRECALC_TABLE "polyval_htable", 256,  PRECALC_REGION_RAM,    PRECALC_SHARED_NO
