; =============================================================================
; c64-aes256-ecdsa library version constants (c64-lib-contract SPEC.md §1
; pattern, scoped down per docs/modular_restructure_plan.md Phase 3)
;
; LIB_ABI_VERSION now exists per docs/lib_contract_alignment_plan.md (§1
; alignment work) -- it matches LIB_VERSION_MAJOR per SPEC §7. The
; SHARED_PRIMITIVES bitmask (c64-lib-contract SPEC §5/§8) remains out of
; scope for this round; add it when a shared primitive is actually adopted.
;
; Versioning policy: semver 2.0.0 -- https://semver.org/
;   MAJOR — incompatible API changes (symbol removals, calling convention)
;   MINOR — additive API changes (new exports, no removals/renames)
;   PATCH — bugfix or perf improvement with no API change
;
; No git tags exist for this repo yet, so this starts at the first
; modular-restructure release, v0.1.0.
; =============================================================================

.segment "LIB_AES256ECDSA_CODE"

.export LIB_VERSION_MAJOR
.export LIB_VERSION_MINOR
.export LIB_VERSION_PATCH
.export LIB_ABI_VERSION

LIB_VERSION_MAJOR = 0
LIB_VERSION_MINOR = 1
LIB_VERSION_PATCH = 0

; Matches LIB_VERSION_MAJOR per SPEC §7. This project is pre-1.0, so per
; SPEC §9/§7 breaking changes happen freely with MINOR bumps until v1.0.
LIB_ABI_VERSION = 0
