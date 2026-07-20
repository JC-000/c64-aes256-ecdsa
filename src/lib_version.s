; =============================================================================
; c64-aes256-ecdsa library version constants (c64-lib-contract SPEC.md §1
; pattern, scoped down per docs/modular_restructure_plan.md Phase 3)
;
; These are internal / forward-looking only: this repo is not consumed by
; any external project yet, so there is no ABI to break. LIB_ABI_VERSION
; and the SHARED_PRIMITIVES bitmask (c64-lib-contract SPEC §5/§8) are
; deliberately NOT defined here -- both are meaningless until this repo
; actually ships to an external consumer, which is out of scope for the
; modular-restructure effort. Add them only when that day comes.
;
; Versioning policy: semver 2.0.0 -- https://semver.org/
;   MAJOR — incompatible API changes (symbol removals, calling convention)
;   MINOR — additive API changes (new exports, no removals/renames)
;   PATCH — bugfix or perf improvement with no API change
;
; No git tags exist for this repo yet, so this starts at the first
; modular-restructure release, v0.1.0.
; =============================================================================

.segment "CODE"

.export LIB_VERSION_MAJOR
.export LIB_VERSION_MINOR
.export LIB_VERSION_PATCH

LIB_VERSION_MAJOR = 0
LIB_VERSION_MINOR = 1
LIB_VERSION_PATCH = 0
