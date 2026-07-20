# c64-lib-contract alignment plan

**Status: COMPLETE (2026-07-20).** All four phases (A/B/C/D, covering SPEC
§1-6 and §8.0) landed and were independently re-verified by a second agent
in every case — not just implementer self-report. The entire round proved
**provably behavior-inert on the default build**: `build/aes256keygen.prg`
is byte-for-byte identical (confirmed via `cmp`) to its state immediately
before this round started, across every phase including the all-module
segment rename. Two new additive `make` targets exist (`make lib`, `make
lib-ecdsa-sign`) with zero effect on the default `make`/`make run` path.

**Real findings during execution, not just mechanical compliance work:**
- Phase D's dependency trace for `lib-ecdsa-sign` corrected this plan's own
  starting assumption that `hmac_drbg.s` belonged in the archive —
  `ecdsa_sign.s` itself has no import edge to it (RFC-6979 nonce
  derivation happens at the caller level, e.g. `pkcs10.s`, which imports
  both `hmac_drbg.s` and `ecdsa_sign.s` separately and wires `k` through
  `ecdsa_k_ptr`). `ecdsa_sign.s` is nonce-source-agnostic.
- Phase D also found and documented a real caveat rather than shipping a
  silently-broken minimal archive: `ecdsa_points.s`'s `ec_show_progress`
  and `ecdsa_mod.s`'s `fp_mod_inv` debug path both unconditionally call
  into `disk_io.s`/`display.s` print routines with no `.ifdef` guard, so
  `lib-ecdsa-sign.a` does NOT actually link standalone as packaged today —
  confirmed by an actual link attempt against a throwaway test file,
  reproduced independently by the verifier. Documented in the Makefile as
  a `CAVEAT` block with two remediation paths (link the full archive, or a
  future patch gating the debug prints behind a build flag).

**Goal (unchanged):** bring c64-aes256-ecdsa into full adopter
compliance with [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
SPEC.md v0.4.1, mirroring `c64-nist-curves` (the most fully-adopted
reference implementation). This is the trigger condition
`docs/modular_restructure_plan.md`'s "Deferred / out of scope" section
named for §4 segment prefixing and §6 build targets ("revisit if/when this
project itself becomes an adopter another consumer vendors") — the user has
now asked for exactly that. `c64-lib-contract`'s own README already lists
"future c64-aes256-ecdsa" as an anticipated adopter.

**Why this matters even before any actual vendoring happens:** a consumer
composing several vendored libraries needs its *own* ZP/REU/segment
allocations to already be contract-shaped, or every future vendoring pass
turns into ad-hoc collision surgery. This round is entirely internal
groundwork — no external library is vendored in this pass.

## Section-by-section status (SPEC.md §1-6, §8.0)

| § | What | Status before this round | Result |
|---|---|---|---|
| 1 | `LIB_VERSION_*` / `LIB_ABI_VERSION` | `LIB_VERSION_MAJOR/MINOR/PATCH` present; `LIB_ABI_VERSION` deferred | ✅ `LIB_ABI_VERSION = 0` added, matching `LIB_VERSION_MAJOR` |
| 2 | `.exportzp` ZP contract | `src/zp_config.s` existed, `.ifndef`-guarded, `.exportzp`'d | ✅ Audited, fully compliant, zero gaps, zero changes needed — see `docs/zp_contract_audit.md` |
| 3 | REU symbol contract | Not documented | ✅ N/A determination + forward-looking vendoring-risk note — see `docs/reu_contract_status.md` |
| 4 | `LIB_<X>_` segment naming | Bare `CODE`/`RODATA`/`DATA`/`BSS`/`HICODE` | ✅ Renamed to `LIB_AES256ECDSA_*` across all 34 modules + `linker.cfg`; proven byte-identical output via `cmp` |
| 5 | Aggregate manifest equates | None | ✅ `src/lib_manifest.s`: `ZP_USAGE_BYTES=36`, `REU_BANKS_USED=0`, `RESIDENT_BYTES=34300`, `COLD_BYTES=800` (the `do_ecdsa_test` diagnostic path) |
| 6 | Build target conventions | None | ✅ `make lib` (full archive, 303420B) + `make lib-ecdsa-sign` (46094B, minimal RFC-6979-sign object set) — see the plan's "real findings" note above for the caveat this uncovered |
| 8.0 | Precalc-table catch-loop | Not done | ✅ 5 tables enumerated (`sqtab` [§8.1 shareable], `aes_sbox`, `aes_inv_sbox`, `sha256_k`, `polyval_htable`) — `docs/precalc-tables.md` + `src/precalc_table.inc` (verbatim copy) + `src/precalc_manifest.s` |

**Segment prefix decision:** `LIB_AES256ECDSA_` (dropping the `c64-` repo
prefix and dashes, matching `c64-nist-curves` → `LIB_NISTCURVES_`).

## Execution plan

**Phase A (parallel, independent — dispatched as a team):**
- §1: add `LIB_ABI_VERSION` to `lib_version.s`.
- §2: audit `zp_config.s` against SPEC §2 for full compliance.
- §3: write the N/A determination + forward-looking REU note (a short doc, no code).
- §8.0: enumerate precalc tables, write `docs/precalc-tables.md`, copy `precalc_table.inc`, add `LIB_PRECALC_TABLE` invocations (new `src/precalc_manifest.s`).

These four are independent of each other and of §4/§5/§6 — safe to run
concurrently.

**Phase B (sequential, after A): §4 segment renaming.** Touches all 34
modules plus `linker.cfg`. Verified the same way Phase 5 batches were:
clean link + full test suite, since this is a mechanical rename (segment
string literals only, no export/import semantics change) but still
touches every file and the linker config.

**Phase C (after B): §5 manifest equates.** `RESIDENT_BYTES`/`COLD_BYTES`
need the final segment layout from B to classify meaningfully (unlike
`c64-nist-curves`, this app doesn't have a clean "boot-only init" cold
category — most of its ~29KB is genuinely hot application code, not a
library serving narrow verify/sign calls. `COLD_BYTES` may legitimately be
near-zero or this app's disk-I/O/UI/menu code, judgment call at execution
time).

**Phase D (after B): §6 build targets.** Have an agent propose minimal
`make lib-<variant>` boundaries by tracing `src/exports.inc`'s dependency
graph (already fully mapped from the modular restructure) rather than
hand-designing them — mirrors how `c64-nist-curves` derived
`lib-p256-verify` etc. from its own dependency structure.

**Out of scope for this round** (explicitly deferred, matching the
modular-restructure plan's own precedent of not over-scoping):
actually vendoring `c64-polyval`/`c64-nist-curves`; opening a PR against
`c64-lib-contract`'s own `adopters.md` to register this project (a
separate repo — flagged as a follow-up, not done automatically); §8
shared-primitive *promotion* itself (only the §8.0 catch-loop enumeration
is in scope, per the SPEC's own distinction between "enumerate" and
"promote").
