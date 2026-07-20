# Modular restructuring plan (contract shape, no external vendoring)

**Status:** proposed, not started.
**Scope:** give this repo the same internal shape `c64-lib-contract` adopters
use (`zp_config.s`, real multi-object build, consumer-overridable ZP,
documented export surface) *without* vendoring `c64-polyval` /
`c64-nist-curves` yet. That de-duplication is real and worth doing later
(see [Deferred](#deferred-out-of-scope-for-this-plan)), but it's a second,
independent project — pulling it in now would force every phase below to
also solve "what happens when this symbol comes from a submodule instead of
a local file," which roughly doubles the risk surface for no benefit until
the local shape is already sound.

## Why this is worth doing even without vendoring

Today `src/main.s` is a single `.include` chain — 32 files, one `.o`
(`build/aes256keygen.o`), zero real linker-level separation. The 13 stray
`.export`s in the tree are inert: in a one-translation-unit build every
label is already globally visible, so nothing is actually being *hidden or
declared*. Concretely:

- The zero-page map is defined in three different places with no single
  source of truth: `src/constants.s:62-74`, `src/ecdsa_fp.s:13-22`, and one
  stray equate in `src/ecdsa_points.s:726`. `HANDOFF.md`'s "zero-page usage"
  table is a fourth, hand-maintained copy of the same information. There is
  no mechanism that catches a new module claiming an address one of these
  three files already uses — it would silently corrupt state at runtime,
  exactly the class of bug `c64-lib-contract` §2 exists to convert into an
  assemble-time error.
- `linker.cfg` already gestures at the target shape (it carves out `ZP2`
  `ZP3` `ZP4` as named free-byte pools, per its own header comment "so
  future ca65 code can allocate zero page without colliding") but nothing
  in `src/*.s` actually claims ZP through that mechanism — the equates are
  hardcoded, not `.ifndef`-guarded, not `.exportzp`. The linker config was
  set up for a contract that the source never adopted.
- There is no way to answer "does module A depend on module B" other than
  reading both files, because nothing declares it. That's the actual
  blocker for eventually vendoring `c64-polyval`/`c64-nist-curves` — you
  can't cleanly delete `ecdsa_fp.s` in favor of an external `fp256.s` until
  you know, with certainty, every internal caller of `fp_copy`/`fp_mod_mul`/etc.

None of this requires an external library to fix. It's the prerequisite for
being able to *safely consider* one later.

## Constraints carried through every phase

- **Byte-identical output is the safety net.** `make verify` already
  compares against `build/aes256keygen.prg.original`; keep that working (or
  add an equivalent snapshot before Phase 1) and re-run it after every
  module conversion, not just at the end. A ca65 multi-object build is not
  guaranteed to place bytes identically to a single-TU `.include` chain
  (link order now determines placement instead of textual order), so
  "binary identical" is the wrong bar past Phase 5 start — see that phase
  for the real bar.
- **The full Python suite (`tools/run_all_tests.py`, ~227 tests across 9
  suites) must pass after every phase**, not just at the end. This project
  has a recent, still-fresh history of subtle correctness bugs surviving
  partial verification (`HANDOFF.md`'s fp_mod_inv carry-loss bug, Bug 4/Bug
  5) — cheap to re-run, expensive to debug three phases later.
- **Module include/link order is load-bearing.** The quarter-square table
  at `$7800` (`sqtab_lo`/`sqtab_hi`, runtime-built by `fp_init_sqtab`) and
  the `HICODE` cutover at `$7C00` (PKCS#10/ECDSA-test modules) both depend
  on what comes before them in the binary. `linker.cfg`'s `MAIN`/`QSTAB`/
  `HIMEM` regions already encode the address constraints; the *order
  within* `MAIN` and `HIMEM` must still match `src/main.s`'s current
  `.include` order until proven otherwise, because nothing has verified
  those modules are order-independent.
- **No behavior changes.** This is a structural refactor. Any bug found
  along the way (e.g. Bug 4/5-class issues) gets logged, not fixed inline —
  mixing "restructure" and "fix" diffs makes both harder to review and
  impossible to bisect.

## Phase 0 — Symbol map (inventory, no source changes)

Deliverable: `docs/symbol_map.md`, one entry per `src/*.s` file, in the
shape of `c64-nist-curves/src/exports.inc` (see that file for the exact
format this project should copy):

```
; module.s
; EXPORTS: <every label other files reference>
; IMPORTS:
;   ZP: <zero-page symbols read/written from elsewhere>
;   data: <BSS/data labels from data.s/tables.s consumed here>
;   constants: <hardware/KERNAL equates from constants.s used here>
;   <other-module>: <routines called there>
```

Build this mechanically, not by hand-reading 13,900 lines: for each file,
`grep` every label it *defines* (`^[a-z_][a-z0-9_]*:`), then grep the rest
of `src/*.s` for references to each label to find its consumers. A short
throwaway Python script under `tools/` can do the cross-reference and emit
a first draft; a human pass then fills in the ZP/constants imports (harder
to detect mechanically since they're bare equate references, not calls).

This map is the actual deliverable of Phase 0 — everything after this
phase is mechanical work *driven by* the map, not independent judgment
calls about what depends on what. It also directly produces:

- The **leaf-module list** (files with no internal imports — expected to
  include `constants.s`, `data.s`, `tables.s`, `strings.s`, `debug_strings.s`,
  `boot.s`'s data literals) that Phase 5 converts first.
- The **duplicate-ZP-claim list** that Phase 1 must reconcile (already know
  of one: `ecdsa_fp.s`'s `fp_*` block vs. `constants.s`'s `zp_*` block don't
  collide today, but nothing enforces that going forward).

## Phase 1 — `src/zp_config.s`

Follow `c64-nist-curves/src/zp_config.s` exactly: one file, every ZP slot
`.ifndef`-guarded, `.exportzp`'d at the bottom, grouped by subsystem with a
comment banner (SHA temps / AES temps / fp_* field-arithmetic / general
pointers). Concretely:

1. Move every bare `= $XX` ZP equate out of `constants.s` (lines 62-74),
   `ecdsa_fp.s` (lines 13-22), and `ecdsa_points.s` (line 726) into
   `zp_config.s`, preserving the current addresses exactly (no relocation
   in this phase — that's a separate, riskier change).
2. Wrap each in `.ifndef <name> / <name> = $addr / .endif` and add the
   `.exportzp` block.
3. Delete the originals; `.include "zp_config.s"` once from `main.s`.

   **Correction (verified experimentally, 2026-07-18, same root cause as
   the Phase 5 finding above): do NOT add `.importzp <name>` to every
   consuming file in this phase.** `.importzp` hits the identical ca65
   restriction as `.import` — hard error (`Symbol 'X' is already
   defined`) the moment a file `.importzp`s a symbol that's also
   `.exportzp`-defined elsewhere in the same single-TU `.include` chain.
   Consumers keep working unmodified in this phase purely because ca65
   already gives every `.include`d file global visibility of every label,
   the same mechanism that lets the 13 existing stray `.export`s do
   nothing today. Adding real `.importzp` lines to a consumer is Phase 5's
   job (done together with that module's own conversion, via the
   `remainder.s` mechanism described there) — not this phase's. This
   phase only *centralizes and exports* the definitions; it does not wire
   up any importer.
4. Fold `HANDOFF.md`'s "ZERO-PAGE USAGE" table and `linker.cfg`'s
   "occupancy map" comment into a single generated-from-`zp_config.s`
   source of truth — pick one of the two doc locations to keep and point
   the other at it, so there is exactly one hand-maintained copy left
   (`zp_config.s` itself; both docs become "see zp_config.s").

Verification: `make verify` (byte-identical — this phase changes no
addresses, only where they're declared) + full test suite.

## Phase 2 — `linker.cfg` rework to the consumer-override shape

Current `linker.cfg` already has the right `MEMORY{}` shape (`ZP2`/`ZP3`/
`ZP4` free pools alongside `MAIN`/`QSTAB`/`HIMEM`) — it just doesn't yet
receive anything from a real `.exportzp` contract. Once Phase 1 lands:

1. Confirm the `SEGMENTS{}` block's `ZEROPAGE: load = ZP4` /
   `ZP2: load = ZP2` / `ZP3: load = ZP3` targets line up with where
   `zp_config.s`'s `.exportzp`'d symbols actually land — they should,
   since Phase 1 didn't move addresses, but this is the point where a
   mismatch would first become *visible* (ld65 placement error) rather
   than silently wrong.
2. Update the header comment's "occupancy map" to say "see
   `src/zp_config.s`" instead of hand-duplicating the address table (per
   Phase 1 step 4).
3. Leave address assignment exactly as-is. Do **not** use this phase to
   also relocate slots into the free `ZP2`/`ZP3`/`ZP4` pools — that's a
   legitimate future cleanup (some of the current fixed slots could
   probably be freed up) but it's an address change, which is exactly the
   kind of thing that should happen in its own reviewable, single-purpose
   commit with its own test run, not bundled into a structural phase.

Verification: `make verify` (still byte-identical) + full test suite.

## Phase 3 — `lib_version.s` / manifest (internal, low-risk, additive)

Even though this repo isn't being consumed by anything yet, add
`src/lib_version.s` (`LIB_VERSION_MAJOR/MINOR/PATCH`, no `LIB_ABI_VERSION`
claim until there's an actual external ABI to version) now rather than
later, for two reasons: it's zero-risk (pure new equates, nothing to
break), and it gives Phases 4-5 a natural place to record the manifest
numbers (`ZP_USAGE_BYTES`, `RESIDENT_BYTES`) that fall out of the
multi-object conversion for free once `build/labels.txt` reflects real
per-module boundaries. Skip `LIB_ABI_VERSION` and the `SHARED_PRIMITIVES`
bitmask (`c64-lib-contract` SPEC §5/§8) entirely — those are meaningless
until this repo actually ships to a consumer, which is explicitly out of
scope here.

## Phase 4 — Author `src/exports.inc`

Promote the Phase 0 symbol map from a docs-only artifact to the
`c64-nist-curves`-style `src/exports.inc` that ships alongside the source
and is the checklist Phase 5 works off directly, module by module, marking
each one done as its `.export`/`.import` lines land in the real source
file (Phase 0's `docs/symbol_map.md` can then be deleted or reduced to a
pointer at this file — same "one source of truth" principle as Phase 1).

## Phase 5 — Multi-object conversion (the big phase, done incrementally)

**Revision history on this phase, both found by direct ca65 experimentation
before delegating any work, in case a future reader wonders why this
section doesn't match its own earlier drafts:**

- *First draft* assumed `.export`/`.import` were both no-ops in the
  existing single-TU `.include` build, so modules could gain real
  `.export`/`.import` lines one at a time with the monolithic `make` build
  staying green as a safety net throughout. Wrong: `.export` is a no-op,
  but `.import` of a symbol also `.include`-defined in the same
  translation unit is a hard ca65 error (`Symbol 'X' is already defined`).
- *Second draft* (the "correction" below in older versions of this
  section) tried to preserve the single-TU safety net anyway by
  introducing `src/remainder.s` and having `main.s` `.include` it
  alongside individually-`.include`d converted modules. Also wrong, for
  the same underlying reason: `.include` is pure text substitution with
  no scope boundary, so nesting the not-yet-converted modules one level
  deeper via a second file changes nothing — ca65 still sees one flat
  token stream, and a converted module's `.import` still collides with
  the still-present textual definition inside `remainder.s`. Verified
  experimentally: a minimal repro (`user.s` importing `my_symbol`,
  `remainder.s` defining it, both `.include`d from `top.s`) reproduces the
  identical error at `remainder.s`, not `user.s`.
- **Current design (validated end-to-end, 2026-07-18):** the only way
  `.import` actually works is across a *real* translation-unit boundary —
  i.e. `remainder.s` must be its own top-level file, assembled with its
  own standalone `ca65` invocation into its own `remainder.o`, linked via
  `ld65` alongside every already-converted module's `.o`. This means real
  multi-object linking starts with the *first* converted module, not a
  deferred "final cutover" — there is no way to keep the current single
  monolithic `.o` build working as a safety net once even one module goes
  real. Confirmed working with a minimal 5-file prototype (`zp_config.o`
  exporting a ZP equate via `.exportzp`, `mod_a.o` importing it and
  exporting a routine, `remainder.o` importing *both* the ZP equate and
  `mod_a`'s routine — modeling a not-yet-converted module that depends on
  a new leaf *and* an already-extracted sibling — plus a `main.o` calling
  into `remainder.o`, all linked successfully into a working `.prg` via a
  minimal `ld65` config).

**Consequence for the verification bar:** `make verify` byte-identical
output is **not achievable past this point**, not even for the first
converted module. `ld65` linking multiple objects does not reproduce the
exact byte layout of a single monolithic `.o` compiled from one big
`.include` chain, and — separately — converting modules in dependency-safe
order (leaf-first, per `exports.inc`'s "Suggested Phase 5 conversion
order") does not match their *original textual position* in `main.s`
(e.g. `data.s` was originally included ~15th but is dependency-safe to
convert ~4th), so extraction itself reorders binary content regardless of
linking mechanics. This mirrors what already happened with the
print-relocation cleanup (task #31): once real code movement/extraction
starts, the verification bar shifts from `make verify` to the full
functional test suite. Given each real VICE-backed test-suite run costs
several minutes to tens of minutes, **convert in risk-ordered batches (a
handful of modules at a time) and verify once per batch**, not once per
module — running the full suite 32 times would be prohibitively slow for
no extra safety margin over batching.

### Mechanics

1. Create `src/remainder.s`: a new top-level file containing the exact
   `.include` chain of every module *not yet* converted, in their
   original relative order (initially: everything `main.s` currently
   `.include`s except `constants.s`/`zp_config.s`/`lib_version.s`, which
   stay directly in `main.s` since nothing about them needs to change
   here). Preserve the `HICODE` segment switch inside `remainder.s` at the
   same point it currently occurs in `main.s`, for whichever modules
   haven't been extracted out of that region yet.
2. Add a small, centrally-maintained header block at the top of
   `remainder.s` (before its `.include` chain) with:
   - `.importzp`/`.import` for every symbol any module *still inside*
     `remainder.s` references that now lives in an *already-converted*
     module (e.g. once `data.s` is extracted, anything still in
     `remainder.s` that reads `iv_data` needs `.import iv_data` added
     here — once, centrally, not by editing every individual pending
     file that happens to reference it).
   - `.export` for every symbol defined by a module *still inside*
     `remainder.s` that an *already-converted* module needs to reference
     (e.g. `prng.s`, once extracted, needs `extra_sid_count` from
     `sid_config.s`, which stays in `remainder.s` for a long time — add
     `.export extra_sid_count` etc. to this header, sourced from
     `sid_config.s`'s existing bare labels, no edit to `sid_config.s`
     itself needed until *it* gets extracted).
   This header is the only thing that changes in `remainder.s` beyond
   shrinking its `.include` list — individual not-yet-converted source
   files are never touched until it's their own turn.
3. For each module being converted in the current batch: add `.export`
   lines for what `exports.inc` says other modules need from it, and
   `.import`/`.importzp` lines for what it needs from elsewhere (whether
   that's `zp_config.s`, another already-converted module, or — via the
   header above — something still in `remainder.o`). Compile it standalone
   (`ca65 -I src -o build/<module>.o src/<module>.s`) to confirm it
   assembles cleanly on its own.
4. Remove the batch's modules from `remainder.s`'s `.include` chain.
5. Build `remainder.o` (`ca65 -I src -o build/remainder.o
   src/remainder.s`) and every converted module's `.o`, then link with
   `ld65 -C build_ca65/linker.cfg -o build/aes256keygen.prg
   build/main.o build/remainder.o <converted module .o's...>` (object
   order on the command line affects layout within a shared segment but
   not correctness — see the Constraints section on `$7800`/`$7C00`
   placement, which is enforced by the linker config's segment/address
   rules regardless of which object contributes to a segment).
6. Run the full test suite (batched, not per-module — see above). A
   `make verify` byte-diff is expected and not itself a failure signal;
   the test suite is the real bar from this point forward.
7. Once `remainder.s`'s `.include` list is empty (every module converted),
   delete it, replace `main.s`'s role with a real `MODULES` list in the
   Makefile (mirror `c64-nist-curves/Makefile`'s pattern — `SRC_DIR`/
   `MODULES`/pattern rule for `%.o` from `%.s`), and `main.s` shrinks to
   just the `LOADADDR` segment stub (consider splitting that into its own
   `src/loadaddr.s` per `c64-https`/`c64-wireguard`'s convention).

Final verification at that last cutover: full test suite pass plus a
manual `build/labels.txt` diff review to confirm no symbol silently moved
to an unexpected address (re-check `$7800` sqtab and the `HICODE` `$7C00`
cutover explicitly).

## Phase 6 — Makefile cleanup

Once Phase 5 is complete, `Makefile` no longer needs the
`ca65 -I src -o ... src/main.s` single-invocation form at all — replace it
with the per-module pattern rule + link step from Phase 5 step 5
permanently, matching `c64-nist-curves/Makefile`'s shape (including
`build/%.o: src/%.s` pattern rule, keeping `run`/`clean`/`verify` targets).
**In practice this happened incrementally, for free, as a side effect of
Phase 5's own batches** — the `MODULES`/pattern-rule Makefile shape was
already in place from batch 1 onward, so by the time Phase 5's final batch
landed, this rewrite was already done; Phase 6 only needed the pilot
scaffold cleanup below.

**Correction (found during Phase 6 itself, 2026-07-19):** an earlier draft
of this section incorrectly grouped `build_ca65/linker.cfg` in with the
unused pilot-test scaffold. That's wrong — `build_ca65/linker.cfg` is the
real, actively-used linker config (`LINKER_CFG` in the Makefile references
it directly) and must NOT be deleted. Only `build_ca65/build.sh`,
`build_ca65/pilot_test.py`, and `build_ca65/pilot_test.s` were the
genuinely unused pilot scaffold — confirmed via `grep -rl` across
`*.py`/`Makefile`/`*.md`/`*.s` (only self-references within `build_ca65/`
and descriptive mentions in README.md, no active build path used them) and
deleted. README.md's build instructions and technical-notes section were
updated to describe the real multi-object build instead of the stale
single-object `ca65`/`ld65` example they still carried.

## Deferred / out of scope for this plan

- **Vendoring `c64-polyval` / `c64-nist-curves`.** Real, worth doing (see
  the duplication analysis from this conversation — `aes_encrypt.s` /
  `aes_decrypt.s` / `polyval.s` / `gcm_siv.s` and `ecdsa_fp.s` / `ecdsa_mod.s`
  / `ecdsa_points.s` closely mirror those libraries' internals), but it's
  strictly easier *after* this plan: Phase 4's `exports.inc` is exactly the
  artifact that tells you, with confidence, which local symbols a vendored
  replacement would need to satisfy.
- **`LIB_<X>_` segment prefixing** (`c64-lib-contract` SPEC §4) — only
  matters once something else links against this repo's segments. Revisit
  if/when this project itself becomes an adopter another consumer vendors.
- **ZP address relocation** into the `ZP2`/`ZP3`/`ZP4` free pools — flagged
  in Phase 2 as explicitly deferred; do as its own follow-up once the
  contract shape exists to make it safe.
- **`make lib` / archive build targets** (`c64-lib-contract` SPEC §6) — no
  purpose until there's a consumer.

## Suggested sequencing

Phases 0-4 are additive/low-risk and can land in short order. Phase 5 is
the real work and should be its own tracked effort, module-group by
module-group (start with the leaf group Phase 0 identifies, then work up
through `ecdsa_*`/`gcm_siv`/`aes_*` last since those are both the largest
and the ones a future vendoring pass most wants a clean `exports.inc`
for). Phase 6 is a small cleanup once Phase 5 finishes.
