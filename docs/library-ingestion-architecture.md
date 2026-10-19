# c64-aes256-ecdsa library-ingestion architecture

This document describes how c64-aes256-ecdsa ingests sibling C64 crypto libraries as
git submodules and links their archives, and — more importantly — *why* each decision
was made the way it was. It is the consumer-side counterpart to
[c64-lib-contract](https://github.com/JC-000/c64-lib-contract)'s `SPEC.md`, and it is
the doc referenced from that repo's `consumers.md` row for this project (see §10).

**Written against c64-lib-contract SPEC v0.11.0 (2026-08-22).** Section references of
the form "§N" below are SPEC sections at that version unless prefixed with a document
name. Section numbers in the contract are stable identifiers (SPEC §0), so a later
contract revision will not renumber the clauses cited here — but it may change their
content, so re-verify against the pinned version before treating this doc as current.

The project consumes exactly one library today: **c64-polyval**, vendored at
`libs/polyval`. This document therefore reads as a single
deep case study rather than an inventory. That is deliberate: the ingestion of one
library exercised every core section of the contract (§1, §2, §4, §5, §6) and turned up
a series of failure modes that are *silent* — no error, no warning, exit 0 — each of
which is recorded below with the mechanism that makes it silent.

## 1. What is ingested, and the shape of the pin

| Property | Value | Where it lives |
|---|---|---|
| Upstream | `https://github.com/JC-000/c64-polyval.git` | `.gitmodules` |
| Vendored at | `libs/polyval` | `.gitmodules` |
| Pin | tag **v0.7.1** = `3852441` — *not* v0.7.0, see §1.1 | the gitlink SHA itself |
| Variant consumed | POLYVAL-only, **SHORT** profile, no AES (`polyval-short.a`) | `tools/integration/build_polyval.sh` |
| Archive path | `build/lib/polyval-short.a` | `Makefile` (`POLYVAL_ARCHIVE`) |
| Ingestion wrapper | `tools/integration/build_polyval.sh` | — |
| Member surgery | **none** — the archive is copied byte-for-byte from upstream's own output | §6.1 |

**The gitlink SHA is the pin.** There is no separate pin file, no version string
duplicated into a Makefile variable, and nothing in `src/` that names a version in a way
a build would read. This is SPEC §6 intent: `git submodule status` is the single
authoritative answer to "what version is linked", and `git diff` on a bump shows exactly
one changed line. Anything that restated the version elsewhere would be a second
claimant that could silently drift — the same class of defect §2 and §6.2 exist to
prevent for ZP addresses.

Comments in the tree that *name* a version (`build_ca65/linker.cfg`, `src/zp_config.s`)
are documentation of the pin, not inputs to it. They are worth updating on a bump but a
stale one cannot mis-build anything.

### 1.1 Why the pin is v0.7.1 and not v0.7.0

The earliest 0.7.x tag is the wrong instinct here, and v0.7.0 looks superficially fine, so
the reason is worth recording.

**v0.7.0 does not link into this project at all.** Its `src/data.s` reserves and exports
the library's AES + GCM-SIV buffers unconditionally: the file *documents* a
`LIB_POLYVAL_NO_AES` gate in a comment, but the `.ifndef` / `.endif` implementing it is
simply absent. So `polyval-short.a` built from that tag collides with this project's
`src/data.s` on **20 symbols** (`aes_state` plus all 19 `gcmsiv_*`) and `ld65` stops at
`Duplicate external identifier: 'gcmsiv_saved_exp'`.

That gap is [c64-polyval#47](https://github.com/JC-000/c64-polyval/issues/47) (closed),
fixed by [PR #48](https://github.com/JC-000/c64-polyval/pull/48) and released in v0.7.1 by
[PR #49](https://github.com/JC-000/c64-polyval/pull/49). **v0.7.1 is therefore the first
usable tag for any consumer that owns its own AES/GCM-SIV** — which is the generalisable
form of this note, and the reason it belongs in the doc rather than only in the commit
that moved the pin. The same rationale is recorded at `Makefile:60-71`.

The distance from the fix to the tag is one line: `git diff 4f32ddd v0.7.1 -- src/` is a
single change to the version stamp in `src/lib_version.s`. Nothing else in the library
moved, so every line-number citation in this document is equally valid against the fix
commit and against the tag.

**A note on loose-commit pins.** For a window during this work the gitlink pointed at
`4f32ddd` — the fix commit itself, on an unmerged branch — because no tag yet carried the
gate. That is worth doing once with a known expiry, and worth being uncomfortable about:
a loose commit on an unmerged branch is only as durable as upstream's merge strategy, and
had #48 been squash-merged with its branch deleted, nothing would have referenced
`4f32ddd`, it would have become eligible for garbage collection, and
`git submodule update --init` would have started failing on every fresh clone including
CI — unfixable from this repo, since the object would be gone from upstream. #48 was
merged as a real merge commit, so `4f32ddd` is an ancestor of v0.7.1 and the hazard never
materialised. The general rule stands regardless: a loose-commit pin is a temporary state
with a defined exit, not a resting place.

**Structure of the ingestion.** Three files, and only three, carry consumer-side
obligations:

- `tools/integration/build_polyval.sh` — builds and verifies the archive. Owns the
  variant choice, the global defines, and the three relocated ZP addresses.
- `build_ca65/linker.cfg` — places the library's three §4 segments, and narrows this
  project's own ZP pool out of the way of the archive's ZP claim.
- `Makefile` — declares `POLYVAL_ARCHIVE`, appends it to the `ld65` line, and drives the
  wrapper.

Plus one source-level obligation: `src/gcm_siv.s:17-23` reaches `polyval_acc` by
`.importzp` (not `.import` — it is a zero-page slot; see §3.5).

### 1.2 What was replaced

`src/polyval.s` — a second, independent RFC 8452 GF(2^128) implementation — is
**deleted**, along with the POLYVAL buffers `src/data.s` used to reserve. This closes
item 1 of [c64-aes256-ecdsa#27](https://github.com/JC-000/c64-aes256-ecdsa/issues/27).
`polyval` is gone from `MODULES` in the `Makefile`; `src/data.s:34` records that
`polyval_h` / `polyval_temp` / `polyval_htable` now come from the archive's own `data.o`
in segments `LIB_POLYVAL_BSS` / `LIB_POLYVAL_HTABLE`.

The motivation is not code reuse for its own sake. Two implementations of the same
primitive in one fleet means two places for an RFC 8452 conformance bug to live, two
places to fix it, and — since neither was the other's oracle — no mechanism by which a
divergence would be noticed. The library is the one with the KAT suite.

## 2. Why SHORT, not LONG

c64-polyval ships two multiply profiles. The decision is workload-driven and is not
close:

| Profile | Per-block | H precompute | Table RAM | Suited to |
|---|---|---|---|---|
| SHORT | — | ~29k cy | 256 B | H rederived per message, few blocks |
| LONG | ~3,915 cy | ~255,263 cy | ~8.5 KB | H stable across many blocks (TLS 1.3, WireGuard) |

(Figures from `libs/polyval/README.md:168` and `libs/polyval/API.md:168`.)

**This project's workload is the SHORT case, unambiguously.** Its GCM-SIV hashes at most
~5 blocks per message (≤64 B plaintext plus the length block), and it rederives H per
message — RFC 8452 derives the authentication key from the nonce, so H is per-message by
construction, not by implementation choice. Under LONG, the ~255k-cycle precompute would
be paid on **every single message** and amortised across ~5 blocks; it would dominate the
message cost by an order of magnitude. The documented crossover — where LONG's cheaper
per-block cost finally repays its precompute — is around **68 blocks (~1 KB of plaintext
per message)** (`libs/polyval/README.md:171-172`, `API.md:189`). This project is an order
of magnitude below it and structurally cannot approach it.

The crossover is clock-invariant (`README.md:195-196`): running on an accelerated C64
does not move it, because both sides of the comparison scale together. So this is not a
decision that a faster target would revisit.

**LONG also does not fit.** Its ~8.5 KB of tables are `LIB_POLYVAL_LONG_HTABLE8` (4 KB)
and `LIB_POLYVAL_LONG_REDUCE8` (4 KB), gated behind
`.if POLYVAL_PROFILE = POLYVAL_PROFILE_LONG` at `libs/polyval/src/data.s:63-139`. This
project's `MAIN` region is `$0801-$77FF` and was already full to within 7 bytes before
the swap; `HIMEM` is `$7C00-$CFFF` and is already carrying 13.6 KB of SHORT code (§6).
There is no 8.5 KB hole anywhere in the map.

Because that gate is a profile conditional, the SHORT archive reserves only what SHORT
needs: **32 B of BSS** (`polyval_h` 16 B + `polyval_temp` 16 B, `data.s:32-34`) and the
**256 B page-aligned `polyval_htable`** (`data.s:42-43`). That is the whole RW footprint
the cfg has to find room for.

### 2.1 Why *no-AES*, separately

`polyval-short.a` is the `(POLYVAL_PROFILE=short × POLYVAL_NO_AES=1)` pair. The no-AES
half is a correctness requirement, not a size optimisation. This project ships its own
`src/aes_encrypt.s` and `src/gcm_siv.s`; the library's `data.o` gates its AES and GCM-SIV
buffers behind `LIB_POLYVAL_NO_AES` (`libs/polyval/src/data.s:154-224`, upstream
c64-polyval#47). Without that gate the archive's `aes_state` / `gcmsiv_*` exports collide
with `src/data.s`'s identically-named ones and `ld65` rejects the link.

This is not a hypothetical. It is exactly what tag v0.7.0 does, and it is the reason the
pin is v0.7.1 (§1.1). The gate is a `.ifndef LIB_POLYVAL_NO_AES` — note the *negative*
sense: passing the define suppresses the block. Two knob names are in play and they are
easy to conflate: `POLYVAL_NO_AES` is the **make** variable, and `LIB_POLYVAL_NO_AES` is
the **ca65 define** it sets (`libs/polyval/Makefile:109-111`). The `PIN_` table and the
profile pair in §5.2 are expressed in terms of the former.

This is the loud failure mode of the several described in this document — and it is the
only loud one.

## 3. Zero page: why the overrides exist, and the three rules that keep them honest

### 3.1 The collision

c64-polyval's §2 defaults are `polyval_acc=$10` (16 B), `pv_mul_input=$20` (16 B),
`pv_mul_nibble=$30`. This project's map (`src/zp_config.s`) puts `sha_temp2`'s tail at
`$10-$11` and `sha256_round` at `$12`, and the whole `fp_*` bignum pointer block at
`$22-$2b`. Two of the three library defaults land on top of live state.

They are relocated into the free ZP4 pool via SPEC §6.2's `CONTRACT_ZP_DEFINES`. **As
landed, the three addresses are:**

| Slot | Library default | Relocated to | Size |
|---|---|---|---|
| `polyval_acc` | `$10` | **`$40`** (`0x40`) | 16 B (`$40-$4F`) |
| `pv_mul_input` | `$20` | **`$50`** (`0x50`) | 16 B (`$50-$5F`) |
| `pv_mul_nibble` | `$30` | **`$60`** (`0x60`) | 1 B |

They are written in exactly one place: `tools/integration/build_polyval.sh:102-104`
(`PV_ACC` / `PV_MUL_INPUT` / `PV_MUL_NIBBLE`). The freedom of `$40-$60` was established by
a repo-wide grep for zero-page-addressed operands in that window — zero hits; every
`$4x`/`$5x`/`$60` in `src/` is an immediate, a `.byte` table entry, or an `and #$40` bit
mask.

### 3.2 Rule 1 — `0x` hex, never `$`

The value crosses **two** expansion layers on its way into `ca65`: make expands the
recipe, then `/bin/sh` expands the resulting command line. A `$`-form value is destroyed
differently at each depth, and every one of the outcomes is silent:

| Written | Becomes | Result |
|---|---|---|
| `-D x=$40` | make eats `$4` | slot lands at `$0` — on top of the 6502's own `$00/$01` bank-switch registers |
| `-D x=$$40` | survives make, shell eats `$4` as positional parameter | garbage address |
| `-D x=$$$$40` | shell's **PID** | garbage address, different every run |

`make`, `sh`, `ca65` and `ld65` all exit 0 in every one of those cases (SPEC.md:126).
Nothing anywhere in the toolchain has an opinion about whether a ZP equate is a sensible
address. `0x` (or plain decimal) has no metacharacter in either layer and passes through
both intact.

This is the rule most likely to be broken by someone "tidying up" the script to match the
`$`-hex convention used everywhere else in a 6502 codebase. The post-check in §7 exists
specifically to catch it.

### 3.3 Rule 2 — `CONTRACT_ZP_DEFINES`, never `CA65FLAGS`

`libs/polyval/Makefile:98` hard-assigns:

```
CA65FLAGS = -I $(SRC_DIR) -D POLYVAL_PROFILE=$(PROFILE_VAL) -g
```

and then `+=`s the contract variables onto it at line 146. Passing `CA65FLAGS=...` on the
command line replaces that assignment wholesale, taking `-I src`, the profile define and
`-g` down with it. The build then fails on the missing include path — or, worse, if the
caller helpfully re-supplies `-I src`, it succeeds while building the **LONG** multiply
(the profile define is gone, and LONG is the default) and archives it under the SHORT
name. `CONTRACT_DEFINES` and `CONTRACT_ZP_DEFINES` exist precisely so a consumer can add
defines without touching that assignment.

### 3.4 Rule 3 — the defines must reach **every** member recipe

c64-polyval uses the **include/bake-everywhere** delivery model: no library TU
`.importzp`s its own slots; each one re-derives them through `constants_lib.inc` →
`zp_config.s`'s `.ifndef` guards. So `CONTRACT_ZP_DEFINES` is appended to `CA65FLAGS` and
reaches every recipe (`libs/polyval/Makefile:146`), and that broad scope is the
*conformant* one for this library — upstream documents it as such in the `CONTRACT_*` block just above that line.

Narrowing the defines to `zp_config.o` alone — the intuitively "tidy" scope, and the
right one for a library that used the import/export delivery model — would produce a
build where `zp_config.o` **exports** `polyval_acc = $40` while `data.o` and
`polyval_short.o` had already **baked** `$10` into their instruction operands. The link
succeeds. `build/labels.txt` shows `$40`. The code reads and writes `$10`, on top of
`sha_temp2`. There is no link-time diagnostic for this, because as far as `ld65` is
concerned nothing is unresolved and nothing is duplicated: an equate that was baked at
assembly time leaves no trace to check against.

### 3.5 Why there is no second copy to keep in step

The three addresses are set once, in `build_polyval.sh`, and this project's own assembly
does **not** receive them as defines at all:

- `src/zp_config.s:113-147` deliberately declares nothing for `$40-$60`. It records the
  claim in prose, because that file is the project's single ZP occupancy map, but it does
  not define or `.exportzp` the three names.
- `src/gcm_siv.s:17-23` reaches the accumulator with `.importzp polyval_acc`, resolved
  against the archive's own `zp_config.o`.

So the library is the sole definer and this project is a pure importer. There is exactly
one definition site and one address value in the whole system; the two sides cannot
disagree because there is no second value to disagree with. (The mechanism is
*non-duplication*, not a shared variable — see §11 for why this distinction was worth
recording.)

`src/zp_config.s` must **not** also define and export those three names. That, and not
the library's exports themselves, is what would collide.

### 3.6 Why `ZP_CONFIG_NO_EXPORTS=1` is deliberately *not* passed

This is the natural companion to `LIB_NO_BARE_EXPORTS` and the fleet precedent
(`c64-wireguard/tools/integration/build_x25519.sh`) does pass it. **At the c64-polyval
commit this project pins, it cannot be**: `libs/polyval/src/constants_lib.inc:23` (still
present at v0.7.1) assigns

```
ZP_CONFIG_NO_EXPORTS = 1
```

unguarded — no `.ifndef` — so a `-D` of the same name makes every TU that includes that
header fail with `Symbol 'ZP_CONFIG_NO_EXPORTS' is already defined`. This is the same
upstream defect as c64-x25519#99 (fixed there in v0.11.1 by adding the guard); it is
filed as [c64-polyval#50](https://github.com/JC-000/c64-polyval/issues/50) and still open
— see §9 gap 4.

The consequence is benign here, and understanding why is what makes it safe to leave: the
library's `zp_config.o` keeps its `.exportzp` block, so *it* supplies the three names to
the link and to `build/labels.txt` (which `tools/run_all_tests.py` requires). The other
nine names that block exports are all `polyval_`-prefixed (`polyval_zp_ptr2`,
`polyval_aes_*`, `polyval_zp_ptr`/`_temp`/`_count`) and collide with nothing on this side;
`polyval_short.o` references none of them.

### 3.7 The cfg consequence

The archive's ZP claim is a set of hand-assigned numeric equates. `ld65` knows nothing
about them — they are not a `.segment "ZEROPAGE"` allocation, so they do not participate
in ZP pool accounting, and `ld65` would happily place a future `ZEROPAGE` segment right
on top of them. `build_ca65/linker.cfg:34-42` therefore narrows ZP4 out of the way:

```
ZP4: file = "", define = yes, start = $0061, size = $002F; # $61-$8F (47 bytes)
```

It was `$3D-$8F` (83 B) before the submodule landed. `$3D-$3F` — the three bytes below
the claim — are free but too small to be worth a fourth pool.

## 4. Why `LIB_NO_BARE_EXPORTS=1` is load-bearing *on this pin specifically*

`build_polyval.sh:138` passes `-D LIB_NO_BARE_EXPORTS=1` through `CONTRACT_DEFINES`. Per
SPEC §1/§8.4 this suppresses the **deprecated unprefixed** exports that every contract
library emits identically — `LIB_VERSION_{MAJOR,MINOR,PATCH}`, `LIB_ABI_VERSION`, and the
`LIB_PRECALC_<name>_{SIZE,REGION,SHARED}` triples — leaving only the `LIB_POLYVAL_*`
prefixed forms.

The reason this matters here more than in a typical consumer is that **c64-aes256-ecdsa
is itself a contract adopter**, not only a consumer. Its own `src/lib_version.s:21-24`
exports the bare `LIB_VERSION_MAJOR` / `_MINOR` / `_PATCH` / `LIB_ABI_VERSION`
**ungated** — no `.ifndef LIB_NO_BARE_EXPORTS` guard, the pre-v0.7.0 shape (issue #27
item 3). Both sides of the link claim the same four names.

The collision is not hypothetical and it is not avoided by "just not importing them". `ld65`
pulls archive members **whole**: if anything in the link imports any c64-polyval §1 or §5
equate, `lib_version.o` enters the link uninvited and the two claimants collide with
`Duplicate external identifier`. SPEC §1's TU-isolation rule (SPEC.md:60) exists to
contain exactly this, and it is why the bare exports must live in a TU exporting nothing
else — but TU isolation alone cannot fix it here, because the collision is on the bare
names themselves.

The same pull-in reaches the **`LIB_PRECALC_polyval_htable_*` triple**, which both sides
emitted when this work began: `src/precalc_manifest.s` enumerated `polyval_htable` — a
table this project no longer owns — and the library's
`libs/polyval/src/lib_manifest.s:324` enumerates it too (five-argument form, `"POLYVAL"`
prefix). Both halves have since been closed, independently: this project retired its
entry (`precalc_manifest.s:42-47`), and with the define set the library emits only
`LIB_POLYVAL_PRECALC_polyval_htable_*`. Either fix alone would have sufficed for this
symbol; the define is what generalises, since it covers the §1 version equates too, where
this project has no entry to retire (§9 gap 2).

`build_polyval.sh:211-215` asserts the suppression took effect by grepping
`od65 --dump-exports lib_version.o` for the bare `LIB_VERSION_MAJOR` and failing the build
if it is present — because a define that silently failed to arrive would otherwise not
surface until the far more confusing `ld65` duplicate-symbol error at final link.

The correct long-term fix is on this side: gate this project's own bare exports (issue
#27 item 3, §9). Until then, `LIB_NO_BARE_EXPORTS=1` is what makes the link possible at
all, and it must not be removed as "cleanup" on the grounds that the prefixed forms look
sufficient.

## 5. Build-driving decisions

### 5.1 The archive rule is FORCE-driven, and the sibling `BUILD_DIR` is wiped every time

`Makefile`:

```
.PHONY: FORCE
FORCE:

$(POLYVAL_ARCHIVE): FORCE | $(LIB_DIR)
	bash tools/integration/build_polyval.sh
```

The archive's real inputs are the entire submodule tree plus the define set inside
`build_polyval.sh` — neither expressible as a prerequisite list make can timestamp. So
incrementality is delegated to the sibling Makefile, which is where it belongs and where
it works. A no-op rebuild costs a couple of seconds.

`build_polyval.sh:146` additionally does `rm -rf` on the sibling `BUILD_DIR` before every
build. This is the staleness rule that the FORCE rule alone does not cover:
`POLYVAL_PROFILE` and `POLYVAL_NO_AES` **are not prerequisites of any object**, so their
values do not participate in make's timestamp comparison. Switching profiles in a tree
that already has objects silently reuses the stale `.o` files — producing an archive whose
name says SHORT and whose multiply is LONG. The library's own phony does run `make clean`,
but only for the `BUILD_DIR` it was told about; the wipe here additionally guarantees that
a half-built tree from an interrupted run is never an input.

The consumer build also uses a **separate** `BUILD_DIR` from the library's own default
(`BUILD_DIR="build/consumer-short"`, `build_polyval.sh:75`), so a developer poking at the
submodule by hand — where plain `make` builds the LONG full-AEAD PRG into `build/` — can
never leave objects this build would adopt. It is deliberately nested **under** the
submodule's own `build/` rather than being a sibling directory: `build/` is what
`libs/polyval/.gitignore` ignores, so a top-level `build-consumer-short/` would leave the
submodule permanently showing untracked content in `git status` — noise in exactly the
place where a real gitlink change needs to be visible (§1).

### 5.2 The phony target is invoked; the archive path never is

`build_polyval.sh:148` runs `make -C "$LIB_ROOT" lib-polyval-short`, never
`make .../lib/polyval-short.a`.

c64-polyval has a **make-parse-time** `PIN_` guard at `libs/polyval/Makefile:225-242`.
Every archive goal declares the `(POLYVAL_PROFILE × POLYVAL_NO_AES)` pair it requires
(`PIN_$(LIB_DIR)/polyval-short.a = short-noaes`), and naming an archive path as a goal
without the matching pair is a hard `$(error)`. Guarding at parse time rather than in a
recipe is deliberate upstream: nothing is built before the rejection, so the rejected
invocation cannot leave a half-built tree that becomes the input to the *next* staleness
bug.

The phony wrapper is the only invocation shape that produces a coherent artifact — it
re-invokes `$(MAKE)` behind a `clean` with both knobs pinned
(`libs/polyval/Makefile:331-333`). Naming the archive path here would either trip the guard
or, with the pins passed by hand, silently archive the LONG multiply under the SHORT name.

The motivating case is upstream polyval#40: an invocation that previously **exited 0** and
shipped an archive that was simultaneously unlinkable and manifest-violating. Exit 0 is
the point. The guard converts that into a parse-time error with a message naming the
correct phony target.

### 5.3 Archive placement on the `ld65` line

The archive goes **last**, after every object:

```
ld65 -C $(LINKER_CFG) -o $(PRG) -Ln $(LABELS) -m $(MAPFILE) $(OBJECTS) $(POLYVAL_ARCHIVE)
```

Two reasons, both load-bearing. (1) `ar65` archives are pulled member-by-member on
demand, so anything resolving against them must already have been seen — archive-first
would leave `gcm_siv.o`'s `polyval_*` imports unresolved. (2) `check-boot` requires
`boot.o` to be the first object emitting CODE-segment bytes; archive members contribute
to their own `LIB_POLYVAL_*` segments, but keeping them at the tail makes that invariant
obviously true rather than incidentally true.

## 6. The cfg contract

Three §4 segments, placed in `build_ca65/linker.cfg:92-125`. Attributes are copied from
the library's own `libs/polyval/src/lib_only.cfg` (its SPEC §4 reference placement); only
the memory area differs.

| Segment | Type | Region | Size | Notes |
|---|---|---|---|---|
| `LIB_POLYVAL_SHORT_CODE` | `ro` | HIMEM | 13,614 B | fully unrolled 4-bit Shoup multiply |
| `LIB_POLYVAL_BSS` | `bss` | HIMEM | 32 B | `polyval_h` + `polyval_temp` |
| `LIB_POLYVAL_HTABLE` | `bss`, **`align = $100`** | HIMEM | 256 B | see §6.1 |

All three are `optional = yes`; the two BSS segments are `define = yes`.

**HIMEM, not MAIN.** `LIB_POLYVAL_SHORT_CODE` is ~27× the size of the `src/polyval.s`
loop it replaces (`$1FC` = 508 B), and MAIN (`$0801-$77FF`) was already full to within 7
bytes. Deleting `src/polyval.s` and `data.s`'s 304 B of POLYVAL buffers frees 812 B there
— two orders of magnitude short. HIMEM (`$7C00-$CFFF`) has the room and is already where
this project parks modules too big for MAIN.

Neither shipped profile trades that code size back for cycles, which is the gap behind
[c64-polyval#51](https://github.com/JC-000/c64-polyval/issues/51) (§9 gap 5): a consumer
that is size-bound rather than throughput-bound currently has no third option.

### 6.1 `align = $100` is a performance invariant that fails completely silently

The alignment on `LIB_POLYVAL_HTABLE` is required by SPEC §4 and by the library's own
`lib_only.cfg`. Dropping it is **not** a correctness bug: every htable access is a
linker-resolved `abs,x` with no high-byte address math, so an unaligned table still
hashes correctly. What breaks is that the hot-loop reads cross a page for some indices
(+1 cycle each) and the library's documented ~18.8k-cycle SHORT multiply no longer holds.

What makes this the worst failure mode in this document is that **nothing reports it**.
The alignment request exists *only* in this cfg: `libs/polyval/src/data.s:42-43` reserves
`polyval_htable` with a bare `.res 256` and no source-level `.align`, so `ld65` has no
source-side request to check the segment placement against and emits no diagnostic
whatsoever. `ld65`'s §4 misalignment warning only ever fires against a source-side
`.align`. A wrong build here is a build that passes every test, links clean, produces
correct ciphertext, and is quietly slower — the failure surfaces, if ever, as a benchmark
regression nobody attributes to the cfg.

The mitigation is a manual post-check, and it is worth actually running: after any cfg
edit, confirm `build/aes256keygen.map` shows `LIB_POLYVAL_HTABLE` starting on an `$xx00`
boundary.

## 7. Verification discipline: never compare `.o` or `.a` bytes

`ca65` stamps a wall-clock `OPT_DATETIME` record into every object it emits. Two objects
assembled from identical sources with identical flags therefore **differ in raw bytes**.
This makes byte-comparison of `.o` or `.a` files useless in both directions:

- **False positives** — a diff reports "changed" on every knob you flip, whether or not
  the knob changed anything, so it cannot answer "did this define do anything?".
- **False negatives** — two builds that land in the same wall-clock second compare
  identical, so it reports a false identity exactly when you are iterating fastest.

Compare **linked PRGs**, or `od65` structural dumps. `build_polyval.sh:157-221` takes the
`od65` route and checks four things against the assembled objects, before the archive is
allowed to be published:

1. **The nine public POLYVAL routines** are exported by `polyval_short.o` (`polyval_init`,
   `polyval_double`, `polyval_right_shift_1`, `polyval_shift_left_4`,
   `polyval_precompute_table`, `polyval_multiply`, `polyval_xor_table_entry`,
   `polyval_update`, `polyval_finalize`). `polyval_finalize` is a bare `rts` in the SHORT
   profile and has no caller here, but it is part of the published ABI — its absence would
   mean the wrong member set was archived.
2. **The three buffers** `polyval_h` / `polyval_temp` / `polyval_htable` are exported by
   `data.o`, now that `src/data.s` no longer reserves them.
3. **The three ZP slots, by value** — not merely by presence. This is the check that
   matters: presence alone passes with all three silently sitting at `$00` (§3.2). The
   failure message points at the `0x`-not-`$` rule, because that is the cause.
4. **The bare contract exports are absent** (§4).

On any failure the script deletes `$ARCHIVE` before exiting non-zero, so a failed
verification cannot leave a stale-but-plausible archive that the next `make` treats as
satisfying its prerequisite.

Note also (SPEC.md:550) that `od65` reads single `.o` files **only**. Pointed at an `.a`
it prints `<name>: (no xo65 object file)` and **exits 0** — a script that greps that
output sees no symbols and reports a silent false negative. The post-checks above are
therefore run against the sibling's individual objects in `libs/polyval/build/consumer-short/`, not
against the copied archive. Auditing a shipped archive requires extracting its members
first.

## 8. What is *not* adopted, and why

Recorded explicitly so a reviewer is not left guessing whether an omission is an oversight.

| Clause | Status | Why |
|---|---|---|
| **§6.7** (equate-reserved regions) | n/a | c64-polyval places no equate-reserved region — every buffer is segment-resident (`LIB_POLYVAL_BSS`, `LIB_POLYVAL_HTABLE`), so `ld65` enforces non-overlap natively. There is nothing for a consumer-side reservation check to do. |
| **§3** (REU layout) | n/a | `LIB_POLYVAL_REU_BANKS_USED = 0`. The library touches no REU bank, so there is no bank budget to assert and no collision surface with this project's own REU use. |
| **§8** (shared crypto primitives) | n/a on both sides | c64-polyval declares no shared primitive, and this project owns none. No `SHARED_*` deferral switches, no `APP_OWNED` shape, no disjointness/coverage asserts — there is nothing shared to be disjoint about. |

§6.1 (no member surgery) **is** satisfied, and trivially so: the archive is upstream's own
`make` artifact, copied unmodified. No member drops, no generated glue TU, no
`zp_config` rebuild-and-re-archive. The §8.0-shaped work that c64-https needed to satisfy
§6.1 has no analogue here because the requested shape is expressible entirely through
§6.2 knobs (`CONTRACT_DEFINES` + `CONTRACT_ZP_DEFINES`).

## 9. Known open gaps

Gaps 1-3 are contract debt on *this* repo's adopter side, tracked against
[c64-aes256-ecdsa#27](https://github.com/JC-000/c64-aes256-ecdsa/issues/27). Gaps 4-5 are
upstream, in c64-polyval, and were filed by this project during this work. None of the
five blocks the current link.

1. **Unregistered §2 ZP prefix** (issue #27 item 2). This project's ZP slots are not
   registered under a contract §2 prefix. Consequence today: a second library whose
   defaults overlap this project's `$0e-$12` / `$22-$2b` blocks would be found by manual
   grep rather than by a registry lookup — which is exactly how the c64-polyval collision
   in §3.1 *was* found.

2. **Pre-v0.7.0 §1 version equates** (issue #27 item 3). `src/lib_version.s:21-24` exports
   the bare `LIB_VERSION_*` / `LIB_ABI_VERSION` ungated, with no `LIB_AES256ECDSA_`-prefixed
   forms. This is what forces `LIB_NO_BARE_EXPORTS=1` on every library this project ever
   links (§4), and it will collide with the *second* library the moment one is added,
   whether or not that library can be built with the suppression define.

3. **`src/precalc_table.inc` is a stale four-parameter pre-v0.7.0 copy** — *found during
   this round, not yet filed*. SPEC §8.4's canonical macro takes **five** arguments
   (`name, size_bytes, region, shared, lib`) and emits both the prefixed
   `LIB_<X>_PRECALC_<name>_*` triple and the deprecated bare one, with an `.error` guard
   for the case where `LIB_NO_BARE_EXPORTS` is set but the lib-prefix argument is missing
   (SPEC.md:630-651). This repo's copy (`src/precalc_table.inc:45-53`) is the four-argument
   form: it emits **only** the bare triple. Consequence: this repo exports **zero**
   `LIB_AES256ECDSA_PRECALC_*` symbols, so the cross-adopter
   `od65 --dump-exports | grep _PRECALC_` audit finds nothing prefixed here, and all four
   of `src/precalc_manifest.s:58-61`'s tables are enumerated in the collision-prone form
   only. The contract requires this file to be copied **verbatim** and updated by
   coordinated cross-repo PR; the fix is a re-copy plus adding the `"AES256ECDSA"`
   argument at each of the four call sites. (A fifth entry, `polyval_htable`, was retired
   during this work now that the library owns that table — `precalc_manifest.s:42-47`
   records why and names the successor symbols. The remaining four are genuinely this
   project's, so retiring rather than re-prefixing was the right call there.)

4. **c64-polyval's unguarded `ZP_CONFIG_NO_EXPORTS`** (§3.6) —
   [c64-polyval#50](https://github.com/JC-000/c64-polyval/issues/50), filed by this
   project, **open at v0.7.1**. The c64-x25519 fix (that repo's #99, landed in v0.11.1) is
   the template: add the `.ifndef` guard. Until it lands, the workaround in §3.6 stands
   and is benign.

5. **No compact POLYVAL profile** —
   [c64-polyval#51](https://github.com/JC-000/c64-polyval/issues/51), filed by this
   project, open. `LIB_POLYVAL_SHORT_CODE` is 13,614 B of fully-unrolled multiply, which
   is what forces the archive into HIMEM rather than MAIN (§6). Neither shipped profile
   trades code size back for cycles, so a consumer that is size-bound rather than
   throughput-bound has no option to pick.

**Closed since this work began:** the missing `LIB_POLYVAL_NO_AES` implementation at
v0.7.0 ([#47](https://github.com/JC-000/c64-polyval/issues/47), fixed by
[#48](https://github.com/JC-000/c64-polyval/pull/48), released in v0.7.1 by
[#49](https://github.com/JC-000/c64-polyval/pull/49)) — see §1.1.

### 9.1 Latent hazard — the `$7800` quarter-square window

`src/ecdsa_fp.s:25-26` places this project's quarter-square multiply tables at fixed
addresses:

```
sqtab_lo = $7800   ; 512 bytes: low bytes of floor(n^2/4)
sqtab_hi = $7a00   ; 512 bytes: high bytes
```

with `build_ca65/linker.cfg:65` modelling the window as a real `QSTAB` memory area
(`$7800`, `$0400`, page-aligned).

`$7800` is **exactly** c64-x25519's default `LIB_SHARED_SQTAB_BASE`
(`c64-x25519/src/constants.s:201-202`). If these two are ever composed in one link, there
are two independent claimants on one 1 KB window — and because both sides reach it through
hand-assigned equates rather than segment allocations, `ld65` has nothing to compare and
will not say a word (the §3.7 mechanism again, at a different scale).

This is not a bug today: c64-x25519 is not consumed by this project and there is no plan
to consume it. It is recorded because the collision would be silent, would corrupt both
implementations' multiplies simultaneously, and the window is a *coincidence of
convention* — both projects independently picked the same natural page-aligned hole — so
nothing about either codebase hints at the overlap. SPEC §8.1 covers `sqtab` as a shared
primitive precisely so that composition becomes a declared, assertable arrangement rather
than a coincidence; adopting it here is the fix if the composition is ever wanted (gap 1
above is a prerequisite).

## 10. Relationship to c64-lib-contract

This document is the consumer-side lead doc required by
[c64-lib-contract](https://github.com/JC-000/c64-lib-contract)'s `consumers.md` intake
procedure. Per that procedure:

- **Step 3** — the `consumers.md` row for c64-aes256-ecdsa links to this file.
- **Step 5** — this section is the required cross-link back to the contract, so a library
  author reading this repo can navigate to the spec that governs the conventions cited
  throughout: <https://github.com/JC-000/c64-lib-contract>.

The contract sections this ingestion actually exercises are **§1** (version
identification, and the `LIB_NO_BARE_EXPORTS` deprecation gate — §4 above), **§2** (zero
page — §3), **§4** (segment names and the htable alignment — §6), **§5** (manifest
equates, via `LIB_POLYVAL_REU_BANKS_USED` — §8), **§6.1** (no member surgery — §1),
**§6.2** (`CONTRACT_DEFINES` / `CONTRACT_ZP_DEFINES` — §3.3, §3.4) and **§8.4** (the
precalc catch loop — §9 gap 3). §3, §6.7 and §8 are n/a with reasons recorded in §8 above.

Version pinning: this document was written against **SPEC v0.11.0 (2026-08-22)**. Each
SPEC version is tagged `v<version>` in the contract repo, so the exact revision cited here
can be checked out and diffed rather than inferred from `main`. A tag's `SPEC.md` states
its own version on its third line — check it rather than assuming, since a recent tag does
not imply recent content.

## 11. Note on this document's own provenance

The design facts above were verified against the working tree at the time of writing
rather than transcribed from the design brief, and four briefed details did not survive
that check. They are recorded here because each is the kind of plausible-but-wrong detail
that a later reader might otherwise reintroduce:

- **The pin is not tag v0.7.0.** It is v0.7.1, and v0.7.0 is not merely "older" — it does
  not link at all (§1.1). During this work the pin was briefly the loose fix commit
  `4f32ddd`; it is now the tag. Any future doc, comment or automation that reaches for
  "the earliest 0.7.x" is wrong.
- The three ZP addresses live in `tools/integration/build_polyval.sh:105-107`, **not** in a
  Makefile variable, and this project's own assembly is not driven by them at all — it
  imports the slots from the library's `zp_config.o` (§3.5). The single-source-of-truth
  property comes from having exactly one *definer*, not from a shared variable feeding two
  builds.
- `libs/polyval`'s `CA65FLAGS` hard-assign is `-I $(SRC_DIR) -D POLYVAL_PROFILE=... -g`
  (`Makefile:98`). It does not carry `-t c64` (§3.3).
- The make-level knob is `POLYVAL_NO_AES`; `LIB_POLYVAL_NO_AES` is the `ca65` define it
  sets (`libs/polyval/Makefile:109-111`). The `PIN_` table and the profile pair are
  expressed in terms of the former (§2.1, §5.2).

Line numbers cited throughout are as of the working tree at writing time; the ingestion
files were being actively edited during this round, so treat them as navigation aids and
grep for the quoted text if one does not land.
