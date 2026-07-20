# REU layout contract status (c64-lib-contract SPEC §3)

**Status: N/A.** This project claims no REU banks and therefore needs no
`src/reu_config.s`. This document records the determination, the evidence
behind it, and a forward-looking note for whoever vendors a REU-bank-claiming
library into this project in a future round (see
`docs/lib_contract_alignment_plan.md`, §3 row).

## 1. The N/A determination

SPEC §3 governs libraries that "use any 17xx-series RAM Expansion Unit (REU)
banks for precompute tables or scratch" — i.e. code that reserves specific
REU banks/offsets at fixed addresses to cache a precomputed data structure
(the canonical example being `c64-nist-curves`' and `c64-x25519`'s 128 KB
`mul_8x8` multiplication-table cache at REU banks `$00`/`$01`, or
`c64-nist-curves`' Lim-Lee comb anchors at bank `$02` — see
`c64-nist-curves/src/reu_config.s`, which exports
`LIB_NISTCURVES_REU_BANK_MUL` and `LIB_NISTCURVES_REU_BANK_COMB` for exactly
that reason).

This project's REU code (`src/reu_core.s`, `src/reu_advanced.s`) does none of
that. It is generic end-user REU utility functionality that operates over
"whatever REU is present" as an undifferentiated whole-device resource, never
reserving or addressing a specific bank range for a precomputed table:

- **`detect_reu` / `reu_detect`** (`src/reu_core.s`) — auto-detects whether an
  REU is attached at all and how large it is, by writing a signature to each
  bank from 255 down to 0 and reading it back from 0 up until a mismatch is
  found (the `prog8reu`-derived detection method). It has no notion of a
  "claimed" bank — it walks and probes the entire device.
- **`fill_reu` / `refill_reu_core`** (`src/reu_advanced.s`) — wipes or fills
  the *entire* detected REU (banks `0` through `reu_banks` inclusive, or all
  256 banks in the 16 MB case) with either zeros (via the fixed-C64-address
  fast DMA path) or random bytes (via `prepare_fill_buffer` /
  `fast_random_byte`). This is a bulk end-user utility ("wipe my REU" /
  "fill my REU with random data"), not a library building a cached table at a
  reserved address.
- **`offer_save_reu_to_disk`** (`src/reu_advanced.s`) — streams the REU's
  contents to a disk file (optionally spanning multiple REU-refill passes if
  the disk has more free space than the REU has capacity). Again this walks
  the whole device (`reu_read_bank` / `reu_read_addr_hi` sweep from bank 0
  forward) rather than reading a specific reserved region.
- **`do_show_reu_status`** (`src/reu_advanced.s`) — a status/menu entry point
  that calls `detect_reu` and then optionally drives the fill/save flows
  above. Purely UI orchestration over the same whole-device operations.

None of these routines reserve a base bank or within-bank offset for a
precomputed table the way SPEC §3 contemplates — there is no `X25519_REU_BANK`-
style equate anywhere in this codebase, no fixed-address cache built once at
boot and read from repeatedly in a hot loop, and no data that would be
corrupted by a consumer relocating "the" REU base, because there is no such
base. The REU here is treated as raw, ownerless storage the end user directs
interactively (detect it, wipe it, fill it, save it), not as a component of
this project's own crypto math. Contrast this with this project's ECDSA/AES
math, which (like `c64-nist-curves`/`c64-x25519`) does *not* use REU at all —
it runs entirely in main RAM/ZP — so there is no REU-resident precompute
table on the crypto side either.

Given that, SPEC §3's obligations do not apply:

- No `src/reu_config.s` is needed (nothing to `.ifndef`-guard or `.export`
  as a bank/offset equate — see §3 below).
- The aggregate `LIB_<X>_REU_BANKS_USED` bitmask (SPEC §3/§5) is simply zero,
  matching the precedent set by `c64-polyval`'s adopters.md row: `✅ n/a (no
  REU claims; LIB_POLYVAL_REU_BANKS_USED = 0)`. This project's own §5
  manifest work (tracked separately per `docs/lib_contract_alignment_plan.md`
  Phase C) will export `LIB_AES256ECDSA_REU_BANKS_USED = 0` on the same
  basis.

## 2. Forward-looking note: bank-awareness needed once a REU-bank-claiming library is vendored

This N/A determination holds **today**, with zero libraries vendored. It will
stop holding, in one specific way, the first time a future round vendors a
library that *does* claim REU banks under SPEC §3 — e.g. `c64-nist-curves`,
which (per its own `src/reu_config.s`) claims:

- `LIB_NISTCURVES_REU_BANK_MUL` (aliased to the shared `LIB_SHARED_REU_MUL_BANK`
  per SPEC §8.2) — banks `$00`+`$01`, the 128 KB `mul_8x8` multiplication
  table.
- `LIB_NISTCURVES_REU_BANK_COMB` — bank `$02`, the Lim-Lee fixed-base comb
  anchor tables.

At that point, this project's **generic** whole-device REU features in
`reu_advanced.s` — `fill_reu`/`refill_reu_core` ("wipe/fill entire REU") and
any future whole-REU benchmark feature — become dangerous exactly because
they are generic: they sweep every bank from `0` to `reu_banks` inclusive
with zero concept of "banks a vendored library has already populated with a
precomputed table." An end user (or a scripted benchmark run) that invokes
"wipe REU" or "fill REU with random data" after `c64-nist-curves` has been
vendored and has built its multiply-table/comb caches at boot would silently
DMA-overwrite those banks — the fill routines have no bank-exclusion logic to
skip them, and there would be no error, just silent corruption of the
vendored library's precomputed table on its next read.

**What will need to change, at vendoring time (not now):**

- `fill_reu`/`refill_reu_core` (and any benchmark routine built the same way)
  will need to become bank-aware: before sweeping banks `0..reu_banks`, skip
  any bank claimed by a vendored library's own `LIB_<X>_REU_BANK_*` /
  `LIB_<X>_REU_BANKS_USED` equates (imported from that library's
  `reu_config.s`, per SPEC §3), the same way a consumer composes multiple
  libraries' `REU_BANKS_USED` masks today (SPEC §3's worked example:
  `.assert (LIB_NISTCURVES_REU_BANKS_USED .and LIB_X25519_REU_BANKS_USED) = 0`).
- This is **not an immediate action item**. No library is vendored in this
  round (per `docs/lib_contract_alignment_plan.md`'s "Out of scope for this
  round" section). This paragraph exists so the person who does the actual
  vendoring later finds the risk already documented instead of discovering it
  via a corrupted comb table.

## 3. No `src/reu_config.s` needed today

SPEC §3 requires a `reu_config.s` (or equivalent) only from libraries that
claim REU banks. This project claims none of its own — see §1 above — so no
such file exists in `src/`, and none should be added speculatively. The file
becomes relevant only in one of two future scenarios, neither of which has
happened yet:

1. This project's own crypto code starts using REU for a precompute cache
   (it does not today — AES/ECDSA math here runs entirely in main RAM/ZP,
   matching the non-REU posture of `c64-nist-curves`'/`c64-x25519`'s
   variable-base scalar-mult paths).
2. A vendored library brings its *own* `reu_config.s` (e.g.
   `c64-nist-curves/src/reu_config.s`), which this project would then
   `.import` from and compose against per §2 above — that file lives in the
   vendored library's tree, not this project's.

Until either happens, "no `reu_config.s`" is the correct, compliant state for
this project under SPEC §3.
