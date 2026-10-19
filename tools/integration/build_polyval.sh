#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_polyval.sh - build the c64-polyval sibling archive
# via the library's own contract §6 `lib-polyval-short` target and copy it to
# build/lib/polyval-short.a for the aes256keygen link.
#
# Replaces the in-tree src/polyval.s (deleted): the SHORT archive is fully
# self-contained (its own data.o supplies polyval_h / polyval_temp /
# polyval_htable; its ZP slots are baked numeric equates) and imports nothing
# from this project, so we link it directly with zero source patches. The
# consumer-side obligations are build_ca65/linker.cfg (three §4-prefixed
# segments) and src/gcm_siv.s's .importzp of polyval_acc.
#
# --- Pin ---------------------------------------------------------------------
# libs/polyval is pinned to tag v0.7.1, the first usable tag: v0.7.0 lacks the
# LIB_POLYVAL_NO_AES gate. See the Makefile's c64-polyval block for why.
#
# --- Variant: SHORT, POLYVAL-only ------------------------------------------
# `lib-polyval-short` is (POLYVAL_PROFILE=short x POLYVAL_NO_AES=1): the
# 4-bit Shoup multiply with Tier-1 unrolling, no AES, no GCM-SIV glue. This
# project's GCM-SIV hashes <= 5 blocks per message and rederives H per
# message, which is exactly the workload SHORT is tuned for; LONG's
# ~255k-cycle H precompute and 8.5 KB of tables would be paid per message
# and never amortised. The NO_AES half matters just as much: this project
# ships its own aes_encrypt.s / gcm_siv.s, and the library's data.o gates its
# AES + GCM-SIV buffers behind LIB_POLYVAL_NO_AES (c64-polyval issue #47) --
# without that gate the archive's aes_state / gcmsiv_* exports collide with
# src/data.s's identically-named ones at ld65 ("Duplicate external
# identifier").
#
# --- Invoke the PHONY target, never the archive path -----------------------
# c64-polyval/Makefile:220-237 has a make-PARSE-TIME guard that hard-errors if
# an archive path is named as a goal without the matching (POLYVAL_PROFILE x
# POLYVAL_NO_AES) pair. The phony re-invokes $(MAKE) behind a `clean` with
# both knobs pinned, which is the only invocation shape that produces a
# coherent artifact. Naming build-short/lib/polyval-short.a directly here
# would either trip the guard or (with the pins passed by hand) silently
# archive the LONG multiply under the SHORT name.
#
# --- rm -rf the sibling BUILD_DIR before every build -----------------------
# POLYVAL_PROFILE / POLYVAL_NO_AES are not prerequisites of any object, so
# their values do not participate in make's timestamp comparison: a profile
# switch silently reuses stale .o files. The library's own phony does run
# `make clean`, but only for the BUILD_DIR it was told about -- we wipe it
# here too so a half-built tree from an interrupted run is never an input.
# The library builds in seconds; determinism wins.
#
# --- Defines go through CONTRACT_DEFINES / CONTRACT_ZP_DEFINES -------------
# NEVER through CA65FLAGS. CA65FLAGS is a hard-assign in the library's
# Makefile (`CA65FLAGS = -I src -D POLYVAL_PROFILE=... -g`, then `+=` for the
# contract variables): passing it on the command line clobbers `-I src`, the
# profile define and `-g` all at once.
#
# c64-polyval uses the include/bake-everywhere delivery model -- no library TU
# .importzp's its own slots; each one re-derives them through
# constants_lib.inc -> zp_config.s's .ifndef guards -- so CONTRACT_ZP_DEFINES
# is appended to CA65FLAGS and reaches EVERY member recipe. That is the
# correct scope here: narrowing it to zp_config.o would export the overridden
# address while data.o and polyval_short.o had baked the default, a silent
# mismatch with no diagnostic from anything.
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_ROOT="$PROJECT_ROOT/libs/polyval"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/polyval-short.a"

# A BUILD_DIR of our own, so a developer poking at the submodule by hand
# (`make` there builds the LONG full-AEAD PRG into `build/`) can never leave
# objects that this build would adopt. Kept UNDER `build/` because that is
# what libs/polyval/.gitignore ignores -- a sibling directory like
# `build-consumer-short/` would leave the submodule permanently showing
# untracked content in `git status`.
BUILD_DIR="build/consumer-short"

# --- ZP slot addresses: THE single source of truth -------------------------
#
# c64-polyval defaults these to polyval_acc=$10 (16 B), pv_mul_input=$20
# (16 B), pv_mul_nibble=$30. All three collide with this project's map (see
# src/zp_config.s): $10-$11 is the tail of sha_temp2 and $12 is sha256_round;
# $22-$2B is the whole fp_* bignum pointer block. Relocated into the ZP4 pool
# ($3D-$8F in build_ca65/linker.cfg), verified free by a repo-wide grep for
# zero-page-addressed operands in $40-$60 (zero hits; every $4x/$5x/$60 in
# src/ is an immediate, a .byte table entry, or an `and #$40` bit mask).
#
# These three lines are the ONLY place the addresses are written. Nothing in
# src/ repeats them: the library's own zp_config.o exports polyval_acc /
# pv_mul_input / pv_mul_nibble at whatever value was baked here, and
# src/gcm_siv.s reaches polyval_acc by `.importzp`. There is therefore no
# second copy that could drift out of step -- and the post-check at the
# bottom of this file re-reads the assembled .o to prove the values landed.
#
# `0x` hex, NEVER `$`. A `$`-form value crosses TWO expansion layers inside
# the sibling build (make expands the recipe, then /bin/sh expands the
# resulting command line): `$40` loses `$4` to make, `$$40` survives make and
# is then eaten by the shell as positional parameter $4, and `$$$$40` yields
# the shell's PID. Every one of those failure modes is SILENT -- make, sh,
# ca65 and ld65 all exit 0, and the slot lands at $00 (i.e. on top of the
# 6502's own $00/$01 bank-switch registers) or at a garbage address. `0x`
# has no metacharacter in either layer.
PV_ACC=0x40         # $40-$4F  16-byte POLYVAL accumulator
PV_MUL_INPUT=0x50   # $50-$5F  16-byte multiply input scratch
PV_MUL_NIBBLE=0x60  # $60      1-byte nibble param for polyval_xor_table_entry

# --- Global (non-ZP) defines ----------------------------------------------
# LIB_NO_BARE_EXPORTS=1 (c64-lib-contract SPEC §1/§8.4) suppresses the
# DEPRECATED unprefixed exports -- LIB_VERSION_MAJOR/MINOR/PATCH,
# LIB_ABI_VERSION, LIB_PRECALC_<name>_* -- that every contract library emits
# identically. src/lib_version.s and src/lib_manifest.s in THIS project emit
# the same bare names, so without this define ld65 rejects the link with
# "Duplicate external identifier" the moment the polyval manifest enters it.
# Only the LIB_POLYVAL_*-prefixed forms survive, which is what we want to see
# in build/labels.txt anyway.
#
# NOTE: ZP_CONFIG_NO_EXPORTS=1 is deliberately NOT passed, even though it is
# the natural companion flag and the fleet precedent
# (c64-wireguard/tools/integration/build_x25519.sh) does pass it. In
# c64-polyval at the pinned commit it CANNOT be: src/constants_lib.inc:23
# assigns
#   ZP_CONFIG_NO_EXPORTS = 1
# unguarded (no .ifndef), so a -D of the same name makes every TU that
# includes that header fail with
#   src/constants_lib.inc(23): Error: Symbol 'ZP_CONFIG_NO_EXPORTS' is already defined
# This is the same upstream bug that was c64-x25519#99 (fixed there in
# v0.11.1 by adding the .ifndef guard); in c64-polyval it is still open as
# c64-polyval#50. Re-check it before assuming this constraint still holds:
# https://github.com/JC-000/c64-polyval/issues/50
# Consequence, and why it is harmless here: the library's zp_config.o keeps
# its .exportzp block, so IT supplies polyval_acc / pv_mul_input /
# pv_mul_nibble to the link (and to build/labels.txt, which
# tools/run_all_tests.py requires). src/zp_config.s therefore must NOT also
# define+export those three names -- that, not the exports themselves, is
# what would collide. The other nine names the block exports are all
# `polyval_`-prefixed (polyval_zp_ptr2, polyval_aes_*, polyval_zp_ptr/
# _temp/_count) and collide with nothing on our side; polyval_short.o
# references none of them.
CONTRACT_FLAGS="-D LIB_NO_BARE_EXPORTS=1"
CONTRACT_ZP_FLAGS="-D polyval_acc=$PV_ACC -D pv_mul_input=$PV_MUL_INPUT -D pv_mul_nibble=$PV_MUL_NIBBLE"

if [[ ! -f "$LIB_ROOT/Makefile" ]]; then
    echo "error: $LIB_ROOT is empty -- run 'git submodule update --init libs/polyval'" >&2
    exit 1
fi

rm -rf "${LIB_ROOT:?}/$BUILD_DIR"

make -C "$LIB_ROOT" lib-polyval-short \
    BUILD_DIR="$BUILD_DIR" \
    LIB_DIR="$BUILD_DIR/lib" \
    CONTRACT_DEFINES="$CONTRACT_FLAGS" \
    CONTRACT_ZP_DEFINES="$CONTRACT_ZP_FLAGS"

mkdir -p "$OUT_DIR"
cp "$LIB_ROOT/$BUILD_DIR/lib/polyval-short.a" "$ARCHIVE"

# =============================================================================
# Post-checks: structural od65 dumps of the assembled objects.
#
# Do NOT byte-compare .o or .a files to verify anything here or anywhere
# else: ca65 stamps a wall-clock OPT_DATETIME record into every object, so
# two objects assembled from identical sources with identical flags differ in
# raw bytes. Compare linked PRGs, or od65 dumps like these.
# =============================================================================
fail=0

check_export() {   # check_export <object> <symbol>
    if ! od65 --dump-exports "$LIB_ROOT/$BUILD_DIR/$1.o" | grep -q "\"$2\""; then
        echo "ERROR: $1.o does not export '$2'" >&2
        fail=1
    fi
}

check_zp_value() { # check_zp_value <symbol> <expected-decimal>
    local got
    got=$(od65 --dump-exports "$LIB_ROOT/$BUILD_DIR/zp_config.o" \
          | grep -A2 "\"$1\"" | sed -n 's/.*Value:.*(\([0-9]*\)).*/\1/p' | head -1)
    if [[ "$got" != "$2" ]]; then
        echo "ERROR: zp_config.o exports $1 = ${got:-<absent>}, expected $2." >&2
        echo "       The -D override did not reach ca65 intact -- see the" >&2
        echo "       '0x hex, NEVER \$' note above; a mangled value is silent" >&2
        echo "       everywhere else in the toolchain." >&2
        fail=1
    fi
}

# The nine public POLYVAL routines (c64-polyval API.md). polyval_finalize is
# a bare rts in the SHORT profile (the result is already in polyval_acc) and
# has no caller in this project, but it is part of the published ABI, so its
# absence would mean the wrong member set was archived.
for sym in polyval_init polyval_double polyval_right_shift_1 \
           polyval_shift_left_4 polyval_precompute_table polyval_multiply \
           polyval_xor_table_entry polyval_update polyval_finalize; do
    check_export polyval_short "$sym"
done

# Buffers the archive owns now that src/data.s no longer reserves them.
for sym in polyval_h polyval_temp polyval_htable; do
    check_export data "$sym"
done

# ZP slots: presence AND value. The value check is the one that matters --
# presence alone would pass with all three silently sitting at $00.
check_zp_value polyval_acc    $((PV_ACC))
check_zp_value pv_mul_input   $((PV_MUL_INPUT))
check_zp_value pv_mul_nibble  $((PV_MUL_NIBBLE))

# The bare contract exports MUST be absent: their presence means
# LIB_NO_BARE_EXPORTS did not reach ca65, and the link will fail with
# "Duplicate external identifier" against src/lib_version.s.
if od65 --dump-exports "$LIB_ROOT/$BUILD_DIR/lib_version.o" | grep -q '"LIB_VERSION_MAJOR"'; then
    echo "ERROR: polyval archive still exports the bare LIB_VERSION_MAJOR --" >&2
    echo "       LIB_NO_BARE_EXPORTS=1 did not take effect (SPEC §1)." >&2
    fail=1
fi

if (( fail )); then
    rm -f "$ARCHIVE"
    exit 1
fi

echo "built $ARCHIVE (polyval SHORT, no AES; polyval_acc=$PV_ACC pv_mul_input=$PV_MUL_INPUT pv_mul_nibble=$PV_MUL_NIBBLE)"
