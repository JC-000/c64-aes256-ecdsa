PRG = build/aes256keygen.prg
LABELS = build/labels.txt
MAPFILE = build/aes256keygen.map

LINKER_CFG = build_ca65/linker.cfg

SRC_DIR = src
BUILD_DIR = build

# Modules built as real, separately-assembled ca65 objects (Phase 5,
# docs/modular_restructure_plan.md - this MODULES list is the final Phase 5
# state: all 32 src/*.s modules are real objects, src/remainder.s is gone).
# main.o first for LOADADDR.
#
# boot.o MUST come immediately after main.o, before every other object:
# src/boot.s's BASIC stub hardcodes "SYS 2064" as a literal ASCII byte
# string (not a symbolic reference to `start`), which only lands on the
# real `start` label if boot.s's basic_stub is the very first thing
# ca65/ld65 place in the CODE segment right after the 2-byte LOADADDR
# header - i.e. boot.o must be the first object to contribute real
# CODE-segment bytes. Discovered directly (2026-07-18, batch 1): an
# earlier ordering here put data.o/ecdsa_fp.o/etc. before the
# then-current holder of boot.s's code (src/remainder.s, since deleted),
# which pushed basic_stub off of $0801 and made "RUN" jump into the middle
# of unrelated data - the full test suite's main menu never appeared.
# zp_config.o/lib_version.o/constants.o are pure equates (zero bytes
# emitted into CODE) so their position never matters; every other module
# emits real bytes and so must stay after boot.o. This SYS-address
# fragility is pre-existing (not introduced by Phase 5) - see boot.s's
# comment documenting the same "$0810"/"2064" pairing - but only Phase 5's
# multi-object reordering was able to disturb it.
MODULES = main boot zp_config lib_version precalc_manifest lib_manifest constants data ecdsa_fp \
          polyval prng strings tables der_encode debug_strings \
          aes_encrypt disk_io display hmac_drbg reu_advanced reu_core \
          sha256 sid_config aes_decrypt base64 ecdsa_mod gcm_siv \
          benchmark ecdsa_curve ecdsa_points ecdsa_sign ecdsa_test \
          csr pkcs10_build pkcs10 main_loop

SRC = $(addprefix $(SRC_DIR)/,$(addsuffix .s,$(MODULES)))
OBJECTS = $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(MODULES)))

LIB_DIR = $(BUILD_DIR)/lib

.PHONY: all clean run verify lib lib-ecdsa-sign

all: $(PRG)

# Build via ca65/ld65 (cc65 suite): assemble every module to its own .o,
# then link them all in one ld65 invocation. Mirrors c64-nist-curves/
# Makefile's MODULES/pattern-rule shape.
$(PRG): $(OBJECTS) $(LINKER_CFG) | $(BUILD_DIR)
	ld65 -C $(LINKER_CFG) -o $(PRG) -Ln $(LABELS) -m $(MAPFILE) $(OBJECTS)

# Pattern rule: assemble each src/%.s to build/%.o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s | $(BUILD_DIR)
	ca65 -I $(SRC_DIR) -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

run: $(PRG)
	x64sc -autostart $(PRG)

clean:
	rm -f $(PRG) $(LABELS) $(MAPFILE) $(OBJECTS)
	rm -rf $(LIB_DIR)

# --- Library archives (c64-lib-contract SPEC §6) -----------------------------
#
# Phase D of docs/lib_contract_alignment_plan.md. Consumers fetch one of
# these .a files and link directly against build_ca65/linker.cfg's
# LIB_AES256ECDSA_* segments -- no source patching. Modeled closely on
# c64-nist-curves/Makefile's "Library archives" section (the reference
# adopter implementation); see that file for the sibling project's own
# per-curve variant set.
#
#   aes256ecdsa.a             -- full archive: every module this project
#                                 ships EXCEPT main.o and boot.o. Neither is
#                                 imported by any other module (exports.inc:
#                                 boot.s "EXPORTS: (none...)"; main.s carries
#                                 no EXPORTS at all -- it is only the 2-byte
#                                 LOADADDR stub) -- a consumer supplies its
#                                 own PRG entry point and BASIC/SYS
#                                 trampoline, exactly the role c64-nist-
#                                 curves' excluded main.o plays for that
#                                 project's own test-driver PRG.
#
#                                 ecdsa_test.s and debug_strings.s are KEPT,
#                                 unlike nist-curves' excluded data_test.o:
#                                 both have real production callers inside
#                                 this archive, not just test-harness
#                                 callers. csr.s's do_generate_csr
#                                 unconditionally jsrs ecdsa_test.s's
#                                 do_ecdsa_test as a pre-flight RFC-6979
#                                 known-answer self-check (menu J -> 2) before
#                                 it will sign a CSR (src/lib_manifest.s's own
#                                 SPEC §5 COLD_BYTES writeup independently
#                                 confirms do_ecdsa_test is reachable only
#                                 from that one call site, not dead code).
#                                 aes_decrypt.s/aes_encrypt.s/boot.s all jsr
#                                 debug_strings.s message labels from their
#                                 normal (non-test) execution paths. Excluding
#                                 either module would leave those callers
#                                 with unresolved externals the moment a
#                                 consumer pulls csr.o/aes_decrypt.o/
#                                 aes_encrypt.o out of this archive -- unlike
#                                 nist-curves' data_test.o, which has zero
#                                 callers inside the library proper.
#
#   aes256ecdsa-ecdsa-sign.a  -- ECDSA sign only: this project's most
#                                 distinctive capability versus the rest of
#                                 the c64-lib-contract ecosystem
#                                 (c64-nist-curves ships ECDSA VERIFY only;
#                                 this project's RFC-6979-style deterministic
#                                 k generation + ECDSA SIGN is genuinely
#                                 unique in the ecosystem). Object set traced
#                                 from src/exports.inc's IMPORTS lists (the
#                                 authoritative, verified module dependency
#                                 map) as the actual transitive closure
#                                 ecdsa_sign.s needs to link and run:
#                                   zp_config.o     - ZP equates (SPEC §2)
#                                   lib_version.o   - LIB_VERSION_*/
#                                                     LIB_ABI_VERSION (§1)
#                                   lib_manifest.o  - aggregate manifest
#                                                     equates (§5)
#                                   precalc_manifest.o - precalc-table
#                                                     enumeration (§8.0);
#                                                     zero code cost, pure
#                                                     equates like the three
#                                                     above
#                                   constants.o     - chrout; pulled in by
#                                                     ecdsa_mod.o and
#                                                     ecdsa_points.o
#                                   ecdsa_fp.o      - leaf field primitives
#                                                     (fp_add/fp_mul/...) +
#                                                     fp_wide; zero outgoing
#                                                     edges per exports.inc
#                                   ecdsa_mod.o     - modular arithmetic
#                                                     (fp_mod_*), needs
#                                                     ecdsa_fp.o + constants.o
#                                   ecdsa_curve.o   - curve params + point
#                                                     scratch (ec_p*/ec_t*),
#                                                     needs ecdsa_mod.o +
#                                                     ecdsa_fp.o
#                                   ecdsa_points.o  - point add/double/
#                                                     scalar-mul, needs
#                                                     ecdsa_curve.o +
#                                                     ecdsa_mod.o + ecdsa_fp.o
#                                                     + constants.o
#                                   ecdsa_sign.o    - itself
#                                 Deliberately does NOT include hmac_drbg.o /
#                                 sha256.o: per exports.inc, ecdsa_sign.s's
#                                 own IMPORTS line has no hmac_drbg.s edge --
#                                 it consumes k as an already-populated
#                                 pointer (ecdsa_k_ptr) rather than deriving
#                                 it itself. The HMAC-DRBG k-derivation +
#                                 SHA-256 wiring is a caller-level concern
#                                 (see src/pkcs10.s, which imports both
#                                 hmac_drbg.s and ecdsa_sign.s and wires them
#                                 together at the CSR-signing call site) --
#                                 verified directly against exports.inc
#                                 rather than assumed from this file's own
#                                 name.
#
#                                 CAVEAT -- NOT linkable alone as packaged.
#                                 Two debug/progress-print jsrs are
#                                 unconditionally compiled into the crypto
#                                 hot path and were found only by tracing
#                                 exports.inc's real IMPORTS lines (not by
#                                 trusting the hand-designed starting set
#                                 above): ecdsa_points.s's ec_show_progress
#                                 (called from ec_scalar_mul's per-bit loop)
#                                 jsrs disk_io.s::print_decimal, and
#                                 ecdsa_mod.s's fp_mod_inv debug-hex-dump path
#                                 jsrs display.s::print_hex_byte -- both
#                                 confirmed by direct grep of the two source
#                                 files, not just the exports.inc summary.
#                                 disk_io.s is itself a member of exports.inc's
#                                 8-module circular dependency group 1
#                                 (aes_encrypt.s, disk_io.s, display.s,
#                                 hmac_drbg.s, reu_advanced.s, reu_core.s,
#                                 sha256.s, sid_config.s): pulling disk_io.o
#                                 into this archive to satisfy one routine
#                                 call would drag in that entire group's
#                                 mutual .o-granularity dependencies at ar65's
#                                 whole-object linking grain, ballooning this
#                                 "minimal" archive back to most of the
#                                 application. This archive therefore ships
#                                 the true minimal object set from the
#                                 dependency trace above rather than papering
#                                 over the gap with the circular group;
#                                 verified directly (2026-07-20) via a
#                                 standalone `ld65` link attempt against only
#                                 this archive + build_ca65/linker.cfg, which
#                                 fails with:
#                                   Unresolved external 'print_decimal' referenced in:
#                                     src/ecdsa_points.s(825)
#                                   Unresolved external 'print_hex_byte' referenced in:
#                                     src/ecdsa_mod.s(473), (475), (491), (493)
#                                   ld65: Error: 2 unresolved external(s) found - cannot create output file
#                                 A consumer that wants a link-clean sign-only
#                                 archive today must either (a) link the full
#                                 `aes256ecdsa.a` instead of this trimmed one,
#                                 or (b) wait for a follow-up that strips the
#                                 two debug-print call sites behind a
#                                 build-time flag -- already flagged
#                                 independently in exports.inc's own
#                                 ecdsa_mod.s notes as "a candidate for a
#                                 conditional/feature-flag strip".
#
# Object-set composition is computed below as Make variables so the
# inventory stays self-describing, matching c64-nist-curves' pattern.

LIB_FULL_OBJS = $(filter-out $(BUILD_DIR)/main.o $(BUILD_DIR)/boot.o,$(OBJECTS))

# Shared contract-equate objects every archive includes: version + manifest
# + precalc-table enumeration + zp config (SPEC §1/§5/§8.0/§2). All four are
# pure-equate translation units (zero CODE-segment bytes emitted) so
# including them in the minimal ecdsa-sign archive below costs nothing.
LIB_CORE_OBJS = $(BUILD_DIR)/zp_config.o $(BUILD_DIR)/lib_version.o \
                $(BUILD_DIR)/lib_manifest.o $(BUILD_DIR)/precalc_manifest.o

# Minimal ECDSA-sign object set -- see the comment block above for the full
# exports.inc trace and the standalone-linkability caveat this archive ships
# with.
LIB_ECDSA_SIGN_OBJS = $(LIB_CORE_OBJS) $(BUILD_DIR)/constants.o \
                $(BUILD_DIR)/ecdsa_fp.o $(BUILD_DIR)/ecdsa_mod.o \
                $(BUILD_DIR)/ecdsa_curve.o $(BUILD_DIR)/ecdsa_points.o \
                $(BUILD_DIR)/ecdsa_sign.o

lib:            $(LIB_DIR)/aes256ecdsa.a
lib-ecdsa-sign: $(LIB_DIR)/aes256ecdsa-ecdsa-sign.a

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

# ar65 a <archive> <objs>... creates / appends; rm -f first so each rebuild
# starts from an empty archive (ar65 has no replace-all flag) -- same
# pattern as c64-nist-curves/Makefile.
$(LIB_DIR)/aes256ecdsa.a: $(LIB_FULL_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_FULL_OBJS)

$(LIB_DIR)/aes256ecdsa-ecdsa-sign.a: $(LIB_ECDSA_SIGN_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_ECDSA_SIGN_OBJS)

# Phase 5 note: a real multi-object ld65 link does not reproduce the exact
# byte layout of the old single-.include monolithic build (different
# extraction order vs. original textual position, plus ld65's own object
# layout mechanics) - a byte-diff here is EXPECTED from this point forward,
# not a failure signal. The full functional test suite
# (tools/run_all_tests.py) is the real correctness bar; see
# docs/modular_restructure_plan.md's "Phase 5" section.
verify: $(PRG)
	@cmp -s $(PRG) build/aes256keygen.prg.original && echo "PASS: Binary identical" || echo "FAIL: Binary differs (expected post-Phase-5 - see Makefile comment)"
