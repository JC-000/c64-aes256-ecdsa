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
MODULES = main boot zp_config lib_version constants data ecdsa_fp \
          polyval prng strings tables der_encode debug_strings \
          aes_encrypt disk_io display hmac_drbg reu_advanced reu_core \
          sha256 sid_config aes_decrypt base64 ecdsa_mod gcm_siv \
          benchmark ecdsa_curve ecdsa_points ecdsa_sign ecdsa_test \
          csr pkcs10_build pkcs10 main_loop

SRC = $(addprefix $(SRC_DIR)/,$(addsuffix .s,$(MODULES)))
OBJECTS = $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(MODULES)))

.PHONY: all clean run verify

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

# Phase 5 note: a real multi-object ld65 link does not reproduce the exact
# byte layout of the old single-.include monolithic build (different
# extraction order vs. original textual position, plus ld65's own object
# layout mechanics) - a byte-diff here is EXPECTED from this point forward,
# not a failure signal. The full functional test suite
# (tools/run_all_tests.py) is the real correctness bar; see
# docs/modular_restructure_plan.md's "Phase 5" section.
verify: $(PRG)
	@cmp -s $(PRG) build/aes256keygen.prg.original && echo "PASS: Binary identical" || echo "FAIL: Binary differs (expected post-Phase-5 - see Makefile comment)"
