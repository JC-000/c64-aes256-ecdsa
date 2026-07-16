PRG = build/aes256keygen.prg
LABELS = build/labels.txt
OBJ = build/aes256keygen.o
LISTING = build/aes256keygen.lst
MAPFILE = build/aes256keygen.map

LINKER_CFG = build_ca65/linker.cfg

SRC = $(wildcard src/*.s)

.PHONY: all clean run verify

all: $(PRG)

# Build via ca65/ld65 (cc65 suite). Same two-step pipeline as
# build_ca65/build.sh, just targeting build/ instead of build_ca65/ so
# tools/run_all_tests.py and tools/test_*.py find their outputs at the
# paths they've always used.
$(PRG): $(SRC) | build
	ca65 -I src -o $(OBJ) -l $(LISTING) src/main.s
	ld65 -C $(LINKER_CFG) -o $(PRG) -Ln $(LABELS) -m $(MAPFILE) $(OBJ)

build:
	mkdir -p build

run: $(PRG)
	x64sc -autostart $(PRG)

clean:
	rm -f $(PRG) $(LABELS) $(OBJ) $(LISTING) $(MAPFILE)

verify: $(PRG)
	@cmp -s $(PRG) build/aes256keygen.prg.original && echo "PASS: Binary identical" || echo "FAIL: Binary differs!"
