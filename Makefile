PRG = build/aes256keygen.prg
LABELS = build/labels.txt

SRC = $(wildcard src/*.asm)

.PHONY: all clean run verify

all: $(PRG)

$(PRG): $(SRC) | build
	cd src && acme -f cbm -o ../$(PRG) --vicelabels ../$(LABELS) main.asm

build:
	mkdir -p build

run: $(PRG)
	x64sc -autostart $(PRG)

clean:
	rm -f $(PRG) $(LABELS)

verify: $(PRG)
	@cmp -s $(PRG) build/aes256keygen.prg.original && echo "PASS: Binary identical" || echo "FAIL: Binary differs!"
