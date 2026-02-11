PRG = build/aes256keygen.prg
SRC = src/aes256keygen.asm src/ecdsa_p256.asm
LABELS = build/labels.txt

.PHONY: all clean run

all: $(PRG)

$(PRG): $(SRC) | build
	acme -f cbm -o $(PRG) --vicelabels $(LABELS) src/aes256keygen.asm

build:
	mkdir -p build

run: $(PRG)
	x64sc -autostart $(PRG)

clean:
	rm -f $(PRG) $(LABELS)
