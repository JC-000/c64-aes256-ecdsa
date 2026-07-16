#!/usr/bin/env bash
# build.sh - build the real ca65/ld65 port of the C64 AES-256/ECDSA project.
#
# main.s .include's every translated module (src/*.s) in the same order
# as the original ACME src/main.asm, so the whole program assembles as one
# translation unit / one object file. ld65 then links it against
# linker.cfg, which reproduces the ACME build's memory layout ($0801 load
# address, $7800-$7BFF quarter-square table reservation, $7C00 high-memory
# overflow area for the PKCS#10/ECDSA modules).
#
# NOTE: this script is a standalone dev/pilot convenience that writes its
# output into build_ca65/ (labels in ld65's own -Ln format). The canonical
# project build is now `make` at the repo root (see ../Makefile), which
# runs the equivalent ca65/ld65 commands and writes build/aes256keygen.prg +
# build/labels.txt - the paths tools/run_all_tests.py and tools/test_*.py
# expect by default.
#
# Usage: build_ca65/build.sh   (run from anywhere; paths are relative to
# this script's location)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

SRC_DIR="$ROOT/src"
OUT_DIR="$ROOT/build_ca65"

OBJ="$OUT_DIR/aes256keygen.o"
PRG="$OUT_DIR/aes256keygen.prg"
LABELS="$OUT_DIR/aes256keygen.labels"
LISTING="$OUT_DIR/aes256keygen.lst"
MAPFILE="$OUT_DIR/aes256keygen.map"

echo "== Assembling (ca65) =="
ca65 -I "$SRC_DIR" -o "$OBJ" -l "$LISTING" "$SRC_DIR/main.s"

echo "== Linking (ld65) =="
ld65 -C "$HERE/linker.cfg" -o "$PRG" -Ln "$LABELS" -m "$MAPFILE" "$OBJ"

echo "== Done =="
ls -l "$PRG"
