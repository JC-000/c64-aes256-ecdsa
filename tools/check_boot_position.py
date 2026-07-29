#!/usr/bin/env python3
"""
check_boot_position.py - assert the boot.o link-position invariant

src/boot.s's BASIC stub hardcodes "SYS 2064" as a literal ASCII byte string,
not a symbolic reference to `start` (see the Makefile's MODULES comment and
src/boot.s's own header comment for the full story). This only produces a
working PRG if boot.o is the first object to contribute real CODE-segment
bytes after main.o's 2-byte LOADADDR stub -- ld65 does not error on module
reordering that breaks this, so a build that silently jumps into garbage on
RUN still reports success. This happened once already during the modular
restructure (docs/modular_restructure_plan.md, Phase 5 batch 1).

This check reads the built .prg directly and confirms the BASIC stub bytes
land exactly where basic_stub/start must be for "SYS 2064" to work, plus
cross-checks build/labels.txt agrees. It is independent of `make verify`
(which compares against a pre-Phase-5 snapshot and is expected to always
report "differs" post-restructure -- see the Makefile comment on that
target) and independent of the full VICE test suite (which would only
eventually surface this as a generic 60s menu-wait timeout with no message
pointing at the real cause).

Exit 0 on success, exit 1 with a clear message on failure.
"""

import os
import sys

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Bytes 2.. of the .prg, immediately following the 2-byte LOADADDR header:
# a BASIC line "10 SYS 2064" followed by the end-of-program marker.
#   word  basic_end (next-line pointer) = $080B -> 0b 08
#   word  10 (line number)              -> 0a 00
#   byte  $9E (SYS token)
#   bytes "2064" (ASCII)
#   byte  0 (end of line)
#   word  0 (end of BASIC program)
EXPECTED_STUB = bytes([0x0B, 0x08, 0x0A, 0x00, 0x9E]) + b"2064" + bytes([0x00, 0x00, 0x00])
LOADADDR = bytes([0x01, 0x08])  # $0801, little-endian
EXPECTED_START_ADDR = 0x080D  # $0801 + 12-byte BASIC stub


def read_labels(path):
    labels = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            # ld65 -Ln format: "al 0000XXXX .name"
            if len(parts) == 3 and parts[0] == "al" and parts[2].startswith("."):
                labels[parts[2][1:]] = int(parts[1], 16)
    return labels


def main():
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found -- build first")
        return 1
    if not os.path.exists(LABELS_PATH):
        print(f"FATAL: {LABELS_PATH} not found -- build first")
        return 1

    with open(PRG_PATH, "rb") as f:
        data = f.read()

    errors = []

    if data[:2] != LOADADDR:
        errors.append(
            f"LOADADDR mismatch: expected {LOADADDR.hex()}, got {data[:2].hex()}"
        )

    actual_stub = data[2:2 + len(EXPECTED_STUB)]
    if actual_stub != EXPECTED_STUB:
        errors.append(
            "BASIC stub bytes mismatch immediately after LOADADDR -- boot.o "
            "is very likely no longer the first object contributing "
            "CODE-segment bytes after main.o. \"SYS 2064\" would jump into "
            "garbage on RUN.\n"
            f"    expected: {EXPECTED_STUB.hex()}\n"
            f"    actual:   {actual_stub.hex()}"
        )

    def fmt_addr(addr):
        return f"{addr:#06x}" if addr is not None else "MISSING"

    labels = read_labels(LABELS_PATH)
    start_addr = labels.get("start")
    basic_stub_addr = labels.get("basic_stub")
    if basic_stub_addr != 0x0801:
        errors.append(
            f"labels.txt: basic_stub = {fmt_addr(basic_stub_addr)}, expected $0801"
        )
    if start_addr != EXPECTED_START_ADDR:
        errors.append(
            f"labels.txt: start = {fmt_addr(start_addr)}, "
            f"expected {EXPECTED_START_ADDR:#06x} -- SYS 2064 will not reach `start`"
        )

    if errors:
        print("FAIL: boot.o link-position invariant VIOLATED")
        for e in errors:
            print(f"  - {e}")
        print(
            "\nCheck the Makefile's MODULES list: boot.o must immediately "
            "follow main.o and precede every module that emits real "
            "CODE-segment bytes."
        )
        return 1

    print(f"PASS: boot.o link-position invariant holds (start = ${start_addr:04X})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
