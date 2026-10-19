#!/usr/bin/env python3
"""
check_boot_position.py - assert the boot.o link-position invariant

src/boot.s's BASIC stub hardcodes its SYS target as a literal ASCII digit
string, not a symbolic reference to `start` (ca65 cannot render a link-time
address as decimal text at assembly time, so there is no way to make it
symbolic). Two independent things therefore have to line up, and ld65 checks
neither:

  1. boot.o must be the first object to contribute real CODE-segment bytes
     after main.o's 2-byte LOADADDR stub, or the BASIC stub is not at $0801
     and "RUN" jumps into garbage. This happened once already during the
     modular restructure (docs/modular_restructure_plan.md, Phase 5 batch 1).

  2. The digits inside that stub must name the address `start` actually
     landed on. If they do not, RUN jumps somewhere near `start` but not at
     it -- past the first instructions, or into the middle of one.

WHAT THIS FILE USED TO DO, AND WHY IT IS NOW WRITTEN THIS WAY
------------------------------------------------------------
Until 2026-08-23 this script hardcoded

    EXPECTED_START_ADDR = 0x080D  # $0801 + 12-byte BASIC stub

and separately hardcoded the stub bytes containing "2064" -- while its own
failure message for that check read "SYS 2064 will not reach `start`". Those
two constants disagree: "2064" is $0810, `start` was $080D, and the gate
passed that off-by-3 for the entire life of the file. The real consequence
was live in every build: SYS landed 3 bytes into `start`, skipping its
`jsr clrscr`, which is why the program never cleared the screen on RUN.

So the check no longer hardcodes either side. It PARSES the SYS digits out of
the built image and compares them against the `start` label ld65 actually
emitted. A stub and a `start` that disagree cannot both be "expected" any
more, because the expectation is now the relationship between them rather than
two independently-written constants that can drift apart. Concretely: this
version fails against the old "2064" stub, which is the property the previous
version lacked.

Independent of `make verify` (which compares against a pre-Phase-5 snapshot
and is expected to always report "differs" post-restructure -- see the
Makefile comment on that target) and independent of the full VICE test suite
(which would only eventually surface a broken boot as a generic 60s menu-wait
timeout with no message pointing at the real cause).

Exit 0 on success, exit 1 with a clear message on failure.
"""

import os
import sys

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

LOADADDR = 0x0801           # C64 BASIC start-of-program
SYS_TOKEN = 0x9E            # BASIC's SYS keyword token


class StubError(Exception):
    """The bytes at $0801 are not a parseable `<line> SYS <digits>` stub."""


def parse_basic_stub(body):
    """Parse the BASIC stub at the head of the PRG body (post-LOADADDR).

    Returns (sys_target, line_number, next_line_ptr, stub_len).
    Raises StubError with a specific reason if the bytes are not a stub --
    which is the signature of boot.o no longer being the first object to emit
    CODE-segment bytes.
    """
    if len(body) < 8:
        raise StubError(f"image is only {len(body)} bytes; too short to hold a BASIC stub")

    next_line_ptr = body[0] | (body[1] << 8)
    line_number = body[2] | (body[3] << 8)

    if body[4] != SYS_TOKEN:
        raise StubError(
            f"expected the SYS token ${SYS_TOKEN:02X} at $0805, found ${body[4]:02X}"
        )

    digits = bytearray()
    i = 5
    while i < len(body) and body[i] != 0x00:
        digits.append(body[i])
        i += 1
    if i >= len(body):
        raise StubError("BASIC line is not terminated by $00")
    if not digits:
        raise StubError("SYS token is followed by no address digits")

    text = digits.decode("ascii", errors="replace")
    if not text.isdigit():
        raise StubError(f"SYS operand {text!r} is not a decimal number")

    i += 1  # step over the $00 end-of-line
    if i + 2 > len(body):
        raise StubError("image ends before the end-of-program marker")
    if body[i] != 0x00 or body[i + 1] != 0x00:
        raise StubError(
            "expected the $0000 end-of-program marker after the BASIC line, "
            f"found ${body[i]:02X}{body[i + 1]:02X}"
        )

    return int(text), line_number, next_line_ptr, i + 2


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
    for path in (PRG_PATH, LABELS_PATH):
        if not os.path.exists(path):
            print(f"FATAL: {path} not found -- build first")
            return 1

    with open(PRG_PATH, "rb") as f:
        data = f.read()

    errors = []

    load_addr = data[0] | (data[1] << 8)
    if load_addr != LOADADDR:
        errors.append(
            f"LOADADDR is ${load_addr:04X}, expected ${LOADADDR:04X} -- main.o is "
            "no longer supplying the load address, or is not linked first"
        )

    labels = read_labels(LABELS_PATH)
    start_addr = labels.get("start")
    basic_stub_addr = labels.get("basic_stub")

    # --- Invariant 1: the stub is at $0801, i.e. boot.o came first ----------
    if basic_stub_addr is None:
        errors.append("labels.txt has no `basic_stub` symbol")
    elif basic_stub_addr != LOADADDR:
        errors.append(
            f"labels.txt: basic_stub = ${basic_stub_addr:04X}, expected ${LOADADDR:04X} "
            "-- boot.o is no longer the first object contributing CODE-segment "
            'bytes after main.o, so "RUN" would jump into garbage'
        )

    if start_addr is None:
        errors.append("labels.txt has no `start` symbol")

    # --- Invariant 2: the stub's SYS digits name `start` exactly ------------
    stub = None
    try:
        stub = parse_basic_stub(data[2:])
    except StubError as exc:
        errors.append(
            f"the bytes at ${LOADADDR:04X} are not a valid BASIC SYS stub ({exc}) "
            "-- almost certainly boot.o is no longer the first object "
            "contributing CODE-segment bytes after main.o"
        )

    if stub is not None and start_addr is not None:
        sys_target, line_number, next_line_ptr, stub_len = stub
        implied_start = LOADADDR + stub_len

        if sys_target != start_addr:
            delta = sys_target - start_addr
            errors.append(
                f"the BASIC stub says SYS {sys_target} (${sys_target:04X}) but "
                f"`start` is at ${start_addr:04X} -- SYS misses it by {delta:+d} "
                "bytes.\n"
                "    RUN would begin execution part-way into `start`, skipping "
                "or splitting its first instruction(s).\n"
                f'    Fix: src/boot.s\'s stub should read .byte "{start_addr}".'
            )

        if implied_start != start_addr:
            errors.append(
                f"the stub occupies {stub_len} bytes, so `start` should follow it "
                f"at ${implied_start:04X}, but labels.txt puts `start` at "
                f"${start_addr:04X} -- something is being linked between the "
                "BASIC stub and boot.s's entry code"
            )

        expected_ptr = LOADADDR + stub_len - 2
        if next_line_ptr != expected_ptr:
            errors.append(
                f"the stub's next-line pointer is ${next_line_ptr:04X}, expected "
                f"${expected_ptr:04X} (the end-of-program marker) -- the BASIC "
                "line header does not match the line's actual length"
            )

    if errors:
        print("FAIL: boot.o link-position invariant VIOLATED")
        for e in errors:
            print(f"  - {e}")
        print(
            "\nCheck the Makefile's MODULES list (boot.o must immediately follow "
            "main.o and precede every module that emits real CODE-segment "
            "bytes), and src/boot.s's basic_stub digits."
        )
        return 1

    sys_target, line_number, next_line_ptr, stub_len = stub
    print(
        f"PASS: boot.o link-position invariant holds "
        f"(basic_stub = ${LOADADDR:04X}, {stub_len}-byte stub, "
        f"SYS {sys_target} -> start = ${start_addr:04X})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
