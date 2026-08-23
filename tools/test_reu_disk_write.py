#!/usr/bin/env python3
"""test_reu_disk_write.py - Bug 5 regression: disk-write error must be surfaced.

Bug 5 (see HANDOFF.md "COMPLETED SINCE HANDOFF" item 8): write_block_to_file in
src/reu_advanced.s originally checked KERNAL STATUS with `AND #$80` only (device
not present, bit 7), so a genuine IEC *write-timeout* (STATUS bit 1) was ignored
and the program silently reported a successful save on real data loss. The fix
widened the fatal mask to `AND #$82` (bits 7 and 1) and checks after every byte.

This test guards that fix two ways:

  1. DETERMINISTIC MASK GUARD - reads the actual loaded program bytes and asserts
     the write_block_to_file byte-check is `jsr chrout / jsr readst / AND #$82`
     (opcode bytes 20 D2 FF 20 B7 FF 29 82) and that the regressed
     `AND #$80` form (…29 80) is NOT what guards that site. A future edit
     narrowing the mask back to bit-7-only makes the $82 pattern vanish and
     fails this test - exactly the original bug.

  2. REAL FAILURE INJECTION - drives the key-save UI (which reaches the same
     KERNAL SAVE / STATUS-check disk-write machinery) against a device that is
     not present (drive 9, unattached), and asserts the program surfaces
     "ERROR SAVING FILE!" rather than reporting success - i.e. it does not
     silently claim success on a failed write.

Usage:
    python3 tools/test_reu_disk_write.py

Honors C64_PORT_RANGE_START. Uses the existing build/aes256keygen.prg as-is.
"""

import os
import sys
import tempfile
import time

from c64_test_harness import (
    Labels,
    ScreenGrid,
    ViceConfig,
    ViceInstanceManager,
    dump_screen,
    read_bytes,
    send_key,
    send_text,
    wait_for_text,
    write_bytes,
)
from c64_test_harness.disk import DiskImage

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

PORT_RANGE_START = int(os.environ.get("C64_PORT_RANGE_START", "6541"))
PORT_RANGE_END = PORT_RANGE_START + 20

SAFETY_ADDR = 0x0339
SAFETY_JMP = bytes([0x4C, 0x39, 0x03])

# jsr chrout ($FFD2) ; jsr readst ($FFB7) ; and #$82  -- write_block_to_file's
# per-byte fatal-status check after the Bug 5 fix.
SIG_FIXED = bytes([0x20, 0xD2, 0xFF, 0x20, 0xB7, 0xFF, 0x29, 0x82])
# ...the pre-fix (regressed) form: and #$80 instead.
SIG_REGRESSED = bytes([0x20, 0xD2, 0xFF, 0x20, 0xB7, 0xFF, 0x29, 0x80])

CODE_START = 0x0801
CODE_LEN = 0x7000  # covers the whole ~28 KB program


def test_mask_guard(transport, results):
    """Read the loaded program and assert the $82 fatal mask is intact."""
    mem = read_bytes(transport, CODE_START, CODE_LEN)

    fixed_at = mem.find(SIG_FIXED)
    regressed_at = mem.find(SIG_REGRESSED)
    n_fixed = mem.count(SIG_FIXED)

    fixed_addr = CODE_START + fixed_at if fixed_at >= 0 else -1
    ok = fixed_at >= 0 and regressed_at < 0 and n_fixed == 1
    if ok:
        msg = (f"write_block_to_file check = jsr chrout/readst/AND #$82 at "
               f"${fixed_addr:04X} (mask byte ${mem[fixed_at + 7]:02X}); "
               f"regressed AND #$80 form absent")
    else:
        msg = (f"fixed_present={fixed_at >= 0} (n={n_fixed}) "
               f"regressed_present={regressed_at >= 0} "
               f"-- expected exactly one $82 site and no $80 site")
    results.append(("Bug 5 mask guard: write_block_to_file uses AND #$82 (not #$80)", ok, msg))


def test_write_error_surfaced(transport, results):
    """Drive key-save to a non-present device (drive 9) and confirm the program
    reports ERROR SAVING FILE! rather than silently claiming success."""
    # blank screen so stale success/error text can't satisfy a needle
    write_bytes(transport, 0x0400, bytes([0x20] * 1000))

    send_key(transport, "5")  # 5 = SAVE KEY
    grid = wait_for_text(transport, "DRIVE NUMBER", timeout=20.0, verbose=False)
    if grid is None:
        results.append(("Bug 5 injection: reached drive prompt", False, "no DRIVE NUMBER prompt"))
        return
    time.sleep(0.1)
    send_text(transport, "9")   # device 9 is not attached -> device not present
    send_key(transport, "\r")

    grid = wait_for_text(transport, "FILENAME (AESKEY)", timeout=20.0, verbose=False)
    if grid is None:
        results.append(("Bug 5 injection: reached filename prompt", False, "no FILENAME prompt"))
        return
    time.sleep(0.1)
    send_key(transport, "\r")   # accept default name

    # The KERNAL OPEN to a missing device times out (STATUS bit 7) and OPEN
    # returns carry set -> save_key_to_disk bails to the error path.
    grid = wait_for_text(transport, "ERROR SAVING FILE", timeout=45.0, verbose=False)
    surfaced = grid is not None

    # Whatever happened, make sure the program did NOT falsely claim success.
    check = grid if grid is not None else ScreenGrid.from_transport(transport)
    text = check.continuous_text().upper()
    false_success = ("VERIFICATION OK" in text) or ("FILE SAVED SUCCESSFULLY" in text)

    ok = surfaced and not false_success
    if not ok:
        dump_screen(transport, "Bug 5 injection")
    results.append(
        ("Bug 5 injection: failed write surfaces ERROR (no silent success)",
         ok,
         "ERROR SAVING FILE! shown, no false success" if ok
         else f"error_surfaced={surfaced} false_success={false_success}"))


def main():
    os.chdir(PROJECT_ROOT)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found (build first)")
        sys.exit(2)
    _ = Labels.from_file(LABELS_PATH)  # sanity: labels present

    results = []

    # A disk on drive 8 keeps that drive healthy; the injection deliberately
    # targets drive 9 (unattached) instead.
    fd, dpath = tempfile.mkstemp(prefix="reu_dw_", suffix=".d64")
    os.close(fd)
    os.unlink(dpath)
    disk = DiskImage.create(dpath, name="reudw", disk_id="dw")

    config = ViceConfig(
        prg_path=PRG_PATH, warp=True, ntsc=True, sound=False,
        disk_image=disk, drive_unit=8,
    )
    with ViceInstanceManager(
        config=config,
        port_range_start=PORT_RANGE_START,
        port_range_end=PORT_RANGE_END,
    ) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid} port={inst.port}")
        t = inst.transport
        if wait_for_text(t, "Q=QUIT", timeout=60.0, verbose=False) is None:
            dump_screen(t, "no main menu")
            print("FATAL: main menu never appeared")
            mgr.release(inst)
            sys.exit(2)
        write_bytes(t, SAFETY_ADDR, SAFETY_JMP)

        test_mask_guard(t, results)
        test_write_error_surfaced(t, results)

        mgr.release(inst)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    passed = failed = 0
    for name, ok, msg in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         {msg}")
        if ok:
            passed += 1
        else:
            failed += 1
    print("-" * 60)
    print(f"  {passed}/{passed + failed} passed")
    sys.exit(0 if failed == 0 and passed > 0 else 1)


if __name__ == "__main__":
    main()
