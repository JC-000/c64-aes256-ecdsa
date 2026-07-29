#!/usr/bin/env python3
"""test_reu.py - REU present/absent + menu-'G' status/fill/save coverage.

Closes two test-suite-audit findings (docs/test_suite_audit.md):

  * Coverage: "REU status/fill/save UI (menu 'G') never exercised"
  * Negative-Path: "REU-absent and REU-present paths are both completely dark"

`detect_reu` (src/reu_core.s) runs on every boot and sets `reu_present`
(0/1) and `reu_size_kb` (word), but nothing has ever asserted on it, and no
test ever attached a REU to VICE.  `do_show_reu_status` (src/reu_advanced.s),
reached via main-menu key 'G', is the whole REU status / fill(zero|random) /
save-to-disk feature and is never driven by any script.

This UI-driven test covers three scenarios against real VICE:

  1. REU absent  (default VICE config): assert reu_present==0 from memory,
     drive 'G', confirm the on-screen "REU: NOT PRESENT" report.
  2. REU present (VICE `-reu -reusize <KB>`): assert reu_present==1 and
     reu_size_kb==configured size, then drive 'G' to exercise the status
     display, a zero-fill, and a random-fill.
  3. REU save-to-disk (REU present + a mounted D64): drive 'G', random-fill,
     accept the save prompt, and confirm the write completes and a file
     lands on the image.

Usage:
    python3 tools/test_reu.py [--port-range-start N] [--reu-size-kb KB]

Requires: Python 3.10+, c64_test_harness >= 0.12.4, VICE x64sc.
Uses the existing build/ artifacts as-is (does NOT rebuild).
"""

import argparse
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
from c64_test_harness.disk import DiskFormat, DiskImage

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Port range: honour C64_PORT_RANGE_START so concurrent sibling sessions
# don't collide (see docs/test_suite_audit.md infrastructure-lane finding).
DEFAULT_PORT_RANGE_START = int(os.environ.get("C64_PORT_RANGE_START", "6510"))
PORT_RANGE_SPAN = 8

# Default REU size to attach for the present-path scenarios.
DEFAULT_REU_SIZE_KB = 512

MENU_NEEDLE = "Q=QUIT"          # part of the always-visible menu footer
SCREEN_RAM = 0x0400
SCREEN_LEN = 1000
SCREEN_SPACE = 0x20             # PETSCII/screen-code space


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, cond, desc):
        if cond:
            self.passed += 1
            print(f"    PASS: {desc}")
        else:
            self.failed += 1
            print(f"    FAIL: {desc}")
        return bool(cond)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def read_reu_state(transport, labels):
    """Return (reu_present:int, reu_size_kb:int) read straight from memory."""
    present = read_bytes(transport, labels["reu_present"], 1)[0]
    lo, hi = read_bytes(transport, labels["reu_size_kb"], 2)
    return present, lo | (hi << 8)


def clear_screen_ram(transport):
    """Blank screen RAM so a later wait_for_text() can't match stale text.

    The C64 program never clears the screen between operations, so markers
    printed by a prior menu action linger and would false-positive-match on
    the next poll before the CPU has actually run (the binary monitor only
    resume()s between polls while the needle is absent). Blanking guarantees
    every marker we wait on is freshly printed by the action under test.
    """
    write_bytes(transport, SCREEN_RAM, bytes([SCREEN_SPACE]) * SCREEN_LEN)


def wait_boot(transport, timeout=60.0):
    grid = wait_for_text(transport, MENU_NEEDLE, timeout=timeout, verbose=False)
    return grid is not None


def make_manager(config, port_start):
    return ViceInstanceManager(
        config=config,
        port_range_start=port_start,
        port_range_end=port_start + PORT_RANGE_SPAN,
    )


def drive_fill(transport, results, fill_key, prefix, complete_timeout):
    """From the main menu: press G, answer the fill prompts, wait for done.

    fill_key: "0" for zero-fill, "R" for random-fill.
    Returns the ScreenGrid at "FILL REU?" (for status assertions) or None.
    """
    clear_screen_ram(transport)
    send_key(transport, "G")

    grid = wait_for_text(transport, "FILL REU?", timeout=30.0, verbose=False)
    if not results.check(grid is not None, f"{prefix}: 'G' shows fill prompt"):
        dump_screen(transport, f"{prefix} no fill prompt")
        return None

    send_key(transport, "Y")                      # yes, fill
    ft = wait_for_text(transport, "R=RANDOM", timeout=20.0, verbose=False)
    if not results.check(ft is not None, f"{prefix}: fill-type prompt shown"):
        dump_screen(transport, f"{prefix} no fill-type prompt")
        return grid

    send_key(transport, fill_key)                 # 0=zero / R=random
    done = wait_for_text(
        transport, "FILL COMPLETE", timeout=complete_timeout, verbose=False
    )
    results.check(done is not None, f"{prefix}: fill completes")
    if done is None:
        dump_screen(transport, f"{prefix} fill did not complete")
    return grid


# ---------------------------------------------------------------------------
# Scenario 1: REU absent
# ---------------------------------------------------------------------------

def run_reu_absent(labels, port_start):
    print("\n=== Scenario 1: REU ABSENT (default VICE config) ===")
    results = Results()
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with make_manager(config, port_start) as mgr:
        inst = mgr.acquire()
        print(f"  VICE PID={inst.pid}, port={inst.port}")
        t = inst.transport

        if not results.check(wait_boot(t), "boot: main menu appears"):
            dump_screen(t, "absent boot")
            mgr.release(inst)
            return results

        present, size = read_reu_state(t, labels)
        results.check(present == 0, f"reu_present == 0 (got {present})")
        results.check(size == 0, f"reu_size_kb == 0 (got {size})")

        # Drive menu 'G' -- absent path prints "REU: NOT PRESENT" then returns.
        clear_screen_ram(t)
        send_key(t, "G")
        grid = wait_for_text(t, "NOT PRESENT", timeout=30.0, verbose=False)
        if results.check(grid is not None, "'G' reports REU NOT PRESENT"):
            txt = grid.continuous_text().upper()
            results.check(
                "REU STATUS" in txt, "status header shown on absent path"
            )
        else:
            dump_screen(t, "absent G")

        back = wait_for_text(t, MENU_NEEDLE, timeout=20.0, verbose=False)
        results.check(back is not None, "returns to main menu after 'G'")

        mgr.release(inst)

    return results


# ---------------------------------------------------------------------------
# Scenario 2: REU present (no disk)
# ---------------------------------------------------------------------------

def run_reu_present(labels, port_start, reu_size_kb):
    print(f"\n=== Scenario 2: REU PRESENT ({reu_size_kb} KB, no disk) ===")
    results = Results()
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
        extra_args=["-reu", "-reusize", str(reu_size_kb)],
    )

    with make_manager(config, port_start) as mgr:
        inst = mgr.acquire()
        print(f"  VICE PID={inst.pid}, port={inst.port}")
        t = inst.transport

        if not results.check(wait_boot(t), "boot: main menu appears"):
            dump_screen(t, "present boot")
            mgr.release(inst)
            return results

        present, size = read_reu_state(t, labels)
        results.check(present == 1, f"reu_present == 1 (got {present})")
        results.check(
            size == reu_size_kb,
            f"reu_size_kb == {reu_size_kb} (got {size})",
        )

        # --- G press #1: status display + zero-fill ---
        grid = drive_fill(t, results, "0", "zero-fill", complete_timeout=90.0)
        if grid is not None:
            txt = grid.continuous_text().upper()
            results.check("REU: PRESENT" in txt, "status shows REU: PRESENT")
            results.check(
                f"SIZE: {reu_size_kb} KB" in txt,
                f"status shows SIZE: {reu_size_kb} KB",
            )
        back = wait_for_text(t, MENU_NEEDLE, timeout=20.0, verbose=False)
        results.check(back is not None, "returns to menu after zero-fill")

        # --- G press #2: random-fill (then decline save; no disk) ---
        drive_fill(t, results, "R", "random-fill", complete_timeout=240.0)
        # Random fill offers a save-to-disk prompt.
        save = wait_for_text(t, "SAVE TO DISK", timeout=20.0, verbose=False)
        if results.check(save is not None, "random-fill offers save-to-disk"):
            send_key(t, "N")                      # decline (no disk attached)
        back = wait_for_text(t, MENU_NEEDLE, timeout=20.0, verbose=False)
        results.check(back is not None, "returns to menu after declining save")

        mgr.release(inst)

    return results


# ---------------------------------------------------------------------------
# Scenario 3: REU present + save-to-disk
# ---------------------------------------------------------------------------

def run_reu_save_disk(labels, port_start, reu_size_kb):
    print(f"\n=== Scenario 3: REU PRESENT + save-to-disk ({reu_size_kb} KB) ===")
    results = Results()

    tmpdir = tempfile.mkdtemp(prefix="reu_test_")
    d64_path = os.path.join(tmpdir, "reusave.d64")
    disk = DiskImage.create(
        d64_path, name="REUSAVE", disk_id="01", fmt=DiskFormat.D64
    )

    # Pre-fill most of the image so the save writes only a small number of
    # blocks (the save loop runs until the disk is full); this keeps the IEC
    # write path fast to exercise while still proving it completes end-to-end.
    filler_path = os.path.join(tmpdir, "filler.bin")
    with open(filler_path, "wb") as f:
        f.write(b"\xAA" * 150000)             # ~590 blocks, leaves ~70 free
    disk.write_file(filler_path, "filler")

    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
        extra_args=["-reu", "-reusize", str(reu_size_kb)],
        disk_image=disk,
        drive_unit=8,
    )

    with make_manager(config, port_start) as mgr:
        inst = mgr.acquire()
        print(f"  VICE PID={inst.pid}, port={inst.port}")
        t = inst.transport

        if not results.check(wait_boot(t), "boot: main menu appears"):
            dump_screen(t, "save boot")
            mgr.release(inst)
            return results

        present, _ = read_reu_state(t, labels)
        results.check(present == 1, "reu_present == 1 (with disk config)")

        # Drive G -> random-fill (only random offers save).
        drive_fill(t, results, "R", "save/random-fill", complete_timeout=240.0)

        save = wait_for_text(t, "SAVE TO DISK", timeout=20.0, verbose=False)
        if not results.check(save is not None, "save-to-disk prompt shown"):
            dump_screen(t, "no save prompt")
            mgr.release(inst)
            return results
        send_key(t, "Y")                          # accept save

        drive = wait_for_text(t, "DRIVE NUMBER", timeout=20.0, verbose=False)
        if results.check(drive is not None, "drive-number prompt shown"):
            send_key(t, "\r")                     # Enter -> default drive 8

        fname = wait_for_text(t, "FILENAME", timeout=20.0, verbose=False)
        if results.check(fname is not None, "filename prompt shown"):
            time.sleep(0.1)
            send_text(t, "reusave")
            time.sleep(0.1)
            send_key(t, "\r")

        # Write loop runs until the (nearly-full) disk fills, then reports done.
        done = wait_for_text(t, "SAVE COMPLETE", timeout=240.0, verbose=False)
        if results.check(done is not None, "save reports SAVE COMPLETE"):
            # The block count is printed immediately after "SAVE COMPLETE. ",
            # so wait for it separately rather than asserting on the grid that
            # merely happened to catch the first half of the line.
            count = wait_for_text(
                t, "BLOCKS WRITTEN", timeout=20.0, verbose=False
            )
            results.check(count is not None, "save reports a block count")
        else:
            dump_screen(t, "save did not complete")

        back = wait_for_text(t, MENU_NEEDLE, timeout=20.0, verbose=False)
        results.check(back is not None, "returns to menu after save")

        mgr.release(inst)

    # VICE has exited and flushed the image -- inspect it on the host.
    disk_after = DiskImage(d64_path)
    names = [str(e).lower() for e in disk_after.list_files()]
    results.check(
        any("reusave" in n for n in names),
        f"saved file present on D64 (dir: {names})",
    )

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="REU present/absent + menu-G tests")
    parser.add_argument(
        "--port-range-start",
        type=int,
        default=DEFAULT_PORT_RANGE_START,
        help="First VICE monitor port to try (env C64_PORT_RANGE_START).",
    )
    parser.add_argument(
        "--reu-size-kb",
        type=int,
        default=DEFAULT_REU_SIZE_KB,
        help="REU size to attach for the present-path scenarios.",
    )
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)

    # Use the existing build artifacts as-is (do NOT rebuild).
    for path in (PRG_PATH, LABELS_PATH):
        if not os.path.exists(path):
            print(f"FATAL: {path} not found (build the project first)")
            sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    for name in ("reu_present", "reu_size_kb"):
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(
        f"Labels: reu_present=${labels['reu_present']:04X} "
        f"reu_size_kb=${labels['reu_size_kb']:04X}"
    )

    scenarios = (
        ("REU absent", lambda: run_reu_absent(labels, args.port_range_start)),
        ("REU present", lambda: run_reu_present(
            labels, args.port_range_start, args.reu_size_kb)),
        ("REU save-to-disk", lambda: run_reu_save_disk(
            labels, args.port_range_start, args.reu_size_kb)),
    )

    total = Results()
    timings = []
    for name, run in scenarios:
        started = time.monotonic()
        res = run()
        elapsed = time.monotonic() - started
        timings.append((name, res, elapsed))
        total.passed += res.passed
        total.failed += res.failed
        print(f"  [{name}: {res.passed}/{res.passed + res.failed} passed "
              f"in {elapsed:.1f}s]")

    print("\n=== Per-scenario ===")
    for name, res, elapsed in timings:
        n = res.passed + res.failed
        print(f"  {name:<18} {res.passed}/{n} passed  {elapsed:.1f}s")

    grand = total.passed + total.failed
    print(f"\n=== Results: {total.passed}/{grand} passed "
          f"in {sum(t for _, _, t in timings):.1f}s ===")
    sys.exit(0 if total.failed == 0 else 1)


if __name__ == "__main__":
    main()
