"""Shared utilities for C64 direct-memory test suites."""

import os
import random
import time

from c64_test_harness import ScreenGrid, jsr, run_prg_via_sys, wait_for_text

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRG_PATH = os.environ.get(
    "C64_PRG_PATH", os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
)

SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def robust_jsr(transport, addr, timeout=10.0, retries=3, verbose=False):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                if verbose:
                    print(f"  [retry {attempt+1}/{retries}] jsr(${addr:04X}) failed: {e}")
                time.sleep(0.3)
                continue
            raise


def generate_random_string(min_len=1, max_len=63, rng=None):
    """Generate a random string of safe characters with random length."""
    r = rng or random
    length = r.randint(min_len, max_len)
    return "".join(r.choice(SAFE_CHARS) for _ in range(length))


def generate_random_bytes(length, rng=None):
    """Generate random bytes of the given length."""
    r = rng or random
    return bytes(r.randint(0, 255) for _ in range(length))


def current_screen_text(transport):
    """Snapshot the current screen as continuous text, without resuming."""
    return ScreenGrid.from_transport(transport).continuous_text()


def wait_for_operation(transport, needle, baseline, timeout=30.0, poll_interval=0.5):
    """Wait for *needle* to appear on screen as a result of an operation
    that was just triggered by a keypress, WITHOUT falsely matching text
    that was already sitting on screen (in *baseline*, captured right
    before the triggering keypress) from a previous operation.

    This C64 program's screen is a plain scrolling text console that is
    never cleared between operations, and menu selections/results (e.g.
    the "Q=QUIT" footer, or a completion banner like "ENCRYPTION COMPLETE")
    routinely stay within the visible 25-row window across several
    subsequent operations -- especially in scripts that interleave silent
    direct-memory jsr() calls and program restarts that add no (or
    stale-matching) visible output of their own. Plain wait_for_text()
    only calls transport.resume() when the needle is ABSENT, so it matches
    such leftover text on its very first (non-resuming) check, before the
    CPU ever runs the operation that was just triggered. Requiring the
    screen text to differ from the pre-keypress baseline guarantees at
    least one real resume()+poll cycle happens before a match can be
    accepted, so a match here reflects real, new output.
    """
    start = time.monotonic()
    needle_upper = needle.upper()
    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            return None
        try:
            grid = ScreenGrid.from_transport(transport)
            text = grid.continuous_text()
            if text != baseline and needle_upper in text.upper():
                return grid
        except Exception:
            pass
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(poll_interval)


def restart_program(transport, timeout=60.0, prg_path=None):
    """Put the machine into a known state: a freshly booted main menu.

    Resets the machine, waits for READY., writes the PRG image back into
    RAM and starts it with SYS (harness run_prg_via_sys(), which works on
    VICE and the Ultimate 64 alike), then waits for the main menu. Nothing
    is inherited from whatever ran before -- not the CPU's position (after
    direct jsr() tests it is mid-menu-loop, not in BASIC, since harness
    0.13.0's preserve_state), and not program RAM the direct tests wrote.
    """
    with open(prg_path or PRG_PATH, "rb") as f:
        prg = f.read()
    run_prg_via_sys(transport, prg)
    return wait_for_text(transport, "Q=QUIT", timeout=timeout) is not None


def fresh_scenario(transport, test_fn):
    """Wrap a (ok, msg) scenario so it always starts from restart_program().

    Each scenario establishes its own starting state instead of inheriting
    the screen, menu position or program RAM the previous one left behind
    -- so a failure in one scenario cannot cascade into the next.
    """
    def run():
        if not restart_program(transport):
            return False, "could not boot the program to a fresh main menu"
        return test_fn()
    return run


def let_cpu_run(transport, seconds=0.5):
    """Resume the CPU and give it real execution time.

    Under VICE every monitor command halts the 6510 until resume(), so a
    bare sleep after a read or keypress runs nothing at all. Use this when
    the program must get past a point before the next input -- e.g. through
    main_loop's keyboard-buffer flush after a menu command returns.
    """
    transport.resume()
    time.sleep(seconds)
