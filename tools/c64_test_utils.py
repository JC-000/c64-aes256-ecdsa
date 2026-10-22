"""Shared utilities for C64 direct-memory test suites."""

import os
import random
import time
from types import SimpleNamespace

from c64_test_harness import (
    ScreenGrid,
    jsr,
    run_prg_via_sys,
    run_subroutine,
    send_key,
    wait_for_text,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRG_PATH = os.environ.get(
    "C64_PRG_PATH", os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
)

SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def is_hardware(transport):
    """True when *transport* drives an Ultimate 64 / C64 Ultimate, not VICE."""
    return isinstance(transport, Ultimate64Transport)


def robust_jsr(transport, addr, timeout=10.0, retries=3, verbose=False):
    """Call the routine at *addr* and wait for it to return.

    VICE: jsr() with retry for transient connection failures.

    Ultimate hardware: the harness's run_subroutine(), which types SYS into
    a small trampoline, so the machine must be at a BASIC READY. prompt
    (prepare_direct_tests() puts it there). Never retried: on real hardware
    a timeout can mean the routine ran partway, and re-running it would
    test something else.
    """
    if is_hardware(transport):
        run_subroutine(SimpleNamespace(transport=transport), addr, timeout=timeout)
        return None
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


def wait_for_ready_prompt(transport, baseline, timeout=30.0, poll_interval=0.5):
    """Wait until the screen has changed from *baseline* and its last
    non-blank line is BASIC's READY. prompt.

    Stricter than looking for "READY." anywhere: an old READY. line can stay
    on screen, and a blinking cursor alone makes the screen differ from the
    baseline.
    """
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            grid = ScreenGrid.from_transport(transport)
            lines = [l.strip() for l in grid.text_lines() if l.strip()]
            if grid.continuous_text() != baseline and lines and lines[-1] == "READY.":
                return True
        except Exception:
            pass
        try:
            transport.resume()
        except Exception:
            pass
        time.sleep(poll_interval)
    return False


def prepare_direct_tests(transport, timeout=60.0):
    """Put the machine into the state direct-memory tests need.

    Boots the program fresh (restart_program()), so its start-up work has
    run -- key and IV generated, key schedule expanded, the quarter-square
    tables built -- and then, on hardware, quits to BASIC with the menu's Q,
    because run_subroutine() starts each routine by typing SYS at READY.
    VICE's jsr() can call into the running menu, so there it stops after
    the fresh boot.
    """
    if not restart_program(transport, timeout=timeout):
        return False
    if not is_hardware(transport):
        return True
    let_cpu_run(transport)  # past main_loop's keyboard-buffer flush
    baseline = current_screen_text(transport)
    send_key(transport, "q")
    return wait_for_ready_prompt(transport, baseline, timeout=timeout)
