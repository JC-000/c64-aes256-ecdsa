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


# ---------------------------------------------------------------------------
# Hardware selection and per-phase machine setup (VICE or Ultimate)
# ---------------------------------------------------------------------------

# --backend u64 candidates, in preference order: the U64E (ethernet, then
# WiFi), then the C64 Ultimate (ethernet). Each device is listed with all its
# addresses in ~/.config/c64-test-harness/devices.toml, so every spelling of
# a device takes the same DeviceLock.
HARDWARE_HOSTS = ["10.43.23.81", "10.43.23.83", "10.43.23.26"]
# How long to queue behind another lane's hold. A live, heartbeating holder
# extends this anyway; it only bounds the wait on a wedged or dead one.
HARDWARE_LOCK_TIMEOUT = 3600.0


def choose_hardware_host():
    """U64_HOST if set, else the first reachable HARDWARE_HOSTS address
    whose device nobody holds.

    Reachability is the harness's GET-only probe (ping + TCP + REST info),
    which writes nothing. If every reachable device is held, queue on the
    first reachable one: the DeviceLock wait extends while its holder is
    alive and heartbeating. None if nothing answers.
    """
    from c64_test_harness import device_lock_holder, is_u64_reachable

    host = os.environ.get("U64_HOST")
    if host:
        return host
    reachable = []
    for candidate in HARDWARE_HOSTS:
        if not is_u64_reachable(candidate):
            print(f"  {candidate}: not reachable -- trying the next address")
            continue
        reachable.append(candidate)
        holder = device_lock_holder(candidate)
        if holder is None:
            return candidate
        print(f"  {candidate}: held by PID {holder.get('pid')} -- trying the next device")
    if not reachable:
        return None
    print(f"  every reachable device is held; queueing for {reachable[0]}")
    return reachable[0]


def _drive_slots(client):
    """{'a': {...}, 'b': {...}} from GET /v1/drives."""
    slots = {}
    for entry in client.list_drives().get("drives", []):
        slots.update(entry)
    return slots


def unmount_flushed(client, drive, timeout=30.0):
    """Unmount *drive* once the Ultimate has written its last track back.

    Like VICE, the Ultimate's 1541 writes a modified track back to the image
    file only when the head leaves it or the write-busy timeout after the
    last write expires (c1541.cc poll()). Until then the REST remove is
    refused with 403 "Disk has been modified, save first" -- which a save
    that ends on the directory track hits every time. Retry until the
    write-back lands, rather than lose the drive's last writes.
    """
    from c64_test_harness.backends.ultimate64_client import Ultimate64AuthError

    deadline = time.monotonic() + timeout
    while True:
        try:
            client.unmount_disk(drive)
            return
        except Ultimate64AuthError as e:
            if "modified" not in str(e) or time.monotonic() >= deadline:
                raise
            time.sleep(1.0)


class BootError(RuntimeError):
    """A Bench phase could not bring the program up to its main menu."""


class Bench:
    """Where a script's phases run, each from a known machine state.

    VICE: every phase() gets a fresh emulator built from that phase's
    config (REU, disk on drive 8), and the disk image is flushed when the
    emulator exits.

    Ultimate hardware (backend="u64"): one device, chosen by
    choose_hardware_host() and held under its DeviceLock for the whole
    script. Each phase() sets the REU it asks for (then a machine reboot,
    which is what re-initialises the REU), uploads its disk image to the
    device's storage over FTP and mounts it on drive A, and boots the
    program fresh. On leaving the phase the image is unmounted and fetched
    back over the original local file, so host-side checks read what the
    drive wrote. Nothing here uses a REST upload, so a C64 Ultimate's /Temp
    gains nothing. Runs at 1 MHz: these phases are about real drive and
    REU timing. The turbo/REU/cartridge config and drive B are put back on
    exit.
    """

    def __init__(self, backend="vice", port_range_start=6541, port_range_span=20,
                 prg_path=None):
        self.backend = backend
        self.port_range_start = port_range_start
        self.port_range_span = port_range_span
        self.prg_path = prg_path or PRG_PATH
        self._stack = None
        self.host = None
        self.transport = None

    @property
    def hardware(self):
        return self.backend == "u64"

    def __enter__(self):
        if not self.hardware:
            return self
        from contextlib import ExitStack

        from c64_test_harness import create_manager
        from c64_test_harness.backends.ultimate64_helpers import (
            restore_state,
            snapshot_state,
        )

        self.host = choose_hardware_host()
        if self.host is None:
            raise RuntimeError(f"no Ultimate device answers ({', '.join(HARDWARE_HOSTS)})")
        print(f"  hardware target: {self.host} (queueing on its DeviceLock)")
        self._stack = ExitStack()
        mgr = self._stack.enter_context(create_manager(
            backend="u64", u64_hosts=[self.host], lock_timeout=HARDWARE_LOCK_TIMEOUT,
        ))
        target = self._stack.enter_context(mgr.instance())
        self.transport = target.transport
        self.client = self.transport.client
        info = self.client.get_info()
        print(f"  acquired: {info.get('product', '?')} fw "
              f"{info.get('firmware_version', '?')} at {self.host}")
        snap = snapshot_state(self.client)
        self._stack.callback(restore_state, self.client, snap)
        self.transport.set_speed(1)
        self._drives = _drive_slots(self.client)
        print(f"  drives: { {k: {f: v.get(f) for f in ('enabled', 'bus_id', 'type')} for k, v in self._drives.items()} }")
        self._reu = None
        return self

    def __exit__(self, *exc):
        if self._stack is not None:
            b = self._drives.get("b", {})
            if b.get("enabled"):
                self._stack.callback(self.client.drive_on, "b")
            a = self._drives.get("a", {})
            if a.get("image_file"):     # put back whatever drive A had mounted
                # fw 3.15 reports the full path in image_file, image_path empty
                prior = a["image_file"]
                if not prior.startswith("/"):
                    prior = f"{a.get('image_path', '').rstrip('/')}/{prior}"
                self._stack.callback(self.client.mount_disk_path, "a", prior)
            self._stack.close()
        return False

    def _volume(self):
        from c64_test_harness import storage_writable_volumes

        vols = storage_writable_volumes(self.host)
        if not vols:
            raise RuntimeError(
                f"{self.host} has no writable storage volume (USB stick or SD card); "
                "disk phases need one to hold the D64 image"
            )
        return vols[0]

    def phase(self, label, *, disk=None, reu_kb=0, drive9_absent=False,
              text_monitor=False):
        """Context manager yielding a transport whose machine has a freshly
        booted program at its main menu, with *reu_kb* KB of REU (0 = none)
        and *disk* (a DiskImage, or None) on drive 8."""
        if self.hardware:
            return self._hardware_phase(label, disk, reu_kb, drive9_absent)
        return self._vice_phase(label, disk, reu_kb, text_monitor)

    @staticmethod
    def _boot_failed(transport, label):
        from c64_test_harness import dump_screen

        dump_screen(transport, f"{label}: boot")
        raise BootError(f"{label}: program did not boot to its main menu")

    def _vice_phase(self, label, disk, reu_kb, text_monitor):
        from contextlib import contextmanager

        from c64_test_harness import ViceConfig, ViceInstanceManager

        @contextmanager
        def run():
            kwargs = dict(prg_path=self.prg_path, warp=True, ntsc=True, sound=False)
            if reu_kb:
                kwargs["extra_args"] = ["-reu", "-reusize", str(reu_kb)]
            if disk is not None:
                kwargs.update(disk_image=disk, drive_unit=8)
            with ViceInstanceManager(
                config=ViceConfig(**kwargs),
                port_range_start=self.port_range_start,
                port_range_end=self.port_range_start + self.port_range_span,
                enable_text_monitor=text_monitor,
            ) as mgr:
                inst = mgr.acquire()
                print(f"  [{label}] VICE PID={inst.pid} port={inst.port}")
                try:
                    if wait_for_text(inst.transport, "Q=QUIT", timeout=60.0,
                                     verbose=False) is None:
                        self._boot_failed(inst.transport, label)
                    yield inst.transport
                finally:
                    mgr.release(inst)
        return run()

    def _hardware_phase(self, label, disk, reu_kb, drive9_absent):
        from contextlib import contextmanager
        from pathlib import Path

        from c64_test_harness import (
            storage_delete_file,
            storage_get_file,
            storage_mkdir,
            storage_put_file,
        )
        from c64_test_harness.backends.ultimate64_helpers import set_reu

        @contextmanager
        def run():
            client = self.client
            if self._reu != reu_kb:
                set_reu(client, bool(reu_kb),
                        size=f"{reu_kb} KB" if reu_kb else None)
                client.reboot()             # re-initialises the REU
                time.sleep(8.0)
                self._reu = reu_kb
            b = self._drives.get("b", {})
            if drive9_absent and b.get("enabled"):
                client.drive_off("b")
            remote = None
            try:
                if disk is not None:
                    folder = f"/{self._volume()}/c64-aes256-ecdsa"
                    storage_mkdir(self.host, folder)
                    remote = f"{folder}/{os.path.basename(disk.path)}"
                    storage_put_file(self.host, remote, Path(disk.path), overwrite=True)
                    client.drive_on("a")
                    client.mount_disk_path("a", remote)
                print(f"  [{label}] {self.host}: REU {reu_kb or 'off'} KB, "
                      f"disk {remote or 'none'}")
                if not restart_program(self.transport, prg_path=self.prg_path):
                    self._boot_failed(self.transport, label)
                yield self.transport
            finally:
                if remote is not None:
                    unmount_flushed(client, "a")
                    with open(disk.path, "wb") as f:
                        f.write(storage_get_file(self.host, remote))
                    storage_delete_file(self.host, remote, missing_ok=True)
                if drive9_absent and b.get("enabled"):
                    client.drive_on("b")
        return run()
