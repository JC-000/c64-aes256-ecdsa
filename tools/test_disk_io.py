#!/usr/bin/env python3
"""test_disk_io.py - End-to-end disk save/load tests via c64_test_harness.

Exercises the disk-save/load code paths in src/disk_io.s that no other test
in the repo ever touches (menu keys 5/6/7/8) against a *real* D64 image
mounted in VICE, not just a UI walkthrough:

  Phase A (SAVE, keys 5 & 7) - a freshly-generated key and freshly-encrypted
    text are written to a mounted D64. The program's own on-device read-back
    (VERIFICATION OK) is asserted, then after VICE shuts down the D64 file is
    read host-side with c1541 and its bytes are compared to what was in C64
    memory. Also exercises check_file_exists / the default-name overwrite
    path (a second save of the default name must detect the existing file and
    roll AESKEY -> AESKEY1).

  Phase B (LOAD, keys 6 & 8) - a key file and an encrypted-text file are
    authored host-side with known bytes, mounted, and loaded through the UI;
    the resulting C64 memory (key_data / iv_data / encrypt_buffer) is asserted
    byte-for-byte against the known input.

Usage:
    python3 tools/test_disk_io.py [--seed S]

Honors C64_PORT_RANGE_START to avoid port collisions with sibling test runs.
Uses the existing build/aes256keygen.prg as-is (never rebuilds).

Requires: Python 3.10+, c64_test_harness, VICE x64sc + c1541.
"""

import argparse
import os
import random
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
from c64_test_harness.disk import DiskImage, FileType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

PORT_RANGE_START = int(os.environ.get("C64_PORT_RANGE_START", "6541"))
PORT_RANGE_END = PORT_RANGE_START + 20

SCREEN_RAM = 0x0400
SCREEN_LEN = 1000

# JMP $0339 at $0339 - after any stray control transfer the CPU loops
# harmlessly instead of crashing into a banked-out ROM.
SAFETY_ADDR = 0x0339
SAFETY_JMP = bytes([0x4C, 0x39, 0x03])


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def clear_screen(transport):
    """Blank screen RAM so a stale completion marker from a prior operation
    cannot satisfy the next wait_for_text() (the C64 never clears the screen
    between operations - see docs/test_suite_audit.md addendum)."""
    write_bytes(transport, SCREEN_RAM, bytes([0x20] * SCREEN_LEN))


def answer_default(transport, prompt_needle, timeout=20.0):
    """Wait for a prompt, then press RETURN to accept its default."""
    grid = wait_for_text(transport, prompt_needle, timeout=timeout, verbose=False)
    if grid is None:
        return False
    time.sleep(0.05)
    send_key(transport, "\r")
    time.sleep(0.05)
    return True


def parse_hex_bytes(text):
    """Extract whitespace-separated hex byte tokens from a file's text."""
    out = bytearray()
    for tok in text.split():
        tok = tok.strip()
        if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
            out.append(int(tok, 16))
    return bytes(out)


def format_key_hex(key: bytes) -> str:
    """Render 32 key bytes the way save_key_to_disk does: 'XX XX ...' with a
    newline every 8 bytes (read_hex_char skips spaces/newlines, so exact
    layout is not load-bearing, but we mirror the program for realism)."""
    lines = []
    for i in range(0, len(key), 8):
        lines.append(" ".join(f"{b:02X}" for b in key[i : i + 8]))
    return "\r".join(lines) + "\r"


def format_enc_hex(iv: bytes, ct: bytes) -> str:
    """Render IV (16 bytes) then ciphertext the way save_encrypted_to_disk
    does: IV as one hex line, then ciphertext hex with a newline every 8."""
    iv_line = " ".join(f"{b:02X}" for b in iv) + " \r"
    ct_lines = []
    for i in range(0, len(ct), 8):
        ct_lines.append(" ".join(f"{b:02X}" for b in ct[i : i + 8]))
    return iv_line + " \r".join(ct_lines) + " \r"


def new_disk(tag: str) -> DiskImage:
    fd, path = tempfile.mkstemp(prefix=f"diskio_{tag}_", suffix=".d64")
    os.close(fd)
    os.unlink(path)
    return DiskImage.create(path, name="diskio", disk_id="io")


# ---------------------------------------------------------------------------
# UI drivers
# ---------------------------------------------------------------------------

def encrypt_text(transport, plaintext: str, timeout=30.0) -> bool:
    """Menu key 2: enter text, encrypt. Returns True on ENCRYPTION COMPLETE."""
    clear_screen(transport)
    send_key(transport, "2")
    grid = wait_for_text(transport, "ENTER TEXT TO ENCRYPT", timeout=timeout, verbose=False)
    if grid is None:
        return False
    time.sleep(0.1)
    send_text(transport, plaintext)
    send_key(transport, "\r")
    grid = wait_for_text(transport, "ENCRYPTION COMPLETE", timeout=timeout, verbose=False)
    return grid is not None


def save_key(transport, timeout=40.0):
    """Menu key 5 with default drive + default filename. Returns the ScreenGrid
    seen at completion (VERIFICATION OK on success) or None."""
    clear_screen(transport)
    send_key(transport, "5")
    if not answer_default(transport, "DRIVE NUMBER"):
        return None
    if not answer_default(transport, "FILENAME (AESKEY)"):
        return None
    return wait_for_text(transport, "VERIFICATION OK", timeout=timeout, verbose=False)


def save_encrypted(transport, timeout=40.0):
    """Menu key 7 with defaults. Returns completion grid or None."""
    clear_screen(transport)
    send_key(transport, "7")
    if not answer_default(transport, "DRIVE NUMBER"):
        return None
    if not answer_default(transport, "FILENAME (AESMSG)"):
        return None
    # On success the program writes the data, then reads it back and prints
    # "DATA READ FROM DISK:" near the very end.
    return wait_for_text(transport, "DATA READ FROM DISK", timeout=timeout, verbose=False)


def load_key(transport, timeout=40.0):
    """Menu key 6 with defaults. Returns completion grid or None."""
    clear_screen(transport)
    send_key(transport, "6")
    if not answer_default(transport, "DRIVE NUMBER"):
        return None
    if not answer_default(transport, "FILENAME TO LOAD (AESKEY)"):
        return None
    return wait_for_text(transport, "KEY LOADED SUCCESSFULLY", timeout=timeout, verbose=False)


def load_encrypted(transport, timeout=40.0):
    """Menu key 8 with defaults. Returns completion grid or None."""
    clear_screen(transport)
    send_key(transport, "8")
    if not answer_default(transport, "DRIVE NUMBER"):
        return None
    if not answer_default(transport, "FILENAME TO LOAD (AESMSG)"):
        return None
    return wait_for_text(transport, "LOADED SUCCESSFULLY", timeout=timeout, verbose=False)


def return_to_menu(transport, timeout=15.0):
    wait_for_text(transport, "Q=QUIT", timeout=timeout, verbose=False)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def run_phase_a(labels, disk, results, seed):
    """SAVE side. Captures the in-memory bytes that should land on disk and
    performs the on-device assertions. Host-side D64 byte comparison happens
    in the caller after VICE has shut down (so the image is flushed)."""
    captured = {}
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
        print(f"  [A] VICE PID={inst.pid} port={inst.port}, disk={disk.path}")
        t = inst.transport

        if wait_for_text(t, "Q=QUIT", timeout=60.0, verbose=False) is None:
            dump_screen(t, "phase A: no main menu")
            results.append(("phase A boot", False, "main menu never appeared"))
            mgr.release(inst)
            return captured
        write_bytes(t, SAFETY_ADDR, SAFETY_JMP)

        # --- capture the generated key, then save it (key 5) ---
        key = read_bytes(t, labels["key_data"], 32)
        captured["key"] = key
        print(f"  [A] key_data = {key.hex().upper()}")

        grid = save_key(t)
        ok = grid is not None
        if not ok:
            dump_screen(t, "save_key failed")
        results.append(("save_key: on-device VERIFICATION OK", ok,
                        "device read-back matched" if ok else "no VERIFICATION OK"))
        return_to_menu(t)

        # --- overwrite path: a second save of the *default* name must detect
        # the existing AESKEY (check_file_exists) and roll to a new name
        # (increment_filename: suffix 1 -> digit '0', i.e. AESKEY0). The
        # transient "FILE ALREADY EXISTS!"/"TRYING:" lines scroll off in warp
        # mode, so the definitive assertion is host-side in verify_disk_a
        # (both AESKEY and AESKEY0 must exist); here we just drive it and
        # confirm the save completed.
        grid = save_key(t)
        results.append(("check_file_exists: 2nd default save completes (overwrite-protected)",
                        grid is not None,
                        "second save reached VERIFICATION OK" if grid is not None
                        else "second default save did not complete"))
        if grid is None:
            dump_screen(t, "overwrite path")
        return_to_menu(t)

        # --- encrypt text, capture ciphertext, then save it (key 7) ---
        pt = "HELLO DISK IO " + str(seed % 1000)
        if not encrypt_text(t, pt):
            dump_screen(t, "encrypt_text failed")
            results.append(("save_encrypted: encrypt precondition", False, "encrypt did not complete"))
            mgr.release(inst)
            return captured
        return_to_menu(t)
        enc_len = read_bytes(t, labels["encrypt_length"], 1)[0]
        iv = read_bytes(t, labels["iv_data"], 16)
        ct = read_bytes(t, labels["encrypt_buffer"], enc_len)
        captured["iv"] = iv
        captured["ct"] = ct
        print(f"  [A] encrypt_length={enc_len} iv={iv.hex().upper()} ct={ct.hex().upper()}")

        grid = save_encrypted(t)
        ok = grid is not None
        if not ok:
            dump_screen(t, "save_encrypted failed")
        results.append(("save_encrypted: on-device read-back completed", ok,
                        "read data back from disk" if ok else "no DATA READ FROM DISK"))
        return_to_menu(t)

        mgr.release(inst)
    return captured


def verify_disk_a(disk, captured, results):
    """Host-side byte-for-byte check of what Phase A wrote (VICE now stopped,
    so the .d64 is flushed). c1541 must be given the exact stored name, so we
    resolve names case-insensitively from the directory listing."""
    by_upper = {e.name.upper(): e.name for e in disk.list_files()}
    print(f"  [A] D64 dir: {sorted(by_upper.values())}")

    def check(want_upper, expected, label):
        real = by_upper.get(want_upper)
        if real is None:
            results.append((label, False, f"{want_upper} not present in dir {sorted(by_upper)}"))
            return
        # c1541 -read defaults to PRG; these are SEQ files, so the ",s" type
        # suffix is required or it reports FILE NOT FOUND.
        try:
            raw = disk.read_file_bytes(real + ",s").decode("latin-1")
        except Exception as e:  # noqa: BLE001
            results.append((label, False, f"read_file_bytes({real + ',s'!r}) failed: {e}"))
            return
        got = parse_hex_bytes(raw)
        ok = got == expected
        results.append((label, ok,
                        "bytes match memory" if ok
                        else f"expected {expected.hex().upper()} got {got.hex().upper()}"))

    if "key" in captured:
        check("AESKEY", captured["key"], "D64 AESKEY file bytes == saved key_data")
        # AESKEY0's mere existence proves check_file_exists refused to clobber
        # AESKEY and increment_filename rolled the name; its bytes must also
        # equal the (unchanged) key.
        check("AESKEY0", captured["key"],
              "check_file_exists overwrite-protection: AESKEY0 created, bytes == key_data")
    if "iv" in captured and "ct" in captured:
        check("AESMSG", captured["iv"] + captured["ct"],
              "D64 AESMSG file bytes == saved IV||ciphertext")


def run_phase_b(labels, results, rng):
    """LOAD side. Author known files host-side, then load through the UI and
    assert C64 memory matches."""
    known_key = bytes(rng.randrange(256) for _ in range(32))
    known_ct = bytes(rng.randrange(256) for _ in range(32))
    known_iv = bytes(rng.randrange(256) for _ in range(16))

    disk = new_disk("load")
    with tempfile.TemporaryDirectory() as td:
        kf = os.path.join(td, "key.seq")
        ef = os.path.join(td, "enc.seq")
        with open(kf, "w", newline="") as f:
            f.write(format_key_hex(known_key))
        with open(ef, "w", newline="") as f:
            f.write(format_enc_hex(known_iv, known_ct))
        disk.write_file(kf, "aeskey", FileType.SEQ)
        disk.write_file(ef, "aesmsg", FileType.SEQ)

    print(f"  [B] authored D64 dir: {[ (e.name, e.file_type) for e in disk.list_files() ]}")
    print(f"  [B] known_key={known_key.hex().upper()}")

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
        print(f"  [B] VICE PID={inst.pid} port={inst.port}")
        t = inst.transport
        if wait_for_text(t, "Q=QUIT", timeout=60.0, verbose=False) is None:
            dump_screen(t, "phase B: no main menu")
            results.append(("phase B boot", False, "main menu never appeared"))
            mgr.release(inst)
            return
        write_bytes(t, SAFETY_ADDR, SAFETY_JMP)

        # --- load key (key 6) ---
        grid = load_key(t)
        if grid is None:
            dump_screen(t, "load_key failed")
            results.append(("load_key: KEY LOADED SUCCESSFULLY", False, "no success message"))
        else:
            got = read_bytes(t, labels["key_data"], 32)
            ok = got == known_key
            results.append(("load_key: key_data memory == authored disk key", ok,
                            "loaded key matches" if ok
                            else f"expected {known_key.hex().upper()} got {got.hex().upper()}"))
        return_to_menu(t)

        # --- load encrypted (key 8) ---
        grid = load_encrypted(t)
        if grid is None:
            dump_screen(t, "load_encrypted failed")
            results.append(("load_encrypted: LOADED SUCCESSFULLY", False, "no success message"))
        else:
            got_len = read_bytes(t, labels["encrypt_length"], 1)[0]
            got_iv = read_bytes(t, labels["iv_data"], 16)
            got_ct = read_bytes(t, labels["encrypt_buffer"], got_len)
            ok = got_iv == known_iv and got_ct == known_ct
            results.append(("load_encrypted: iv_data+encrypt_buffer == authored disk data", ok,
                            "loaded IV+ciphertext match" if ok
                            else f"len={got_len} iv={got_iv.hex().upper()} ct={got_ct.hex().upper()}"))
        return_to_menu(t)

        mgr.release(inst)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)
    ap = argparse.ArgumentParser(description="Disk save/load end-to-end tests")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    seed = args.seed if args.seed is not None else random.randint(0, 2**32 - 1)
    rng = random.Random(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found (build first)")
        sys.exit(2)
    labels = Labels.from_file(LABELS_PATH)
    for name in ("key_data", "encrypt_length", "iv_data", "encrypt_buffer"):
        if labels.address(name) is None:
            print(f"FATAL: label '{name}' not found in {LABELS_PATH}")
            sys.exit(2)

    results = []

    print("\n=== Phase A: SAVE (keys 5 & 7) ===")
    disk_a = new_disk("save")
    captured = run_phase_a(labels, disk_a, results, seed)
    verify_disk_a(disk_a, captured, results)

    print("\n=== Phase B: LOAD (keys 6 & 8) ===")
    run_phase_b(labels, results, rng)

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
