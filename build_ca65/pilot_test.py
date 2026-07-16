#!/usr/bin/env python3
"""pilot_test.py - THROWAWAY ca65-port pilot verification script.

Boots build_ca65/pilot_test.prg (produced by ca65+ld65) in VICE via the
c64-test-harness, then:
  1. jsr()'s inc_counter a few times and confirms counter_byte incremented.
  2. Sets up copy_src/copy_dst, jsr()'s copy_bytes, confirms the copy.
  3. read_bytes()'s the $7800 qstab_table region and confirms it landed at
     the correct page-aligned address with the expected byte pattern.

This is NOT part of the real project's test suite - it only exists to
de-risk the ca65/ld65 toolchain switch before any real code is ported.
"""

import os
import sys

from c64_test_harness import Labels, ViceConfig, ViceInstanceManager, jsr, read_bytes, write_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
PRG_PATH = os.path.join(HERE, "pilot_test.prg")
LABELS_PATH = os.path.join(HERE, "pilot_test.labels")


def main():
    labels = Labels.from_file(LABELS_PATH)
    for name in ["inc_counter", "copy_bytes", "counter_byte", "copy_src", "copy_dst", "copy_len", "qstab_table"]:
        if labels.address(name) is None:
            print(f"FATAL: label '{name}' not found in {LABELS_PATH}")
            sys.exit(1)
    print("All expected labels resolved:")
    for name in ["inc_counter", "copy_bytes", "counter_byte", "copy_src", "copy_dst", "copy_len", "qstab_table"]:
        print(f"  {name:14s} = ${labels.address(name):04X}")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    passed = failed = 0

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        # Give the emulator a moment to finish booting/loading the PRG
        # before we start poking at memory. The harness's ViceConfig with
        # prg_path already handles load+run; we just need the CPU to have
        # settled at the `main: jmp main` idle loop.
        import time
        time.sleep(2.0)

        # --- Test 1: inc_counter ------------------------------------------------
        counter_addr = labels.address("counter_byte")
        write_bytes(transport, counter_addr, bytes([0]))
        before = read_bytes(transport, counter_addr, 1)[0]
        for _ in range(5):
            jsr(transport, labels.address("inc_counter"))
        after = read_bytes(transport, counter_addr, 1)[0]
        if before == 0 and after == 5:
            print(f"PASS: inc_counter x5 -> counter_byte {before} -> {after}")
            passed += 1
        else:
            print(f"FAIL: inc_counter -> expected 0 -> 5, got {before} -> {after}")
            failed += 1

        # --- Test 2: copy_bytes --------------------------------------------------
        src_addr = labels.address("copy_src")
        dst_addr = labels.address("copy_dst")
        len_addr = labels.address("copy_len")
        test_pattern = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])
        write_bytes(transport, src_addr, test_pattern)
        write_bytes(transport, len_addr, bytes([len(test_pattern)]))
        write_bytes(transport, dst_addr, bytes([0] * len(test_pattern)))
        jsr(transport, labels.address("copy_bytes"))
        result = read_bytes(transport, dst_addr, len(test_pattern))
        if result == test_pattern:
            print(f"PASS: copy_bytes -> dst == {result.hex()}")
            passed += 1
        else:
            print(f"FAIL: copy_bytes -> expected {test_pattern.hex()}, got {result.hex()}")
            failed += 1

        # --- Test 3: qstab_table page-alignment / placement ----------------------
        qstab_addr = labels.address("qstab_table")
        expected_prefix = bytes(range(16))
        actual = read_bytes(transport, qstab_addr, 16)
        alignment_ok = (qstab_addr == 0x7800) and (qstab_addr % 256 == 0)
        content_ok = (actual == expected_prefix)
        if alignment_ok and content_ok:
            print(f"PASS: qstab_table at ${qstab_addr:04X} (page-aligned), bytes == {actual.hex()}")
            passed += 1
        else:
            print(
                f"FAIL: qstab_table at ${qstab_addr:04X} (aligned={alignment_ok}), "
                f"bytes={actual.hex()} expected={expected_prefix.hex()}"
            )
            failed += 1

        mgr.release(inst)

    total = passed + failed
    print(f"\nResults: {passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
