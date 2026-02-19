#!/usr/bin/env python3
"""
test_polyval_direct.py - Direct-Memory POLYVAL Regression Test

Tests every routine in polyval.asm by calling them directly via jsr(),
writing inputs and reading outputs through VICE memory access.

Tested routines:
  polyval_init            - zero accumulator
  polyval_double          - left-shift 128 bits + reduction
  polyval_right_shift_1   - right-shift 128 bits + reduction
  polyval_shift_left_4    - left-shift 4 bits (4x double)
  polyval_xor_table_entry - XOR htable[nibble] into acc
  polyval_precompute_table - build htable[0..15] from H
  polyval_multiply        - 4-bit table multiply (tested in isolation)
  polyval_update          - XOR block + multiply
  Full POLYVAL pipeline   - init + precompute + multi-block update

Usage:
    python3 tools/test_polyval_direct.py [--seed S] [--verbose] [--workers N]

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from polyval_reference import (
    polyval,
    polyval_dot,
    polyval_double as py_double,
    polyval_right_shift_1 as py_right_shift_1,
    polyval_precompute_table as py_precompute_table,
    polyval_multiply_table as py_multiply_table,
    bytes_to_int,
    int_to_bytes,
)

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceProcess,
    ViceTransport,
    dump_screen,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)
from c64_test_harness.backends.vice_manager import ViceInstanceManager
from c64_test_utils import robust_jsr

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

DEFAULT_SEED = 8452  # deterministic by default (RFC number)
DEFAULT_WORKERS = 1
PORT_RANGE_START = 6510

VERBOSE = False


# ---------------------------------------------------------------------------
# Low-level C64 helpers
# ---------------------------------------------------------------------------

def write_acc(transport, labels, val: bytes):
    assert len(val) == 16
    write_bytes(transport, labels["polyval_acc"], val)


def read_acc(transport, labels) -> bytes:
    return read_bytes(transport, labels["polyval_acc"], 16)


def write_h(transport, labels, val: bytes):
    assert len(val) == 16
    write_bytes(transport, labels["polyval_h"], val)


def read_htable(transport, labels) -> list[bytes]:
    raw = read_bytes(transport, labels["polyval_htable"], 256)
    return [raw[i * 16:(i + 1) * 16] for i in range(16)]


def write_temp(transport, labels, val: bytes):
    assert len(val) == 16
    write_bytes(transport, labels["polyval_temp"], val)


def random_block(rng=None) -> bytes:
    if rng:
        return bytes(rng.randint(0, 255) for _ in range(16))
    return bytes(random.randint(0, 255) for _ in range(16))


# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def ok(self, name: str):
        self.passed += 1
        if VERBOSE:
            print(f"  PASS: {name}")

    def fail(self, name: str, detail: str = ""):
        self.failed += 1
        msg = f"  FAIL: {name}"
        if detail:
            msg += f"\n{detail}"
        print(msg)
        self.errors.append(name)

    def check(self, name: str, got: bytes, expected: bytes,
              context: str = "") -> bool:
        if got == expected:
            self.ok(name)
            return True
        else:
            lines = [f"    expected: {expected.hex()}",
                     f"    got:      {got.hex()}"]
            if context:
                lines.insert(0, f"    {context}")
            self.fail(name, "\n".join(lines))
            return False


# ---------------------------------------------------------------------------
# Test: polyval_init
# ---------------------------------------------------------------------------

def test_init(transport, labels, results: TestResults):
    print("\n[polyval_init]")
    write_acc(transport, labels, bytes(range(0x10, 0x20)))
    robust_jsr(transport, labels["polyval_init"], timeout=5.0)
    results.check("init zeros accumulator", read_acc(transport, labels),
                  b'\x00' * 16)


# ---------------------------------------------------------------------------
# Test: polyval_double
# ---------------------------------------------------------------------------

def test_double(transport, labels, results: TestResults):
    print("\n[polyval_double]")

    cases = [
        (b'\x01' + b'\x00' * 15,           "0x01 -> 0x02 (simple shift)"),
        (b'\x80' + b'\x00' * 15,           "0x80 -> carry into byte 1"),
        (b'\x00' * 15 + b'\x80',           "MSB set -> reduction"),
        (b'\x00' * 15 + b'\x40',           "bit 126 -> bit 127 no reduce"),
        (b'\xff' * 16,                      "all-ones"),
        (b'\x00' * 16,                      "zero stays zero"),
        (b'\xaa' * 16,                      "alternating bits 0xAA"),
        (b'\x55' * 16,                      "alternating bits 0x55"),
    ]

    for val, desc in cases:
        write_acc(transport, labels, val)
        robust_jsr(transport, labels["polyval_double"], timeout=5.0)
        expected = int_to_bytes(py_double(bytes_to_int(val)))
        results.check(f"double: {desc}", read_acc(transport, labels), expected)

    for i in range(8):
        val = random_block()
        write_acc(transport, labels, val)
        robust_jsr(transport, labels["polyval_double"], timeout=5.0)
        expected = int_to_bytes(py_double(bytes_to_int(val)))
        results.check(f"double: random #{i+1}", read_acc(transport, labels),
                      expected, context=f"input: {val.hex()}")


# ---------------------------------------------------------------------------
# Test: polyval_right_shift_1
# ---------------------------------------------------------------------------

def test_right_shift(transport, labels, results: TestResults):
    print("\n[polyval_right_shift_1]")

    cases = [
        (b'\x02' + b'\x00' * 15,           "0x02 -> 0x01 (simple)"),
        (b'\x00\x01' + b'\x00' * 14,       "byte 1 bit 0 -> byte 0 MSB"),
        (b'\x01' + b'\x00' * 15,           "LSB=1 triggers $E1 reduction"),
        (b'\x00' * 15 + b'\x80',           "MSB only"),
        (b'\xff' * 16,                      "all-ones"),
        (b'\x00' * 16,                      "zero stays zero"),
        (b'\x03' + b'\x00' * 15,           "0x03 -> 0x01 + reduction"),
        (b'\xaa' * 16,                      "alternating bits 0xAA"),
    ]

    for val, desc in cases:
        write_acc(transport, labels, val)
        robust_jsr(transport, labels["polyval_right_shift_1"], timeout=5.0)
        expected = int_to_bytes(py_right_shift_1(bytes_to_int(val)))
        results.check(f"rshift: {desc}", read_acc(transport, labels), expected)

    for i in range(8):
        val = random_block()
        write_acc(transport, labels, val)
        robust_jsr(transport, labels["polyval_right_shift_1"], timeout=5.0)
        expected = int_to_bytes(py_right_shift_1(bytes_to_int(val)))
        results.check(f"rshift: random #{i+1}", read_acc(transport, labels),
                      expected, context=f"input: {val.hex()}")


# ---------------------------------------------------------------------------
# Test: polyval_shift_left_4
# ---------------------------------------------------------------------------

def test_shift_left_4(transport, labels, results: TestResults):
    print("\n[polyval_shift_left_4]")

    cases = [
        b'\x01' + b'\x00' * 15,
        b'\x00' * 15 + b'\x80',
        b'\xff' * 16,
        b'\x00' * 14 + b'\x10\x00',
    ]

    for val in cases:
        write_acc(transport, labels, val)
        robust_jsr(transport, labels["polyval_shift_left_4"], timeout=5.0)
        v = bytes_to_int(val)
        for _ in range(4):
            v = py_double(v)
        expected = int_to_bytes(v)
        results.check(f"shl4: {val.hex()}", read_acc(transport, labels), expected)

    for i in range(6):
        val = random_block()
        write_acc(transport, labels, val)
        robust_jsr(transport, labels["polyval_shift_left_4"], timeout=5.0)
        v = bytes_to_int(val)
        for _ in range(4):
            v = py_double(v)
        expected = int_to_bytes(v)
        results.check(f"shl4: random #{i+1}", read_acc(transport, labels),
                      expected, context=f"input: {val.hex()}")


# ---------------------------------------------------------------------------
# Test: polyval_precompute_table
# ---------------------------------------------------------------------------

def test_precompute_table(transport, labels, results: TestResults):
    print("\n[polyval_precompute_table]")

    h_values = [
        ("25629347589242761d31f826ba4b757b", "RFC 8452 Appendix A"),
        ("01" + "00" * 15, "H = 1"),
        ("ff" * 16, "H = all-ones"),
        ("00" * 16, "H = 0"),
    ]

    for i in range(3):
        h_values.append((random_block().hex(), f"random H #{i+1}"))

    for h_hex, desc in h_values:
        h = bytes.fromhex(h_hex) if isinstance(h_hex, str) else h_hex
        write_h(transport, labels, h)
        robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
        c64_table = read_htable(transport, labels)
        py_table = py_precompute_table(bytes_to_int(h))

        all_match = True
        for i in range(16):
            expected = int_to_bytes(py_table[i])
            if c64_table[i] != expected:
                results.fail(f"table {desc}: entry [{i}]",
                             f"    expected: {expected.hex()}\n"
                             f"    got:      {c64_table[i].hex()}")
                all_match = False
                break

        if all_match:
            results.ok(f"table: {desc} (16/16 entries)")


# ---------------------------------------------------------------------------
# Test: polyval_xor_table_entry
# ---------------------------------------------------------------------------

def test_xor_table_entry(transport, labels, results: TestResults):
    print("\n[polyval_xor_table_entry]")

    h = bytes.fromhex("25629347589242761d31f826ba4b757b")
    write_h(transport, labels, h)
    robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
    py_table = py_precompute_table(bytes_to_int(h))

    acc_val = random_block()
    write_acc(transport, labels, acc_val)
    write_bytes(transport, labels["pv_mul_nibble"], b'\x00')
    robust_jsr(transport, labels["polyval_xor_table_entry"], timeout=5.0)
    results.check("xor_table: nibble 0 (no-op)", read_acc(transport, labels), acc_val)

    for nibble in range(1, 16):
        acc_val = random_block()
        write_acc(transport, labels, acc_val)
        write_bytes(transport, labels["pv_mul_nibble"], bytes([nibble]))
        robust_jsr(transport, labels["polyval_xor_table_entry"], timeout=5.0)
        expected = int_to_bytes(bytes_to_int(acc_val) ^ py_table[nibble])
        results.check(f"xor_table: nibble {nibble}", read_acc(transport, labels), expected)


# ---------------------------------------------------------------------------
# Test: polyval_multiply (in isolation)
# ---------------------------------------------------------------------------

def test_multiply_isolated(transport, labels, results: TestResults):
    print("\n[polyval_multiply — isolated]")

    h_keys = [
        bytes.fromhex("25629347589242761d31f826ba4b757b"),
        b'\x01' + b'\x00' * 15,
        b'\xff' * 16,
    ]
    for _ in range(3):
        h_keys.append(random_block())

    for h_idx, h in enumerate(h_keys):
        write_h(transport, labels, h)
        robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
        py_table = py_precompute_table(bytes_to_int(h))

        acc_values = [
            b'\x01' + b'\x00' * 15,
            b'\xff' * 16,
            b'\x00' * 16,
        ]
        for _ in range(5):
            acc_values.append(random_block())

        for acc_idx, acc_val in enumerate(acc_values):
            write_acc(transport, labels, acc_val)
            robust_jsr(transport, labels["polyval_multiply"], timeout=30.0)
            expected = int_to_bytes(
                py_multiply_table(bytes_to_int(acc_val), py_table)
            )
            tag = f"multiply: H#{h_idx} acc#{acc_idx}"
            results.check(tag, read_acc(transport, labels), expected,
                          context=f"H: {h.hex()}, acc: {acc_val.hex()}")


# ---------------------------------------------------------------------------
# Test: polyval_update
# ---------------------------------------------------------------------------

def test_update(transport, labels, results: TestResults):
    print("\n[polyval_update]")

    h = bytes.fromhex("25629347589242761d31f826ba4b757b")
    write_h(transport, labels, h)
    robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
    py_table = py_precompute_table(bytes_to_int(h))

    cases = [
        (b'\x00' * 16, b'\x01' + b'\x00' * 15, "zero acc + simple block"),
        (b'\xff' * 16, b'\xff' * 16, "all-ones XOR all-ones = 0"),
        (b'\x00' * 16, b'\x00' * 16, "zero XOR zero = 0"),
    ]

    for i in range(5):
        cases.append((random_block(), random_block(), f"random #{i+1}"))

    for acc_val, block, desc in cases:
        write_acc(transport, labels, acc_val)
        write_temp(transport, labels, block)
        robust_jsr(transport, labels["polyval_update"], timeout=30.0)
        xored = bytes_to_int(acc_val) ^ bytes_to_int(block)
        expected = int_to_bytes(py_multiply_table(xored, py_table))
        results.check(f"update: {desc}", read_acc(transport, labels), expected,
                      context=f"acc: {acc_val.hex()}, block: {block.hex()}")


# ---------------------------------------------------------------------------
# Test: full POLYVAL pipeline
# ---------------------------------------------------------------------------

def test_full_pipeline(transport, labels, results: TestResults):
    print("\n[full POLYVAL pipeline]")

    # RFC 8452 Appendix A
    h = bytes.fromhex("25629347589242761d31f826ba4b757b")
    x1 = bytes.fromhex("4f4f95668c83dfb6401762bb2d01a262")
    x2 = bytes.fromhex("d1a24ddd2721d006bbe45f20d3c9f362")
    expected = bytes.fromhex("f7a3b47b846119fae5b7866cf5e5b77e")

    write_h(transport, labels, h)
    robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
    robust_jsr(transport, labels["polyval_init"], timeout=5.0)
    write_temp(transport, labels, x1)
    robust_jsr(transport, labels["polyval_update"], timeout=30.0)
    write_temp(transport, labels, x2)
    robust_jsr(transport, labels["polyval_update"], timeout=30.0)
    results.check("RFC 8452 Appendix A: POLYVAL(H, X1, X2)",
                  read_acc(transport, labels), expected)

    # Single block: H=1, X=1
    h = b'\x01' + b'\x00' * 15
    block = b'\x01' + b'\x00' * 15
    _run_pipeline(transport, labels, h, [block], results, "single block: H=1, X=1")

    # H=0 -> zero
    h = b'\x00' * 16
    block = random_block()
    _run_pipeline(transport, labels, h, [block], results, "H=0 -> zero output")

    # Zero block
    h = random_block()
    _run_pipeline(transport, labels, h, [b'\x00' * 16], results, "zero block")

    # Random: 1 block
    for i in range(5):
        h = random_block()
        blocks = [random_block()]
        _run_pipeline(transport, labels, h, blocks, results, f"random 1-block #{i+1}")

    # Random: 2 blocks
    for i in range(5):
        h = random_block()
        blocks = [random_block(), random_block()]
        _run_pipeline(transport, labels, h, blocks, results, f"random 2-block #{i+1}")

    # Random: 3 blocks
    for i in range(3):
        h = random_block()
        blocks = [random_block() for _ in range(3)]
        _run_pipeline(transport, labels, h, blocks, results, f"random 3-block #{i+1}")

    # Random: 4 blocks
    for i in range(3):
        h = random_block()
        blocks = [random_block() for _ in range(4)]
        _run_pipeline(transport, labels, h, blocks, results, f"random 4-block #{i+1}")

    # Chained 6-block
    h = random_block()
    write_h(transport, labels, h)
    robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
    robust_jsr(transport, labels["polyval_init"], timeout=5.0)
    blocks = [random_block() for _ in range(6)]
    for block in blocks:
        write_temp(transport, labels, block)
        robust_jsr(transport, labels["polyval_update"], timeout=30.0)
    expected = polyval(h, *blocks)
    results.check("chained 6-block (single precompute)",
                  read_acc(transport, labels), expected, context=f"H: {h.hex()}")


def _run_pipeline(transport, labels, h: bytes, blocks: list[bytes],
                  results: TestResults, desc: str):
    write_h(transport, labels, h)
    robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)
    robust_jsr(transport, labels["polyval_init"], timeout=5.0)
    for block in blocks:
        write_temp(transport, labels, block)
        robust_jsr(transport, labels["polyval_update"], timeout=30.0)
    expected = polyval(h, *blocks)
    results.check(f"pipeline: {desc}", read_acc(transport, labels), expected,
                  context=f"H: {h.hex()}, {len(blocks)} block(s)")


# ---------------------------------------------------------------------------
# Test: multiply consistency (table vs dot product)
# ---------------------------------------------------------------------------

def test_multiply_vs_dot(transport, labels, results: TestResults):
    print("\n[multiply vs dot product consistency]")

    for i in range(10):
        h = random_block()
        acc_val = random_block()

        write_h(transport, labels, h)
        robust_jsr(transport, labels["polyval_precompute_table"], timeout=30.0)

        write_acc(transport, labels, acc_val)
        robust_jsr(transport, labels["polyval_multiply"], timeout=30.0)
        c64_result = read_acc(transport, labels)

        expected = int_to_bytes(polyval_dot(bytes_to_int(acc_val),
                                            bytes_to_int(h)))
        results.check(f"dot consistency #{i+1}", c64_result, expected,
                      context=f"H: {h.hex()}, acc: {acc_val.hex()}")


# ---------------------------------------------------------------------------
# All test groups
# ---------------------------------------------------------------------------

TEST_GROUPS = [
    ("polyval_init", test_init),
    ("polyval_double", test_double),
    ("polyval_right_shift_1", test_right_shift),
    ("polyval_shift_left_4", test_shift_left_4),
    ("polyval_precompute_table", test_precompute_table),
    ("polyval_xor_table_entry", test_xor_table_entry),
    ("polyval_multiply (isolated)", test_multiply_isolated),
    ("polyval_update", test_update),
    ("full pipeline", test_full_pipeline),
    ("multiply vs dot", test_multiply_vs_dot),
]


# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------

def run_sequential(labels: Labels) -> TestResults:
    print("\n=== Starting VICE ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceProcess(config) as vice:
        if not vice.wait_for_monitor(timeout=30.0):
            print("FATAL: Could not connect to VICE monitor")
            sys.exit(1)
        print(f"  VICE started (PID {vice.pid})")

        transport = ViceTransport(port=config.port)

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Ready")

        results = TestResults()
        for group_name, test_fn in TEST_GROUPS:
            try:
                test_fn(transport, labels, results)
            except Exception as e:
                results.fail(f"{group_name}: EXCEPTION", f"    {type(e).__name__}: {e}")
                print(f"  (continuing with next test group...)")

    return results


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def worker_run(worker_id, transport, labels, groups):
    """Run a subset of test groups on one VICE instance."""
    t0 = time.monotonic()
    results = TestResults()
    print(f"  [Worker {worker_id}] Starting ({len(groups)} test groups)")

    for group_name, test_fn in groups:
        try:
            test_fn(transport, labels, results)
        except Exception as e:
            results.fail(f"[W{worker_id}] {group_name}: EXCEPTION",
                         f"    {type(e).__name__}: {e}")

    duration = time.monotonic() - t0
    print(f"  [Worker {worker_id}] Done: {results.passed} passed, {results.failed} failed ({duration:.1f}s)")
    return worker_id, results


def run_parallel(labels: Labels, num_workers: int) -> TestResults:
    # Distribute test groups round-robin
    batches = [[] for _ in range(num_workers)]
    for i, group in enumerate(TEST_GROUPS):
        batches[i % num_workers].append(group)

    port_end = PORT_RANGE_START + num_workers
    print(f"\n=== Starting {num_workers} VICE instances (ports {PORT_RANGE_START}-{port_end - 1}) ===")
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(
        config=config,
        port_range_start=PORT_RANGE_START,
        port_range_end=port_end,
    ) as mgr:
        instances = []
        for i in range(num_workers):
            inst = mgr.acquire()
            pid = inst.process.pid if inst.process else "?"
            print(f"  Instance {i}: port {inst.port}, PID {pid}")
            instances.append(inst)

        print("\n=== Waiting for main menus ===")
        for i, inst in enumerate(instances):
            grid = wait_for_text(inst.transport, "Q=QUIT", timeout=60.0)
            if grid is None:
                print(f"  FATAL: Instance {i} (port {inst.port}) menu did not appear")
                dump_screen(inst.transport, f"startup_{i}")
                sys.exit(1)
            print(f"  Instance {i}: menu ready")

        combined = TestResults()

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            futures = {}
            for i, inst in enumerate(instances):
                fut = pool.submit(worker_run, i, inst.transport, labels, batches[i])
                futures[fut] = i

            for fut in as_completed(futures):
                try:
                    wid, results = fut.result()
                    combined.passed += results.passed
                    combined.failed += results.failed
                    combined.errors.extend(results.errors)
                except Exception as e:
                    wid = futures[fut]
                    print(f"  [Worker {wid}] EXCEPTION: {e}")
                    combined.failed += 1

        for inst in instances:
            mgr.release(inst)

    return combined


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    seed = DEFAULT_SEED
    if "--seed" in sys.argv:
        idx = sys.argv.index("--seed")
        if idx + 1 < len(sys.argv):
            seed = int(sys.argv[idx + 1])
    random.seed(seed)

    VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv

    num_workers = DEFAULT_WORKERS
    if "--workers" in sys.argv:
        idx = sys.argv.index("--workers")
        if idx + 1 < len(sys.argv):
            num_workers = int(sys.argv[idx + 1])

    print(f"POLYVAL Direct Regression Test")
    print(f"Seed: {seed} (reproduce with --seed {seed})")
    print(f"Workers: {num_workers}")

    # Build
    print("\n=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    required_labels = [
        "polyval_acc", "polyval_h", "polyval_temp", "polyval_htable",
        "polyval_init", "polyval_double", "polyval_right_shift_1",
        "polyval_shift_left_4", "polyval_precompute_table",
        "polyval_multiply", "polyval_update",
        "polyval_xor_table_entry", "pv_mul_nibble",
    ]
    for name in required_labels:
        if labels.address(name) is None:
            print(f"FATAL: '{name}' label not found in {LABELS_PATH}")
            sys.exit(1)
    print(f"  Labels loaded ({len(required_labels)} symbols)")
    if VERBOSE:
        for name in required_labels:
            print(f"    {name}: ${labels[name]:04X}")

    t0 = time.time()

    # Run tests
    if num_workers > 1:
        results = run_parallel(labels, num_workers)
    else:
        results = run_sequential(labels)

    elapsed = time.time() - t0
    total = results.passed + results.failed

    # Summary
    print("\n" + "=" * 60)
    print(f"POLYVAL Direct Regression Test — {elapsed:.1f}s")
    print("=" * 60)
    print(f"  Passed: {results.passed}/{total}")
    print(f"  Failed: {results.failed}/{total}")
    if results.failed == 0:
        print(f"\n  ALL {total} TESTS PASSED")
    else:
        print(f"\n  {results.failed} TEST(S) FAILED:")
        for name in results.errors:
            print(f"    - {name}")
    print("=" * 60)

    sys.exit(0 if results.failed == 0 else 1)


if __name__ == "__main__":
    main()
