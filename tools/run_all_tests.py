#!/usr/bin/env python3
"""run_all_tests.py — Unified parallel test runner for c64-aes256-ecdsa.

Launches N VICE instances via ViceInstanceManager, boots them all with the
built PRG, then runs each test suite across the pool in parallel.

Each VICE instance in warp mode consumes ~1 CPU core and ~170 MB RAM.
The default worker count is min(cpu_count - 2, 10).

Usage:
    python3 tools/run_all_tests.py [--workers N] [--iterations N]
                                   [--fail-fast] [--seed N] [--verbose]
                                   [--backend vice|u64] [--native-speed]
                                   [--with-ecdsa]

--backend u64 runs the same suites on Ultimate hardware (one device, queued
through the harness DeviceLock): U64_HOST picks the device, otherwise the
first of HARDWARE_HOSTS whose lock is free. Hardware runs at the device's
maximum CPU speed (48 MHz U64E, 64 MHz C64 Ultimate) and is put back to
1 MHz on exit. --native-speed keeps it at 1 MHz; there the HMAC-DRBG suite
(an ECDSA signature, ~40 min at 1 MHz) only runs with --with-ecdsa.
"""

from __future__ import annotations

import os
import random
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
# PRG_PATH / LABELS_PATH default to `make`'s build outputs (the ca65/ld65
# toolchain as of the Makefile cutover; previously ACME). C64_PRG_PATH /
# C64_LABELS_PATH remain available to point the runner at a different
# build's outputs without touching these defaults - e.g. to validate a
# one-off build produced by a different script/toolchain. C64_SKIP_BUILD=1
# skips the `make clean && make` step in build() below (useful when
# PRG_PATH/LABELS_PATH have been overridden this way, so `make` doesn't
# need to run at all).
PRG_PATH = os.environ.get(
    "C64_PRG_PATH", os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
)
LABELS_PATH = os.environ.get(
    "C64_LABELS_PATH", os.path.join(PROJECT_ROOT, "build", "labels.txt")
)

sys.path.insert(0, TOOLS_DIR)

from c64_test_harness import (
    Labels,
    C64Transport as ViceTransport,  # compat shim: harness renamed this in v0.4.0
    dump_screen,
    read_bytes,
    send_key,
    send_text,
    wait_for_text,
    write_bytes,
)
from c64_test_harness.backends.vice_lifecycle import ViceConfig
from c64_test_harness.backends.vice_manager import ViceInstanceManager
from c64_test_harness import create_manager, device_lock_holder, is_u64_reachable

from c64_test_utils import fresh_scenario, prepare_direct_tests, restart_program

# ---------------------------------------------------------------------------
# Lazy imports for test modules (they have heavy top-level imports)
# ---------------------------------------------------------------------------

_test_modules = {}


def _import_test_module(name):
    if name not in _test_modules:
        _test_modules[name] = __import__(name)
    return _test_modules[name]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT_RANGE_START = int(os.environ.get("C64_PORT_RANGE_START", "6510"))
# Other projects' VICE runs often hold ports in this neighbourhood, so the
# pool is offered this many spare ports beyond num_workers; the harness
# allocator skips (and cross-process locks) any port already in use.
PORT_RANGE_HEADROOM = 64

# --backend u64 candidates, in preference order: the U64E (ethernet, then
# WiFi), then the C64 Ultimate (ethernet). Each device is listed with all its
# addresses in ~/.config/c64-test-harness/devices.toml, so every spelling of
# a device takes the same DeviceLock.
HARDWARE_HOSTS = ["10.43.23.81", "10.43.23.83", "10.43.23.26"]
# How long to queue behind another lane's hold. A live, heartbeating holder
# extends this anyway; it only bounds the wait on a wedged or dead one.
HARDWARE_LOCK_TIMEOUT = 3600.0

# All labels needed across all test suites
ALL_REQUIRED_LABELS = [
    # SHA-256
    "sha256_hash", "sha256_init", "sha256_update", "sha256_final",
    "sha256_h0", "sha256_block", "sha256_process_block",
    "input_buffer", "input_length",
    # AES-CBC encrypt
    "encrypt_input", "aes_key_expansion",
    "encrypt_buffer", "encrypt_length", "key_data", "iv_data",
    # AES-CBC decrypt
    "decrypt_buffer", "decrypt_data",
    # POLYVAL
    "polyval_acc", "polyval_h", "polyval_temp", "polyval_htable",
    "polyval_init", "polyval_double", "polyval_right_shift_1",
    "polyval_shift_left_4", "polyval_precompute_table",
    "polyval_multiply", "polyval_update",
    "polyval_xor_table_entry", "pv_mul_nibble",
    # GCM-SIV
    "gcmsiv_nonce", "gcmsiv_pt_buf", "gcmsiv_pt_len",
    "gcmsiv_ct_buf", "gcmsiv_tag", "gcmsiv_tag_valid",
    "gcmsiv_dec_buf", "gcmsiv_encrypt", "gcmsiv_decrypt",
    # HMAC-DRBG (UI-driven test)
    "pkcs10_privkey", "pkcs10_k_buf",
    "hmac_key", "hmac_val", "drbg_output",
    "pkcs10_der_len", "der_buf",
]


def optimal_workers() -> int:
    cores = os.cpu_count() or 4
    # Each VICE in warp saturates ~1 core; leave 2 for Python + OS
    return max(1, min(cores - 2, 10))


def parse_args():
    workers = optimal_workers()
    iterations = 50
    fail_fast = False
    smoke = False
    seed = random.randint(0, 2**32 - 1)
    verbose = False
    backend = os.environ.get("C64_BACKEND", "vice")
    with_ecdsa = False
    native_speed = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--workers" and i + 1 < len(args):
            workers = int(args[i + 1])
            i += 2
        elif args[i] == "--iterations" and i + 1 < len(args):
            iterations = int(args[i + 1])
            i += 2
        elif args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--fail-fast":
            fail_fast = True
            i += 1
        elif args[i] == "--verbose":
            verbose = True
            i += 1
        elif args[i] == "--backend" and i + 1 < len(args):
            backend = args[i + 1]
            i += 2
        elif args[i] == "--with-ecdsa":
            with_ecdsa = True
            i += 1
        elif args[i] == "--native-speed":
            native_speed = True
            i += 1
        elif args[i] == "--smoke-test":
            smoke = True
            i += 1
        else:
            print(f"Unknown argument: {args[i]}")
            sys.exit(1)

    if backend not in ("vice", "u64"):
        print(f"Unknown backend: {backend} (expected vice or u64)")
        sys.exit(1)
    return (workers, iterations, fail_fast, seed, verbose, smoke, backend,
            with_ecdsa, native_speed)


# ---------------------------------------------------------------------------
# Build & boot helpers
# ---------------------------------------------------------------------------

def build() -> bool:
    if os.environ.get("C64_SKIP_BUILD") == "1":
        print("=== Building === (skipped: C64_SKIP_BUILD=1, using existing build output)")
        if not os.path.exists(PRG_PATH):
            print(f"  FATAL: {PRG_PATH} not found")
            return False
        print("  Build OK (pre-built)")
        return True
    print("=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    result = subprocess.run(["make"], capture_output=True, text=True, cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print(f"  Build FAILED:\n{result.stderr}")
        return False
    if not os.path.exists(PRG_PATH):
        print(f"  FATAL: {PRG_PATH} not found after build")
        return False
    # A zero exit code from ld65 does not mean a clean build: a missing
    # .importzp for a symbol crossing an object boundary produces only an
    # "Address size mismatch" warning, not an error (this exact class has
    # already bitten this project's modular restructure twice -- see
    # src/lib_manifest.s and docs/test_suite_audit.md's Post-Refactor-
    # Validation finding). Fail loudly on any linker/assembler warning
    # instead of silently discarding stdout/stderr on success.
    # A pristine tree emits six benign ca65 warnings: file-local
    # `sym = zp_...` equates in base64.s/csr.s are defined after their
    # first use, so ca65's single pass falls back to absolute addressing
    # (same byte on 6502; costs 1 extra byte + 1 cycle per site).
    # Allowlisted by file+symbol so line numbers may drift; any other
    # warning -- including new instances of this class -- still fails.
    # Reordering the equates to fix them for real is HANDOFF.md future
    # work item 6 (it changes the binary, so it needs a full suite run).
    known_benign = re.compile(
        r"src/(?:base64|csr)\.s\(\d+\): Warning: Didn't use zeropage "
        r"addressing for '(?:b64_ws_ptr|csr_wf_hi|csr_wf_lo|csr_ws_hi|"
        r"csr_ws_lo|csr_field_ptr)'$"
    )
    combined_output = result.stdout + result.stderr
    warnings = [
        line for line in combined_output.splitlines()
        if "Warning:" in line and not known_benign.search(line.strip())
    ]
    if warnings:
        print("  Build FAILED: ld65/ca65 emitted warning(s) on an otherwise-successful build:")
        for w in warnings:
            print(f"    {w}")
        return False
    print("  Build OK")
    return True


def boot_instances(mgr, num_workers):
    """Acquire N instances and wait for each to reach the main menu."""
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
            return None
        print(f"  Instance {i}: menu ready")

    return instances


# ---------------------------------------------------------------------------
# Smoke test — parallel hello-world
# ---------------------------------------------------------------------------

SCREEN_BASE = 0x0400


def smoke_worker(worker_id: int, transport: ViceTransport) -> tuple[int, bool, str]:
    """Write a unique pattern to screen RAM and read it back."""
    row = worker_id + 5
    addr = SCREEN_BASE + row * 40 + 15
    pattern = bytes([worker_id & 0xFF] * 10)

    write_bytes(transport, addr, pattern)
    readback = read_bytes(transport, addr, 10)

    if bytes(readback) == pattern:
        return worker_id, True, f"Worker {worker_id}: wrote/read pattern OK"
    else:
        return worker_id, False, (
            f"Worker {worker_id}: MISMATCH — "
            f"wrote {pattern.hex()} got {bytes(readback).hex()}"
        )


def run_smoke_test(instances):
    """Run parallel write/read on all instances to verify the pool works."""
    num = len(instances)
    print(f"\n=== Smoke test: parallel write/read on {num} instances ===")

    t0 = time.monotonic()
    results = []

    with ThreadPoolExecutor(max_workers=num) as pool:
        futures = {}
        for i, inst in enumerate(instances):
            fut = pool.submit(smoke_worker, i, inst.transport)
            futures[fut] = i

        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                wid = futures[fut]
                results.append((wid, False, f"Worker {wid}: EXCEPTION {e}"))

    duration = time.monotonic() - t0
    passed = sum(1 for _, ok, _ in results if ok)
    failed = num - passed

    for wid, ok, msg in sorted(results):
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {msg}")

    print(f"  Smoke test: {passed}/{num} passed ({duration:.2f}s)")
    return failed == 0


# ---------------------------------------------------------------------------
# Suite runners — each distributes work across the instance pool
# ---------------------------------------------------------------------------

SuiteResult = tuple[str, int, int, float]  # (name, passed, failed, duration)


def run_suite_simple(
    suite_name: str,
    module_name: str,
    instances: list,
    labels: Labels,
    iterations: int,
) -> SuiteResult:
    """Run a test suite that has run_tests(transport, labels, iterations, False).

    Distributes iterations evenly: each worker gets iterations // N.
    Works for: test_sha256_direct, test_aes_cbc_direct, test_aes_cbc_decrypt_direct.
    """
    mod = _import_test_module(module_name)
    num = len(instances)
    per_worker = max(1, iterations // num)

    print(f"\n{'=' * 60}")
    print(f"  {suite_name} ({per_worker} iterations x {num} workers = {per_worker * num} tests)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    results = []

    def worker(wid, transport):
        print(f"  [Worker {wid}] Starting {suite_name} ({per_worker} iterations)")
        t = time.monotonic()
        passed, failed = mod.run_tests(transport, labels, per_worker, False)
        d = time.monotonic() - t
        print(f"  [Worker {wid}] Done: {passed} passed, {failed} failed ({d:.1f}s)")
        return wid, passed, failed

    with ThreadPoolExecutor(max_workers=num) as pool:
        futures = {}
        for i, inst in enumerate(instances):
            fut = pool.submit(worker, i, inst.transport)
            futures[fut] = i

        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                wid = futures[fut]
                print(f"  [Worker {wid}] EXCEPTION: {e}")
                results.append((wid, 0, per_worker))

    duration = time.monotonic() - t0
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    return suite_name, total_passed, total_failed, duration


def run_suite_polyval(
    instances: list,
    labels: Labels,
) -> SuiteResult:
    """Run POLYVAL tests — distributes test groups round-robin across workers."""
    mod = _import_test_module("test_polyval_direct")
    num = len(instances)

    # Distribute test groups round-robin
    batches = [[] for _ in range(num)]
    for i, group in enumerate(mod.TEST_GROUPS):
        batches[i % num].append(group)

    suite_name = "POLYVAL"
    print(f"\n{'=' * 60}")
    print(f"  {suite_name} ({len(mod.TEST_GROUPS)} test groups across {num} workers)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    results = []

    with ThreadPoolExecutor(max_workers=num) as pool:
        futures = {}
        for i, inst in enumerate(instances):
            fut = pool.submit(mod.worker_run, i, inst.transport, labels, batches[i])
            futures[fut] = i

        for fut in as_completed(futures):
            try:
                wid, worker_results = fut.result()
                results.append((wid, worker_results.passed, worker_results.failed))
            except Exception as e:
                wid = futures[fut]
                print(f"  [Worker {wid}] EXCEPTION: {e}")
                results.append((wid, 0, 1))

    duration = time.monotonic() - t0
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    return suite_name, total_passed, total_failed, duration


def run_suite_gcmsiv_encrypt(
    instances: list,
    labels: Labels,
    iterations: int,
) -> SuiteResult:
    """Run GCM-SIV encrypt tests — generates cases then distributes round-robin."""
    mod = _import_test_module("test_gcmsiv_encrypt_direct")
    num = len(instances)

    rng = random.Random(random.getrandbits(64))
    cases = mod.generate_test_cases(iterations, rng)

    # Distribute cases round-robin
    batches = [[] for _ in range(num)]
    for i, case in enumerate(cases):
        batches[i % num].append(case)

    suite_name = "GCM-SIV Encrypt"
    print(f"\n{'=' * 60}")
    print(f"  {suite_name} ({len(cases)} tests across {num} workers)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    results = []

    with ThreadPoolExecutor(max_workers=num) as pool:
        futures = {}
        for i, inst in enumerate(instances):
            fut = pool.submit(mod.worker, i, inst.transport, labels, batches[i])
            futures[fut] = i

        for fut in as_completed(futures):
            try:
                wid, passed, failed, dur, vectors = fut.result()
                results.append((wid, passed, failed))
            except Exception as e:
                wid = futures[fut]
                print(f"  [Worker {wid}] EXCEPTION: {e}")
                results.append((wid, 0, len(batches[wid])))

    duration = time.monotonic() - t0
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    return suite_name, total_passed, total_failed, duration


def run_suite_gcmsiv_decrypt(
    instances: list,
    labels: Labels,
    iterations: int,
) -> SuiteResult:
    """Run GCM-SIV decrypt tests — generates cases then distributes round-robin."""
    mod = _import_test_module("test_gcmsiv_decrypt_direct")
    num = len(instances)

    rng = random.Random(random.getrandbits(64))
    cases = mod.generate_test_cases(iterations, rng)

    # Distribute cases round-robin
    batches = [[] for _ in range(num)]
    for i, case in enumerate(cases):
        batches[i % num].append(case)

    suite_name = "GCM-SIV Decrypt"
    print(f"\n{'=' * 60}")
    print(f"  {suite_name} ({len(cases)} tests across {num} workers)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    results = []

    with ThreadPoolExecutor(max_workers=num) as pool:
        futures = {}
        for i, inst in enumerate(instances):
            fut = pool.submit(mod.worker, i, inst.transport, labels, batches[i])
            futures[fut] = i

        for fut in as_completed(futures):
            try:
                wid, passed, failed, dur = fut.result()
                results.append((wid, passed, failed))
            except Exception as e:
                wid = futures[fut]
                print(f"  [Worker {wid}] EXCEPTION: {e}")
                results.append((wid, 0, len(batches[wid])))

    duration = time.monotonic() - t0
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    return suite_name, total_passed, total_failed, duration


def run_suite_gcmsiv_polyval(
    instances: list,
    labels: Labels,
    iterations: int,
) -> SuiteResult:
    """Run GCM-SIV roundtrip tests — each worker runs full suite independently."""
    mod = _import_test_module("test_gcmsiv_polyval")
    num = len(instances)
    per_worker = max(1, iterations // num)

    suite_name = "GCM-SIV Roundtrip"
    print(f"\n{'=' * 60}")
    print(f"  {suite_name} ({per_worker} iterations x {num} workers)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    results = []

    with ThreadPoolExecutor(max_workers=num) as pool:
        futures = {}
        for i, inst in enumerate(instances):
            fut = pool.submit(mod.worker_run, i, inst.transport, labels, per_worker)
            futures[fut] = i

        for fut in as_completed(futures):
            try:
                wid, passed, failed, dur = fut.result()
                results.append((wid, passed, failed))
            except Exception as e:
                wid = futures[fut]
                print(f"  [Worker {wid}] EXCEPTION: {e}")
                results.append((wid, 0, 1))

    duration = time.monotonic() - t0
    total_passed = sum(r[1] for r in results)
    total_failed = sum(r[2] for r in results)
    return suite_name, total_passed, total_failed, duration


# ---------------------------------------------------------------------------
# UI-driven suite helpers
# ---------------------------------------------------------------------------

def run_suite_csr(
    instances: list,
    labels: Labels,
) -> SuiteResult:
    """Run CSR integration tests on a single instance (UI-driven).

    Uses test_csr_harness module's individual test functions. Each scenario
    starts from a freshly booted program (fresh_scenario), so neither the
    direct-memory suites nor an earlier scenario decide its starting state.
    """
    suite_name = "CSR (PKCS#10)"
    print(f"\n{'=' * 60}")
    print(f"  {suite_name} (4 UI-driven scenarios on instance 0)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    transport = instances[0].transport

    mod = _import_test_module("test_csr_harness")
    passed = 0
    failed = 0

    scenarios = [
        ("Full CSR", mod.test_full_csr),
        ("CN-only CSR", mod.test_cn_only),
        ("No CN (Country+Org)", mod.test_no_cn),
        ("All empty (rejection)", mod.test_all_empty_rejected),
    ]

    for scenario_name, test_fn in scenarios:
        run = fresh_scenario(transport, lambda: test_fn(transport, labels))
        try:
            ok, msg = run()
            if ok:
                passed += 1
            else:
                print(f"  FAIL: {scenario_name}: {msg}")
                failed += 1
        except Exception as e:
            print(f"  FAIL: {scenario_name}: EXCEPTION {e}")
            failed += 1

    duration = time.monotonic() - t0
    return suite_name, passed, failed, duration


def run_suite_hmac_drbg(
    instances: list,
    labels: Labels,
) -> SuiteResult:
    """Run HMAC-DRBG / RFC 6979 test on a single instance (UI-driven).

    This test drives PKCS#10 CSR generation (J->3) which includes ECDSA
    key generation — very slow even in warp mode (~5-10 minutes).
    Restarts the program first.
    """
    suite_name = "HMAC-DRBG (RFC 6979)"
    print(f"\n{'=' * 60}")
    print(f"  {suite_name} (1 UI-driven test on instance 0, ~5-10 min)")
    print(f"{'=' * 60}")

    t0 = time.monotonic()
    transport = instances[0].transport

    # Boot the program fresh: this test must not inherit earlier suites' state
    print("  Booting program fresh on instance 0...")
    if not restart_program(transport):
        print("  FATAL: Could not restart program for HMAC-DRBG test")
        return suite_name, 0, 1, time.monotonic() - t0

    mod = _import_test_module("test_hmac_drbg")

    try:
        ok, msg = mod.test_rfc6979_via_pkcs10(transport, labels)
        if ok:
            print(f"  PASS: {msg}")
            return suite_name, 1, 0, time.monotonic() - t0
        else:
            print(f"  FAIL: {msg}")
            return suite_name, 0, 1, time.monotonic() - t0
    except Exception as e:
        print(f"  FAIL: EXCEPTION {e}")
        return suite_name, 0, 1, time.monotonic() - t0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_suites(instances, labels, iterations, fail_fast, include_ecdsa=True):
    """Run every suite across *instances*; returns (suite_results, wall_time)."""
    wall_start = time.monotonic()
    suite_results: list[SuiteResult] = []

    # Order: fastest first for fail-fast benefit. The direct-memory suites
    # come first: they need the state prepare_direct_tests() set up, and the
    # UI suites after them boot the program fresh for every scenario.
    suites = [
        ("SHA-256", lambda: run_suite_simple(
            "SHA-256", "test_sha256_direct",
            instances, labels, iterations)),
        ("AES-CBC Encrypt", lambda: run_suite_simple(
            "AES-CBC Encrypt", "test_aes_cbc_direct",
            instances, labels, iterations)),
        ("AES-CBC Decrypt", lambda: run_suite_simple(
            "AES-CBC Decrypt", "test_aes_cbc_decrypt_direct",
            instances, labels, iterations)),
        ("POLYVAL", lambda: run_suite_polyval(instances, labels)),
        ("GCM-SIV Encrypt", lambda: run_suite_gcmsiv_encrypt(
            instances, labels, iterations)),
        ("GCM-SIV Decrypt", lambda: run_suite_gcmsiv_decrypt(
            instances, labels, iterations)),
        ("GCM-SIV Roundtrip", lambda: run_suite_gcmsiv_polyval(
            instances, labels, iterations)),
        ("CSR (PKCS#10)", lambda: run_suite_csr(instances, labels)),
    ]
    if include_ecdsa:
        suites.append(("HMAC-DRBG (RFC 6979)", lambda: run_suite_hmac_drbg(
            instances, labels)))
    else:
        print("\n  SKIP: HMAC-DRBG (RFC 6979) -- an ECDSA signature at 1 MHz "
              "(~40 min); pass --with-ecdsa to run it")

    for suite_name, run_fn in suites:
        result = run_fn()
        suite_results.append(result)
        _, passed, failed, duration = result
        if failed > 0 and fail_fast:
            print(f"\n  {suite_name} had failures — aborting (--fail-fast).")
            break

    return suite_results, time.monotonic() - wall_start


def choose_hardware_host() -> str | None:
    """U64_HOST if set, else the first reachable HARDWARE_HOSTS address
    whose device nobody holds.

    Reachability is the harness's GET-only probe (ping + TCP + REST info),
    which writes nothing. If every reachable device is held, queue on the
    first reachable one: the DeviceLock wait extends while its holder is
    alive and heartbeating. None if nothing answers.
    """
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


def run_on_vice(num_workers, labels, iterations, fail_fast, smoke_only):
    port_end = PORT_RANGE_START + num_workers + PORT_RANGE_HEADROOM
    print(f"\n=== Starting {num_workers} VICE instances "
          f"(free ports from {PORT_RANGE_START}-{port_end - 1}) ===")

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    with ViceInstanceManager(
        config=config,
        port_range_start=PORT_RANGE_START,
        port_range_end=port_end,
    ) as mgr:
        instances = boot_instances(mgr, num_workers)
        if instances is None:
            return None

        if not run_smoke_test(instances):
            print("\nSmoke test FAILED — aborting.")
            return None
        print("  Smoke test passed — parallel VICE pool verified.\n")

        if smoke_only:
            for inst in instances:
                mgr.release(inst)
            return [], 0.0

        results = run_suites(instances, labels, iterations, fail_fast)

        for inst in instances:
            mgr.release(inst)
    return results


def run_on_hardware(labels, iterations, fail_fast, smoke_only, with_ecdsa,
                    native_speed):
    print("\n=== Selecting an Ultimate device ===")
    host = choose_hardware_host()
    if host is None:
        print(f"  FATAL: no Ultimate device answers ({', '.join(HARDWARE_HOSTS)})")
        return None
    print(f"  target: {host} (queueing on its DeviceLock, up to "
          f"{HARDWARE_LOCK_TIMEOUT / 60:.0f} min behind a stalled holder)")

    with create_manager(
        backend="u64", u64_hosts=[host], lock_timeout=HARDWARE_LOCK_TIMEOUT,
    ) as mgr:
        with mgr.instance() as target:
            transport = target.transport
            info = transport.client.get_info()
            print(f"  acquired: {info.get('product', '?')} "
                  f"fw {info.get('firmware_version', '?')} at {host}")

            # Speed is part of the known state too: set it explicitly
            # (bodyless per-item config PUTs, nothing left in /Temp) and put
            # the shared device back to 1 MHz however the run ends.
            if not native_speed:
                transport.set_speed(None)
            mhz = transport.get_speed()
            print(f"  CPU speed: {mhz} MHz")
            try:
                # Known state before anything runs: reset, reload the PRG,
                # boot to the menu, then quit to BASIC for run_subroutine().
                print("  Booting program fresh and quitting to BASIC...")
                if not prepare_direct_tests(transport):
                    dump_screen(transport, "hardware prepare")
                    print("  FATAL: could not boot the program and reach READY.")
                    return None

                if not run_smoke_test([target]):
                    print("\nSmoke test FAILED — aborting.")
                    return None
                print("  Smoke test passed — hardware memory path verified.\n")
                if smoke_only:
                    return [], 0.0

                return run_suites([target], labels, iterations, fail_fast,
                                  include_ecdsa=with_ecdsa or mhz != 1)
            finally:
                if not native_speed:
                    transport.set_speed(1)
                    print("  CPU speed restored to 1 MHz")


def main() -> int:
    (num_workers, iterations, fail_fast, seed, verbose, smoke_only,
     backend, with_ecdsa, native_speed) = parse_args()
    random.seed(seed)
    if backend == "u64":
        num_workers = 1

    print(f"c64-aes256-ecdsa — Unified Test Runner")
    print(f"Backend: {backend}, Workers: {num_workers}, "
          f"Iterations: {iterations}, Seed: {seed}")
    print()

    if not build():
        return 1

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in ALL_REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"  FATAL: missing labels: {', '.join(missing)}")
        return 1
    print(f"  Labels loaded ({len(ALL_REQUIRED_LABELS)} symbols verified)")

    if backend == "u64":
        outcome = run_on_hardware(labels, iterations, fail_fast, smoke_only,
                                  with_ecdsa, native_speed)
    else:
        outcome = run_on_vice(num_workers, labels, iterations, fail_fast,
                              smoke_only)
    if outcome is None:
        return 1
    suite_results, wall_time = outcome
    if smoke_only:
        return 0

    # --- Final summary ---
    print("\n" + "=" * 70)
    print("  FINAL RESULTS")
    print("=" * 70)
    grand_passed = 0
    grand_failed = 0
    for name, passed, failed, duration in suite_results:
        total = passed + failed
        status = "PASS" if failed == 0 else "FAIL"
        grand_passed += passed
        grand_failed += failed
        print(f"  [{status}] {name:25s}  {passed:4d}/{total:4d} passed  ({duration:.1f}s)")
    print("-" * 70)
    grand_total = grand_passed + grand_failed
    print(f"  Total: {grand_passed}/{grand_total} passed")
    print(f"  Wall time: {wall_time:.1f}s")
    where = ("on Ultimate hardware" if backend == "u64"
             else f"across {num_workers} VICE instances")
    if grand_failed == 0:
        print(f"\n  ALL {grand_total} TESTS PASSED {where}")
    else:
        print(f"\n  {grand_failed} TEST(S) FAILED")
    print("=" * 70)

    return 0 if grand_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
