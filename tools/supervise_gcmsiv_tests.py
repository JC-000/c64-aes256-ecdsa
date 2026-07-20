#!/usr/bin/env python3
"""
supervise_gcmsiv_tests.py - Launch and coordinate two Claude agents to develop
GCM-SIV encrypt and decrypt tests for the C64 AES-256-GCM-SIV implementation.

Agent 1 (Encrypt): Creates tools/test_gcmsiv_encrypt_direct.py
Agent 2 (Decrypt): Creates tools/test_gcmsiv_decrypt_direct.py

Both agents run in parallel, each with its own VICE instance.
After both succeed, a chained validation runs encrypt vectors through the decrypt test.

Usage:
    python3 tools/supervise_gcmsiv_tests.py
"""

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
VECTORS_PATH = TOOLS_DIR / "gcmsiv_test_vectors.json"

TIMEOUT_SECONDS = 30 * 60  # 30 minutes per agent

# ---------------------------------------------------------------------------
# Agent prompt templates
# ---------------------------------------------------------------------------

ENCRYPT_AGENT_PROMPT = textwrap.dedent(r"""
You are developing a direct-memory test for the C64's AES-256-GCM-SIV ENCRYPT implementation.

## Your Task
Create the file `tools/test_gcmsiv_encrypt_direct.py` that tests the C64's `gcmsiv_encrypt` routine
by writing inputs directly to memory and reading outputs, comparing against a Python reference.

## Algorithm (C64's GCM-SIV with CBC-MAC)
The Python reference is already on disk at `tools/gcmsiv_reference.py`. Import and use it:
```python
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import gcmsiv_reference
```

## Key Memory Addresses (from build/labels.txt)
Read the exact addresses from build/labels.txt using `Labels.from_file()`. The key labels are:
- `key_data` - 32-byte main AES-256 key
- `aes_key_expansion` - MUST call before gcmsiv_encrypt
- `gcmsiv_nonce` ($45a9) - 12-byte nonce
- `gcmsiv_pt_buf` ($45b5) - 64-byte plaintext input buffer
- `gcmsiv_pt_len` ($45f5) - 1-byte plaintext length (max 64)
- `gcmsiv_ct_buf` ($45f6) - 64-byte ciphertext output buffer
- `gcmsiv_tag` ($4676) - 16-byte authentication tag output
- `gcmsiv_encrypt` ($1d79) - encrypt entry point

## CRITICAL: Key Expansion
You MUST call `jsr(transport, labels["aes_key_expansion"])` BEFORE calling
`jsr(transport, labels["gcmsiv_encrypt"])`. The encrypt routine calls `aes_encrypt_block`
internally which uses the pre-expanded key. gcmsiv_encrypt does its own internal key
derivation and expansion for subkeys, but it needs the MAIN key expanded first because
`gcmsiv_derive_keys` calls `aes_encrypt_block` with the main key.

## Test Pattern (follow tools/test_aes_cbc_direct.py)
```python
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, C64Transport as ViceTransport,
    dump_screen, read_bytes, write_bytes, jsr, wait_for_text,
)
```

ALWAYS use `ViceInstanceManager` to start VICE and obtain a transport - never construct
`ViceProcess` or a transport directly (this risks port collisions with concurrent
agents/processes). Pattern:
```python
config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
with ViceInstanceManager(config=config) as mgr:
    inst = mgr.acquire()
    transport = inst.transport
    ... run tests using `transport` ...
    mgr.release(inst)
```
`jsr()` is event-based (it waits for the CPU to stop internally) - no retry wrapper is needed
around it.

For each test:
1. `write_bytes(transport, labels["key_data"], key)` - 32 bytes
2. `jsr(transport, labels["aes_key_expansion"], timeout=5.0)` - expand the main key
3. `write_bytes(transport, labels["gcmsiv_nonce"], nonce)` - 12 bytes
4. `write_bytes(transport, labels["gcmsiv_pt_buf"], plaintext)` - up to 64 bytes
5. `write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(plaintext)]))`
6. `jsr(transport, labels["gcmsiv_encrypt"], timeout=60.0)` - run encrypt (slow!)
7. `ct = read_bytes(transport, labels["gcmsiv_ct_buf"], len(plaintext))` - read ciphertext
8. `tag = read_bytes(transport, labels["gcmsiv_tag"], 16)` - read tag
9. Compare ct and tag against `gcmsiv_reference.encrypt(key, nonce, plaintext)`

## Test Cases
Include boundary sizes: 1, 15, 16, 17, 32, 48, 63, 64 bytes, plus random lengths up to 50 total tests.
Use `--iterations N` to control count (default 50), `--seed S` for reproducibility.

## Timeout
GCM-SIV is computationally expensive on the 6502 (~17+ AES operations per encrypt).
Use `timeout=60.0` for each `jsr(gcmsiv_encrypt)` call, and enable warp mode.

## Save Test Vectors
On successful completion, save all test vectors to `tools/gcmsiv_test_vectors.json`:
```python
vectors = [{
    "key": key.hex(), "nonce": nonce.hex(), "plaintext": pt.hex(),
    "ciphertext": ct.hex(), "tag": tag.hex()
}, ...]
json.dump(vectors, open("tools/gcmsiv_test_vectors.json", "w"), indent=2)
```

## Structure
Follow the structure of `tools/test_aes_cbc_direct.py`:
- Parse --iterations, --seed args
- Build via make
- Load labels from build/labels.txt
- Start VICE via ViceInstanceManager (config=ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)); acquire() an instance and use inst.transport
- Wait for "Q=QUIT" menu
- Run tests
- Print summary

## Self-Iteration
After writing the test file, run it:
```
python3 tools/test_gcmsiv_encrypt_direct.py --iterations 10
```
If tests fail, diagnose the error, fix your code, and re-run. Repeat up to 10 times.

When done (all tests pass OR you've exhausted retries), print exactly one of:
- `AGENT_DONE_SUCCESS` (all tests passed)
- `AGENT_DONE_FAILURE` (tests still failing after retries)

IMPORTANT: Make sure the test file runs with `--iterations 10` first for quick validation,
then save vectors with the default 50 iterations on success.
""").strip()

DECRYPT_AGENT_PROMPT = textwrap.dedent(r"""
You are developing a direct-memory test for the C64's AES-256-GCM-SIV DECRYPT implementation.

## Your Task
Create the file `tools/test_gcmsiv_decrypt_direct.py` that tests the C64's `gcmsiv_decrypt` routine
by writing inputs directly to memory and reading outputs, comparing against a Python reference.

## Algorithm (C64's GCM-SIV with CBC-MAC)
The Python reference is already on disk at `tools/gcmsiv_reference.py`. Import and use it:
```python
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import gcmsiv_reference
```

Use `gcmsiv_reference.encrypt(key, nonce, plaintext)` to generate (ciphertext, tag) pairs,
then feed those to the C64's decrypt and verify the output matches.

## Key Memory Addresses (from build/labels.txt)
Read the exact addresses from build/labels.txt using `Labels.from_file()`. The key labels are:
- `key_data` - 32-byte main AES-256 key
- `aes_key_expansion` - MUST call before gcmsiv_decrypt
- `gcmsiv_nonce` ($45a9) - 12-byte nonce
- `gcmsiv_ct_buf` ($45f6) - 64-byte ciphertext input buffer
- `gcmsiv_pt_len` ($45f5) - 1-byte length (ciphertext length = plaintext length)
- `gcmsiv_tag` ($4676) - 16-byte authentication tag input
- `gcmsiv_dec_buf` ($4636) - 64-byte decrypted output buffer
- `gcmsiv_tag_valid` ($46e9) - 1-byte tag verification result (0=fail, 1=pass)
- `gcmsiv_decrypt` ($211d) - decrypt entry point

## CRITICAL: Key Expansion
You MUST call `jsr(transport, labels["aes_key_expansion"])` BEFORE calling
`jsr(transport, labels["gcmsiv_decrypt"])`. The decrypt routine needs the main key
expanded because `gcmsiv_derive_keys` calls `aes_encrypt_block` with the main key.

## CRITICAL: Decrypt reads from gcmsiv_dec_buf
The decrypted output is at `gcmsiv_dec_buf` ($4636), NOT at `gcmsiv_pt_buf`.
The C64 internally copies dec_buf to pt_buf for tag recomputation, but the result
you should read is from `gcmsiv_dec_buf`.

## CRITICAL: Tag tampering clears dec_buf
On tag mismatch, the C64 zeros out `gcmsiv_dec_buf` entirely (64 bytes) and sets
`gcmsiv_tag_valid` to 0. Test this behavior!

## Test Pattern (follow tools/test_aes_cbc_decrypt_direct.py)
```python
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager, C64Transport as ViceTransport,
    dump_screen, read_bytes, write_bytes, jsr, wait_for_text,
)
```

ALWAYS use `ViceInstanceManager` to start VICE and obtain a transport - never construct
`ViceProcess` or a transport directly (this risks port collisions with concurrent
agents/processes). Pattern:
```python
config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
with ViceInstanceManager(config=config) as mgr:
    inst = mgr.acquire()
    transport = inst.transport
    ... run tests using `transport` ...
    mgr.release(inst)
```
`jsr()` is event-based (it waits for the CPU to stop internally) - no retry wrapper is needed
around it.

For each test:
1. Generate random key (32 bytes), nonce (12 bytes), plaintext (1-64 bytes)
2. Encrypt with Python: `ct, tag = gcmsiv_reference.encrypt(key, nonce, plaintext)`
3. Write to C64 memory:
   - `write_bytes(transport, labels["key_data"], key)`
   - `jsr(transport, labels["aes_key_expansion"], timeout=5.0)`
   - `write_bytes(transport, labels["gcmsiv_nonce"], nonce)`
   - `write_bytes(transport, labels["gcmsiv_ct_buf"], ct)`
   - `write_bytes(transport, labels["gcmsiv_pt_len"], bytes([len(plaintext)]))`
   - `write_bytes(transport, labels["gcmsiv_tag"], tag)`
4. `jsr(transport, labels["gcmsiv_decrypt"], timeout=60.0)`
5. Read results:
   - `dec = read_bytes(transport, labels["gcmsiv_dec_buf"], len(plaintext))`
   - `valid = read_bytes(transport, labels["gcmsiv_tag_valid"], 1)[0]`
6. Verify: `valid == 1` and `dec == plaintext`

## Tag Tampering Tests
After the normal tests, include ~5 tag tampering tests:
1. Generate valid encrypt: `ct, tag = gcmsiv_reference.encrypt(key, nonce, pt)`
2. Flip a bit in the tag: `bad_tag = bytearray(tag); bad_tag[0] ^= 0x01`
3. Write ct + bad_tag to C64, run decrypt
4. Verify: `gcmsiv_tag_valid == 0` and `gcmsiv_dec_buf` is all zeros (64 bytes)

## Test Cases
Include boundary sizes: 1, 15, 16, 17, 32, 48, 63, 64 bytes, plus random lengths.
Total ~50 tests including tag tampering. Use `--iterations N` and `--seed S` args.

Also support `--vectors PATH` argument: if provided, load test vectors from a JSON file
(produced by the encrypt test) instead of generating with Python reference.
Format: [{"key": hex, "nonce": hex, "plaintext": hex, "ciphertext": hex, "tag": hex}, ...]

## Timeout
GCM-SIV is computationally expensive. Use `timeout=60.0` for each `jsr(gcmsiv_decrypt)`.

## Structure
Follow `tools/test_aes_cbc_decrypt_direct.py`:
- Parse --iterations, --seed, --vectors args
- Build via make
- Load labels
- Start VICE via ViceInstanceManager (config=ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)); acquire() an instance and use inst.transport
- Wait for "Q=QUIT" menu
- Run tests
- Print summary

## Self-Iteration
After writing the test file, run it:
```
python3 tools/test_gcmsiv_decrypt_direct.py --iterations 10
```
If tests fail, diagnose the error, fix your code, and re-run. Repeat up to 10 times.

When done (all tests pass OR you've exhausted retries), print exactly one of:
- `AGENT_DONE_SUCCESS` (all tests passed)
- `AGENT_DONE_FAILURE` (tests still failing after retries)

IMPORTANT: Make sure the test file runs with `--iterations 10` first for quick validation.
""").strip()


# ---------------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------------

def stream_agent_output(proc, prefix: str, result: dict):
    """Read agent stdout line by line, prefix and print, watch for sentinels."""
    try:
        for line in iter(proc.stdout.readline, ""):
            if not line:
                break
            line = line.rstrip("\n")
            print(f"[{prefix}] {line}", flush=True)
            if "AGENT_DONE_SUCCESS" in line:
                result["status"] = "success"
            elif "AGENT_DONE_FAILURE" in line:
                result["status"] = "failure"
    except Exception as e:
        print(f"[{prefix}] Stream error: {e}", flush=True)


def run_agent(name: str, prompt: str, result: dict):
    """Launch a Claude agent subprocess and monitor its output."""
    print(f"\n{'='*60}")
    print(f"Launching Agent: {name}")
    print(f"{'='*60}\n", flush=True)

    env = os.environ.copy()
    # Remove CLAUDECODE to avoid nested session errors
    env.pop("CLAUDECODE", None)
    env.pop("CLAUDE_CODE_SESSION_ID", None)

    cmd = [
        "claude",
        "--print",
        "--model", "sonnet",
        "--output-format", "text",
        "--dangerously-skip-permissions",
        "-p", prompt,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(PROJECT_ROOT),
            env=env,
        )
        result["pid"] = proc.pid
        print(f"[{name}] Started (PID {proc.pid})", flush=True)

        # Stream output with timeout
        stream_thread = threading.Thread(
            target=stream_agent_output, args=(proc, name, result)
        )
        stream_thread.start()
        stream_thread.join(timeout=TIMEOUT_SECONDS)

        if stream_thread.is_alive():
            print(f"[{name}] TIMEOUT after {TIMEOUT_SECONDS}s, killing...", flush=True)
            proc.kill()
            result["status"] = "timeout"
        else:
            proc.wait()
            if result.get("status") is None:
                result["status"] = "unknown"

        print(f"\n[{name}] Final status: {result['status']}", flush=True)

    except Exception as e:
        print(f"[{name}] Launch error: {e}", flush=True)
        result["status"] = "error"
        result["error"] = str(e)


def run_chained_validation():
    """Run decrypt test using encrypt-generated vectors for end-to-end validation."""
    print(f"\n{'='*60}")
    print("Phase 2: Chained Validation (encrypt vectors -> decrypt test)")
    print(f"{'='*60}\n", flush=True)

    if not VECTORS_PATH.exists():
        print("SKIP: No test vectors file found (encrypt agent may not have saved them)")
        return False

    # Verify vectors file is valid JSON
    try:
        with open(VECTORS_PATH) as f:
            vectors = json.load(f)
        print(f"Loaded {len(vectors)} test vectors from {VECTORS_PATH}")
    except Exception as e:
        print(f"ERROR: Could not load vectors: {e}")
        return False

    decrypt_test = TOOLS_DIR / "test_gcmsiv_decrypt_direct.py"
    if not decrypt_test.exists():
        print("SKIP: Decrypt test file not found")
        return False

    print("Running decrypt test with encrypt-generated vectors...\n", flush=True)

    result = subprocess.run(
        ["python3", str(decrypt_test), "--vectors", str(VECTORS_PATH), "--iterations", "50"],
        capture_output=False,
        text=True,
        cwd=str(PROJECT_ROOT),
        timeout=TIMEOUT_SECONDS,
    )

    if result.returncode == 0:
        print("\n[CHAINED] PASS: All encrypt vectors decrypted successfully")
        return True
    else:
        print(f"\n[CHAINED] FAIL: Decrypt test returned {result.returncode}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    print("=" * 60)
    print("GCM-SIV Test Supervisor")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Timeout per agent: {TIMEOUT_SECONDS}s")

    # Verify prerequisites
    if not (PROJECT_ROOT / "tools" / "gcmsiv_reference.py").exists():
        print("FATAL: tools/gcmsiv_reference.py not found")
        sys.exit(1)

    if not (PROJECT_ROOT / "build" / "aes256keygen.prg").exists():
        print("Building project...")
        subprocess.run(["make"], cwd=str(PROJECT_ROOT), check=True)

    # Phase 1: Launch both agents in parallel
    print(f"\n{'='*60}")
    print("Phase 1: Launching Agents in Parallel")
    print(f"{'='*60}")

    encrypt_result = {"status": None}
    decrypt_result = {"status": None}

    encrypt_thread = threading.Thread(
        target=run_agent,
        args=("ENCRYPT", ENCRYPT_AGENT_PROMPT, encrypt_result),
    )
    decrypt_thread = threading.Thread(
        target=run_agent,
        args=("DECRYPT", DECRYPT_AGENT_PROMPT, decrypt_result),
    )

    encrypt_thread.start()
    decrypt_thread.start()

    encrypt_thread.join()
    decrypt_thread.join()

    # Phase 1 results
    print(f"\n{'='*60}")
    print("Phase 1 Results")
    print(f"{'='*60}")
    print(f"  Encrypt Agent: {encrypt_result['status']}")
    print(f"  Decrypt Agent: {decrypt_result['status']}")

    both_passed = (
        encrypt_result["status"] == "success"
        and decrypt_result["status"] == "success"
    )

    # Phase 2: Chained validation (only if both passed)
    chained_ok = False
    if both_passed:
        try:
            chained_ok = run_chained_validation()
        except Exception as e:
            print(f"Chained validation error: {e}")
    else:
        print("\nSkipping chained validation (not both agents succeeded)")

    # Final summary
    print(f"\n{'='*60}")
    print("FINAL SUMMARY")
    print(f"{'='*60}")
    print(f"  Encrypt Agent:       {encrypt_result['status']}")
    print(f"  Decrypt Agent:       {decrypt_result['status']}")
    print(f"  Chained Validation:  {'PASS' if chained_ok else 'SKIP/FAIL'}")

    if both_passed and chained_ok:
        print(f"\n  [+] ALL PHASES PASSED")
        sys.exit(0)
    elif both_passed:
        print(f"\n  [~] Agents passed, chained validation pending/failed")
        sys.exit(0)
    else:
        print(f"\n  [-] SOME PHASES FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
