# Test Suite Audit

**Scope:** Independent audit of the c64-aes256-ecdsa test suite across five lanes — coverage, depth, infrastructure health, post-refactor validation, and negative-path testing. Every finding below was gathered by a lane agent and then independently re-verified by a second, skeptical pass against the actual repo state (line numbers, grep output, and in several cases live command execution) before being included here.

**Update (2026-07-20, same day):** all `tools/*.py` harness-compatibility breakage this report identified (15 files total, across the original audit and the addendum below) has since been fixed and individually re-verified by actually running each script against real VICE — see the addendum's "findings from actually running the harness-compatibility fix" section for what that pass additionally found and fixed. The coverage/depth/negative-path gaps in the main body below (missing tests, not broken ones) remain open.

## Executive Summary

The project's core crypto correctness suites are genuinely solid: SHA-256, AES-256-CBC, POLYVAL, and GCM-SIV all run to 100% today (9 canonical suites, ~227 tests, wired through `tools/run_all_tests.py`), and the GCM-SIV/POLYVAL suite in particular checks real RFC 8452 and NIST reference vectors rather than only self-referential Python re-implementations. Against that solid core, this audit confirmed **32 distinct, currently-true gaps** (14 high, 14 medium, 4 low severity) spanning five large, entirely untested user-facing features (REU status/fill/save, SID config, RNG stream display, benchmark timing, and all disk save/load), several depth gaps in the crypto tests that are already passing (no wrong-key rejection test, tag-only tamper coverage, no boundary/overflow inputs), a standalone-test-runner rot problem (import/API breakage across most of the individually-runnable scripts), zero CI/CD of any kind, and two post-refactor invariants (the boot.o link-position requirement and the `.importzp` warning class) that are enforced today only by a human rereading a Makefile comment. None of these gaps threaten the correctness of the crypto that is tested — they are coverage and process gaps, not evidence of active corruption — but several (disk-write paths, REU, wrong-key handling) are exactly the kind of gap that lets a real regression ship silently.

---

## Coverage

Features and code paths that are never invoked by any test — dead ground from the harness's perspective, whether or not they're dead in the running program.

- **[HIGH] REU status/fill/save UI (menu 'G') never exercised** — `do_show_reu_status` in `src/reu_advanced.s`, the entire REU status/fill(zero or random)/save-to-disk feature reached via main-menu key `G`, is never invoked by any of the 9 registered suites or any standalone `tools/test_*.py` script. No script ever sends key `G`, and no script references `do_show_reu_status`, `reu_fill_random`, or any REU fill/save label.
  *Evidence:* `src/main_loop.s:109-111` dispatches `petscii_g -> do_show_reu_status`; `grep -rn "reu_" tools/*.py` returns zero matches.
  *Suggested action:* Add a UI-driven test sending `G` from the main menu, driving at least one zero-fill and the save-to-disk path, asserting REU-present vs REU-absent behavior on both branches.

- **[HIGH] SID config (menu 'I') and RNG stream (menu 'H') never exercised** — `do_config_sid` and `do_random_stream` in `src/sid_config.s` are dispatched on keys `I`/`H` but no script ever sends either key. The underlying RNG primitive (`drbg_random_byte`) is independently well-tested via GCM-SIV/HMAC-DRBG, but the SID-chip-count config UI and the stream display/rate-calculation code have zero coverage of any kind.
  *Evidence:* `src/main_loop.s:113-119`; `grep -n 'send_key(transport, "H")\|"I")' tools/*.py` — no matches.
  *Suggested action:* UI-driven test sending `I` to configure extra SID chips and verify resulting state; a test sending `H` briefly and confirming start/stop and rate stats.

- **[HIGH] `do_benchmark` (menu 'E', CBC/GCM timing) never exercised** — Unlike its sibling `do_load_nist_vectors` (menu 'F'), which IS covered by `tools/test_csr.py`'s `test_key_preserved_after_nist`, the CIA-timer-based CBC/GCM-SIV throughput benchmark has zero coverage anywhere in the repo (verified with a repo-wide, not just `tools/`-scoped, grep).
  *Evidence:* `src/main_loop.s:101-107`; `src/benchmark.s:34`; no match for "benchmark" in any `.py` file repo-wide.
  *Suggested action:* Add a test sending `E`, waiting for the results screen, sanity-checking non-zero iteration/elapsed counts, and confirming key/state survive afterward.

- **[HIGH] Disk save/load code paths (menu keys 5/6/7/8, and every "SAVE TO DISK" prompt) never executed end-to-end** — `do_save_key`, `do_load_key`, `do_save_encrypted`, `do_load_encrypted` are never invoked by any script, and every UI flow that reaches a save prompt (CSR text, PKCS#10, GCM-SIV) always answers `N`. The entire disk-write path — filename entry, `build_write_filename`, `check_file_exists`, `write_hex_digit`, the actual KERNAL `SAVE` call — is never exercised, despite being core, README-documented functionality. Confirmed repo-wide: no script anywhere sends `Y` at any prompt.
  *Evidence:* `src/disk_io.s:50,239,391,968,1345`; zero `"5"/"6"/"7"/"8"` or `"Y"` sends anywhere in the repo.
  *Suggested action:* Add at least one end-to-end save-then-load-back test against a real D64 image in the harness.

- **[MEDIUM] `detect_reu` runs on every boot but its output is never asserted** — Runs unconditionally in `boot.s`'s startup (not dead code), but no test reads `reu_present`/`reu_size_kb` back, and no harness configuration ever attaches a REU, so only the REU-absent branch is exercised at all, and even that is unasserted.
  *Evidence:* `src/boot.s:28,61`; zero `reu_present`/`reu_size_kb`/any REU-name reference anywhere in `tools/*.py`.
  *Suggested action:* Assert on `reu_present`/`reu_size_kb` after boot in an existing suite; add a REU-attached VICE config if feasible to cover the present-path.

- **[MEDIUM] `do_ecdsa_test` (menu J→2, RFC 6979 A.2.5 diagnostic) never exercised** — The CSR submenu's own fixed-vector self-check is a genuinely distinct code path from the HMAC-DRBG suite (different privkey/k/hash triple, different verification strategy), but no script ever sends `2` after entering the CSR submenu — only `1` and `3` are ever sent. If `do_ecdsa_test`'s own comparison logic or embedded vector regressed, nothing would catch it. Independently corroborated by the project's own `src/lib_manifest.s`, which documents this routine as reachable "only via menu J→2" with "nothing else in the codebase" calling it.
  *Evidence:* `src/csr.s:56-67`; `src/ecdsa_test.s:31`; only `"1"`/`"3"` ever sent after `"J"` in any script.
  *Suggested action:* Add a short UI test sending `J` then `2` and asserting a pass message.

- **[MEDIUM] GCM-SIV UI wrapper routines (menu keys A/B/C/D) never exercised** — The 3 official GCM-SIV suites all call the lower-level `gcmsiv_encrypt`/`gcmsiv_decrypt` primitives directly via `jsr()`, bypassing `do_gcm_siv_encrypt/decrypt/save/load` entirely. The input-prompt handling, buffer wiring, and disk save/load variants specific to the UI path are untested even though the harder-to-get-right crypto core is well covered.
  *Evidence:* `src/gcm_siv.s:51,686,984,1159`; zero `"A"/"B"/"C"/"D"` sends anywhere in `tools/*.py`.
  *Suggested action:* Add a UI-driven GCM-SIV test exercising encrypt/decrypt/save/load through the actual menu.

- **[LOW] `display.s`, `main_loop.s`, `boot.s` have no dedicated/direct test** — Only implicitly, unassertedly exercised as a side effect of every other test booting the program. The canonical 9-suite runner only ever drives menu key `J` at the top level (7 of 9 suites bypass the UI entirely via direct-memory calls); no test checks display formatting, or that two consecutive boots produce different keys.
  *Evidence:* zero matches for `display_key_only`/`print_hex_byte`/etc. in `tools/*.py`; boot.s key material is cross-checked by CSR tests but never validated for boot-to-boot randomness.
  *Suggested action:* Low priority given these are thin dispatch/formatting/bootstrap layers; optionally add one display-formatting assertion and one boot-to-boot key-variability check.

- **[MEDIUM] No regression test for `make lib` / `make lib-ecdsa-sign` archive builds** — Neither target is ever invoked by `run_all_tests.py`'s `build()` (which only runs plain `make`) or any test/CI. The documented CAVEAT (`lib-ecdsa-sign` fails standalone `ld65` link with exactly 2 unresolved externals) was established once, by hand, and nothing would notice if that count silently changed in either direction.
  *Evidence:* Makefile:231-232 and CAVEAT block; `grep -rln "make lib\|lib-ecdsa-sign\|ar65" tools/ .github/` — no matches; no `.github/` directory exists at all.
  *Suggested action:* Add a lightweight test that builds both archive targets and re-verifies the unresolved-external count for `lib-ecdsa-sign`.

## Depth

Code paths that ARE exercised by the passing suites, but only shallowly — the crypto primitives themselves are the asset most worth protecting here.

- **[HIGH] No wrong-key decrypt rejection test anywhere (AES-CBC or GCM-SIV)** — Every decrypt test uses the exact key that produced the ciphertext. No test decrypts valid ciphertext+tag with a deliberately wrong key to confirm AES-CBC produces garbage (expected, unauthenticated) or that GCM-SIV correctly reports `tag_valid==0` when only the key is wrong. A bug where the C64 silently reuses stale expanded-key state from a prior call would go completely undetected.
  *Evidence:* `tools/test_aes_cbc_decrypt_direct.py:110-172`; `tools/test_gcmsiv_decrypt_direct.py:104-156,203-237`.
  *Suggested action:* Add a mismatched-key decrypt case to both suites.

- **[HIGH] GCM-SIV tamper test only corrupts the tag, never a ciphertext byte** — `test_decrypt_tampered` exclusively flips a tag bit while leaving ciphertext untouched (same pattern repeated in `test_gcmsiv_polyval.py`). This only proves the C64 compares the tag field byte-for-byte — it never proves authentication actually covers the ciphertext content. A bug where the recomputed tag is derived independently of the (possibly tampered) ciphertext buffer would pass every existing test.
  *Evidence:* `tools/test_gcmsiv_decrypt_direct.py:203-237`, `generate_test_cases:244-276` (only "Boundary"/"Random"/"Tamper"-on-tag cases exist).
  *Suggested action:* Add a case with a correct tag and a corrupted ciphertext byte, asserting rejection.

- **[HIGH] Direct-memory tests never write an out-of-range length byte** — `encrypt_input` computes block count directly from `input_length` with no upper-bound check of its own (the only clamp lives in the UI text-entry loop, which the direct-memory `jsr()` harness bypasses entirely). Every direct test caps its generated length at the valid maximum; none ever writes 64/65/200/255 into `input_length`/`gcmsiv_pt_len` to check for independent protection against overflowing `encrypt_buffer` (80 bytes) or `gcmsiv_ct_buf` (64 bytes).
  *Evidence:* `src/aes_encrypt.s:149-190` (no bound check in `encrypt_input`); `src/constants.s:98-99`; `MAX_INPUT_LEN=63`/`boundary_sizes` caps in all five direct test files.
  *Suggested action:* Add a direct-memory overflow test writing an out-of-range length and asserting either a graceful clamp or, if none exists, flag the missing guard as a real bug.

- **[MEDIUM] HMAC-DRBG/RFC 6979 test never checks a fixed published vector** — `test_rfc6979_via_pkcs10` derives its "expected" output using a hand-written Python HMAC-DRBG re-implementation fed the C64's own live-generated private key — never the fixed RFC 6979 Appendix A.2.5 vector. Two independent same-project implementations of the same spec sharing a misunderstanding (wrong separator byte, K/V init order) would agree with each other while being non-conformant, and the test would still PASS. (The fixed vector does exist in `src/ecdsa_curve.s` and is exercised on-device by `do_ecdsa_test` — but that routine is itself never driven by any test, per the coverage-lane finding above, so nothing ties the two together today.) HMAC-SHA256 is also never tested against RFC 4231 vectors anywhere.
  *Evidence:* `tools/test_hmac_drbg.py:59-76,141-183`; zero references to "6979"/"A.2.5"/"4231" anywhere in test tooling.
  *Suggested action:* Add a standalone check of the DRBG (or the full pipeline) against the fixed RFC 6979 A.2.5 vector, independent of live-generated key material.

- **[MEDIUM] Most POLYVAL primitive tests validate only against a same-repo hand-written Python reference** — Of 10 POLYVAL test groups, only one case inside `test_full_pipeline` checks a real published RFC 8452 Appendix A vector. Every other group (double, right-shift, shift-left-4, precompute-table, xor-table-entry, isolated-multiply, update, multiply-vs-dot) compares only against `polyval_reference.py`, a from-scratch re-implementation of the same algorithm. A shared reduction-constant or byte-order bug in both the 6502 asm and the Python reference would pass every one of these checks.
  *Evidence:* `tools/test_polyval_direct.py:399-413` (only fixed vector) vs. `160-358,365-389,484-501` (self-referential groups).
  *Suggested action:* Add published/external vectors (or cross-check against a vetted library) at the primitive level, not just the full-pipeline level.

- **[MEDIUM] AES-CBC and GCM-SIV never exercise degenerate all-zero/all-0xFF key/IV/nonce/plaintext** — All key/IV/nonce/plaintext material comes from random generation or (for GCM-SIV) the standard RFC 8452 vectors — none of which happen to be degenerate. POLYVAL's own primitive tests do include `\x00*16`/`\xff*16` cases, showing the test author understands this class of edge case, but it's never carried through to the AES key schedule, CBC chaining, or GCM-SIV key material where a degenerate value could hit a different code path (e.g. a degenerate AES-256 key schedule).
  *Evidence:* `tools/test_aes_cbc_direct.py:304-306,320-323`; `tools/test_gcmsiv_encrypt_direct.py:222-237`; contrast with `tools/test_polyval_direct.py:168,202,232`.
  *Suggested action:* Add one pinned all-zero and one all-0xFF key/IV/nonce/plaintext case to each pipeline-level suite.

- **[MEDIUM] CSR harness never tests field-length overflow or subject-format-breaking characters** — Distinct from the already-tracked Bug 6. All four CSR scenarios use short, well-formed ASCII values well under the per-field length ceilings (country=2, state/city/org/ou=32, cn/email=40 chars in `src/csr.s`). `csr_get_field` performs zero character-class filtering — any byte including `/` or `=` is accepted verbatim and later embedded in the `/C=xx/ST=xx/...` subject line the harness itself parses.
  *Evidence:* `tools/test_csr_harness.py:456-657` (all four field dicts); `src/csr.s` `csr_get_field`/`csr_collect_fields` length constants.
  *Suggested action:* Add a boundary-length case per field and a case with an embedded `/` or `=` in an Org/CN value.

- **[LOW] AES-CBC encrypt/decrypt lacks a 0-byte (empty) input boundary case that SHA-256's suite has** — `test_sha256_direct.py` explicitly covers 0-byte input; the CBC suites' boundary lists start at 1 byte, so PKCS#7 padding of empty plaintext (expected: one full 16-byte 0x10 pad block) and `encrypt_input`'s own zero-length bail-out are both untested from the Python side.
  *Evidence:* `tools/test_aes_cbc_direct.py:293-299`; `tools/test_aes_cbc_decrypt_direct.py:364-370`; `src/aes_encrypt.s:151-153`.
  *Suggested action:* Add an explicit 0-byte case mirroring `test_sha256_empty`.

## Infrastructure

Health of the test-running machinery itself, independent of what it does or doesn't cover.

- **[HIGH] Six standalone `tools/test_*.py` scripts fail immediately with `ImportError` against harness 0.12.4** — `test_csr.py`, `test_aes_cbc.py`, `test_aes_cbc_decrypt.py`, `test_sha256.py`, `test_pkcs10.py`, and `test_validate_direct_tests.py` all still import the renamed `ViceTransport` class with no alias; the installed harness renamed it to `C64Transport`. Reproduced live for all six. A prior commit explicitly documented leaving these unfixed as out of scope. *Note: at verification time, another concurrent session in this workspace had begun patching these files in the uncommitted working tree — check `git status` before treating this as still-open.*
  *Evidence:* Live `python3 tools/<script>.py --help` runs on all six; bare `ViceTransport,` import at cited line numbers.
  *Suggested action:* Apply the same `C64Transport as ViceTransport` alias fix already used in the `_direct`/`_harness` files, or formally deprecate the standalone scripts.

- **[HIGH] The 8 scripts that DID get the import-alias fix are still broken standalone by a second, unfixed API removal** — `test_hmac_drbg.py`, `test_aes_cbc_direct.py`, `test_aes_cbc_decrypt_direct.py`, `test_gcmsiv_decrypt_direct.py`, `test_gcmsiv_encrypt_direct.py`, `test_sha256_direct.py`, `test_polyval_direct.py`, `test_csr_harness.py` all crash at runtime with `AttributeError: 'ViceProcess' object has no attribute 'wait_for_monitor'` — harness 0.12.4 removed that method. Only `test_gcmsiv_polyval.py` was actually fully ported to the current `ViceInstanceManager` pattern and genuinely runs standalone end-to-end (verified live: 15/15 passed). The import-alias fix on the other 8 silences the *first* crash and creates a false impression of health while they remain fully broken standalone.
  *Evidence:* Live reproduction of the exact `AttributeError` on all 8; confirmed `ViceProcess` in harness 0.12.4 exposes only `start/stop/wait_for_exit/pid/kill_on_port/get_listener_pid`; `git show 7073378` confirms only `test_gcmsiv_polyval.py` was fully ported.
  *Suggested action:* Port the remaining 8 scripts' `__main__` entry points to `ViceInstanceManager`, following `test_gcmsiv_polyval.py`'s already-fixed pattern.

- **[MEDIUM] No CI/CD runs any part of the test suite** — No `.github/` directory, no workflow YAML anywhere, no active git hooks (only unused `.sample` stubs). `run_all_tests.py` only imports the standalone scripts' helper functions as library code — a plain `__import__`, which never executes their `if __name__ == "__main__":` blocks — so the import/attribute breakage above is structurally invisible to the one "working" path and can only ever be caught by someone running a script directly.
  *Evidence:* No `.github`, no `.pre-commit-config*`, no active `.git/hooks`; `run_all_tests.py`'s `_import_test_module` mechanism.
  *Suggested action:* Stand up minimal CI (even a manually-triggered workflow) that runs each standalone script's actual entry point, not just imports it.

- **[MEDIUM] HMAC-DRBG suite has a single ~10-minute timeout with zero retry** — `run_suite_hmac_drbg` calls the scenario exactly once; a `wait_for_text()` timeout (VICE stall, dropped monitor connection) returns a graceful `(False, msg)` that's treated as an ordinary FAIL with no retry. `restart_program()` has the same one-shot shape. There is no suite-level or scenario-level re-attempt after a transient failure — a human must restart the entire run.
  *Evidence:* `tools/run_all_tests.py:486-491,550-579`; `tools/test_hmac_drbg.py:78` (`timeout=600` with a single internal budget).
  *Suggested action:* Add a bounded retry (e.g. 1-2 re-attempts with a fresh transport) around the restart-and-run sequence.

- **[MEDIUM] `c64-test-harness` dependency is not version-pinned anywhere** — No `requirements.txt`, `setup.py`, or `pyproject.toml` in the repo; the only install guidance is an unpinned `pip install -e ../c64-test-harness` in the README. The exact class-rename and method-removal breakage documented above has already happened twice with nothing to force a compatibility check.
  *Evidence:* No dependency-manifest files anywhere; `README.md:114`; confirmed installed harness is 0.12.4 via `pip show`; two real commits (`a8456a8`, `7073378`) already fixing drift damage.
  *Suggested action:* Pin a harness version/tag/commit, or add a minimal smoke import check that fails loudly on API drift.

- **[LOW] VICE port-range collision handling is undocumented and inconsistent** — `run_all_tests.py` reads `C64_PORT_RANGE_START` from the environment, but this is undocumented anywhere outside its own source, and four standalone `_direct.py` scripts hardcode `PORT_RANGE_START = 6510` with no environment override and no CLI flag — exactly the port-collision failure mode this session already hit with concurrent sibling-project sessions.
  *Evidence:* `grep -rn "C64_PORT_RANGE_START"` → one hit; 4 hardcoded `PORT_RANGE_START = 6510` constants; no mention in README.md.
  *Suggested action:* Thread the same env-var override through the four standalone scripts and document it in the README.

## Post-Refactor Validation

Invariants introduced or made fragile by the modular restructure / lib-contract-alignment work, currently protected only by convention or documentation.

- **[HIGH] `boot.o` link-position invariant has zero automated protection, and `make verify` is structurally incapable of catching it** — The Makefile documents in detail that `boot.o` must be the first object contributing real CODE bytes after `main.o`, or the BASIC stub's literal `SYS 2064` bytes stop pointing at `start` and the program silently jumps into garbage on RUN — a real bug hit once already. `ld65` does not error on module reordering, so a broken build reports success. `make verify`'s recipe (`cmp ... && echo PASS || echo FAIL`) always exits 0 regardless of branch, and since Phase 5 a byte-diff from the original is already the *expected* state, so the FAIL text prints on every run whether or not `boot.o` moved — the diagnostic signal is textually identical to the normal, harmless, expected diff. The only thing that would eventually surface this is the full VICE suite hanging on a generic 60s menu-wait timeout, with no message pointing at `MODULES` ordering.
  *Evidence:* Makefile ~lines 10-32 (MODULES comment) and line 256 (`verify` recipe, confirmed to always exit 0); `run_all_tests.py`'s `build()` never calls `make verify`.
  *Suggested action:* Add a targeted assertion (e.g. check the linker map for `boot.o`'s segment offset, or verify the BASIC stub bytes directly) as part of the build step, independent of the full-suite functional timeout.

- **[HIGH] Missing `.importzp` produces only a linker warning, silently discarded by the test harness on a successful build** — A byte-sized constant crossing an object boundary without `.importzp` produces an `ld65` "Address size mismatch" warning, not an error — reproduced live with the installed `ld65`. `run_all_tests.py`'s `build()` only inspects `result.stdout`/`result.stderr` when the return code is non-zero; on success it prints "Build OK" and discards all output unread. This exact warning class has already bitten this project's modular restructure twice per the codebase's own `src/lib_manifest.s` documentation.
  *Evidence:* `tools/run_all_tests.py:151-169` (stdout/stderr never referenced on success); live reproduction of the warning with local `ld65`; `src/lib_manifest.s:170-173`.
  *Suggested action:* Grep `result.stdout`/`stderr` for `Warning:` even on a zero exit code and fail loudly if any appear.

- **[HIGH] `make lib` and `make lib-ecdsa-sign` are entirely outside the automated test suite** — Neither archive target is ever built or linked by any automated run; the default `make`/`make verify`/full suite only ever touch the `.prg` target. The documented CAVEAT (`aes256ecdsa-ecdsa-sign.a` fails standalone link with exactly 2 unresolved externals) was established via one manual, one-off `ld65` link attempt on 2026-07-20, not a repeatable check — a future module reshuffling `LIB_FULL_OBJS`/`LIB_ECDSA_SIGN_OBJS` could break either archive indefinitely with everything else green.
  *Evidence:* `grep -rn "make lib\|lib-ecdsa-sign\|aes256ecdsa.a\|ar65" tools/*.py` — zero matches; Makefile lines 165-209 (CAVEAT prose), 231-232, 255 (`verify` depends only on `$(PRG)`).
  *Suggested action:* Same as the coverage-lane recommendation — wire both archive targets and the standalone-link check into an automated step.

- **[MEDIUM] Bug 6 / Bug 7 (documented in HANDOFF.md) are not encoded as known-failure/xfail markers anywhere** — The harness has no skip/xfail/known-issue mechanism at all (confirmed by grep). `run_suite_csr`/`run_suite_hmac_drbg` report plain pass/fail; a genuinely new regression in the same code paths would produce a failure signature indistinguishable from the already-triaged issue, discoverable only by a human separately rereading HANDOFF.md.
  *Evidence:* `HANDOFF.md:181,183`; no skip/xfail infrastructure anywhere in `tools/run_all_tests.py`.
  *Suggested action:* Add a lightweight known-issue tag/marker (even just a comment cross-reference plus a distinct failure message) so new vs. known failures are distinguishable in suite output.

- **[MEDIUM] Documented future REU bank-exclusion requirement has no enforcement mechanism** — `docs/reu_contract_status.md` explicitly documents that generic REU wipe/benchmark routines sweep every bank with zero exclusion logic, and that this becomes dangerous the moment a REU-bank-claiming library is vendored in. This is legitimately "nothing to test yet," but there is no forward-looking guard of any kind (no TODO-tagged/skipped test, no manifest-equate-gated assertion, no tracked issue) — the only mechanism is a future human/agent independently rereading this doc section before vendoring proceeds.
  *Evidence:* `docs/reu_contract_status.md:73-108`; no corresponding test/assertion/tracked-issue anywhere in `tools/` or `src/`; only one open GitHub issue exists and it's unrelated.
  *Suggested action:* File a tracked issue (not just a doc section) and/or add a skipped test stub that documents the expected future assertion, so it surfaces in normal issue triage rather than requiring doc rediscovery.

## Negative-Path

Deliberately adversarial/fault-injection conditions — the class of test most likely to catch a regression that a "happy path" suite would sail past.

- **[HIGH] No regression test guards the Bug 5 IEC write-timeout fatal-bitmask fix** — `write_block_to_file` in `src/reu_advanced.s` originally checked KERNAL STATUS with `AND #$80` only (device-not-present), missing the actual IEC write-timeout bit; the fix widened the mask to `AND #$82`. HANDOFF.md's own "REMAINING FUTURE WORK" explicitly flags that this fix (and Bug 4's) was verified only via ad-hoc, uncommitted VICE scripts during development and has no permanent test. A future regression narrowing the mask back to bit-7-only — exactly the original bug — would pass every existing test.
  *Evidence:* `src/reu_advanced.s:1297-1326`; `HANDOFF.md:213,221`; zero matches for `write_block_to_file`/`$82`/write-timeout/device-not-present anywhere in `tools/*.py`.
  *Suggested action:* Simulate a write-timeout or device-not-present condition (e.g. detached drive 8) and assert the program reports an error rather than silently succeeding.

- **[HIGH] REU-absent and REU-present paths are both completely dark** — No test ever configures VICE's REU emulation, and the companion harness's `ViceConfig` dataclass has no REU-related field at all (no `reu`/`reusize`/`reuimage` option, and no test uses `extra_args` to smuggle one in). `detect_reu`/`reu_present` branching and the entire REU menu feature (including the Bug 5 code) are unverified in *either* direction — no test even asserts which way VICE's default REU state falls.
  *Evidence:* `src/reu_core.s` (`detect_reu`/`reu_present`); `../c64-test-harness/.../vice_lifecycle.py` `ViceConfig` (no REU field); zero "REU" references anywhere in `tools/*.py`.
  *Suggested action:* Add a REU field to the harness's `ViceConfig` (or use `extra_args`) and drive both the present and absent branches explicitly.

- **[MEDIUM] CSR-to-disk save is never actually performed in any test (only declined)** — All four CSR scenarios explicitly press `N` at the "SAVE CSR TO DISK" prompt; no scenario ever answers `Y`. No `ViceConfig` anywhere attaches a real disk image to drive 8. The CSR disk-save path — which reaches the same `write_block_to_file`/`disk_io.s` routines implicated in Bug 5 — is never exercised at all, success case or error case.
  *Evidence:* `tools/test_csr_harness.py:361-374` (`decline_save_and_return`), used at lines 497/550/609; zero `disk_image`/`DiskImage` usage anywhere in `tools/*.py`.
  *Suggested action:* Add one scenario that accepts the save, verifies the file lands on the mounted image, and (per the coverage-lane finding above) loads it back for round-trip verification.

- **[LOW] CSR field boundary lengths and control-character/non-ASCII input are untested** — `csr_get_field` correctly enforces the max-length cutoff in source but only special-cases Return and Delete; any other byte (PETSCII control/color codes, non-ASCII) is accepted verbatim and later embedded in DER encoding. All test data is short, well-formed ASCII well under the 32/40-char limits.
  *Evidence:* `src/csr.s:201-234` (`csr_get_field`), `625-635` (buffer sizes); `tools/test_csr_harness.py:456-514` (`test_full_csr` field values).
  *Suggested action:* Add a boundary-length CSR field test and a control-character/non-ASCII injection test (this overlaps with, and can be combined with, the depth-lane CSR finding above).

---

## If You Fix Nothing Else: Top 10, Ordered by Real-World Risk

Ranked not just by severity tag but by what a shipped regression would actually cost — silent data loss and silent build breakage rank above missing-but-safe edge cases.

1. **Disk save/load paths (menu 5/6/7/8, all "SAVE TO DISK" prompts) have zero end-to-end coverage** — the one feature category that can silently lose a user's key or ciphertext material. *(Coverage, high)*
2. **No regression test guards the Bug 5 IEC write-timeout fix** — a real, previously-shipped silent-data-corruption bug on disk writes, with its regression test explicitly documented as never having existed. *(Negative-path, high)*
3. **`boot.o` link-position invariant has zero automated protection, and `make verify` cannot catch it** — a build that reports success while jumping into garbage on RUN; already happened once during the restructure. *(Post-refactor, high)*
4. **Missing `.importzp` produces only a warning, silently discarded by the harness on success** — the same failure class that has already bitten the restructure twice, with no mechanism to catch a third occurrence. *(Post-refactor, high)*
5. **No wrong-key decrypt rejection test (AES-CBC or GCM-SIV)** — a stale-expanded-key-state bug would go completely undetected in the crypto core the project is built around. *(Depth, high)*
6. **GCM-SIV tamper test only ever corrupts the tag, never the ciphertext** — never actually proves authentication covers ciphertext content. *(Depth, high)*
7. **REU-absent and REU-present paths are both completely dark, in either direction** — an entire subsystem (including the Bug-5-adjacent write path) is unverified whether or not a REU is attached. *(Negative-path / Coverage, high)*
8. **REU status/fill/save UI (menu 'G') never exercised** — the user-facing entry point into the same untested REU/disk-write machinery. *(Coverage, high)*
9. **Direct-memory tests never write an out-of-range length byte** — the one test surface actually capable of reaching `encrypt_input`/`gcmsiv_encrypt`'s unguarded buffer paths is never used to do so. *(Depth, high)*
10. **8 of 9 "fixed" standalone test scripts are still broken by an unfixed second API removal (`wait_for_monitor`)** — the import-alias patch created a false impression of health; only one script (`test_gcmsiv_polyval.py`) genuinely runs standalone today. *(Infrastructure, high)*

*Honorable mentions just outside the top 10:* `make lib`/`make lib-ecdsa-sign` archive builds are entirely unautomated with only a one-off manual verification of their known caveat (Post-refactor, high); `do_benchmark`, SID config, and the RNG stream display remain fully untested user-facing menu features (Coverage, high) but carry lower real-world risk than the disk/REU/crypto-authentication items above since nothing they do is persisted or security-relevant.

---

## Addendum: findings from actually running the harness-compatibility fix (2026-07-20)

The findings above came from static source inspection and a skeptical re-verification pass. A separate, follow-on effort actually fixed and *ran* every standalone `tools/test_*.py` script end-to-end against harness v0.12.4 (see finding "Six standalone scripts fail immediately with ImportError" and "8 scripts... still broken... by `wait_for_monitor`" above — both are now fixed). That execution surfaced real bugs static analysis alone did not catch. **All three of the following have since been fixed and re-verified** (a third follow-on pass, same day):

- **[FIXED] Four scripts shared one root-cause synchronization bug: `wait_for_text(transport, "Q=QUIT")` is not a valid completion signal.** `"Q=QUIT"` is part of the C64 program's always-visible static menu footer, present on screen continuously (including *during* an in-progress operation, not just before/after it). The harness's binary-monitor transport only calls `resume()` internally when a `wait_for_text()` poll's needle is *absent*; since `"Q=QUIT"` is present from the very first poll, `resume()` is never called and the CPU never actually runs the operation before the test reads back results. Affected `tools/test_sha256.py`, `tools/test_aes_cbc.py`, `tools/test_aes_cbc_decrypt.py`, and `validate_direct_tests.py`'s UI-driven CBC cross-validation section.
  **Fix:** replaced the `"Q=QUIT"` needle at every genuinely post-operation call site with an operation-specific completion marker verified against the live 6502 source (`"ENCRYPTION COMPLETE"` / `"DECRYPTED (HEX)"` / `"SHA-256 HASH"` — all confirmed printed only after the corresponding routine actually runs, not part of the static footer). The one legitimate use of `"Q=QUIT"` — waiting for the initial menu right after VICE boot, before any keypress — was correctly left unchanged in every file.
  **A second-order version of the same bug was found and fixed during the fix itself:** the C64's screen is never cleared between operations, so from the 2nd test iteration onward the *new* completion markers were themselves already stale-visible on screen from the prior iteration, reproducing the identical trap one level up. Each file needed an additional guard beyond the marker swap: `test_aes_cbc.py` added a fixed-budget unconditional-`resume()` helper before each check; `test_aes_cbc_decrypt.py` blanks screen RAM directly before each iteration; `validate_direct_tests.py` added a baseline-diff requirement (screen text must differ from a pre-keypress snapshot, not just contain the needle) — this file interleaves silent `jsr()` calls and `RUN` restarts between UI iterations, so no single fixed needle was ever going to be reliably unique to fresh output.
  **Verified:** `test_sha256.py` 10/10, `test_aes_cbc.py` 10/10 (two independent seeds), `test_aes_cbc_decrypt.py` 10/10, `validate_direct_tests.py` 15/15 and 24/24 (two independent seeds) — all real, correct byte-for-byte matches against Python/OpenSSL references, not just "ran without crashing."

- **[FIXED] `validate_direct_tests.py` referenced a label that has never existed: `gcmsiv_ct_len`.** Introduced already-wrong in commit `6ad725e`; `build/labels.txt` only ever exported `gcmsiv_pt_len` (reused for both encrypt-plaintext and decrypt-ciphertext length in the working reference file, `tools/test_gcmsiv_polyval.py`). **Fix:** `gcmsiv_ct_len` → `gcmsiv_pt_len`, both in `required_labels` and in `gcmsiv_direct_decrypt()`.

- **[MEDIUM, still open] `tools/supervise_gcmsiv_tests.py` is not a VICE test at all, and its underlying purpose is complete.** It has no direct harness dependency — it spawns two autonomous `claude --print --dangerously-skip-permissions` subprocesses instructed to *write* `tools/test_gcmsiv_encrypt_direct.py`/`tools/test_gcmsiv_decrypt_direct.py` from scratch. Those files already exist, are already integrated into `run_all_tests.py`'s 9 unified suites, and already pass reliably. The only harness-related content was stale API guidance embedded in its prompt strings (already fixed for correctness, but not exercised — running it for real means unsupervised, permission-bypassed nested agents with file-write access, a decision outside the scope of any of the fix passes so far). *Suggested action, still open:* archive or clearly re-label this file as historical/bootstrap-only rather than an active part of the test suite.

- **[LOW, still open] Possible dropped keypress after the NIST self-test returns to the main menu** — see `HANDOFF.md` "Bug 8." Filed upstream as [c64-test-harness#138](https://github.com/JC-000/c64-test-harness/issues/138) pending triage on whether the root cause is this project, VICE emulation, or harness transport timing.
