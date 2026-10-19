.setcpu "6502"

; =============================================================================
; lib_manifest.s - c64-aes256-ecdsa aggregate ABI manifest (c64-lib-contract
;                  SPEC §5, "Aggregate manifest equates")
;
; Consumer-facing assemble-time equates that summarize this project's
; resource footprint, mirroring c64-nist-curves/src/lib_manifest.s (the
; reference adopter). Per docs/lib_contract_alignment_plan.md Phase C, this
; is executed after Phase B's segment rename (§4), since RESIDENT_BYTES/
; COLD_BYTES are read off the final LIB_AES256ECDSA_CODE/HICODE segment
; totals in build/aes256keygen.map.
;
;   LIB_AES256ECDSA_ZP_USAGE_BYTES - Total bytes claimed in zero page (sum
;                                    of widths of every .exportzp slot in
;                                    src/zp_config.s).
;   LIB_AES256ECDSA_REU_BANKS_USED - Bitmask of REU bank indices claimed.
;                                    Zero -- see docs/reu_contract_status.md
;                                    for the full N/A determination (this
;                                    project's REU code is generic
;                                    whole-device end-user tooling, not a
;                                    precompute-table cache at a reserved
;                                    bank; its crypto math runs entirely in
;                                    main RAM/ZP).
;   LIB_AES256ECDSA_RESIDENT_BYTES - Approx CPU-RAM-resident code+rodata
;                                    footprint.
;   LIB_AES256ECDSA_COLD_BYTES     - Approx code+rodata footprint a
;                                    consumer MAY page-overlay.
;
; --- RESIDENT_BYTES / COLD_BYTES classification rationale ---
;
; Unlike c64-nist-curves (a narrow verify-only library with a clean
; boot-once-init vs. verify-hot-path split), this project is a full
; interactive menu application (main_loop.s dispatches to every feature:
; AES encrypt/decrypt, GCM-SIV, ECDSA sign, CSR/PKCS#10 build, REU
; fill/detect/save, benchmark, disk I/O, ...). There is no "only called
; once at boot" category the way a library serving a handful of narrow API
; entry points has -- any menu option can be invoked by the interactive
; user at any time, in any order, so almost everything reachable from the
; main menu dispatch must be treated as resident. The one genuine
; exception found: do_ecdsa_test (src/ecdsa_test.s), the RFC 6979
; known-answer diagnostic test-vector path reachable only via the CSR
; submenu (menu J -> 2, see src/csr.s's @do_ecdsa_test dispatch). Its own
; module header calls it a "test harness", it is not on the path of any
; core AES / GCM-SIV / ECDSA-sign / CSR-emit functionality, and nothing
; else in the codebase calls into it -- a consumer could defer/overlay it
; without breaking core functionality, satisfying SPEC §5's COLD_BYTES
; definition. No other genuinely-optional candidate was found; forcing a
; larger COLD_BYTES split without a real deferred-loading candidate would
; misrepresent the resident set, so everything else stays resident.
;
; Byte counts are read off build/aes256keygen.map's "Segment list" totals
; (ld65 -m output), same methodology as c64-nist-curves/src/lib_manifest.s:
;
;   LIB_AES256ECDSA_CODE     006CCB  = 27851
;   LIB_AES256ECDSA_HICODE   001A02  =  6658
;                                     -------
;   total code+rodata                34509
;
;   ecdsa_test.o (LIB_AES256ECDSA_HICODE, do_ecdsa_test + its UI strings)
;                             000317  =   791
;
;   resident = total - cold = 34509 - 791 = 33718
;
; Rounded to the nearest 100 for the +-5% manifest commitment (SPEC §5):
; RESIDENT_BYTES = 33700, COLD_BYTES = 800. Build size as of this equate
; refresh: build/aes256keygen.prg = 49969 bytes.
;
; --- Scope of the two segments summed above ---
;
; ONLY the two LIB_AES256ECDSA_* segments are summed. Since the
; c64-polyval submodule replaced src/polyval.s, the linked image also
; carries LIB_POLYVAL_SHORT_CODE (00352E = 13614), LIB_POLYVAL_BSS
; (000020 = 32) and LIB_POLYVAL_HTABLE (000100 = 256) from
; build/lib/polyval-short.a. Those are c64-polyval's footprint, declared
; by its own LIB_POLYVAL_RESIDENT_BYTES / LIB_POLYVAL_COLD_BYTES equates
; (libs/polyval/src/lib_manifest.s), and folding them in here would
; double-count them against a consumer that budgets for both libraries.
; The same reasoning applies to the ZP block below.
;
; --- Why these numbers moved since the last refresh ---
;
; The previous values (CODE 006F75 = 28533, HICODE 0019A3 = 6563, total
; 35096, resident 34300) predate both the c64-polyval swap and the two
; PRs that landed between (#25 harness-compat, #26 input-bounds/REU
; channel), so the delta is not attributable to the swap alone:
; LIB_AES256ECDSA_CODE fell by 682 bytes NET and LIB_AES256ECDSA_HICODE
; ROSE by 95 bytes NET, for a total code+rodata delta of -587. Do not read
; the 682 as the size of what the swap removed: the swap took out 508
; bytes of src/polyval.s code and 304 bytes of src/data.s POLYVAL
; reservations (812 together, both in LIB_AES256ECDSA_CODE), and #25/#26
; added roughly 130 bytes back into the same segment. The HICODE rise is
; entirely #25/#26 -- the swap touched nothing in HICODE.
;
; The PRG grew 36355 -> 49969 (+13614, exactly LIB_POLYVAL_SHORT_CODE)
; because the library's code is larger than the in-tree implementation it
; replaced. MAIN headroom nonetheless improved from 7 to 820 bytes:
; LIB_AES256ECDSA_CODE now ends at $74CB rather than $77F8, MAIN runs to
; $77FF, and every LIB_POLYVAL_* segment lives in HIMEM rather than
; competing for MAIN.
;
; No separate BSS/DATA segment exists in this project's OWN linker.cfg
; besides LOADADDR/LIB_AES256ECDSA_CODE/LIB_AES256ECDSA_HICODE, so no RW
; state needed excluding from the code+rodata total the way
; c64-nist-curves excludes its fp_*/ec_*/sha_state BSS. (LIB_POLYVAL_BSS
; and LIB_POLYVAL_HTABLE are RW, but they are the library's, per the
; scope note above.)
; =============================================================================

.segment "LIB_AES256ECDSA_CODE"


; -----------------------------------------------------------------------------
; Zero-page usage
; -----------------------------------------------------------------------------
; Sum of widths of every `.exportzp` slot in src/zp_config.s as of this
; equate refresh (widths cross-referenced against each slot's own
; documented byte-width comment, and against the free-byte gaps
; build_ca65/linker.cfg carves out as ZP2/ZP3/ZP4 around them):
;
;   kbd_buffer                (KERNAL keyboard buffer count)     1
;   zp_ptr                    (2-byte pointer)                   2
;   zp_temp                                                      1
;   zp_count                                                     1
;   zp_ptr2                   (2 bytes)                          2
;   zp_round, zp_col                                             2
;   zp_tmp1..zp_tmp4                                              4
;   sha_temp1                 (4 bytes: $0A-$0D)                 4
;   sha_temp2                 (4 bytes: $0E-$11)                 4
;   sha256_round                                                 1
;   fp_src1, fp_src2, fp_dst, fp_misc  (2 B each ptr)             8
;   fp_carry, fp_loop                                            2
;   fp_mul_i, fp_mul_j                                           2
;   ec_scalar_ptr              (2-byte pointer to 32-byte scalar) 2
;                                                              ---
;                                                                36
;
; kbd_buffer ($C6) is the KERNAL's own keyboard-buffer-count cell -- not a
; project-owned slot -- but zp_config.s exports it for visibility, so it
; counts toward the ZP claim from a consumer's collision-check perspective,
; matching how c64-nist-curves counts its own hardware-adjacent proc_port.
;
; UNCHANGED by the c64-polyval swap: the .exportzp list in src/zp_config.s
; is byte-for-byte the same set of slots as at the last refresh, so this
; project's own ZP surface is still 36 bytes. The three POLYVAL ZP slots
; the link now carries -- polyval_acc ($40-$4F), pv_mul_input ($50-$5F),
; pv_mul_nibble ($60) -- are declared by the ARCHIVE's zp_config.o, not by
; ours, and belong to c64-polyval's own LIB_POLYVAL_ZP_USAGE_BYTES (= 45)
; claim. They are deliberately not folded in here: a consumer sizing a ZP
; collision assert against both libraries adds the two equates, and
; counting the library's slots on both sides would double-count them.
; What DID change is only the free-pool bookkeeping, which is not part of
; this equate: build_ca65/linker.cfg narrows its ZP4 pool from $3D-$8F to
; $61-$8F so a future `.segment "ZEROPAGE"` allocation cannot land on the
; library's $40-$60. See src/zp_config.s's POLYVAL block for the full
; occupancy map and the relocation rationale.
; -----------------------------------------------------------------------------
.ifndef LIB_AES256ECDSA_ZP_USAGE_BYTES
  LIB_AES256ECDSA_ZP_USAGE_BYTES = 36
.endif


; -----------------------------------------------------------------------------
; REU bank bitmask
; -----------------------------------------------------------------------------
; Zero. This project claims no REU banks -- see docs/reu_contract_status.md
; for the full N/A determination (§1: this project's REU code, src/reu_core.s
; and src/reu_advanced.s, is generic whole-device end-user tooling -- detect/
; fill/wipe/save the entire attached REU -- not a library reserving a fixed
; bank/offset for a precomputed table the way SPEC §3 contemplates; this
; project's own AES/ECDSA crypto math runs entirely in main RAM/ZP and never
; touches the REU at all). c64-polyval reaches the same determination for
; itself: LIB_POLYVAL_REU_BANKS_USED = 0, "n/a (no REU claims)". Since the
; vendoring, that is no longer an outside precedent this project merely
; cites for support -- it is the recorded claim of an actual dependency
; linked into this image, and the fact that it claims no banks either is
; what keeps the zero above true for the linked whole rather than only for
; this project's own translation units.
; -----------------------------------------------------------------------------
.ifndef LIB_AES256ECDSA_REU_BANKS_USED
  LIB_AES256ECDSA_REU_BANKS_USED = 0
.endif


; -----------------------------------------------------------------------------
; Resident footprint (approx)
; -----------------------------------------------------------------------------
; Code + rodata that MUST stay in CPU RAM at runtime, since any main-menu
; option (main_loop.s) can be invoked by the interactive user at any time
; in any order -- see the file header comment above for the full
; reasoning. Total LIB_AES256ECDSA_CODE + LIB_AES256ECDSA_HICODE segment
; size (build/aes256keygen.map) minus the one identified cold candidate
; (do_ecdsa_test, see COLD_BYTES below): 34509 - 791 = 33718, rounded to
; 33700 for the +-5% manifest commitment. Excludes the LIB_POLYVAL_*
; segments, which c64-polyval declares itself -- see the file header's
; "Scope of the two segments summed above".
; -----------------------------------------------------------------------------
.ifndef LIB_AES256ECDSA_RESIDENT_BYTES
  LIB_AES256ECDSA_RESIDENT_BYTES = 33700
.endif


; -----------------------------------------------------------------------------
; Cold (overlay-able) footprint
; -----------------------------------------------------------------------------
; do_ecdsa_test (src/ecdsa_test.s) -- the RFC 6979 known-answer diagnostic
; test-vector path, reachable only via the CSR submenu (menu J -> 2, see
; src/csr.s @do_ecdsa_test dispatch). Its own module header describes it as
; a "test harness"; nothing else in the codebase calls into it, and it is
; not on the path of any core AES / GCM-SIV / ECDSA-sign / CSR-emit
; functionality. A consumer could defer/page-overlay it without breaking
; core functionality:
;
;   ecdsa_test.o (LIB_AES256ECDSA_HICODE)   000317 = 791
;
; Rounded to 800 for the +-5% manifest commitment. No other genuinely
; optional/deferred candidate was found in this pass -- everything else
; reachable from the main menu dispatch is treated as resident per the
; RESIDENT_BYTES reasoning above, rather than forcing a larger cold split
; without a real candidate.
; -----------------------------------------------------------------------------
.ifndef LIB_AES256ECDSA_COLD_BYTES
  LIB_AES256ECDSA_COLD_BYTES = 800
.endif


; --- Exports ---
; Force absolute address-size on the exports: these integer-equate values
; can fit in zero-page so ca65 would otherwise tag them as `zeropage` and
; ld65 would warn "Address size mismatch" at every `.import ... ; lda #<sym`
; import site (the same warning class this project's modular restructure
; already hit and fixed twice). These symbols are scalar parameters, not
; actual addresses, so absolute is correct. Matches the pattern in
; c64-nist-curves/src/lib_manifest.s.
.export LIB_AES256ECDSA_ZP_USAGE_BYTES:abs
.export LIB_AES256ECDSA_REU_BANKS_USED:abs
.export LIB_AES256ECDSA_RESIDENT_BYTES:abs
.export LIB_AES256ECDSA_COLD_BYTES:abs
