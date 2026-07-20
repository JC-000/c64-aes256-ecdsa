.setcpu "6502"

; =============================================================================
; zp_config.s - single source of truth for zero-page allocation across
; c64-aes256-ecdsa.
;
; This is a pure relocation of equates that previously lived scattered
; across constants.s, ecdsa_fp.s, and ecdsa_points.s (see docs/symbol_map.md,
; "Duplicate zero-page claims" for the pre-consolidation inventory). No
; addresses changed as part of this move.
;
; Every slot is wrapped in .ifndef so a future consumer (a program that
; .include's this project's modules alongside its own zero-page map) can
; predefine any of these names before this file is included to override the
; address and avoid a collision. Nothing overrides them today - this is
; groundwork, mirroring the pattern in c64-nist-curves/src/zp_config.s.
;
; See build_ca65/linker.cfg for how the surrounding free zero-page bytes
; ($13-$21, $2C-$38, $3D-$8F) are exposed as ZP2/ZP3/ZP4 for future use.
; =============================================================================

.segment "ZEROPAGE"

; --- Immovable (hardware/KERNAL) ---
; Not a project-owned slot; centralized here for visibility only. Do not
; relocate: $C6 is the KERNAL's own keyboard-buffer-count cell.
.ifndef kbd_buffer
  kbd_buffer    = $c6           ; keyboard buffer count (KERNAL-fixed)
.endif

; --- General-purpose pointers / temps (was constants.s) ---
.ifndef zp_ptr
  zp_ptr        = $fb           ; 2-byte pointer
.endif
.ifndef zp_temp
  zp_temp       = $fd           ; temp storage
.endif
.ifndef zp_count
  zp_count      = $fe           ; loop counter
.endif
.ifndef zp_ptr2
  zp_ptr2       = $02           ; second pointer (2 bytes)
.endif

; --- AES temps (was constants.s) ---
.ifndef zp_round
  zp_round      = $04           ; aes round counter
.endif
.ifndef zp_col
  zp_col        = $05           ; aes column counter
.endif
.ifndef zp_tmp1
  zp_tmp1       = $06           ; aes temp
.endif
.ifndef zp_tmp2
  zp_tmp2       = $07           ; aes temp
.endif
.ifndef zp_tmp3
  zp_tmp3       = $08           ; aes temp
.endif
.ifndef zp_tmp4
  zp_tmp4       = $09           ; aes temp
.endif

; --- SHA temps (was constants.s) ---
.ifndef sha_temp1
  sha_temp1     = $0a           ; SHA-256 temp (4 bytes: $0A-$0D)
.endif
.ifndef sha_temp2
  sha_temp2     = $0e           ; SHA-256 temp (4 bytes: $0E-$11)
.endif
.ifndef sha256_round
  sha256_round  = $12           ; SHA-256 round counter
.endif

; --- fp_* field-arithmetic working variables (was ecdsa_fp.s) ---
; Using free ZP locations $22-$2B (not used by KERNAL or BASIC).
.ifndef fp_src1
  fp_src1       = $22           ; 2 bytes: pointer to first operand
.endif
.ifndef fp_src2
  fp_src2       = $24           ; 2 bytes: pointer to second operand
.endif
.ifndef fp_dst
  fp_dst        = $26           ; 2 bytes: pointer to destination
.endif
.ifndef fp_misc
  fp_misc       = $28           ; 2 bytes: misc pointer (modulus)
.endif
.ifndef fp_carry
  fp_carry      = $2a           ; 1 byte: carry/borrow result
.endif
.ifndef fp_loop
  fp_loop       = $2b           ; 1 byte: loop counter (dead - zero refs, see symbol_map.md)
.endif

; Multiply working ZP ($39-$3E: free)
.ifndef fp_mul_i
  fp_mul_i      = $39           ; outer loop index
.endif
.ifndef fp_mul_j
  fp_mul_j      = $3a           ; inner loop index
.endif

; --- EC scalar multiplication (was ecdsa_points.s) ---
.ifndef ec_scalar_ptr
  ec_scalar_ptr = $3b           ; ZP pointer to 32-byte scalar k
.endif

; --- Exports ---
.exportzp kbd_buffer
.exportzp zp_ptr, zp_temp, zp_count, zp_ptr2
.exportzp zp_round, zp_col, zp_tmp1, zp_tmp2, zp_tmp3, zp_tmp4
.exportzp sha_temp1, sha_temp2, sha256_round
.exportzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j
.exportzp ec_scalar_ptr

; Restore the active segment: this file is pulled into main.s's single-TU
; .include chain (unlike c64-nist-curves, where zp_config.s is its own
; translation unit), so without this every module .include'd after this
; one would silently land in the ZEROPAGE segment instead of CODE.
.segment "LIB_AES256ECDSA_CODE"
