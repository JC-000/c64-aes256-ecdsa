; =============================================================================
; ecdsa_test.asm - Test harness and UI for ECDSA P-256
; do_ecdsa_test, UI strings, RFC 6979 verification
; ca65 port note: mechanical translation of !text/!byte to .byte "..."/.byte.
; No ACME anonymous labels or '* =' directives in the original.
; =============================================================================

        .segment "LIB_AES256ECDSA_HICODE"

.importzp fp_dst, fp_src1, fp_src2, zp_ptr, zp_count
.import chrout
.import fp_r1, fp_r2, fp_r0
.import fp_wide
.import ecdsa_hash_ptr, ecdsa_privkey_ptr, ecdsa_k_ptr, ecdsa_sig_r, ecdsa_sig_s
.import ecdsa_test_hash, ecdsa_test_privkey, ecdsa_test_k, ecdsa_test_r, ecdsa_test_s
.import print_string, display_hex_block, print_hex_byte
.import fp_init_sqtab, fp_zero, fp_mul, fp_cmp
.import fp_mod_reduce, fp_mod_inv, fp_mod_mul
.import ec_set_modp
.import ecdsa_sign

.export do_ecdsa_test

; =============================================================================
; do_ecdsa_test: run RFC 6979 test vector and compare results
; Uses the known private key, k, and hash to produce (r,s)
; then compares against expected values.
;
; This is called from the menu when the user presses 'J' (or a sub-option).
; =============================================================================
do_ecdsa_test:
        lda #$0d
        jsr chrout
        lda #<ecdsa_test_hdr_msg
        ldy #>ecdsa_test_hdr_msg
        jsr print_string

        ; Initialize quarter-square table
        lda #<ecdsa_init_msg
        ldy #>ecdsa_init_msg
        jsr print_string
        jsr fp_init_sqtab

        ; === TEST 1: Basic multiply 3*5=15 ===
        lda #<ecdsa_test1_msg
        ldy #>ecdsa_test1_msg
        jsr print_string

        ; Set fp_r1 = 3
        lda #<fp_r1
        sta fp_dst
        lda #>fp_r1
        sta fp_dst+1
        jsr fp_zero
        lda #3
        sta fp_r1+31

        ; Set fp_r2 = 5
        lda #<fp_r2
        sta fp_dst
        lda #>fp_r2
        sta fp_dst+1
        jsr fp_zero
        lda #5
        sta fp_r2+31

        ; Multiply: fp_wide = fp_r1 * fp_r2
        lda #<fp_r1
        sta fp_src1
        lda #>fp_r1
        sta fp_src1+1
        lda #<fp_r2
        sta fp_src2
        lda #>fp_r2
        sta fp_src2+1
        jsr fp_mul

        ; Show last 4 bytes of fp_wide (should be 00 00 00 0F)
        lda fp_wide+60
        jsr print_hex_byte
        lda fp_wide+61
        jsr print_hex_byte
        lda fp_wide+62
        jsr print_hex_byte
        lda fp_wide+63
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; === TEST 2: mod_reduce (15 mod p should be 15) ===
        lda #<ecdsa_test2_msg
        ldy #>ecdsa_test2_msg
        jsr print_string
        jsr ec_set_modp
        jsr fp_mod_reduce       ; fp_r0 = fp_wide mod p
        ; Show result (should be ...0F)
        lda fp_r0+28
        jsr print_hex_byte
        lda fp_r0+29
        jsr print_hex_byte
        lda fp_r0+30
        jsr print_hex_byte
        lda fp_r0+31
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; === TEST 3: fp_mod_inv(7, p) ===
        lda #<ecdsa_test3_msg
        ldy #>ecdsa_test3_msg
        jsr print_string

        ; fp_r1 = 7
        lda #<fp_r1
        sta fp_dst
        lda #>fp_r1
        sta fp_dst+1
        jsr fp_zero
        lda #7
        sta fp_r1+31

        ; inverse
        lda #<fp_r1
        sta fp_src1
        lda #>fp_r1
        sta fp_src1+1
        jsr ec_set_modp
        jsr fp_mod_inv          ; fp_r0 = 7^(-1) mod p

        ; Show first 4 bytes (should be 24924924)
        lda #<ecdsa_test3r_msg
        ldy #>ecdsa_test3r_msg
        jsr print_string
        lda fp_r0
        jsr print_hex_byte
        lda fp_r0+1
        jsr print_hex_byte
        lda fp_r0+2
        jsr print_hex_byte
        lda fp_r0+3
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; === TEST 4: Verify 7 * inv(7) mod p == 1 ===
        lda #<ecdsa_test4_msg
        ldy #>ecdsa_test4_msg
        jsr print_string
        lda #<fp_r1
        sta fp_src1
        lda #>fp_r1
        sta fp_src1+1
        lda #<fp_r0
        sta fp_src2
        lda #>fp_r0
        sta fp_src2+1
        jsr ec_set_modp
        jsr fp_mod_mul          ; fp_r0 = 7 * inv mod p
        ; Show last 4 bytes (should be 00000001)
        lda fp_r0+28
        jsr print_hex_byte
        lda fp_r0+29
        jsr print_hex_byte
        lda fp_r0+30
        jsr print_hex_byte
        lda fp_r0+31
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        lda #<ecdsa_computing_msg
        ldy #>ecdsa_computing_msg
        jsr print_string

        ; Set up pointers for signing
        lda #<ecdsa_test_hash
        sta ecdsa_hash_ptr
        lda #>ecdsa_test_hash
        sta ecdsa_hash_ptr+1
        lda #<ecdsa_test_privkey
        sta ecdsa_privkey_ptr
        lda #>ecdsa_test_privkey
        sta ecdsa_privkey_ptr+1
        lda #<ecdsa_test_k
        sta ecdsa_k_ptr
        lda #>ecdsa_test_k
        sta ecdsa_k_ptr+1

        ; Sign!
        jsr ecdsa_sign

        ; Display computed r
        lda #<ecdsa_r_label
        ldy #>ecdsa_r_label
        jsr print_string
        lda #<ecdsa_sig_r
        sta zp_ptr
        lda #>ecdsa_sig_r
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; Display computed s
        lda #<ecdsa_s_label
        ldy #>ecdsa_s_label
        jsr print_string
        lda #<ecdsa_sig_s
        sta zp_ptr
        lda #>ecdsa_sig_s
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; Compare r with expected
        lda #<ecdsa_verify_msg
        ldy #>ecdsa_verify_msg
        jsr print_string

        lda #<ecdsa_sig_r
        sta fp_src1
        lda #>ecdsa_sig_r
        sta fp_src1+1
        lda #<ecdsa_test_r
        sta fp_src2
        lda #>ecdsa_test_r
        sta fp_src2+1
        jsr fp_cmp
        bne @r_fail
        ; Compare s
        lda #<ecdsa_sig_s
        sta fp_src1
        lda #>ecdsa_sig_s
        sta fp_src1+1
        lda #<ecdsa_test_s
        sta fp_src2
        lda #>ecdsa_test_s
        sta fp_src2+1
        jsr fp_cmp
        bne @s_fail

        lda #<ecdsa_pass_msg
        ldy #>ecdsa_pass_msg
        jsr print_string
        jmp @test_done

@r_fail:
@s_fail:
        lda #<ecdsa_fail_msg
        ldy #>ecdsa_fail_msg
        jsr print_string

        ; Show expected r for comparison
        lda #<ecdsa_expr_label
        ldy #>ecdsa_expr_label
        jsr print_string
        lda #<ecdsa_test_r
        sta zp_ptr
        lda #>ecdsa_test_r
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<ecdsa_exps_label
        ldy #>ecdsa_exps_label
        jsr print_string
        lda #<ecdsa_test_s
        sta zp_ptr
        lda #>ecdsa_test_s
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

@test_done:
        rts

; --- ECDSA UI messages ---
ecdsa_test1_msg:
        .byte "T1:3*5="
        .byte 0
ecdsa_test2_msg:
        .byte "T2:15 MOD P="
        .byte 0
ecdsa_test3_msg:
        .byte "T3:INV(7)..."
        .byte 0
ecdsa_test3r_msg:
        .byte "="
        .byte 0
ecdsa_test4_msg:
        .byte "T4:7*INV="
        .byte 0
ecdsa_test_hdr_msg:
        .byte "=== ECDSA P-256 TEST ==="
        .byte $0d
        .byte "RFC 6979 A.2.5 (SHA-256)"
        .byte $0d, 0
ecdsa_init_msg:
        .byte "BUILDING MULTIPLY TABLE..."
        .byte $0d, 0
ecdsa_computing_msg:
        .byte "COMPUTING ECDSA SIGNATURE..."
        .byte $0d
        .byte "(THIS WILL TAKE SEVERAL MINUTES)"
        .byte $0d, 0
ecdsa_r_label:
        .byte "R = "
        .byte 0
ecdsa_s_label:
        .byte $0d
        .byte "S = "
        .byte 0
ecdsa_verify_msg:
        .byte $0d
        .byte "VERIFYING AGAINST KNOWN VECTOR..."
        .byte $0d, 0
ecdsa_pass_msg:
        .byte "*** TEST PASSED ***"
        .byte $0d, 0
ecdsa_fail_msg:
        .byte "*** TEST FAILED ***"
        .byte $0d, 0
ecdsa_expr_label:
        .byte "EXPECTED R = "
        .byte 0
ecdsa_exps_label:
        .byte $0d
        .byte "EXPECTED S = "
        .byte 0
