; =============================================================================
; benchmark.asm - AES benchmark, CIA timer, NIST test vector verification
; Related: aes_encrypt.asm, gcm_siv.asm
; =============================================================================

        .segment "CODE"

.importzp zp_ptr, zp_count
.import chrout
.import input_buffer, gcmsiv_pt_buf, input_length, gcmsiv_pt_len, iv_data
.import cbc_vector, key_data, aes_state, nist_saved_key, nist_saved_iv
.import bench_iterations, current_block, block_count, timer_start_lo
.import timer_start_hi, timer_end_lo, timer_end_hi, timer_elapsed
.import benchmark_header_msg, bench_cbc_msg, bench_gcm_msg, bench_block_msg
.import bench_iters_msg, bench_time_msg, bench_jiffies_msg, bench_done_msg
.import instructions_msg, nist_header_msg, nist_expanding_msg, nist_key_msg
.import nist_iv_msg, nist_pt_msg, nist_ct_msg, nist_verify_msg
.import nist_result_msg, nist_pass_msg, nist_cbc_test_msg
.import nist_cbc_result_msg, nist_cbc_pass_msg, nist_cbc_fail_msg
.import nist_fail_msg, nist_note_msg
.import print_string, print_hex_byte, display_hex_block
.import copy_block_to_state, xor_state_with_iv, aes_encrypt_block
.import copy_state_to_output, aes_key_expansion
.import generate_gcmsiv_nonce, gcmsiv_derive_keys
.import gcmsiv_compute_tag_base, gcmsiv_finalize_tag, gcmsiv_ctr_encrypt

; --- Full EXPORTS list per src/exports.inc's benchmark.s entry ---
.export do_benchmark, do_load_nist_vectors

; =============================================================================
; do_benchmark - benchmark AES-CBC and AES-GCM-SIV encryption speeds
; Uses CIA timer for accurate timing
; =============================================================================
do_benchmark:
        lda #$0d
        jsr chrout

        lda #<benchmark_header_msg
        ldy #>benchmark_header_msg
        jsr print_string

        ; prepare test data - fill input buffer with 64 bytes of test pattern
        ldx #0
@fill_test:
        txa
        sta input_buffer,x
        sta gcmsiv_pt_buf,x
        inx
        cpx #64
        bne @fill_test

        lda #64
        sta input_length
        sta gcmsiv_pt_len

        ; =========================================
        ; Benchmark AES-CBC (4 blocks = 64 bytes)
        ; =========================================
        lda #<bench_cbc_msg
        ldy #>bench_cbc_msg
        jsr print_string

        ; reset CBC IV
        ldx #0
@reset_iv1:
        lda iv_data,x
        sta cbc_vector,x
        inx
        cpx #16
        bne @reset_iv1

        ; start timer
        jsr timer_start

        ; run CBC encryption multiple times for measurable result
        lda #0
        sta bench_iterations
        sta bench_iterations+1

@cbc_loop:
        ; encrypt 4 blocks (64 bytes) with CBC
        lda #0
        sta current_block
        lda #4
        sta block_count

@cbc_block_loop:
        jsr copy_block_to_state
        jsr xor_state_with_iv
        jsr aes_encrypt_block
        jsr copy_state_to_output
        inc current_block
        lda current_block
        cmp block_count
        bcc @cbc_block_loop

        ; increment iteration counter
        inc bench_iterations
        bne @cbc_check
        inc bench_iterations+1
@cbc_check:
        ; run for 256 iterations
        lda bench_iterations+1
        cmp #1
        bcc @cbc_loop

        ; stop timer and get result
        jsr timer_stop

        ; display CBC results
        lda #<bench_iters_msg
        ldy #>bench_iters_msg
        jsr print_string
        lda bench_iterations+1
        jsr print_hex_byte
        lda bench_iterations
        jsr print_hex_byte

        lda #<bench_time_msg
        ldy #>bench_time_msg
        jsr print_string

        ; print elapsed time (timer_hi:timer_lo)
        lda timer_elapsed+1
        jsr print_hex_byte
        lda timer_elapsed
        jsr print_hex_byte

        lda #<bench_jiffies_msg
        ldy #>bench_jiffies_msg
        jsr print_string

        ; =========================================
        ; Benchmark AES-GCM-SIV (64 bytes)
        ; =========================================
        lda #<bench_gcm_msg
        ldy #>bench_gcm_msg
        jsr print_string

        ; generate a nonce for GCM-SIV
        jsr generate_gcmsiv_nonce

        ; start timer
        jsr timer_start

        ; run GCM-SIV encryption multiple times
        lda #0
        sta bench_iterations
        sta bench_iterations+1

@gcm_loop:
        ; full GCM-SIV encrypt operation
        jsr gcmsiv_derive_keys
        jsr gcmsiv_compute_tag_base
        jsr gcmsiv_finalize_tag
        jsr gcmsiv_ctr_encrypt

        ; increment iteration counter
        inc bench_iterations
        bne @gcm_check
        inc bench_iterations+1
@gcm_check:
        ; run for 256 iterations
        lda bench_iterations+1
        cmp #1
        bcc @gcm_loop

        ; stop timer and get result
        jsr timer_stop

        ; display GCM results
        lda #<bench_iters_msg
        ldy #>bench_iters_msg
        jsr print_string
        lda bench_iterations+1
        jsr print_hex_byte
        lda bench_iterations
        jsr print_hex_byte

        lda #<bench_time_msg
        ldy #>bench_time_msg
        jsr print_string

        lda timer_elapsed+1
        jsr print_hex_byte
        lda timer_elapsed
        jsr print_hex_byte

        lda #<bench_jiffies_msg
        ldy #>bench_jiffies_msg
        jsr print_string

        ; =========================================
        ; Benchmark single AES block encrypt
        ; =========================================
        lda #<bench_block_msg
        ldy #>bench_block_msg
        jsr print_string

        ; start timer
        jsr timer_start

        ; run single block encryption many times
        lda #0
        sta bench_iterations
        sta bench_iterations+1

@block_loop:
        jsr aes_encrypt_block

        inc bench_iterations
        bne @block_check
        inc bench_iterations+1
@block_check:
        ; run for 256 iterations
        lda bench_iterations+1
        cmp #1
        bcc @block_loop

        jsr timer_stop

        lda #<bench_iters_msg
        ldy #>bench_iters_msg
        jsr print_string
        lda bench_iterations+1
        jsr print_hex_byte
        lda bench_iterations
        jsr print_hex_byte

        lda #<bench_time_msg
        ldy #>bench_time_msg
        jsr print_string

        lda timer_elapsed+1
        jsr print_hex_byte
        lda timer_elapsed
        jsr print_hex_byte

        lda #<bench_jiffies_msg
        ldy #>bench_jiffies_msg
        jsr print_string

        ; done
        lda #<bench_done_msg
        ldy #>bench_done_msg
        jsr print_string

        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; timer_start - start timing using CIA #1 TOD clock or jiffy clock
; =============================================================================
timer_start:
        ; use the jiffy clock at $A0-$A2 (TIME)
        sei                     ; disable interrupts briefly
        lda $a2                 ; low byte of jiffy clock
        sta timer_start_lo
        lda $a1                 ; mid byte
        sta timer_start_hi
        cli
        rts

; =============================================================================
; timer_stop - stop timing and calculate elapsed
; =============================================================================
timer_stop:
        sei
        lda $a2
        sta timer_end_lo
        lda $a1
        sta timer_end_hi
        cli

        ; calculate elapsed = end - start
        lda timer_end_lo
        sec
        sbc timer_start_lo
        sta timer_elapsed
        lda timer_end_hi
        sbc timer_start_hi
        sta timer_elapsed+1
        rts

; =============================================================================
; do_load_nist_vectors - load NIST AES-256 test vectors
; Uses NIST FIPS 197 Appendix C.3 test vector for AES-256
; =============================================================================
do_load_nist_vectors:
        ; Save current key_data and iv_data before overwriting
        ldx #0
@save_key:
        lda key_data,x
        sta nist_saved_key,x
        inx
        cpx #32
        bne @save_key
        ldx #0
@save_iv:
        lda iv_data,x
        sta nist_saved_iv,x
        inx
        cpx #16
        bne @save_iv

        lda #$0d
        jsr chrout

        lda #<nist_header_msg
        ldy #>nist_header_msg
        jsr print_string

        ; Copy NIST test key to key_data
        ldx #0
@copy_key:
        lda nist_test_key,x
        sta key_data,x
        inx
        cpx #32
        bne @copy_key

        ; Copy NIST test IV to iv_data
        ldx #0
@copy_iv:
        lda nist_test_iv,x
        sta iv_data,x
        inx
        cpx #16
        bne @copy_iv

        ; Expand the key
        lda #<nist_expanding_msg
        ldy #>nist_expanding_msg
        jsr print_string
        jsr aes_key_expansion

        ; Display loaded key
        lda #<nist_key_msg
        ldy #>nist_key_msg
        jsr print_string

        lda #<key_data
        sta zp_ptr
        lda #>key_data
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; Display loaded IV
        lda #<nist_iv_msg
        ldy #>nist_iv_msg
        jsr print_string

        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; Show expected plaintext
        lda #<nist_pt_msg
        ldy #>nist_pt_msg
        jsr print_string

        lda #<nist_test_plaintext
        sta zp_ptr
        lda #>nist_test_plaintext
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; Show expected ciphertext
        lda #<nist_ct_msg
        ldy #>nist_ct_msg
        jsr print_string

        lda #<nist_test_ciphertext
        sta zp_ptr
        lda #>nist_test_ciphertext
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; Run verification test
        lda #<nist_verify_msg
        ldy #>nist_verify_msg
        jsr print_string

        ; Copy plaintext to aes_state
        ldx #0
@copy_pt:
        lda nist_test_plaintext,x
        sta aes_state,x
        inx
        cpx #16
        bne @copy_pt

        ; Encrypt
        jsr aes_encrypt_block

        ; Show actual result
        lda #<nist_result_msg
        ldy #>nist_result_msg
        jsr print_string

        lda #<aes_state
        sta zp_ptr
        lda #>aes_state
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; Compare with expected
        ldx #0
@compare:
        lda aes_state,x
        cmp nist_test_ciphertext,x
        bne @mismatch
        inx
        cpx #16
        bne @compare

        ; Match!
        lda #<nist_pass_msg
        ldy #>nist_pass_msg
        jsr print_string

        ; Now test CBC mode with zero IV (should give same result)
        lda #<nist_cbc_test_msg
        ldy #>nist_cbc_test_msg
        jsr print_string

        ; Reset CBC vector to IV (all zeros)
        ldx #0
@reset_cbc:
        lda nist_test_iv,x
        sta cbc_vector,x
        inx
        cpx #16
        bne @reset_cbc

        ; Copy plaintext to aes_state
        ldx #0
@copy_pt2:
        lda nist_test_plaintext,x
        sta aes_state,x
        inx
        cpx #16
        bne @copy_pt2

        ; XOR with IV (CBC mode) - but IV is zero so no change
        ldx #0
@xor_iv:
        lda aes_state,x
        eor cbc_vector,x
        sta aes_state,x
        inx
        cpx #16
        bne @xor_iv

        ; Encrypt
        jsr aes_encrypt_block

        ; Show CBC result
        lda #<nist_cbc_result_msg
        ldy #>nist_cbc_result_msg
        jsr print_string

        lda #<aes_state
        sta zp_ptr
        lda #>aes_state
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; Compare CBC result with expected
        ldx #0
@compare_cbc:
        lda aes_state,x
        cmp nist_test_ciphertext,x
        bne @cbc_mismatch
        inx
        cpx #16
        bne @compare_cbc

        lda #<nist_cbc_pass_msg
        ldy #>nist_cbc_pass_msg
        jsr print_string
        jmp @done

@cbc_mismatch:
        lda #<nist_cbc_fail_msg
        ldy #>nist_cbc_fail_msg
        jsr print_string
        jmp @done

@mismatch:
        lda #<nist_fail_msg
        ldy #>nist_fail_msg
        jsr print_string

@done:
        ; Restore original key_data and iv_data
        ldx #0
@restore_key:
        lda nist_saved_key,x
        sta key_data,x
        inx
        cpx #32
        bne @restore_key
        ldx #0
@restore_iv:
        lda nist_saved_iv,x
        sta iv_data,x
        inx
        cpx #16
        bne @restore_iv
        ; Re-expand original key schedule
        jsr aes_key_expansion

        ; Show note about text input vs hex
        lda #<nist_note_msg
        ldy #>nist_note_msg
        jsr print_string

        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; NIST FIPS 197 Appendix C.3 - AES-256 Test Vector
; =============================================================================

; Key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
nist_test_key:
        .byte $00, $01, $02, $03, $04, $05, $06, $07
        .byte $08, $09, $0a, $0b, $0c, $0d, $0e, $0f
        .byte $10, $11, $12, $13, $14, $15, $16, $17
        .byte $18, $19, $1a, $1b, $1c, $1d, $1e, $1f

; IV: 00000000000000000000000000000000 (all zeros for ECB test)
nist_test_iv:
        .byte $00, $00, $00, $00, $00, $00, $00, $00
        .byte $00, $00, $00, $00, $00, $00, $00, $00

; Plaintext: 00112233445566778899aabbccddeeff
nist_test_plaintext:
        .byte $00, $11, $22, $33, $44, $55, $66, $77
        .byte $88, $99, $aa, $bb, $cc, $dd, $ee, $ff

; Expected Ciphertext: 8ea2b7ca516745bfeafc49904b496089
nist_test_ciphertext:
        .byte $8e, $a2, $b7, $ca, $51, $67, $45, $bf
        .byte $ea, $fc, $49, $90, $4b, $49, $60, $89

