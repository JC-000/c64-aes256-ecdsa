; =============================================================================
; aes_decrypt.asm - AES-256 decryption: display_encrypted, CBC decrypt, inverse ops
; Related: aes_encrypt.asm, tables.asm (inverse S-box)
; =============================================================================

; =============================================================================
; display_encrypted - display the encrypted buffer contents
; =============================================================================
display_encrypted:
        lda #$0d
        jsr chrout
        
        ; check if anything encrypted
        lda encrypt_length
        bne @has_data
        
        lda #<no_encrypted_msg
        ldy #>no_encrypted_msg
        jsr print_string
        rts
        
@has_data:
        ; print header
        lda #<encrypted_header_msg
        ldy #>encrypted_header_msg
        jsr print_string
        
        ; display encrypted bytes
        lda #<encrypt_buffer
        sta zp_ptr
        lda #>encrypt_buffer
        sta zp_ptr+1
        lda encrypt_length
        sta zp_count
        lda #8                  ; bytes per line
        jsr display_hex_block
        
        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        
        rts

; =============================================================================
; do_decrypt_text - decrypt the encrypted buffer and display result
; =============================================================================
do_decrypt_text:
        lda #$0d
        jsr chrout
        
        ; check if anything to decrypt
        lda encrypt_length
        bne @has_data
        
        lda #<no_encrypted_msg
        ldy #>no_encrypted_msg
        jsr print_string
        rts
        
@has_data:
        ; print decrypting message
        lda #<decrypting_msg
        ldy #>decrypting_msg
        jsr print_string
        
        ; perform decryption
        jsr decrypt_buffer
        
        ; print decrypted header
        lda #<decrypted_header_msg
        ldy #>decrypted_header_msg
        jsr print_string
        
        ; show decrypted bytes as hex first (debug)
        lda #<decrypt_data
        sta zp_ptr
        lda #>decrypt_data
        sta zp_ptr+1
        lda decrypt_length
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; print as text label
        lda #<as_text_msg
        ldy #>as_text_msg
        jsr print_string
        
        ; ensure uppercase mode for display
        lda #$8e                ; chr$(142) = uppercase mode
        jsr chrout
        
        ; print decrypted text
        ldx #0
@print_loop:
        cpx decrypt_length
        beq @print_done
        lda decrypt_data,x
        beq @next_char          ; skip nulls but continue
        
        ; only print printable characters ($20-$5F and $C0-$DF)
        cmp #$20                ; space
        bcc @next_char          ; skip control chars
        cmp #$60
        bcc @do_print           ; $20-$5F are printable
        
        ; check for $C0-$DF range (shifted letters)
        cmp #$c0
        bcc @next_char          ; $60-$BF are graphics, skip
        cmp #$e0
        bcs @next_char          ; $E0+ skip
        
        ; convert $C0-$DF to $40-$5F for display
        sec
        sbc #$80
        
@do_print:
        jsr chrout              ; print character
@next_char:
        inx
        cpx #input_buf_size
        bcc @print_loop
        
@print_done:
        lda #$0d
        jsr chrout
        
        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        
        rts

; =============================================================================
; decrypt_buffer - decrypt the encrypted buffer using aes-256
; =============================================================================
decrypt_buffer:
        ; DEBUG: show IV
        lda #<debug_iv_msg
        ldy #>debug_iv_msg
        jsr print_string
        ldx #0
@dbg_iv:
        lda iv_data,x
        jsr print_hex_byte
        lda #$20
        jsr chrout
        inx
        cpx #16
        bne @dbg_iv
        lda #$0d
        jsr chrout
        
        ; DEBUG: show encrypt_length
        lda #<debug_len_msg
        ldy #>debug_len_msg
        jsr print_string
        lda encrypt_length
        jsr print_hex_byte
        lda #$0d
        jsr chrout
        
        ; get number of blocks
        lda encrypt_length
        bne @has_len
        jmp @done
@has_len:
        
        lsr
        lsr
        lsr
        lsr                     ; divide by 16
        sta block_count
        
        ; DEBUG: show block count
        lda #<debug_blk_msg
        ldy #>debug_blk_msg
        jsr print_string
        lda block_count
        jsr print_hex_byte
        lda #$0d
        jsr chrout
        
        ; copy encrypted length to decrypted length
        lda encrypt_length
        sta decrypt_length
        
        ; reset cbc vector to original iv
        ldx #0
@reset_iv:
        lda iv_data,x
        sta cbc_vector,x
        inx
        cpx #16
        bne @reset_iv
        
        ; process each block
        lda #0
        sta current_block
        
@block_loop:
        ; DEBUG: show current block
        lda #<debug_cur_msg
        ldy #>debug_cur_msg
        jsr print_string
        lda current_block
        jsr print_hex_byte
        lda #$0d
        jsr chrout
        
        ; copy encrypted block to state
        jsr copy_cipher_to_state
        
        ; DEBUG: show state after copy
        lda #<debug_state_msg
        ldy #>debug_state_msg
        jsr print_string
        jsr print_state_debug
        
        ; save current ciphertext for cbc (before decryption)
        jsr save_cipher_for_cbc
        
        ; perform aes decryption on state
        jsr aes_decrypt_block
        
        ; DEBUG: show state after decrypt
        lda #<debug_after_dec_msg
        ldy #>debug_after_dec_msg
        jsr print_string
        jsr print_state_debug
        
        ; DEBUG: show cbc_vector before xor
        lda #<debug_cbc_msg
        ldy #>debug_cbc_msg
        jsr print_string
        ldx #0
@dbg_cbc:
        lda cbc_vector,x
        jsr print_hex_byte
        lda #$20
        jsr chrout
        inx
        cpx #16
        bne @dbg_cbc
        lda #$0d
        jsr chrout
        
        ; xor with cbc vector to get plaintext
        jsr xor_state_with_iv
        
        ; DEBUG: show state after xor
        lda #<debug_after_xor_msg
        ldy #>debug_after_xor_msg
        jsr print_string
        jsr print_state_debug
        
        ; copy state to decrypted output
        jsr copy_state_to_decrypt
        
        ; update cbc vector with saved ciphertext
        jsr update_cbc_from_saved
        
        ; next block
        inc current_block
        lda current_block
        cmp block_count
        bcc @block_loop
        
@done:
        rts

; =============================================================================
; print_state_debug - print aes_state as hex (preserves registers)
; =============================================================================
print_state_debug:
        ldx #0
@loop:
        lda aes_state,x
        jsr print_hex_byte
        lda #$20
        jsr chrout
        inx
        cpx #16
        bne @loop
        lda #$0d
        jsr chrout
        rts

; =============================================================================
; copy_cipher_to_state - copy 16 bytes from encrypt buffer to state
; =============================================================================
copy_cipher_to_state:
        lda current_block
        asl
        asl
        asl
        asl
        tay                     ; source offset
        
        ldx #0
@loop:
        lda encrypt_buffer,y
        sta aes_state,x
        iny
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; save_cipher_for_cbc - save current ciphertext block for cbc update
; =============================================================================
save_cipher_for_cbc:
        ldx #0
@loop:
        lda aes_state,x
        sta cbc_temp,x
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; copy_state_to_decrypt - copy decrypted state to output buffer
; =============================================================================
copy_state_to_decrypt:
        lda current_block
        asl
        asl
        asl
        asl
        tay                     ; dest offset
        
        ldx #0
@loop:
        lda aes_state,x
        sta decrypt_data,y
        iny
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; update_cbc_from_saved - update cbc vector from saved ciphertext
; =============================================================================
update_cbc_from_saved:
        ldx #0
@loop:
        lda cbc_temp,x
        sta cbc_vector,x
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; aes_decrypt_block - decrypt one 16-byte block in aes_state
; standard inverse cipher for aes-256 (14 rounds)
; =============================================================================
aes_decrypt_block:
        ; round 14: initial add round key
        lda #14
        sta zp_round
        jsr aes_add_round_key
        
        ; DEBUG: show state after initial add round key
        lda #<dbg_ark14_msg
        ldy #>dbg_ark14_msg
        jsr print_string
        jsr print_state_debug
        
        ; rounds 13 down to 1
        lda #13
        sta zp_round
        
@round_loop:
        jsr aes_inv_shift_rows
        jsr aes_inv_sub_bytes
        jsr aes_add_round_key
        jsr aes_inv_mix_columns
        
        dec zp_round
        lda zp_round
        bne @round_loop
        
        ; DEBUG: show state after main rounds
        lda #<dbg_mainrnd_msg
        ldy #>dbg_mainrnd_msg
        jsr print_string
        jsr print_state_debug
        
        ; round 0: final round (no inv mix columns)
        jsr aes_inv_shift_rows
        jsr aes_inv_sub_bytes
        ; zp_round is already 0
        jsr aes_add_round_key
        
        rts

; =============================================================================
; aes_inv_sub_bytes - inverse substitute using inverse s-box
; =============================================================================
aes_inv_sub_bytes:
        ldx #0
@loop:
        ldy aes_state,x
        lda aes_inv_sbox,y
        sta aes_state,x
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; aes_inv_shift_rows - inverse shift rows
; row 0: no shift
; row 1: shift right 1
; row 2: shift right 2
; row 3: shift right 3
; =============================================================================
aes_inv_shift_rows:
        ; row 1: rotate right by 1
        lda aes_state+13
        pha
        lda aes_state+9
        sta aes_state+13
        lda aes_state+5
        sta aes_state+9
        lda aes_state+1
        sta aes_state+5
        pla
        sta aes_state+1
        
        ; row 2: rotate right by 2 (same as left by 2)
        lda aes_state+2
        pha
        lda aes_state+10
        sta aes_state+2
        pla
        sta aes_state+10
        lda aes_state+6
        pha
        lda aes_state+14
        sta aes_state+6
        pla
        sta aes_state+14
        
        ; row 3: rotate right by 3 (same as left by 1)
        lda aes_state+3
        pha
        lda aes_state+7
        sta aes_state+3
        lda aes_state+11
        sta aes_state+7
        lda aes_state+15
        sta aes_state+11
        pla
        sta aes_state+15
        
        rts

; =============================================================================
; aes_inv_mix_columns - inverse mix columns transformation
; multiplies by inverse matrix: [0e,0b,0d,09]
; =============================================================================
aes_inv_mix_columns:
        lda #0
        sta zp_col
        
@col_loop:
        lda zp_col
        asl
        asl
        sta zp_tmp1             ; save column offset
        tax
        
        ; load column bytes to temp storage
        lda aes_state,x
        sta mc_a0
        lda aes_state+1,x
        sta mc_a1
        lda aes_state+2,x
        sta mc_a2
        lda aes_state+3,x
        sta mc_a3
        
        ; b0 = 0e*a0 ^ 0b*a1 ^ 0d*a2 ^ 09*a3
        lda mc_a0
        jsr gf_mul_0e
        sta mc_b0
        lda mc_a1
        jsr gf_mul_0b
        eor mc_b0
        sta mc_b0
        lda mc_a2
        jsr gf_mul_0d
        eor mc_b0
        sta mc_b0
        lda mc_a3
        jsr gf_mul_09
        eor mc_b0
        sta mc_b0
        
        ; b1 = 09*a0 ^ 0e*a1 ^ 0b*a2 ^ 0d*a3
        lda mc_a0
        jsr gf_mul_09
        sta mc_b1
        lda mc_a1
        jsr gf_mul_0e
        eor mc_b1
        sta mc_b1
        lda mc_a2
        jsr gf_mul_0b
        eor mc_b1
        sta mc_b1
        lda mc_a3
        jsr gf_mul_0d
        eor mc_b1
        sta mc_b1
        
        ; b2 = 0d*a0 ^ 09*a1 ^ 0e*a2 ^ 0b*a3
        lda mc_a0
        jsr gf_mul_0d
        sta mc_b2
        lda mc_a1
        jsr gf_mul_09
        eor mc_b2
        sta mc_b2
        lda mc_a2
        jsr gf_mul_0e
        eor mc_b2
        sta mc_b2
        lda mc_a3
        jsr gf_mul_0b
        eor mc_b2
        sta mc_b2
        
        ; b3 = 0b*a0 ^ 0d*a1 ^ 09*a2 ^ 0e*a3
        lda mc_a0
        jsr gf_mul_0b
        sta mc_b3
        lda mc_a1
        jsr gf_mul_0d
        eor mc_b3
        sta mc_b3
        lda mc_a2
        jsr gf_mul_09
        eor mc_b3
        sta mc_b3
        lda mc_a3
        jsr gf_mul_0e
        eor mc_b3
        sta mc_b3
        
        ; store results back to state
        ldx zp_tmp1             ; restore column offset
        lda mc_b0
        sta aes_state,x
        lda mc_b1
        sta aes_state+1,x
        lda mc_b2
        sta aes_state+2,x
        lda mc_b3
        sta aes_state+3,x
        
        inc zp_col
        lda zp_col
        cmp #4
        beq @col_done
        jmp @col_loop
@col_done:
        rts

; =============================================================================
; gf_mul_09 - multiply by 9 in gf(2^8): 9 = 8 + 1
; =============================================================================
gf_mul_09:
        sta zp_temp
        jsr gf_mul2             ; 2
        jsr gf_mul2             ; 4
        jsr gf_mul2             ; 8
        eor zp_temp             ; 8 + 1 = 9
        rts

; =============================================================================
; gf_mul_0b - multiply by 11 in gf(2^8): 11 = 8 + 2 + 1
; =============================================================================
gf_mul_0b:
        sta zp_temp
        jsr gf_mul2             ; 2
        pha                     ; save 2
        jsr gf_mul2             ; 4
        jsr gf_mul2             ; 8
        eor zp_temp             ; 8 + 1 = 9
        sta zp_temp
        pla                     ; get 2
        eor zp_temp             ; 9 + 2 = 11
        rts

; =============================================================================
; gf_mul_0d - multiply by 13 in gf(2^8): 13 = 8 + 4 + 1
; =============================================================================
gf_mul_0d:
        sta zp_temp
        jsr gf_mul2             ; 2
        jsr gf_mul2             ; 4
        pha                     ; save 4
        jsr gf_mul2             ; 8
        eor zp_temp             ; 8 + 1 = 9
        sta zp_temp
        pla                     ; get 4
        eor zp_temp             ; 9 + 4 = 13
        rts

; =============================================================================
; gf_mul_0e - multiply by 14 in gf(2^8): 14 = 8 + 4 + 2
; =============================================================================
gf_mul_0e:
        jsr gf_mul2             ; 2
        pha                     ; save 2
        jsr gf_mul2             ; 4
        pha                     ; save 4
        jsr gf_mul2             ; 8
        sta zp_temp
        pla                     ; get 4
        eor zp_temp             ; 8 + 4 = 12
        sta zp_temp
        pla                     ; get 2
        eor zp_temp             ; 12 + 2 = 14
        rts

