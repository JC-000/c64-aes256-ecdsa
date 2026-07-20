; =============================================================================
; aes_encrypt.s - AES-256 encryption: clear_buffers, CBC encrypt, key expansion
; Related: aes_decrypt.s, tables.s (S-box, round constants)
; ca65 port note: this module contained no ACME-specific directives (!byte,
; !word, !fill, !text, !source, !zone, * =) in the original source - it is a
; straight mnemonic/label port. See docs/ca65_translation_notes.md for
; cross-module zero-page addressing concerns to verify during
; Integrate.
; =============================================================================

.segment "CODE"

.importzp zp_tmp1, zp_tmp2, zp_tmp3, zp_tmp4, zp_round, zp_col, zp_temp, zp_count
.importzp petscii_return, input_buf_size
.import chrout, getin
.import input_buffer, input_length, input_index, encrypt_buffer
.import encrypt_length, block_count, current_block, pkcs7_pad_value
.import iv_data, cbc_vector, aes_state, expanded_key, key_data
.import input_prompt_msg, encrypting_msg, encrypt_done_msg
.import instructions_msg, no_input_msg
.import dbg_inlen_msg, dbg_inbuf_msg, dbg_blocks_msg, dbg_enclen_msg
.import print_string, print_hex_byte
.import aes_sbox, aes_rcon

; --- Exported for the Python test harness (see tools/run_all_tests.py
; ALL_REQUIRED_LABELS) ---
.export encrypt_input, aes_key_expansion
; --- Rest of exports.inc's full aes_encrypt.s EXPORTS list ---
.export clear_buffers, do_encrypt_text, copy_block_to_state
.export xor_state_with_iv, copy_state_to_output, aes_encrypt_block
.export aes_add_round_key, gf_mul2

; =============================================================================
; clear_buffers - clear input and encrypted buffers
; =============================================================================
clear_buffers:
        lda #0
        ldx #0
@loop:
        sta input_buffer,x
        sta encrypt_buffer,x
        inx
        cpx #input_buf_size
        bne @loop
        sta input_length        ; clear input length
        sta encrypt_length      ; clear encrypted length
        rts

; =============================================================================
; do_encrypt_text - get text input and encrypt it
; =============================================================================
do_encrypt_text:
        ; print prompt
        lda #<input_prompt_msg
        ldy #>input_prompt_msg
        jsr print_string

        ; clear input buffer
        ldx #0
        lda #0
@clear:
        sta input_buffer,x
        inx
        cpx #input_buf_size
        bne @clear

        ; get text input from user
        lda #0
        sta input_index         ; use memory instead of X

@input_loop:
        jsr getin
        beq @input_loop         ; no key, wait

        cmp #petscii_return     ; check for return
        beq @input_done

        cmp #$14                ; check for delete
        beq @do_delete

        ; check buffer not full
        ldx input_index
        cpx #input_buf_size-1
        bcs @input_loop         ; buffer full, ignore

        ; store character
        sta input_buffer,x
        inc input_index

        ; echo character (don't need to preserve anything now)
        jsr chrout

        jmp @input_loop

@do_delete:
        ldx input_index
        beq @input_loop         ; nothing to delete
        dex
        lda #0
        sta input_buffer,x
        stx input_index
        ; echo delete
        lda #$14
        jsr chrout
        jmp @input_loop

@input_done:
        lda input_index
        sta input_length        ; save input length

        ; print newline
        lda #$0d
        jsr chrout

        ; check if any input
        lda input_length
        beq @no_input

        ; print encrypting message
        lda #<encrypting_msg
        ldy #>encrypting_msg
        jsr print_string

        ; perform encryption
        jsr encrypt_input

        ; print done message
        lda #<encrypt_done_msg
        ldy #>encrypt_done_msg
        jsr print_string

        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string

        rts

@no_input:
        lda #<no_input_msg
        ldy #>no_input_msg
        jsr print_string
        rts

; =============================================================================
; encrypt_input - encrypt the input buffer using aes-256
; processes input in 16-byte blocks
; =============================================================================
encrypt_input:
        ; calculate number of blocks needed (round up)
        lda input_length
        bne @has_input
        jmp @done               ; no input
@has_input:

        ; DEBUG: show input length and first bytes
        lda #<dbg_inlen_msg
        ldy #>dbg_inlen_msg
        jsr print_string
        lda input_length
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        lda #<dbg_inbuf_msg
        ldy #>dbg_inbuf_msg
        jsr print_string
        ldx #0
@dbg_in:
        lda input_buffer,x
        jsr print_hex_byte
        lda #$20
        jsr chrout
        inx
        cpx #16
        bne @dbg_in
        lda #$0d
        jsr chrout

        lda input_length        ; reload input_length
        ; PKCS#7: if length is exact multiple of 16, add a full padding block
        ; blocks = (length + 16) / 16 for multiples, else (length + 15) / 16
        ; simplify: blocks = (length / 16) + 1 always works for PKCS#7
        lsr
        lsr
        lsr
        lsr                     ; divide by 16
        clc
        adc #1                  ; always at least one block for padding
        sta block_count

        ; check if input was exact multiple (would cause extra block)
        lda input_length
        and #$0f
        bne @not_exact_mult
        ; exact multiple: we already added 1 extra, that's correct for PKCS#7
        jmp @calc_enc_len
@not_exact_mult:
        ; not exact multiple: the +1 already accounts for partial block
        ; but we over-counted by 1 since division rounded down and we added 1
        ; actually: e.g. length=5 -> 5/16=0, 0+1=1 block. correct.
        ; length=16 -> 16/16=1, 1+1=2 blocks. correct (full pad block).
        ; length=17 -> 17/16=1, 1+1=2 blocks. correct.
        ; length=32 -> 32/16=2, 2+1=3 blocks. correct.
        ; This is correct for all cases!

@calc_enc_len:
        ; calculate padded length (blocks * 16)
        lda block_count
        asl
        asl
        asl
        asl
        sta encrypt_length

        ; DEBUG: show block count and encrypt length
        lda #<dbg_blocks_msg
        ldy #>dbg_blocks_msg
        jsr print_string
        lda block_count
        jsr print_hex_byte
        lda #$20
        jsr chrout
        lda #<dbg_enclen_msg
        ldy #>dbg_enclen_msg
        jsr print_string
        lda encrypt_length
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; reset cbc vector to iv
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
        ; copy input block to state (with padding if needed)
        jsr copy_block_to_state

        ; xor with iv (for first block) or previous cipher (cbc mode)
        jsr xor_state_with_iv

        ; perform aes encryption on state
        jsr aes_encrypt_block

        ; copy state to output and update iv for cbc
        jsr copy_state_to_output

        ; next block
        inc current_block
        lda current_block
        cmp block_count
        bcc @block_loop

@done:
        rts

; =============================================================================
; copy_block_to_state - copy 16 bytes from input to aes state
; applies PKCS#7 padding on the last block
; =============================================================================
copy_block_to_state:
        ; calculate source offset = current_block * 16
        lda current_block
        asl
        asl
        asl
        asl
        sta zp_tmp1             ; source offset

        ; calculate PKCS#7 pad value for last block
        ; pad_len = 16 - (input_length mod 16), but if mod==0, pad_len=16
        lda input_length
        and #$0f                ; mod 16
        beq @full_pad           ; input length is multiple of 16
        ; pad_len = 16 - remainder
        sta zp_tmp2             ; remainder
        lda #16
        sec
        sbc zp_tmp2
        jmp @store_pad
@full_pad:
        lda #16                 ; full block of padding
@store_pad:
        sta pkcs7_pad_value

        ldx #0                  ; state index
@loop:
        ; check if past end of input
        lda zp_tmp1
        cmp input_length
        bcs @pad

        ; copy from input
        tay
        lda input_buffer,y
        jmp @store

@pad:
        ; PKCS#7: pad with the pad length value
        lda pkcs7_pad_value

@store:
        sta aes_state,x
        inc zp_tmp1
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; xor_state_with_iv - xor aes state with iv (or previous ciphertext for cbc)
; =============================================================================
xor_state_with_iv:
        ldx #0
@loop:
        lda aes_state,x
        eor cbc_vector,x
        sta aes_state,x
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; copy_state_to_output - copy encrypted state to output buffer
; also updates cbc vector for next block
; =============================================================================
copy_state_to_output:
        ; calculate dest offset = current_block * 16
        lda current_block
        asl
        asl
        asl
        asl
        tay                     ; dest offset

        ldx #0
@loop:
        lda aes_state,x
        sta encrypt_buffer,y
        sta cbc_vector,x        ; update cbc vector
        iny
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; aes_encrypt_block - encrypt one 16-byte block in aes_state
; uses expanded key in expanded_key
; =============================================================================
aes_encrypt_block:
        ; initial round key addition
        lda #0
        sta zp_round
        jsr aes_add_round_key

        ; main rounds (1 to 13)
        lda #1
        sta zp_round
@round_loop:
        jsr aes_sub_bytes
        jsr aes_shift_rows
        jsr aes_mix_columns
        jsr aes_add_round_key

        inc zp_round
        lda zp_round
        cmp #14
        bcc @round_loop

        ; final round (no mix columns)
        jsr aes_sub_bytes
        jsr aes_shift_rows
        jsr aes_add_round_key

        rts

; =============================================================================
; aes_sub_bytes - substitute each byte using s-box
; =============================================================================
aes_sub_bytes:
        ldx #0
@loop:
        ldy aes_state,x
        lda aes_sbox,y
        sta aes_state,x
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; aes_shift_rows - shift rows of state matrix
; state is column-major: [0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]
; row 0: no shift
; row 1: shift left 1
; row 2: shift left 2
; row 3: shift left 3
; =============================================================================
aes_shift_rows:
        ; row 1: rotate left by 1
        lda aes_state+1
        pha
        lda aes_state+5
        sta aes_state+1
        lda aes_state+9
        sta aes_state+5
        lda aes_state+13
        sta aes_state+9
        pla
        sta aes_state+13

        ; row 2: rotate left by 2
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

        ; row 3: rotate left by 3 (same as right by 1)
        lda aes_state+15
        pha
        lda aes_state+11
        sta aes_state+15
        lda aes_state+7
        sta aes_state+11
        lda aes_state+3
        sta aes_state+7
        pla
        sta aes_state+3

        rts

; =============================================================================
; aes_mix_columns - mix columns transformation
; each column is treated as polynomial and multiplied by fixed polynomial
; =============================================================================
aes_mix_columns:
        lda #0
        sta zp_col

@col_loop:
        ; get column offset (col * 4)
        lda zp_col
        asl
        asl
        tax

        ; load column bytes
        lda aes_state,x
        sta zp_tmp1             ; a0
        lda aes_state+1,x
        sta zp_tmp2             ; a1
        lda aes_state+2,x
        sta zp_tmp3             ; a2
        lda aes_state+3,x
        sta zp_tmp4             ; a3

        ; compute new column values
        ; b0 = 2*a0 ^ 3*a1 ^ a2 ^ a3
        lda zp_tmp1
        jsr gf_mul2
        sta aes_state,x
        lda zp_tmp2
        jsr gf_mul3
        eor aes_state,x
        eor zp_tmp3
        eor zp_tmp4
        sta aes_state,x

        ; b1 = a0 ^ 2*a1 ^ 3*a2 ^ a3
        lda zp_tmp2
        jsr gf_mul2
        sta aes_state+1,x
        lda zp_tmp3
        jsr gf_mul3
        eor aes_state+1,x
        eor zp_tmp1
        eor zp_tmp4
        sta aes_state+1,x

        ; b2 = a0 ^ a1 ^ 2*a2 ^ 3*a3
        lda zp_tmp3
        jsr gf_mul2
        sta aes_state+2,x
        lda zp_tmp4
        jsr gf_mul3
        eor aes_state+2,x
        eor zp_tmp1
        eor zp_tmp2
        sta aes_state+2,x

        ; b3 = 3*a0 ^ a1 ^ a2 ^ 2*a3
        lda zp_tmp4
        jsr gf_mul2
        sta aes_state+3,x
        lda zp_tmp1
        jsr gf_mul3
        eor aes_state+3,x
        eor zp_tmp2
        eor zp_tmp3
        sta aes_state+3,x

        inc zp_col
        lda zp_col
        cmp #4
        bne @col_loop
        rts

; =============================================================================
; gf_mul2 - multiply by 2 in gf(2^8)
; input: a = value
; output: a = value * 2
; =============================================================================
gf_mul2:
        asl
        bcc @no_reduce
        eor #$1b                ; reduce by aes polynomial
@no_reduce:
        rts

; =============================================================================
; gf_mul3 - multiply by 3 in gf(2^8)
; input: a = value
; output: a = value * 3
; =============================================================================
gf_mul3:
        sta zp_temp
        jsr gf_mul2
        eor zp_temp             ; 3*x = 2*x ^ x
        rts

; =============================================================================
; aes_add_round_key - xor state with round key
; round key offset = zp_round * 16
; =============================================================================
aes_add_round_key:
        ; calculate round key offset
        lda zp_round
        asl
        asl
        asl
        asl                     ; * 16
        tay                     ; y = offset into expanded key

        ldx #0
@loop:
        lda aes_state,x
        eor expanded_key,y
        sta aes_state,x
        iny
        inx
        cpx #16
        bne @loop
        rts

; =============================================================================
; aes_key_expansion - expand 256-bit key to round keys
; =============================================================================
aes_key_expansion:
        ; copy original key to first 32 bytes of expanded key
        ldx #0
@copy_key:
        lda key_data,x
        sta expanded_key,x
        inx
        cpx #32
        bne @copy_key

        ; generate remaining round keys
        ; for aes-256: 8 words at a time, need 60 words total (240 bytes)
        lda #8                  ; start at word 8 (byte 32)
        sta zp_count            ; word counter

@expand_loop:
        ; i = zp_count (word index)
        ; temp = w[i-1]
        lda zp_count
        asl
        asl                     ; * 4 = byte offset
        tax

        ; get w[i-1] (previous word)
        lda expanded_key-4,x
        sta zp_tmp1
        lda expanded_key-3,x
        sta zp_tmp2
        lda expanded_key-2,x
        sta zp_tmp3
        lda expanded_key-1,x
        sta zp_tmp4

        ; check if i mod 8 == 0
        lda zp_count
        and #$07
        bne @check_mod4

        ; rotword + subword + rcon
        ; rotword: [a,b,c,d] -> [b,c,d,a]
        lda zp_tmp1
        pha
        lda zp_tmp2
        sta zp_tmp1
        lda zp_tmp3
        sta zp_tmp2
        lda zp_tmp4
        sta zp_tmp3
        pla
        sta zp_tmp4

        ; subword
        ldy zp_tmp1
        lda aes_sbox,y
        sta zp_tmp1
        ldy zp_tmp2
        lda aes_sbox,y
        sta zp_tmp2
        ldy zp_tmp3
        lda aes_sbox,y
        sta zp_tmp3
        ldy zp_tmp4
        lda aes_sbox,y
        sta zp_tmp4

        ; xor with rcon
        lda zp_count
        lsr
        lsr
        lsr                     ; i / 8
        tay
        dey                     ; rcon index (0-based)
        lda aes_rcon,y
        eor zp_tmp1
        sta zp_tmp1
        jmp @do_xor

@check_mod4:
        ; check if i mod 8 == 4
        cmp #4
        bne @do_xor

        ; just subword
        ldy zp_tmp1
        lda aes_sbox,y
        sta zp_tmp1
        ldy zp_tmp2
        lda aes_sbox,y
        sta zp_tmp2
        ldy zp_tmp3
        lda aes_sbox,y
        sta zp_tmp3
        ldy zp_tmp4
        lda aes_sbox,y
        sta zp_tmp4

@do_xor:
        ; w[i] = w[i-8] xor temp
        lda zp_count
        asl
        asl
        tax

        lda expanded_key-32,x   ; w[i-8]
        eor zp_tmp1
        sta expanded_key,x

        lda expanded_key-31,x
        eor zp_tmp2
        sta expanded_key+1,x

        lda expanded_key-30,x
        eor zp_tmp3
        sta expanded_key+2,x

        lda expanded_key-29,x
        eor zp_tmp4
        sta expanded_key+3,x

        ; next word
        inc zp_count
        lda zp_count
        cmp #60                 ; 60 words = 240 bytes
        bcs @expand_done
        jmp @expand_loop

@expand_done:
        ; copy iv to cbc vector
        ldx #0
@copy_iv:
        lda iv_data,x
        sta cbc_vector,x
        inx
        cpx #16
        bne @copy_iv

        rts
