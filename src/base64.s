; =============================================================================
; base64.asm - Base64 encoder for PEM output
; =============================================================================
; Encodes der_buf (length in pkcs10_der_len) into b64_buf.
; Processes 3 bytes -> 4 chars, handles padding ('='), inserts CR every 64 chars.
; =============================================================================

        .segment "HICODE"

.importzp zp_ptr2
.import chrout
.import der_buf
.import pkcs10_der_len
.import pkcs10_pem_begin, pkcs10_pem_end

; --- Full EXPORTS list per src/exports.inc's base64.s entry ---
.export b64_encode, b64_output_pem

; =============================================================================
; b64_encode - encode DER data to base64
; Input: der_buf with pkcs10_der_len bytes
; Output: b64_buf with b64_out_len bytes
; =============================================================================
b64_encode:
        lda #0
        sta b64_src_idx
        sta b64_src_idx+1
        sta b64_out_len
        sta b64_out_len+1
        sta b64_line_pos

@loop:
        ; Check if we have >= 3 bytes remaining
        sec
        lda pkcs10_der_len
        sbc b64_src_idx
        sta b64_remain
        lda pkcs10_der_len+1
        sbc b64_src_idx+1
        sta b64_remain+1

        ; If remain+1 > 0, we definitely have >= 3
        lda b64_remain+1
        bne @full_triple
        lda b64_remain
        cmp #3
        bcs @full_triple
        ; Less than 3 bytes remaining
        cmp #0
        bne @not_zero
        jmp @encode_done
@not_zero:
        cmp #1
        beq @pad2
        jmp @pad1                      ; exactly 2 bytes remaining

@full_triple:
        ; Read 3 bytes from der_buf[src_idx]
        jsr b64_read_src_byte
        sta b64_b0
        jsr b64_read_src_byte
        sta b64_b1
        jsr b64_read_src_byte
        sta b64_b2

        ; char 0: b0 >> 2
        lda b64_b0
        lsr
        lsr
        tax
        lda b64_table,x
        jsr b64_output_char

        ; char 1: (b0 & 3) << 4 | (b1 >> 4)
        lda b64_b0
        and #$03
        asl
        asl
        asl
        asl
        sta b64_tmp
        lda b64_b1
        lsr
        lsr
        lsr
        lsr
        ora b64_tmp
        tax
        lda b64_table,x
        jsr b64_output_char

        ; char 2: (b1 & $0F) << 2 | (b2 >> 6)
        lda b64_b1
        and #$0F
        asl
        asl
        sta b64_tmp
        lda b64_b2
        lsr
        lsr
        lsr
        lsr
        lsr
        lsr
        ora b64_tmp
        tax
        lda b64_table,x
        jsr b64_output_char

        ; char 3: b2 & $3F
        lda b64_b2
        and #$3F
        tax
        lda b64_table,x
        jsr b64_output_char

        jmp @loop

@pad2:
        ; 1 byte remaining: encode to 2 chars + "=="
        jsr b64_read_src_byte
        sta b64_b0

        lda b64_b0
        lsr
        lsr
        tax
        lda b64_table,x
        jsr b64_output_char

        lda b64_b0
        and #$03
        asl
        asl
        asl
        asl
        tax
        lda b64_table,x
        jsr b64_output_char

        lda #'='
        jsr b64_output_char
        lda #'='
        jsr b64_output_char
        jmp @encode_done

@pad1:
        ; 2 bytes remaining: encode to 3 chars + "="
        jsr b64_read_src_byte
        sta b64_b0
        jsr b64_read_src_byte
        sta b64_b1

        lda b64_b0
        lsr
        lsr
        tax
        lda b64_table,x
        jsr b64_output_char

        lda b64_b0
        and #$03
        asl
        asl
        asl
        asl
        sta b64_tmp
        lda b64_b1
        lsr
        lsr
        lsr
        lsr
        ora b64_tmp
        tax
        lda b64_table,x
        jsr b64_output_char

        lda b64_b1
        and #$0F
        asl
        asl
        tax
        lda b64_table,x
        jsr b64_output_char

        lda #'='
        jsr b64_output_char

@encode_done:
        rts

; =============================================================================
; b64_read_src_byte - read next byte from der_buf, advance src_idx
; Returns byte in A. Uses self-modifying code.
; =============================================================================
b64_read_src_byte:
        clc
        lda b64_src_idx
        adc #<der_buf
        sta @rd+1
        lda b64_src_idx+1
        adc #>der_buf
        sta @rd+2
@rd:    lda der_buf                    ; address patched above
        inc b64_src_idx
        bne :+
        inc b64_src_idx+1
:       rts

; =============================================================================
; b64_output_char - write base64 char to b64_buf, handle line breaks
; A = character to write. Uses self-modifying code.
; =============================================================================
b64_output_char:
        pha
        clc
        lda b64_out_len
        adc #<b64_buf
        sta @wr+1
        lda b64_out_len+1
        adc #>b64_buf
        sta @wr+2
        pla
@wr:    sta b64_buf                    ; address patched above
        inc b64_out_len
        bne :+
        inc b64_out_len+1
:
        ; Track line position for CR insertion
        inc b64_line_pos
        lda b64_line_pos
        cmp #64
        bne @no_cr
        ; Insert CR after 64 chars
        lda #0
        sta b64_line_pos
        lda #$0d
        pha
        clc
        lda b64_out_len
        adc #<b64_buf
        sta @cr+1
        lda b64_out_len+1
        adc #>b64_buf
        sta @cr+2
        pla
@cr:    sta b64_buf                    ; address patched above
        inc b64_out_len
        bne :+
        inc b64_out_len+1
:
@no_cr:
        rts

; =============================================================================
; b64_output_pem - write PEM to current chrout channel
; A = 0 for file output, A = 1 for screen output
; =============================================================================
b64_output_pem:
        sta b64_screen_mode

        ; Write "-----BEGIN CERTIFICATE REQUEST-----" + CR
        lda #<pkcs10_pem_begin
        ldy #>pkcs10_pem_begin
        jsr b64_pem_write_str

        ; If screen mode, switch to lowercase mode
        lda b64_screen_mode
        beq @write_b64
        lda #$0e
        jsr chrout

@write_b64:
        lda #0
        sta b64_wr_idx
        sta b64_wr_idx+1

@b64_loop:
        ; Check if we've written all bytes
        lda b64_wr_idx+1
        cmp b64_out_len+1
        bcc @do_write
        bne @b64_done
        lda b64_wr_idx
        cmp b64_out_len
        bcs @b64_done

@do_write:
        ; Read byte from b64_buf[b64_wr_idx]
        clc
        lda b64_wr_idx
        adc #<b64_buf
        sta @rdout+1
        lda b64_wr_idx+1
        adc #>b64_buf
        sta @rdout+2
@rdout: lda b64_buf                    ; address patched above

        ; If screen mode and not CR, translate for PETSCII
        cmp #$0d
        beq @direct_out
        ldx b64_screen_mode
        beq @direct_out

        ; Screen mode translation for lowercase PETSCII:
        ; ASCII A-Z ($41-$5A) -> PETSCII $C1-$DA (uppercase in lc mode)
        ; ASCII a-z ($61-$7A) -> PETSCII $41-$5A (lowercase in lc mode)
        cmp #$61
        bcc @check_upper
        cmp #$7b
        bcs @direct_out
        sec
        sbc #$20
        jmp @direct_out

@check_upper:
        cmp #$41
        bcc @direct_out
        cmp #$5b
        bcs @direct_out
        clc
        adc #$80

@direct_out:
        jsr chrout
        inc b64_wr_idx
        bne :+
        inc b64_wr_idx+1
:       jmp @b64_loop

@b64_done:
        ; Ensure final line has CR
        lda b64_line_pos
        beq @skip_final_cr
        lda #$0d
        jsr chrout
@skip_final_cr:

        ; If screen mode, switch back to uppercase
        lda b64_screen_mode
        beq @write_end
        lda #$8e
        jsr chrout

@write_end:
        ; Write "-----END CERTIFICATE REQUEST-----" + CR
        lda #<pkcs10_pem_end
        ldy #>pkcs10_pem_end
        jsr b64_pem_write_str
        rts

; =============================================================================
; b64_pem_write_str - write null-terminated string via chrout
; A/Y = address low/high
; =============================================================================
b64_pem_write_str:
        sta b64_ws_ptr
        sty b64_ws_ptr+1
        ldy #0
@loop:
        lda (b64_ws_ptr),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts

b64_ws_ptr = zp_ptr2                   ; reuse temporarily

; =============================================================================
; Base64 lookup table (64 entries, ASCII byte values)
; =============================================================================
b64_table:
        ; A-Z ($41-$5A)
        .byte $41, $42, $43, $44, $45, $46, $47, $48
        .byte $49, $4A, $4B, $4C, $4D, $4E, $4F, $50
        .byte $51, $52, $53, $54, $55, $56, $57, $58
        .byte $59, $5A
        ; a-z ($61-$7A)
        .byte $61, $62, $63, $64, $65, $66, $67, $68
        .byte $69, $6A, $6B, $6C, $6D, $6E, $6F, $70
        .byte $71, $72, $73, $74, $75, $76, $77, $78
        .byte $79, $7A
        ; 0-9 ($30-$39)
        .byte $30, $31, $32, $33, $34, $35, $36, $37
        .byte $38, $39
        ; + /
        .byte $2B, $2F

; =============================================================================
; Working variables
; =============================================================================
b64_src_idx:    .word 0
b64_out_len:    .word 0
b64_line_pos:   .byte 0
b64_remain:     .word 0
b64_b0:         .byte 0
b64_b1:         .byte 0
b64_b2:         .byte 0
b64_tmp:        .byte 0
b64_screen_mode: .byte 0
b64_wr_idx:     .word 0

; =============================================================================
; Base64 output buffer (700 bytes)
; =============================================================================
b64_buf:        .res 700, 0
