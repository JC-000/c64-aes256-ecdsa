; =============================================================================
; display.s - display_results, display_hex_block, print_hex_byte, print_string
; =============================================================================
; Ported from ACME src/display.asm to ca65 syntax.
; This module contains no ACME-specific directives (no !byte/!word/!fill/
; !text/!pet/!source/!zone/* =) - all lines are plain 6502 mnemonics, labels,
; and @local cheap labels, which are syntactically identical between ACME
; and ca65. Translation is therefore verbatim. See
; docs/ca65_translation_notes.md for addressing-mode / linkage caveats.
; =============================================================================

.segment "LIB_AES256ECDSA_CODE"

.importzp zp_ptr, zp_temp, zp_count
.import chrout
.import iv_data, key_data
.import iv_header_msg, key_header_msg, done_msg, instructions_msg

.export display_results, display_key_only, display_hex_block
.export print_hex_byte, print_string, print_hex_digit, print_decimal_word

; =============================================================================
; display_results - display iv and key in hex format (initial display)
; =============================================================================
display_results:
        lda #<iv_header_msg
        ldy #>iv_header_msg
        jsr print_string

        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<key_header_msg
        ldy #>key_header_msg
        jsr print_string

        lda #<key_data
        sta zp_ptr
        lda #>key_data
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<done_msg
        ldy #>done_msg
        jsr print_string

        rts

; =============================================================================
; display_key_only - display just the 256-bit key
; =============================================================================
display_key_only:
        lda #$0d
        jsr chrout

        lda #<key_header_msg
        ldy #>key_header_msg
        jsr print_string

        lda #<key_data
        sta zp_ptr
        lda #>key_data
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; also display IV
        lda #<iv_header_msg
        ldy #>iv_header_msg
        jsr print_string

        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string

        rts

; =============================================================================
; display_hex_block - display bytes in hex format
; =============================================================================
display_hex_block:
        sta zp_temp

@row_loop:
        ldx zp_temp
@byte_loop:
        ldy #0
        lda (zp_ptr),y
        jsr print_hex_byte

        lda #$20
        jsr chrout

        inc zp_ptr
        bne @no_carry
        inc zp_ptr+1
@no_carry:

        dec zp_count
        beq @done

        dex
        bne @byte_loop

        lda #$0d
        jsr chrout

        jmp @row_loop

@done:
        lda #$0d
        jsr chrout
        rts

; =============================================================================
; print_hex_byte - print byte as two hex digits
; =============================================================================
print_hex_byte:
        pha

        lsr
        lsr
        lsr
        lsr
        jsr print_hex_digit

        pla
        and #$0f
        jsr print_hex_digit

        rts

; =============================================================================
; print_hex_digit - print single hex digit (0-15 in A)
; =============================================================================
print_hex_digit:
        cmp #10
        bcs @letter
        clc
        adc #'0'
        jmp chrout
@letter:
        clc
        adc #'A'-10
        jmp chrout

; =============================================================================
; print_decimal_word - print 16-bit value in zp_temp/zp_temp+1 as decimal
; =============================================================================
print_decimal_word:
        ; convert 16-bit number to decimal and print
        ; uses successive subtraction method
        lda #0
        sta dec_print_started

        ; 10000s place
        lda #<10000
        sta zp_ptr
        lda #>10000
        sta zp_ptr+1
        jsr @print_digit

        ; 1000s place
        lda #<1000
        sta zp_ptr
        lda #>1000
        sta zp_ptr+1
        jsr @print_digit

        ; 100s place
        lda #100
        sta zp_ptr
        lda #0
        sta zp_ptr+1
        jsr @print_digit

        ; 10s place
        lda #10
        sta zp_ptr
        lda #0
        sta zp_ptr+1
        jsr @print_digit

        ; 1s place - always print
        lda zp_temp
        clc
        adc #$30
        jsr chrout
        rts

@print_digit:
        lda #0
        sta dec_digit

@sub_loop:
        ; subtract divisor from zp_temp
        lda zp_temp
        sec
        sbc zp_ptr
        tax
        lda zp_temp+1
        sbc zp_ptr+1
        bcc @digit_done         ; went negative, done

        sta zp_temp+1
        stx zp_temp
        inc dec_digit
        jmp @sub_loop

@digit_done:
        ; check if we should print this digit
        lda dec_digit
        bne @do_print
        lda dec_print_started
        beq @skip_digit

@do_print:
        lda #1
        sta dec_print_started
        lda dec_digit
        clc
        adc #$30
        jsr chrout

@skip_digit:
        rts

dec_digit:
        .byte 0
dec_print_started:
        .byte 0

; =============================================================================
; print_string - print null-terminated string
; =============================================================================
print_string:
        sta zp_ptr
        sty zp_ptr+1
        ldy #0
@loop:
        lda (zp_ptr),y
        beq @done
        jsr chrout
        iny
        bne @loop
        inc zp_ptr+1
        jmp @loop
@done:
        rts
