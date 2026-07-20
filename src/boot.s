; =============================================================================
; boot.asm - BASIC stub and program entry point
; Related: main_loop.asm, prng.asm, aes_encrypt.asm, display.asm, reu_core.asm
; ca65 port note: mechanical translation of !word/!byte/!text to
; .word/.byte/.byte "..."; 'basic_stub' and 'start' exported for the test
; harness / VICE label file.
;
; Phase 5 batch 6 (final): extracted from src/remainder.s into a real
; standalone ca65 object. CRITICAL: boot.o must be linked immediately after
; main.o (see Makefile's MODULES list and its comment) - basic_stub's SYS
; token hardcodes "2064" as a literal ASCII string, not a symbolic
; reference to `start`, so it only lands correctly if this module's code is
; the very first thing placed in the CODE segment after the 2-byte LOADADDR
; header.
; =============================================================================

        .setcpu "6502"
        .segment "LIB_AES256ECDSA_CODE"

.export basic_stub
.export start

.importzp zp_ptr, zp_count, kbd_buffer
.import chrout, clrscr
.import title_msg, gen_iv_msg, gen_key_msg, expanding_msg, instructions_msg
.import dbg_expkey_msg
.import iv_data, key_data, expanded_key
.import detect_reu
.import init_sid
.import drbg_init_entropy, drbg_fill_bytes
.import print_string, display_hex_block, display_results
.import aes_key_expansion, clear_buffers
.import main_loop

; basic stub: 10 sys 2064
basic_stub:
        .word basic_end         ; pointer to next basic line
        .word 10                ; line number 10
        .byte $9e               ; sys token
        .byte "2064"            ; address as ascii
        .byte 0                 ; end of line
basic_end:
        .word 0                 ; end of basic program

; =============================================================================
; main program entry point ($0810)
; =============================================================================
start:
        jsr clrscr              ; clear screen

        ; set uppercase/graphics mode (default)
        lda #$8e                ; chr$(142) = uppercase mode
        jsr chrout

        ; print title
        lda #<title_msg
        ldy #>title_msg
        jsr print_string

        ; detect REU
        jsr detect_reu

        ; initialize sid for noise generation
        jsr init_sid

        ; seed HMAC-DRBG from SID+CIA entropy
        jsr drbg_init_entropy

        ; clear keyboard buffer
        lda #0
        sta kbd_buffer

        ; print generating message
        lda #<gen_iv_msg
        ldy #>gen_iv_msg
        jsr print_string

        ; generate 16-byte iv
        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        jsr drbg_fill_bytes

        ; print generating key message
        lda #<gen_key_msg
        ldy #>gen_key_msg
        jsr print_string

        ; generate 32-byte key
        lda #<key_data
        sta zp_ptr
        lda #>key_data
        sta zp_ptr+1
        lda #32
        jsr drbg_fill_bytes

        ; expand the key for aes
        lda #<expanding_msg
        ldy #>expanding_msg
        jsr print_string
        jsr aes_key_expansion

        ; DEBUG: show first 16 bytes of expanded key
        lda #<dbg_expkey_msg
        ldy #>dbg_expkey_msg
        jsr print_string
        lda #<expanded_key
        sta zp_ptr
        lda #>expanded_key
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; clear input and output buffers
        jsr clear_buffers

        ; display initial results
        jsr display_results

        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string

        ; enter main input loop
        jmp main_loop
