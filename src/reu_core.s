; =============================================================================
; reu_core.asm - REU detection, stash/fetch, test data
; Related: reu_advanced.asm (additional REU operations)
; =============================================================================

; =============================================================================
; detect_reu - detect presence of REU and determine size
; Sets: reu_present (0=no, 1=yes), reu_size_kb (size in KB, max 16384)
; =============================================================================
detect_reu:
        ; REU detection based on prog8reu by Andrew Gillham
        ; Uses signature-based detection for reliability
        lda #0
        sta reu_present
        sta reu_size_kb
        sta reu_size_kb+1
        sta reu_banks

        ; Call the detection routine
        jsr reu_detect

        ; Check if REU was found
        lda reu_present
        bne @reu_found
        jmp @no_reu

@reu_found:
        ; REU detected - convert banks to KB size
        ; Use lookup table based on bank count
        lda reu_banks

        cmp #0                  ; 0 means 256 banks = 16MB
        bne @not_16mb
        lda #<16384
        sta reu_size_kb
        lda #>16384
        sta reu_size_kb+1
        jmp @print_detected

@not_16mb:
        cmp #$7f                ; 127 banks = 8MB
        bne @not_8mb
        lda #<8192
        sta reu_size_kb
        lda #>8192
        sta reu_size_kb+1
        jmp @print_detected

@not_8mb:
        cmp #$3f                ; 63 banks = 4MB
        bne @not_4mb
        lda #<4096
        sta reu_size_kb
        lda #>4096
        sta reu_size_kb+1
        jmp @print_detected

@not_4mb:
        cmp #$1f                ; 31 banks = 2MB
        bne @not_2mb
        lda #<2048
        sta reu_size_kb
        lda #>2048
        sta reu_size_kb+1
        jmp @print_detected

@not_2mb:
        cmp #$0f                ; 15 banks = 1MB
        bne @not_1mb
        lda #<1024
        sta reu_size_kb
        lda #>1024
        sta reu_size_kb+1
        jmp @print_detected

@not_1mb:
        cmp #$07                ; 7 banks = 512KB
        bne @not_512k
        lda #<512
        sta reu_size_kb
        lda #>512
        sta reu_size_kb+1
        jmp @print_detected

@not_512k:
        cmp #$03                ; 3 banks = 256KB
        bne @not_256k
        lda #<256
        sta reu_size_kb
        lda #>256
        sta reu_size_kb+1
        jmp @print_detected

@not_256k:
        cmp #$01                ; 1 bank = 128KB
        bne @unknown_size
        lda #128
        sta reu_size_kb
        lda #0
        sta reu_size_kb+1
        jmp @print_detected

@unknown_size:
        ; Unknown bank count - calculate size = banks * 64
        lda reu_banks
        sta reu_size_kb
        lda #0
        sta reu_size_kb+1
        ldx #6
@mult:
        asl reu_size_kb
        rol reu_size_kb+1
        dex
        bne @mult

@print_detected:
        lda #<reu_detected_msg
        ldy #>reu_detected_msg
        jsr print_string

        ; Print size in decimal
        lda reu_size_kb
        sta zp_temp
        lda reu_size_kb+1
        sta zp_temp+1
        jsr print_decimal_word

        lda #<reu_kb_msg
        ldy #>reu_kb_msg
        jsr print_string
        rts

@no_reu:
        lda #<reu_not_found_msg
        ldy #>reu_not_found_msg
        jsr print_string
        rts

; =============================================================================
; reu_detect - detect REU presence and size using prog8reu method
; Sets: reu_present (0/1), reu_banks (number of 64KB banks - 1)
; Based on prog8reu by Andrew Gillham
; =============================================================================
reu_detect:
        ; Phase 1: Write signature to each bank (255 down to 0)
        ; signature[0] = bank number, rest = "prog8reu"
        lda #255
        sta reu_test_bank

@write_loop:
        ; Set signature[0] to current bank number
        lda reu_test_bank
        sta reu_signature

        ; Stash signature to REU bank
        jsr reu_cmd_stash_sig

        ; Decrement and continue
        dec reu_test_bank
        lda reu_test_bank
        cmp #$ff                ; wrapped from 0 to 255?
        bne @write_loop

        ; Phase 2: Read back from each bank (0 to 255) and verify
        lda #0
        sta reu_test_bank
        sta reu_present

@read_loop:
        ; Set expected signature[0]
        lda reu_test_bank
        sta reu_signature

        ; Clear xsignature buffer
        ldx #0
        lda #'X'
@clear_xsig:
        sta reu_xsignature,x
        inx
        cpx #9
        bne @clear_xsig

        ; Fetch from REU into xsignature
        jsr reu_cmd_fetch_sig

        ; Compare signature with xsignature
        ldx #0
@compare:
        lda reu_signature,x
        cmp reu_xsignature,x
        bne @mismatch
        inx
        cpx #9
        bne @compare

        ; Match found - REU is present
        lda #1
        sta reu_present

        ; Continue to next bank
        inc reu_test_bank
        beq @all_banks_ok       ; wrapped = all 256 banks exist
        jmp @read_loop

@mismatch:
        ; Bank didn't match - we've found the limit
        ; reu_banks = reu_test_bank - 1
        lda reu_test_bank
        sec
        sbc #1
        sta reu_banks
        rts

@all_banks_ok:
        ; All 256 banks verified - store 0 (means 256)
        lda #0
        sta reu_banks
        rts

; =============================================================================
; reu_cmd_stash_sig - stash signature buffer to REU
; =============================================================================
reu_cmd_stash_sig:
        lda #<reu_signature
        sta $df02               ; C64 address low
        lda #>reu_signature
        sta $df03               ; C64 address high

        lda #0
        sta $df04               ; REU address low
        sta $df05               ; REU address high
        lda reu_test_bank
        sta $df06               ; REU bank

        lda #9                  ; length = 9 bytes
        sta $df07
        lda #0
        sta $df08
        sta $df0a               ; address control

        lda #$90                ; stash with execute
        sta $df01
        rts

; =============================================================================
; reu_cmd_fetch_sig - fetch from REU into xsignature buffer
; =============================================================================
reu_cmd_fetch_sig:
        lda #<reu_xsignature
        sta $df02               ; C64 address low
        lda #>reu_xsignature
        sta $df03               ; C64 address high

        lda #0
        sta $df04               ; REU address low
        sta $df05               ; REU address high
        lda reu_test_bank
        sta $df06               ; REU bank

        lda #9                  ; length = 9 bytes
        sta $df07
        lda #0
        sta $df08
        sta $df0a               ; address control

        lda #$91                ; fetch with execute
        sta $df01
        rts

; Signature buffers for REU detection
reu_signature:
        .byte 0                 ; bank number goes here
        .byte "prog8reu"        ; 8 more bytes

reu_xsignature:
        .res 9, 0                ; buffer for fetched data

reu_test_bank:
        .byte 0

reu_banks:
        .byte 0                 ; number of banks - 1 (0 means 256)
