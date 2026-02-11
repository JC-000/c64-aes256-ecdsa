; =============================================================================
; aes256keygen.asm - aes-256 iv and key generator for commodore 64
; uses sid-based 16-bit lfsr prng
; assembles with acme cross-assembler
; =============================================================================
; for demonstration purposes only - not cryptographically secure
; =============================================================================
; controls:
;   1 - display the stored 256-bit encryption key
;   2 - input text and encrypt it with aes-256
;   3 - display the encrypted output
;   q - quit program
; =============================================================================

        !cpu 6502
        !to "aes256keygen.prg", cbm    ; output as c64 prg file

; =============================================================================
; c64 system equates
; =============================================================================
chrout          = $ffd2         ; kernal: output character
getin           = $ffe4         ; kernal: get character from keyboard
chrin           = $ffcf         ; kernal: input character
clrscr          = $e544         ; basic rom: clear screen

; kernal disk i/o routines
setlfs          = $ffba         ; set logical file parameters
setnam          = $ffbd         ; set filename
open            = $ffc0         ; open logical file
close           = $ffc3         ; close logical file
chkin           = $ffc6         ; set input channel
chkout          = $ffc9         ; set output channel
clrchn          = $ffcc         ; clear i/o channels
chrin           = $ffcf         ; input character
readst          = $ffb7         ; read i/o status
load            = $ffd5         ; load file
save            = $ffd8         ; save file

; REU (Ram Expansion Unit) registers at $DF00
reu_status      = $df00         ; status register
reu_command     = $df01         ; command register
reu_c64_lo      = $df02         ; C64 base address low
reu_c64_hi      = $df03         ; C64 base address high
reu_reu_lo      = $df04         ; REU base address low
reu_reu_hi      = $df05         ; REU base address high
reu_reu_bank    = $df06         ; REU bank
reu_xfer_lo     = $df07         ; transfer length low
reu_xfer_hi     = $df08         ; transfer length high
reu_irq_mask    = $df09         ; interrupt mask
reu_addr_ctrl   = $df0a         ; address control

; REU commands
reu_cmd_stash   = $90           ; C64 -> REU (with execute)
reu_cmd_fetch   = $91           ; REU -> C64 (with execute)
reu_cmd_swap    = $92           ; swap C64 <-> REU
reu_cmd_verify  = $93           ; verify C64 vs REU

; sid chip registers
sid_v3_freq_lo  = $d40e         ; voice 3 frequency low byte
sid_v3_freq_hi  = $d40f         ; voice 3 frequency high byte
sid_v3_ctrl     = $d412         ; voice 3 control register
sid_volume      = $d418         ; volume and filter modes
sid_osc3        = $d41b         ; voice 3 oscillator output (random)

; CIA 1 registers for entropy
cia1_ta_lo      = $dc04         ; timer A low byte
cia1_ta_hi      = $dc05         ; timer A high byte
cia1_tb_lo      = $dc06         ; timer B low byte
cia1_tb_hi      = $dc07         ; timer B high byte

; zero page variables
zp_ptr          = $fb           ; 2-byte pointer
zp_temp         = $fd           ; temp storage
zp_count        = $fe           ; loop counter
zp_ptr2         = $02           ; second pointer (2 bytes)
zp_round        = $04           ; aes round counter
zp_col          = $05           ; aes column counter
zp_tmp1         = $06           ; aes temp
zp_tmp2         = $07           ; aes temp
zp_tmp3         = $08           ; aes temp
zp_tmp4         = $09           ; aes temp
kbd_buffer      = $c6           ; keyboard buffer count

; petscii codes
petscii_1       = $31           ; '1' key
petscii_2       = $32           ; '2' key
petscii_3       = $33           ; '3' key
petscii_4       = $34           ; '4' key
petscii_5       = $35           ; '5' key
petscii_6       = $36           ; '6' key
petscii_7       = $37           ; '7' key
petscii_8       = $38           ; '8' key
petscii_9       = $39           ; '9' key
petscii_a       = $41           ; 'A' key
petscii_b       = $42           ; 'B' key
petscii_c       = $43           ; 'C' key
petscii_d       = $44           ; 'D' key
petscii_e       = $45           ; 'E' key (benchmark)
petscii_f       = $46           ; 'F' key (NIST test vectors)
petscii_g       = $47           ; 'G' key (show REU status)
petscii_h       = $48           ; 'H' key (random hex stream)
petscii_i       = $49           ; 'I' key (configure SID chips)
petscii_j       = $4a           ; 'J' key (generate CSR)
petscii_q       = $51           ; 'q' key
petscii_return  = $0d           ; return key

; aes constants
aes_block_size  = 16            ; 128 bits = 16 bytes
aes_key_size    = 32            ; 256 bits = 32 bytes
aes_rounds      = 14            ; aes-256 uses 14 rounds
aes_expanded_key_size = 240     ; (14+1) * 16 = 240 bytes

; buffer sizes
input_buf_size  = 64            ; max input text size
encrypt_buf_size = 80           ; encrypted output size (input + up to 16 pad)

; =============================================================================
; program start at $0801 with basic stub
; =============================================================================
        * = $0801

; basic stub: 10 sys 2064
basic_stub:
        !word basic_end         ; pointer to next basic line
        !word 10                ; line number 10
        !byte $9e               ; sys token
        !text "2064"            ; address as ascii
        !byte 0                 ; end of line
basic_end:
        !word 0                 ; end of basic program

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
        
        ; seed the lfsr from sid noise
        jsr seed_lfsr
        
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
        jsr generate_bytes
        
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
        jsr generate_bytes
        
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

; =============================================================================
; main_loop - wait for keypress and handle commands
; =============================================================================
main_loop:
        ; clear keyboard buffer
        lda #0
        sta kbd_buffer
        
@wait_key:
        jsr getin               ; get key from buffer
        beq @wait_key           ; no key, keep waiting
        
        ; check for '1' - display key
        cmp #petscii_1
        beq @show_key
        
        ; check for '2' - encrypt text
        cmp #petscii_2
        beq @encrypt_text
        
        ; check for '3' - show encrypted
        cmp #petscii_3
        beq @show_encrypted
        
        ; check for '4' - decrypt and show
        cmp #petscii_4
        beq @decrypt_text
        
        ; check for '5' - save key to disk
        cmp #petscii_5
        beq @save_key
        
        ; check for '6' - load key from disk
        cmp #petscii_6
        beq @load_key
        
        ; check for '7' - save encrypted text to disk
        cmp #petscii_7
        beq @save_encrypted
        
        ; check for '8' - load encrypted text from disk
        cmp #petscii_8
        beq @load_encrypted
        
        ; check for '9' - calculate SHA-256 hash
        cmp #petscii_9
        beq @calc_hash
        
        ; check for 'A' - encrypt with GCM-SIV
        cmp #petscii_a
        beq @gcm_siv_encrypt
        
        ; check for 'B' - decrypt with GCM-SIV
        cmp #petscii_b
        beq @gcm_siv_decrypt
        
        ; check for 'C' - save GCM-SIV to disk
        cmp #petscii_c
        beq @save_gcm_siv
        
        ; check for 'D' - load GCM-SIV from disk
        cmp #petscii_d
        beq @load_gcm_siv
        
        ; check for 'E' - benchmark
        cmp #petscii_e
        beq @benchmark
        
        ; check for 'F' - load NIST test vectors
        cmp #petscii_f
        beq @load_nist
        
        ; check for 'G' - show REU status
        cmp #petscii_g
        beq @show_reu
        
        ; check for 'H' - random hex stream
        cmp #petscii_h
        beq @random_stream
        
        ; check for 'I' - configure SID chips
        cmp #petscii_i
        beq @config_sid
        
        ; check for 'J' - generate CSR
        cmp #petscii_j
        beq @generate_csr
        
        ; check for 'q' or 'Q' - quit
        cmp #petscii_q          ; uppercase Q
        beq @quit
        cmp #$71                ; lowercase q (shifted)
        beq @quit
        
        ; unknown key, keep waiting
        jmp @wait_key
        
@show_key:
        jsr display_key_only
        jmp main_loop
        
@encrypt_text:
        jsr do_encrypt_text
        jmp main_loop
        
@show_encrypted:
        jsr display_encrypted
        jmp main_loop
        
@decrypt_text:
        jsr do_decrypt_text
        jmp main_loop
        
@save_key:
        jsr do_save_key
        jmp main_loop
        
@load_key:
        jsr do_load_key
        jmp main_loop
        
@save_encrypted:
        jsr do_save_encrypted
        jmp main_loop
        
@load_encrypted:
        jsr do_load_encrypted
        jmp main_loop
        
@calc_hash:
        jsr do_calc_sha256
        jmp main_loop
        
@gcm_siv_encrypt:
        jsr do_gcm_siv_encrypt
        jmp main_loop
        
@gcm_siv_decrypt:
        jsr do_gcm_siv_decrypt
        jmp main_loop
        
@save_gcm_siv:
        jsr do_save_gcm_siv
        jmp main_loop
        
@load_gcm_siv:
        jsr do_load_gcm_siv
        jmp main_loop
        
@benchmark:
        jsr do_benchmark
        jmp main_loop
        
@load_nist:
        jsr do_load_nist_vectors
        jmp main_loop
        
@show_reu:
        jsr do_show_reu_status
        jmp main_loop
        
@random_stream:
        jsr do_random_stream
        jmp main_loop
        
@config_sid:
        jsr do_config_sid
        jmp main_loop
        
@generate_csr:
        jsr do_generate_csr
        jmp main_loop
        
@quit:
        ; cleanup and exit
        jsr cleanup
        rts                     ; return to basic

; =============================================================================
; cleanup - turn off sid and print exit message
; =============================================================================
cleanup:
        lda #0
        sta sid_volume
        
        lda #<exit_msg
        ldy #>exit_msg
        jsr print_string
        rts

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
        !byte 0                 ; bank number goes here
        !text "prog8reu"        ; 8 more bytes

reu_xsignature:
        !fill 9, 0              ; buffer for fetched data

reu_test_bank:
        !byte 0

reu_banks:
        !byte 0                 ; number of banks - 1 (0 means 256)

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

; =============================================================================
; do_save_key - save the AES key to disk
; =============================================================================
do_save_key:
        lda #$0d
        jsr chrout
        
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        ; parse drive number from input
        lda filename_buf
        sec
        sbc #$30                ; convert ascii to number
        cmp #10                 ; valid digit?
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        ; print selected drive
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<filename_prompt_msg
        ldy #>filename_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        ; copy user filename
        jsr copy_input_to_filename
        lda #0                  ; user specified name
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        ; use default "AESKEY"
        jsr set_default_filename
        lda #1                  ; using default
        sta using_default_name
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        beq @do_save            ; file doesn't exist, proceed
        
        ; file exists - handle it
        lda #<file_exists_msg
        ldy #>file_exists_msg
        jsr print_string
        
        lda using_default_name
        beq @prompt_new_name
        
        ; using default name, increment it
        jsr increment_filename
        bcs @names_exhausted    ; carry set = no more names to try
        
        lda #<incremented_msg
        ldy #>incremented_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @got_filename       ; check again

@names_exhausted:
        lda #<names_exhausted_msg
        ldy #>names_exhausted_msg
        jsr print_string
        jmp @done
        
@prompt_new_name:
        lda #<enter_new_name_msg
        ldy #>enter_new_name_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @do_save            ; no input, overwrite
        jsr copy_input_to_filename
        jmp @got_filename       ; check again
        
@do_save:
        ; --- print key being saved ---
        lda #<saving_key_msg
        ldy #>saving_key_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        lda #<key_value_msg
        ldy #>key_value_msg
        jsr print_string
        
        ; display key bytes
        lda #<key_data
        sta zp_ptr
        lda #>key_data
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; --- save the key to disk ---
        jsr save_key_to_disk
        bcs @save_error
        
        lda #<save_success_msg
        ldy #>save_success_msg
        jsr print_string
        
        ; --- read key back and display ---
        lda #<reading_back_msg
        ldy #>reading_back_msg
        jsr print_string
        
        jsr read_key_from_disk
        bcs @read_error
        
        ; display read key
        lda #<key_read_msg
        ldy #>key_read_msg
        jsr print_string
        
        lda #<key_read_buf
        sta zp_ptr
        lda #>key_read_buf
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; verify match
        jsr verify_key_match
        bcc @verified
        
        lda #<verify_fail_msg
        ldy #>verify_fail_msg
        jsr print_string
        jmp @done
        
@verified:
        lda #<verify_ok_msg
        ldy #>verify_ok_msg
        jsr print_string
        jmp @done
        
@save_error:
        lda #<save_error_msg
        ldy #>save_error_msg
        jsr print_string
        jmp @done
        
@read_error:
        lda #<read_error_msg
        ldy #>read_error_msg
        jsr print_string
        
@done:
        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; do_load_key - load an AES key from disk
; =============================================================================
do_load_key:
        lda #$0d
        jsr chrout
        
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        ; parse drive number from input
        lda filename_buf
        sec
        sbc #$30                ; convert ascii to number
        cmp #10                 ; valid digit?
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        ; print selected drive
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<load_filename_prompt_msg
        ldy #>load_filename_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        ; copy user filename
        jsr copy_input_to_filename
        lda #0                  ; user specified name
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        ; use default "AESKEY"
        jsr set_default_filename
        lda #1                  ; using default
        sta using_default_name
        
        ; notify user we're using default
        lda #<loading_default_msg
        ldy #>loading_default_msg
        jsr print_string
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        bne @do_load            ; file exists, proceed
        
        ; file doesn't exist
        lda #<file_not_found_msg
        ldy #>file_not_found_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @done
        
@do_load:
        ; --- print loading message ---
        lda #<loading_key_msg
        ldy #>loading_key_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        ; --- read the key from disk ---
        jsr read_key_from_disk
        bcs @load_error
        
        ; --- display the loaded key ---
        lda #<key_loaded_msg
        ldy #>key_loaded_msg
        jsr print_string
        
        lda #<key_read_buf
        sta zp_ptr
        lda #>key_read_buf
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; --- copy loaded key to key_data for use ---
        ldx #0
@copy_key:
        lda key_read_buf,x
        sta key_data,x
        inx
        cpx #32
        bne @copy_key
        
        ; --- re-expand the key for AES ---
        lda #<reexpanding_msg
        ldy #>reexpanding_msg
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
        
        lda #<load_success_msg
        ldy #>load_success_msg
        jsr print_string
        jmp @done
        
@load_error:
        lda #<load_error_msg
        ldy #>load_error_msg
        jsr print_string
        
@done:
        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; do_save_encrypted - save encrypted text to disk
; =============================================================================
do_save_encrypted:
        lda #$0d
        jsr chrout
        
        ; check if there's encrypted data
        lda encrypt_length
        bne @has_data
        
        lda #<no_encrypted_msg
        ldy #>no_encrypted_msg
        jsr print_string
        rts
        
@has_data:
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        ; parse drive number from input
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<msg_filename_prompt_msg
        ldy #>msg_filename_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        ; copy user filename
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        jsr set_default_msg_filename
        lda #1
        sta using_default_name
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        beq @do_save
        
        ; file exists
        lda #<file_exists_msg
        ldy #>file_exists_msg
        jsr print_string
        
        lda using_default_name
        beq @prompt_new_name
        
        ; using default name, increment it
        jsr increment_msg_filename
        bcs @names_exhausted
        
        lda #<incremented_msg
        ldy #>incremented_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @got_filename

@names_exhausted:
        lda #<names_exhausted_msg
        ldy #>names_exhausted_msg
        jsr print_string
        jmp @done
        
@prompt_new_name:
        lda #<enter_new_name_msg
        ldy #>enter_new_name_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @do_save
        jsr copy_input_to_filename
        jmp @got_filename
        
@do_save:
        ; --- print IV being saved ---
        lda #<saving_msg_msg
        ldy #>saving_msg_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        lda #<saving_iv_msg
        ldy #>saving_iv_msg
        jsr print_string
        
        ; display IV
        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #8
        jsr display_hex_block
        
        lda #<enc_value_msg
        ldy #>enc_value_msg
        jsr print_string
        
        ; display encrypted bytes
        lda #<encrypt_buffer
        sta zp_ptr
        lda #>encrypt_buffer
        sta zp_ptr+1
        lda encrypt_length
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; --- save to disk ---
        jsr save_encrypted_to_disk
        bcs @save_error
        
        lda #<save_success_msg
        ldy #>save_success_msg
        jsr print_string
        
        ; --- read back and display ---
        lda #<reading_enc_back_msg
        ldy #>reading_enc_back_msg
        jsr print_string
        
        jsr read_encrypted_with_iv_from_disk
        bcs @read_error
        
        ; display IV read back
        lda #<iv_read_back_msg
        ldy #>iv_read_back_msg
        jsr print_string
        
        lda #<iv_read_buf
        sta zp_ptr
        lda #>iv_read_buf
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; display encrypted data read back
        lda #<enc_read_msg
        ldy #>enc_read_msg
        jsr print_string
        
        lda #<enc_read_buf
        sta zp_ptr
        lda #>enc_read_buf
        sta zp_ptr+1
        lda enc_read_length
        sta zp_count
        lda #8
        jsr display_hex_block
        
        jmp @done
        
@save_error:
        lda #<save_error_msg
        ldy #>save_error_msg
        jsr print_string
        jmp @done
        
@read_error:
        lda #<read_error_msg
        ldy #>read_error_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; set_default_msg_filename - set filename to "AESMSG"
; =============================================================================
set_default_msg_filename:
        ldx #0
@loop:
        lda default_msg_filename,x
        sta actual_filename,x
        beq @done
        inx
        cpx #7
        bne @loop
@done:
        lda #0
        sta actual_filename,x
        lda #6
        sta filename_len
        lda #0
        sta msg_filename_suffix
        rts

; =============================================================================
; increment_msg_filename - increment the numeric suffix for msg files
; returns: carry set if exhausted (reached 9)
; =============================================================================
increment_msg_filename:
        lda msg_filename_suffix
        cmp #10
        bcs @exhausted
        
        inc msg_filename_suffix
        lda msg_filename_suffix
        
        clc
        adc #$2F
        ldx #6
        sta actual_filename,x
        lda #0
        sta actual_filename+7
        lda #7
        sta filename_len
        
        clc
        rts
        
@exhausted:
        sec
        rts

; =============================================================================
; save_encrypted_to_disk - save encrypted buffer to disk as hex
; returns: carry clear = success, carry set = error
; =============================================================================
save_encrypted_to_disk:
        jsr build_write_filename
        
        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam
        
        lda #3
        ldx drive_number
        ldy #3
        jsr setlfs
        
        jsr open
        bcc @open_ok
        jmp @error
@open_ok:
        
        ldx #3
        jsr chkout
        bcc @chkout_ok
        jmp @close_error
@chkout_ok:
        
        ; first write the IV (16 bytes) as hex
        lda #0
        sta save_byte_index
        
@write_iv_loop:
        ldx save_byte_index
        cpx #16
        beq @iv_done
        
        lda iv_data,x
        
        ; write high nibble
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        
        ; write low nibble
        pla
        and #$0f
        jsr write_hex_digit
        
        ; write space
        lda #$20
        jsr chrout
        
        inc save_byte_index
        jmp @write_iv_loop
        
@iv_done:
        ; write newline after IV
        lda #$0d
        jsr chrout
        
        ; now write encrypted bytes as hex
        lda #0
        sta save_byte_index
        
@write_loop:
        ldx save_byte_index
        cpx encrypt_length
        beq @write_done
        
        lda encrypt_buffer,x
        
        ; write high nibble
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        
        ; write low nibble
        pla
        and #$0f
        jsr write_hex_digit
        
        ; write space
        lda #$20
        jsr chrout
        
        ; newline every 8 bytes
        lda save_byte_index
        and #$07
        cmp #$07
        bne @no_newline
        lda #$0d
        jsr chrout
@no_newline:
        
        inc save_byte_index
        jmp @write_loop
        
@write_done:
        jsr readst
        bne @close_error
        
        jsr clrchn
        lda #3
        jsr close
        
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #3
        jsr close
@error:
        sec
        rts

; =============================================================================
; read_encrypted_with_iv_from_disk - read IV and encrypted data, store IV in iv_read_buf
; returns: carry clear = success, carry set = error
; =============================================================================
read_encrypted_with_iv_from_disk:
        jsr build_read_filename
        
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        lda #4
        ldx drive_number
        ldy #4
        jsr setlfs
        
        jsr open
        bcs @error
        
        ldx #4
        jsr chkin
        bcs @close_error
        
        ; first read the IV (16 bytes) into iv_read_buf
        lda #0
        sta read_byte_index
        
@read_iv_loop:
        lda read_byte_index
        cmp #16
        beq @iv_done
        
        ; read high nibble
        jsr read_hex_char
        bcs @close_error
        asl
        asl
        asl
        asl
        sta read_temp_byte
        
        ; read low nibble
        jsr read_hex_char
        bcs @close_error
        ora read_temp_byte
        
        ; store in iv_read_buf
        ldx read_byte_index
        sta iv_read_buf,x
        
        inc read_byte_index
        jmp @read_iv_loop
        
@iv_done:
        ; now read encrypted data into enc_read_buf
        lda #0
        sta read_byte_index
        sta enc_read_length
        
@read_loop:
        lda read_byte_index
        cmp #64
        bcs @read_done
        
        jsr read_hex_char
        bcs @read_done
        asl
        asl
        asl
        asl
        sta read_temp_byte
        
        jsr read_hex_char
        bcs @read_done
        ora read_temp_byte
        
        ldx read_byte_index
        sta enc_read_buf,x
        
        inc read_byte_index
        inc enc_read_length
        jmp @read_loop
        
@read_done:
        jsr clrchn
        lda #4
        jsr close
        
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec
        rts

; =============================================================================
; read_encrypted_from_disk - read encrypted data from disk
; returns: carry clear = success, carry set = error
; =============================================================================
read_encrypted_from_disk:
        jsr build_read_filename
        
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        lda #4
        ldx drive_number
        ldy #4
        jsr setlfs
        
        jsr open
        bcs @error
        
        ldx #4
        jsr chkin
        bcs @close_error
        
        ; first skip the IV (16 bytes = 32 hex chars + spaces)
        lda #0
        sta read_byte_index
        
@skip_iv_loop:
        lda read_byte_index
        cmp #16
        beq @iv_skipped
        
        ; read and discard high nibble
        jsr read_hex_char
        bcs @close_error
        
        ; read and discard low nibble
        jsr read_hex_char
        bcs @close_error
        
        inc read_byte_index
        jmp @skip_iv_loop
        
@iv_skipped:
        ; now read encrypted data
        lda #0
        sta read_byte_index
        sta enc_read_length
        
@read_loop:
        ; check if buffer full
        lda read_byte_index
        cmp #64                 ; max buffer size
        bcs @read_done
        
        ; read high nibble
        jsr read_hex_char
        bcs @read_done          ; EOF or error
        asl
        asl
        asl
        asl
        sta read_temp_byte
        
        ; read low nibble
        jsr read_hex_char
        bcs @read_done
        ora read_temp_byte
        
        ; store byte
        ldx read_byte_index
        sta enc_read_buf,x
        
        inc read_byte_index
        inc enc_read_length
        jmp @read_loop
        
@read_done:
        jsr clrchn
        lda #4
        jsr close
        
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec
        rts

; =============================================================================
; do_load_encrypted - load encrypted text from disk
; =============================================================================
do_load_encrypted:
        lda #$0d
        jsr chrout
        
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        ; parse drive number from input
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<load_msg_filename_prompt
        ldy #>load_msg_filename_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        ; copy user filename
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        jsr set_default_msg_filename
        lda #1
        sta using_default_name
        
        ; notify user we're using default
        lda #<loading_default_msg_msg
        ldy #>loading_default_msg_msg
        jsr print_string
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        bne @do_load
        
        ; file doesn't exist
        lda #<file_not_found_msg
        ldy #>file_not_found_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @done
        
@do_load:
        ; --- print loading message ---
        lda #<loading_enc_msg
        ldy #>loading_enc_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        ; --- read encrypted data from disk ---
        jsr load_encrypted_from_disk
        bcs @load_error
        
        ; --- display the loaded IV ---
        lda #<loaded_iv_msg
        ldy #>loaded_iv_msg
        jsr print_string
        
        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; --- display the loaded encrypted data ---
        lda #<enc_loaded_msg
        ldy #>enc_loaded_msg
        jsr print_string
        
        lda #<encrypt_buffer
        sta zp_ptr
        lda #>encrypt_buffer
        sta zp_ptr+1
        lda encrypt_length
        sta zp_count
        lda #8
        jsr display_hex_block
        
        lda #<enc_load_success_msg
        ldy #>enc_load_success_msg
        jsr print_string
        jmp @done
        
@load_error:
        lda #<enc_load_error_msg
        ldy #>enc_load_error_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; load_encrypted_from_disk - read encrypted data into encrypt_buffer
; returns: carry clear = success, carry set = error
; =============================================================================
load_encrypted_from_disk:
        jsr build_read_filename
        
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        lda #4
        ldx drive_number
        ldy #4
        jsr setlfs
        
        jsr open
        bcs @error
        
        ldx #4
        jsr chkin
        bcs @close_error
        
        ; first read the IV (16 bytes)
        lda #0
        sta read_byte_index
        
@read_iv_loop:
        lda read_byte_index
        cmp #16
        beq @iv_done
        
        ; read high nibble
        jsr read_hex_char
        bcs @close_error        ; EOF or error - file format wrong
        asl
        asl
        asl
        asl
        sta read_temp_byte
        
        ; read low nibble
        jsr read_hex_char
        bcs @close_error
        ora read_temp_byte
        
        ; store byte in iv_data
        ldx read_byte_index
        sta iv_data,x
        
        inc read_byte_index
        jmp @read_iv_loop
        
@iv_done:
        ; now read encrypted data into encrypt_buffer
        lda #0
        sta read_byte_index
        sta encrypt_length
        
@read_loop:
        ; check if buffer full
        lda read_byte_index
        cmp #64                 ; max buffer size
        bcs @read_done
        
        ; read high nibble
        jsr read_hex_char
        bcs @read_done          ; EOF or error
        asl
        asl
        asl
        asl
        sta read_temp_byte
        
        ; read low nibble
        jsr read_hex_char
        bcs @read_done
        ora read_temp_byte
        
        ; store byte in encrypt_buffer
        ldx read_byte_index
        sta encrypt_buffer,x
        
        inc read_byte_index
        inc encrypt_length
        jmp @read_loop
        
@read_done:
        jsr clrchn
        lda #4
        jsr close
        
        ; check we got at least some data
        lda encrypt_length
        beq @error
        
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec
        rts

; =============================================================================
; get_input_line - get a line of input into filename_buf
; =============================================================================
get_input_line:
        lda #0
        sta input_index
        
        ldx #0
@clear:
        sta filename_buf,x
        inx
        cpx #17
        bne @clear
        
@loop:
        jsr getin
        beq @loop
        
        cmp #petscii_return
        beq @done
        
        cmp #$14                ; delete
        beq @delete
        
        ldx input_index
        cpx #16                 ; max 16 chars
        bcs @loop
        
        sta filename_buf,x
        inc input_index
        jsr chrout
        jmp @loop
        
@delete:
        ldx input_index
        beq @loop
        dex
        stx input_index
        lda #0
        sta filename_buf,x
        lda #$14
        jsr chrout
        jmp @loop
        
@done:
        lda #$0d
        jsr chrout
        rts

; =============================================================================
; copy_input_to_filename - copy filename_buf to actual_filename
; =============================================================================
copy_input_to_filename:
        ldx #0
@loop:
        lda filename_buf,x
        beq @done
        sta actual_filename,x
        inx
        cpx #16
        bne @loop
@done:
        stx filename_len
        rts

; =============================================================================
; set_default_filename - set filename to "AESKEY"
; =============================================================================
set_default_filename:
        ; copy "AESKEY" to actual_filename
        ldx #0
@loop:
        lda default_filename,x
        sta actual_filename,x
        beq @done               ; stop at null terminator
        inx
        cpx #7
        bne @loop
@done:
        lda #0
        sta actual_filename,x   ; ensure null terminated
        lda #6
        sta filename_len
        lda #0
        sta filename_suffix     ; reset suffix counter
        rts

; =============================================================================
; increment_filename - increment the numeric suffix
; returns: carry set if we've exhausted all options (reached 9)
; =============================================================================
increment_filename:
        ; check if we've already tried 9
        lda filename_suffix
        cmp #10
        bcs @exhausted          ; already at max
        
        inc filename_suffix
        lda filename_suffix
        
        ; add digit to filename at position 6 (after "AESKEY")
        clc
        adc #$2F                ; convert 1-10 to '0'-'9' (adc #$30 - 1 since we inc'd)
        ldx #6
        sta actual_filename,x
        lda #0
        sta actual_filename+7   ; null terminate
        lda #7
        sta filename_len
        
        clc                     ; success, can try this name
        rts
        
@exhausted:
        sec                     ; no more options
        rts

; =============================================================================
; print_filename - print the current filename
; =============================================================================
print_filename:
        ldx #0
@loop:
        lda actual_filename,x
        beq @done
        jsr chrout
        inx
        cpx #16
        bne @loop
@done:
        rts

; =============================================================================
; check_file_exists - check if file already exists on disk
; sets file_exists_flag (0 = no, 1 = yes)
; uses the command channel to check for file
; =============================================================================
check_file_exists:
        lda #0
        sta file_exists_flag
        
        ; try to open the file for reading
        ; if it opens successfully, file exists
        ; build filename: "0:filename,s,r"
        jsr build_read_filename
        
        ; set filename
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        ; set logical file
        lda #2                  ; logical file 2
        ldx drive_number
        ldy #2                  ; secondary address 2
        jsr setlfs
        
        ; try to open
        jsr open
        bcs @not_found          ; open failed, file doesn't exist
        
        ; check the error channel
        jsr check_disk_error
        bcs @close_not_found    ; error means file not found
        
        ; file opened successfully, it exists
        lda #1
        sta file_exists_flag
        
@close_not_found:
        ; close the file
        jsr clrchn
        lda #2
        jsr close
        rts
        
@not_found:
        ; file doesn't exist
        lda #0
        sta file_exists_flag
        rts

; =============================================================================
; check_disk_error - read error channel, return carry set if error
; =============================================================================
check_disk_error:
        ; open command channel (15)
        lda #0                  ; no filename
        ldx #<cmd_buffer
        ldy #>cmd_buffer
        jsr setnam
        
        lda #15                 ; logical file 15
        ldx drive_number
        ldy #15                 ; command channel
        jsr setlfs
        
        jsr open
        bcs @error
        
        ; read from command channel
        ldx #15
        jsr chkin
        bcs @close_error
        
        ; read first character (error number tens digit)
        jsr chrin
        sta disk_error_code
        
        ; read second character (error number ones digit)  
        jsr chrin
        sta disk_error_code+1
        
        ; clear channel and close
        jsr clrchn
        lda #15
        jsr close
        
        ; check if error code is "00" (no error)
        lda disk_error_code
        cmp #$30                ; '0'
        bne @is_error
        lda disk_error_code+1
        cmp #$30                ; '0'
        bne @is_error
        
        ; no error
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #15
        jsr close
@error:
@is_error:
        sec
        rts

; =============================================================================
; save_key_to_disk - save 32-byte key to disk
; returns: carry clear = success, carry set = error
; =============================================================================
save_key_to_disk:
        ; build full filename with drive: "0:filename,s,w"
        jsr build_write_filename
        
        ; set filename
        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam
        
        ; set logical file
        lda #3                  ; logical file 3
        ldx drive_number
        ldy #3                  ; secondary address 3
        jsr setlfs
        
        ; open file
        jsr open
        bcs @error
        
        ; set output channel
        ldx #3
        jsr chkout
        bcs @close_error
        
        ; write 32 key bytes as hex (64 hex chars + spaces + newlines)
        lda #0
        sta save_byte_index
        
@write_loop:
        ldx save_byte_index
        lda key_data,x
        
        ; write high nibble
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        
        ; write low nibble
        pla
        and #$0f
        jsr write_hex_digit
        
        ; write space
        lda #$20
        jsr chrout
        
        ; check for newline every 8 bytes
        lda save_byte_index
        and #$07
        cmp #$07
        bne @no_newline
        lda #$0d
        jsr chrout
@no_newline:
        
        inc save_byte_index
        lda save_byte_index
        cmp #32
        bne @write_loop
        
        ; check status
        jsr readst
        bne @close_error
        
        ; close file
        jsr clrchn
        lda #3
        jsr close
        
        clc                     ; success
        rts
        
@close_error:
        jsr clrchn
        lda #3
        jsr close
@error:
        sec                     ; error
        rts

; =============================================================================
; write_hex_digit - write a hex digit (0-15) to output channel
; input: A = value 0-15
; =============================================================================
write_hex_digit:
        cmp #10
        bcc @digit
        ; A-F
        clc
        adc #($41 - 10)         ; 'A' - 10
        jmp chrout
@digit:
        ; 0-9
        clc
        adc #$30                ; '0'
        jmp chrout

; =============================================================================
; read_key_from_disk - read 32-byte key from disk
; returns: carry clear = success, carry set = error
; =============================================================================
read_key_from_disk:
        ; build full filename with drive: "0:filename,s,r"
        jsr build_read_filename
        
        ; set filename
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        ; set logical file
        lda #4                  ; logical file 4
        ldx drive_number
        ldy #4                  ; secondary address
        jsr setlfs
        
        ; open file
        jsr open
        bcs @error
        
        ; set input channel
        ldx #4
        jsr chkin
        bcs @close_error
        
        ; read hex text and convert to 32 bytes
        lda #0
        sta read_byte_index
        
@read_loop:
        ; read high nibble character
        jsr read_hex_char
        bcs @close_error        ; error or EOF
        asl
        asl
        asl
        asl
        sta read_temp_byte      ; store high nibble shifted
        
        ; read low nibble character
        jsr read_hex_char
        bcs @close_error
        ora read_temp_byte      ; combine with high nibble
        
        ; store the byte
        ldx read_byte_index
        sta key_read_buf,x
        
        inc read_byte_index
        lda read_byte_index
        cmp #32
        bne @read_loop
        
        ; close file
        jsr clrchn
        lda #4
        jsr close
        
        clc                     ; success
        rts
        
@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec                     ; error
        rts

; =============================================================================
; read_hex_char - read next hex character, skipping spaces/newlines
; returns: A = value 0-15, carry clear on success
;          carry set on error/EOF
; =============================================================================
read_hex_char:
@skip_loop:
        jsr chrin
        pha
        jsr readst
        and #$40                ; EOF?
        bne @eof
        pla
        
        ; skip spaces, newlines, carriage returns
        cmp #$20                ; space
        beq @skip_loop
        cmp #$0d                ; carriage return
        beq @skip_loop
        cmp #$0a                ; line feed
        beq @skip_loop
        
        ; convert hex char to value
        cmp #$30                ; '0'
        bcc @invalid
        cmp #$3a                ; '9' + 1
        bcc @is_digit
        
        ; check for A-F (uppercase)
        cmp #$41                ; 'A'
        bcc @invalid
        cmp #$47                ; 'F' + 1
        bcc @is_upper
        
        ; check for a-f (lowercase)
        cmp #$61                ; 'a'
        bcc @invalid
        cmp #$67                ; 'f' + 1
        bcs @invalid
        
        ; lowercase a-f
        sec
        sbc #($61 - 10)         ; convert 'a'-'f' to 10-15
        clc
        rts
        
@is_upper:
        ; uppercase A-F
        sec
        sbc #($41 - 10)         ; convert 'A'-'F' to 10-15
        clc
        rts
        
@is_digit:
        ; 0-9
        sec
        sbc #$30                ; convert '0'-'9' to 0-9
        clc
        rts
        
@eof:
        pla
@invalid:
        sec
        rts

; =============================================================================
; build_write_filename - build "0:filename,s,w" in write_fname_buf
; =============================================================================
build_write_filename:
        lda #$30                ; '0'
        sta write_fname_buf
        lda #$3a                ; ':'
        sta write_fname_buf+1
        
        ldx #0
@copy:
        lda actual_filename,x
        beq @add_suffix
        sta write_fname_buf+2,x
        inx
        cpx #16
        bne @copy
        
@add_suffix:
        txa
        clc
        adc #2
        tay                     ; y = position after name
        
        lda #$2c                ; ','
        sta write_fname_buf,y
        iny
        lda #$53                ; 'S' (sequential)
        sta write_fname_buf,y
        iny
        lda #$2c                ; ','
        sta write_fname_buf,y
        iny
        lda #$57                ; 'W' (write)
        sta write_fname_buf,y
        iny
        
        sty write_fname_len
        rts

; =============================================================================
; build_read_filename - build "0:filename,s,r" in read_fname_buf
; =============================================================================
build_read_filename:
        lda #$30                ; '0'
        sta read_fname_buf
        lda #$3a                ; ':'
        sta read_fname_buf+1
        
        ldx #0
@copy:
        lda actual_filename,x
        beq @add_suffix
        sta read_fname_buf+2,x
        inx
        cpx #16
        bne @copy
        
@add_suffix:
        txa
        clc
        adc #2
        tay
        
        lda #$2c                ; ','
        sta read_fname_buf,y
        iny
        lda #$53                ; 'S'
        sta read_fname_buf,y
        iny
        lda #$2c                ; ','
        sta read_fname_buf,y
        iny
        lda #$52                ; 'R' (read)
        sta read_fname_buf,y
        iny
        
        sty read_fname_len
        rts

; =============================================================================
; verify_key_match - verify read key matches original
; returns: carry clear = match, carry set = mismatch
; =============================================================================
verify_key_match:
        ldx #0
@loop:
        lda key_data,x
        cmp key_read_buf,x
        bne @mismatch
        inx
        cpx #32
        bne @loop
        
        clc                     ; match
        rts
        
@mismatch:
        sec                     ; mismatch
        rts

; =============================================================================
; print_decimal - print A as decimal number
; =============================================================================
print_decimal:
        ldx #0
        stx decimal_flag
        
        ; hundreds
        ldx #0
@hundreds:
        cmp #100
        bcc @tens
        sbc #100
        inx
        jmp @hundreds
@tens:
        pha
        txa
        beq @skip_hundreds
        ora #$30
        jsr chrout
        inc decimal_flag
@skip_hundreds:
        pla
        
        ; tens
        ldx #0
@tens_loop:
        cmp #10
        bcc @ones
        sbc #10
        inx
        jmp @tens_loop
@ones:
        pha
        txa
        bne @print_tens
        lda decimal_flag
        beq @skip_tens
@print_tens:
        txa
        ora #$30
        jsr chrout
@skip_tens:
        pla
        
        ; ones
        ora #$30
        jsr chrout
        rts

; =============================================================================
; do_gcm_siv_encrypt - encrypt text using AES-256-GCM-SIV mode
; GCM-SIV is a nonce-misuse resistant AEAD mode
; Structure: nonce(12) || ciphertext || tag(16)
; =============================================================================
do_gcm_siv_encrypt:
        lda #$0d
        jsr chrout
        
        ; print prompt
        lda #<gcmsiv_prompt_msg
        ldy #>gcmsiv_prompt_msg
        jsr print_string
        
        ; get input text
        jsr get_gcmsiv_input
        
        ; check if we got any input
        lda gcmsiv_pt_len
        bne @has_input
        
        lda #<no_input_msg
        ldy #>no_input_msg
        jsr print_string
        jmp @done
        
@has_input:
        ; show plaintext length
        lda #<gcmsiv_encrypting_msg
        ldy #>gcmsiv_encrypting_msg
        jsr print_string
        lda gcmsiv_pt_len
        jsr print_decimal
        lda #<bytes_msg
        ldy #>bytes_msg
        jsr print_string
        
        ; generate random 12-byte nonce
        jsr generate_gcmsiv_nonce
        
        ; show nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; perform GCM-SIV encryption
        jsr gcmsiv_encrypt
        
        ; show ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; show authentication tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        lda #<gcmsiv_done_msg
        ldy #>gcmsiv_done_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; get_gcmsiv_input - get plaintext input for GCM-SIV encryption
; =============================================================================
get_gcmsiv_input:
        ; clear buffer
        ldx #0
        lda #0
@clear:
        sta gcmsiv_pt_buf,x
        inx
        cpx #64
        bne @clear
        
        lda #0
        sta gcmsiv_pt_len
        
@input_loop:
        jsr getin
        beq @input_loop
        
        cmp #petscii_return
        beq @input_done
        
        cmp #$14                ; delete
        beq @do_delete
        
        ; check buffer not full
        ldx gcmsiv_pt_len
        cpx #63
        bcs @input_loop
        
        ; store character
        sta gcmsiv_pt_buf,x
        inc gcmsiv_pt_len
        
        ; echo (preserving nothing - we use gcmsiv_pt_len now)
        jsr chrout
        jmp @input_loop
        
@do_delete:
        ldx gcmsiv_pt_len
        beq @input_loop
        dex
        stx gcmsiv_pt_len
        lda #0
        sta gcmsiv_pt_buf,x
        lda #$14
        jsr chrout
        jmp @input_loop
        
@input_done:
        lda #$0d
        jsr chrout
        rts

; =============================================================================
; generate_gcmsiv_nonce - generate 12-byte random nonce
; =============================================================================
generate_gcmsiv_nonce:
        ldx #0
@loop:
        jsr lfsr_random
        sta gcmsiv_nonce,x
        inx
        cpx #12
        bne @loop
        rts

; =============================================================================
; gcmsiv_encrypt - perform AES-256-GCM-SIV encryption
; Uses key_data as the 256-bit key
; Input: gcmsiv_pt_buf (plaintext), gcmsiv_pt_len (length), gcmsiv_nonce (12 bytes)
; Output: gcmsiv_ct_buf (ciphertext), gcmsiv_tag (16 bytes)
; =============================================================================
gcmsiv_encrypt:
        ; GCM-SIV steps:
        ; 1. Derive authentication key and encryption key from main key + nonce
        ; 2. Compute POLYVAL over AAD and plaintext
        ; 3. Derive tag from POLYVAL result
        ; 4. Encrypt plaintext using AES-CTR with tag as IV
        
        ; Step 1: Derive keys using AES
        ; For simplicity, we'll use the existing key directly
        ; and derive subkeys by encrypting nonce-based values
        
        jsr gcmsiv_derive_keys
        
        ; Step 2: Compute POLYVAL (simplified - using CBC-MAC style)
        jsr gcmsiv_compute_tag_base
        
        ; Step 3: Encrypt the tag base to get final tag
        jsr gcmsiv_finalize_tag
        
        ; Step 4: Encrypt plaintext with AES-CTR using tag as IV
        jsr gcmsiv_ctr_encrypt
        
        rts

; =============================================================================
; gcmsiv_derive_keys - derive authentication and encryption keys per RFC 8452
; For AES-256-GCM-SIV: 6 AES encryptions of (counter || nonce)
; Take first 8 bytes of each output:
;   counter=0 -> auth_key[0..7]
;   counter=1 -> auth_key[8..15]
;   counter=2 -> enc_key[0..7]
;   counter=3 -> enc_key[8..15]
;   counter=4 -> enc_key[16..23]
;   counter=5 -> enc_key[24..31]
; =============================================================================
gcmsiv_derive_keys:
        lda #0
        sta gcmsiv_derive_ctr   ; start at counter 0
        
@derive_loop:
        ; Build block: little-endian counter(4) || nonce(12)
        lda gcmsiv_derive_ctr
        sta aes_state
        lda #0
        sta aes_state+1
        sta aes_state+2
        sta aes_state+3
        
        ldx #0
@copy_nonce:
        lda gcmsiv_nonce,x
        sta aes_state+4,x
        inx
        cpx #12
        bne @copy_nonce
        
        ; Encrypt with the main key
        jsr aes_encrypt_block
        
        ; Copy first 8 bytes to appropriate destination
        lda gcmsiv_derive_ctr
        cmp #0
        beq @store_auth_lo
        cmp #1
        beq @store_auth_hi
        cmp #2
        beq @store_enc_0
        cmp #3
        beq @store_enc_1
        cmp #4
        beq @store_enc_2
        cmp #5
        beq @store_enc_3
        jmp @derive_next
        
@store_auth_lo:
        ldx #0
@sal:   lda aes_state,x
        sta gcmsiv_auth_key,x
        inx
        cpx #8
        bne @sal
        jmp @derive_next
        
@store_auth_hi:
        ldx #0
@sah:   lda aes_state,x
        sta gcmsiv_auth_key+8,x
        inx
        cpx #8
        bne @sah
        jmp @derive_next
        
@store_enc_0:
        ldx #0
@se0:   lda aes_state,x
        sta gcmsiv_enc_key,x
        inx
        cpx #8
        bne @se0
        jmp @derive_next
        
@store_enc_1:
        ldx #0
@se1:   lda aes_state,x
        sta gcmsiv_enc_key+8,x
        inx
        cpx #8
        bne @se1
        jmp @derive_next
        
@store_enc_2:
        ldx #0
@se2:   lda aes_state,x
        sta gcmsiv_enc_key+16,x
        inx
        cpx #8
        bne @se2
        jmp @derive_next
        
@store_enc_3:
        ldx #0
@se3:   lda aes_state,x
        sta gcmsiv_enc_key+24,x
        inx
        cpx #8
        bne @se3
        
@derive_next:
        inc gcmsiv_derive_ctr
        lda gcmsiv_derive_ctr
        cmp #6
        bcs @derive_done_loop
        jmp @derive_loop
@derive_done_loop:
        
        ; Now expand the derived encryption key for use in CTR and tag encryption
        ; Save original key, install derived key, expand, restore
        ; Copy current key_data to gcmsiv_saved_key
        ldx #0
@save_key:
        lda key_data,x
        sta gcmsiv_saved_key,x
        lda gcmsiv_enc_key,x
        sta key_data,x
        inx
        cpx #32
        bne @save_key
        
        ; Expand the derived encryption key
        jsr aes_key_expansion
        
        ; Copy expanded key to gcmsiv_expanded_enc_key
        ldx #0
@copy_exp:
        lda expanded_key,x
        sta gcmsiv_exp_enc_key,x
        inx
        bne @copy_exp            ; copies 256 bytes (covers 240 needed)
        
        ; Restore original key and re-expand
        ldx #0
@restore_key:
        lda gcmsiv_saved_key,x
        sta key_data,x
        inx
        cpx #32
        bne @restore_key
        
        jsr aes_key_expansion   ; restore original expanded key
        
        rts

gcmsiv_derive_ctr:
        !byte 0

; =============================================================================
; gcmsiv_compute_tag_base - compute authentication tag base
; Uses AES-CBC-MAC with the derived auth key as POLYVAL approximation
; Processes plaintext blocks then a length block (AAD_len || PT_len in bits)
; =============================================================================
gcmsiv_compute_tag_base:
        ; Install auth key into expanded_key for tag computation
        ; Save current expanded key first
        ldx #0
@save_exp:
        lda expanded_key,x
        sta gcmsiv_saved_exp,x
        lda gcmsiv_exp_enc_key,x  ; temporarily use enc key expansion area
        inx
        bne @save_exp
        
        ; Now expand the auth key (16 bytes padded to 32 with zeros)
        ; For the CBC-MAC tag computation, we use auth_key as a 128-bit key
        ; by placing it in key_data and zero-filling the upper 16 bytes
        ldx #0
@save_keydata:
        lda key_data,x
        sta gcmsiv_saved_key,x
        inx
        cpx #32
        bne @save_keydata
        
        ; Install auth key (padded to 32 bytes for key expansion)
        ldx #0
@install_auth:
        lda gcmsiv_auth_key,x
        sta key_data,x
        inx
        cpx #16
        bne @install_auth
        lda #0
@pad_auth:
        sta key_data,x
        inx
        cpx #32
        bne @pad_auth
        
        jsr aes_key_expansion
        
        ; Clear tag accumulator
        ldx #0
        lda #0
@clear_acc:
        sta gcmsiv_tag_acc,x
        inx
        cpx #16
        bne @clear_acc
        
        ; Process plaintext in 16-byte blocks
        lda #0
        sta gcmsiv_block_idx
        
@process_loop:
        ; Calculate remaining bytes
        lda gcmsiv_pt_len
        sec
        sbc gcmsiv_block_idx
        beq @process_done       ; no more data
        bmi @process_done
        
        ; Copy up to 16 bytes to state, XOR with accumulator
        ldx #0
        ldy gcmsiv_block_idx
        
@copy_block:
        cpy gcmsiv_pt_len
        bcs @pad_block          ; past end of data, pad with zeros
        
        lda gcmsiv_pt_buf,y
        eor gcmsiv_tag_acc,x
        sta aes_state,x
        iny
        inx
        cpx #16
        bne @copy_block
        jmp @encrypt_block
        
@pad_block:
        ; Pad remaining bytes with zeros XORed with accumulator
        lda gcmsiv_tag_acc,x
        sta aes_state,x
        inx
        cpx #16
        bne @pad_block
        
@encrypt_block:
        ; Encrypt the block with auth key
        jsr aes_encrypt_block
        
        ; Update accumulator
        ldx #0
@update_acc:
        lda aes_state,x
        sta gcmsiv_tag_acc,x
        inx
        cpx #16
        bne @update_acc
        
        ; Move to next block
        lda gcmsiv_block_idx
        clc
        adc #16
        sta gcmsiv_block_idx
        
        ; Check if we've processed all data
        cmp gcmsiv_pt_len
        bcc @process_loop
        
@process_done:
        ; Process length block: 64-bit AAD bit length || 64-bit PT bit length
        ; AAD = 0, so first 8 bytes are zero
        ; PT bit length = pt_len * 8, little-endian
        ldx #0
        lda #0
@clear_len_block:
        sta aes_state,x
        inx
        cpx #16
        bne @clear_len_block
        
        ; Store PT bit length at bytes 8-15 (little-endian)
        ; pt_len * 8
        lda gcmsiv_pt_len
        asl                     ; *2
        asl                     ; *4
        asl                     ; *8
        sta aes_state+8
        lda gcmsiv_pt_len
        lsr
        lsr
        lsr
        lsr
        lsr                     ; high bits of *8
        sta aes_state+9
        ; bytes 10-15 stay zero (length fits in 16 bits)
        
        ; XOR with accumulator
        ldx #0
@xor_len:
        lda aes_state,x
        eor gcmsiv_tag_acc,x
        sta aes_state,x
        inx
        cpx #16
        bne @xor_len
        
        ; Encrypt
        jsr aes_encrypt_block
        
        ; Store final accumulator
        ldx #0
@store_final:
        lda aes_state,x
        sta gcmsiv_tag_acc,x
        inx
        cpx #16
        bne @store_final
        
        ; Restore original key and expanded key
        ldx #0
@restore_keydata:
        lda gcmsiv_saved_key,x
        sta key_data,x
        inx
        cpx #32
        bne @restore_keydata
        
        ldx #0
@restore_exp:
        lda gcmsiv_saved_exp,x
        sta expanded_key,x
        inx
        bne @restore_exp
        
        ; Re-expand original key
        jsr aes_key_expansion
        
        rts

; =============================================================================
; gcmsiv_finalize_tag - encrypt tag base with derived enc key to produce final tag
; =============================================================================
gcmsiv_finalize_tag:
        ; Copy tag accumulator to state
        ldx #0
@copy:
        lda gcmsiv_tag_acc,x
        sta aes_state,x
        inx
        cpx #16
        bne @copy
        
        ; XOR in the nonce (first 12 bytes)
        ldx #0
@xor_nonce:
        lda aes_state,x
        eor gcmsiv_nonce,x
        sta aes_state,x
        inx
        cpx #12
        bne @xor_nonce
        
        ; Clear MSB of last byte (as per GCM-SIV spec)
        lda aes_state+15
        and #$7f
        sta aes_state+15
        
        ; Install derived encryption key for this encryption
        jsr gcmsiv_install_enc_key
        
        ; Encrypt to get final tag
        jsr aes_encrypt_block
        
        ; Restore original key
        jsr gcmsiv_restore_orig_key
        
        ; Store tag
        ldx #0
@store:
        lda aes_state,x
        sta gcmsiv_tag,x
        inx
        cpx #16
        bne @store
        
        rts

; =============================================================================
; gcmsiv_install_enc_key - install derived enc key into expanded_key
; =============================================================================
gcmsiv_install_enc_key:
        ; Save original expanded key
        ldx #0
@save:
        lda expanded_key,x
        sta gcmsiv_saved_exp,x
        inx
        bne @save
        
        ; Install derived enc key expanded form
        ldx #0
@install:
        lda gcmsiv_exp_enc_key,x
        sta expanded_key,x
        inx
        bne @install
        rts

; =============================================================================
; gcmsiv_restore_orig_key - restore original expanded key
; =============================================================================
gcmsiv_restore_orig_key:
        ldx #0
@restore:
        lda gcmsiv_saved_exp,x
        sta expanded_key,x
        inx
        bne @restore
        rts

; =============================================================================
; gcmsiv_ctr_encrypt - encrypt plaintext using AES-CTR with tag as IV
; Uses derived encryption key
; =============================================================================
gcmsiv_ctr_encrypt:
        ; Install derived encryption key
        jsr gcmsiv_install_enc_key
        
        ; Copy tag to counter block
        ldx #0
@copy_tag:
        lda gcmsiv_tag,x
        sta gcmsiv_counter,x
        inx
        cpx #16
        bne @copy_tag
        
        ; Set MSB of last byte (counter mode indicator)
        lda gcmsiv_counter+15
        ora #$80
        sta gcmsiv_counter+15
        
        ; Process plaintext
        lda #0
        sta gcmsiv_ct_idx       ; ciphertext output index
        sta gcmsiv_ks_idx       ; keystream index (start at 16 to force generation)
        lda #16
        sta gcmsiv_ks_idx
        
@encrypt_loop:
        ; Check if done
        lda gcmsiv_ct_idx
        cmp gcmsiv_pt_len
        bcs @encrypt_done
        
        ; Check if we need new keystream block
        lda gcmsiv_ks_idx
        cmp #16
        bcc @have_keystream
        
        ; Generate new keystream block
        jsr gcmsiv_gen_keystream
        lda #0
        sta gcmsiv_ks_idx
        
@have_keystream:
        ; XOR plaintext with keystream
        ldx gcmsiv_ct_idx
        ldy gcmsiv_ks_idx
        lda gcmsiv_pt_buf,x
        eor gcmsiv_keystream,y
        sta gcmsiv_ct_buf,x
        
        ; Advance indices
        inc gcmsiv_ct_idx
        inc gcmsiv_ks_idx
        
        jmp @encrypt_loop
        
@encrypt_done:
        ; Restore original key
        jsr gcmsiv_restore_orig_key
        rts

; =============================================================================
; gcmsiv_gen_keystream - generate 16-byte keystream block
; =============================================================================
gcmsiv_gen_keystream:
        ; Copy counter to state
        ldx #0
@copy:
        lda gcmsiv_counter,x
        sta aes_state,x
        inx
        cpx #16
        bne @copy
        
        ; Encrypt counter
        jsr aes_encrypt_block
        
        ; Store keystream
        ldx #0
@store:
        lda aes_state,x
        sta gcmsiv_keystream,x
        inx
        cpx #16
        bne @store
        
        ; Increment counter (32-bit increment on bytes 0-3, little-endian)
        inc gcmsiv_counter
        bne @no_carry
        inc gcmsiv_counter+1
        bne @no_carry
        inc gcmsiv_counter+2
        bne @no_carry
        inc gcmsiv_counter+3
@no_carry:
        rts

; =============================================================================
; do_gcm_siv_decrypt - decrypt ciphertext using AES-256-GCM-SIV mode
; =============================================================================
do_gcm_siv_decrypt:
        lda #$0d
        jsr chrout
        
        ; check if there's ciphertext from GCM-SIV encryption
        lda gcmsiv_pt_len
        bne @has_data
        
        lda #<gcmsiv_no_data_msg
        ldy #>gcmsiv_no_data_msg
        jsr print_string
        jmp @done
        
@has_data:
        ; show what we're decrypting
        lda #<gcmsiv_decrypting_msg
        ldy #>gcmsiv_decrypting_msg
        jsr print_string
        
        ; show nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; show ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; show stored tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; perform GCM-SIV decryption
        jsr gcmsiv_decrypt
        
        ; Check tag verification result
        lda gcmsiv_tag_valid
        bne @tag_ok
        
        ; Tag verification failed
        lda #<gcmsiv_tag_fail_msg
        ldy #>gcmsiv_tag_fail_msg
        jsr print_string
        jmp @done
        
@tag_ok:
        ; Tag verified
        lda #<gcmsiv_tag_ok_msg
        ldy #>gcmsiv_tag_ok_msg
        jsr print_string
        
        ; show decrypted plaintext as hex
        lda #<gcmsiv_pt_hex_msg
        ldy #>gcmsiv_pt_hex_msg
        jsr print_string
        
        lda #<gcmsiv_dec_buf
        sta zp_ptr
        lda #>gcmsiv_dec_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; show decrypted plaintext as text
        lda #<gcmsiv_pt_text_msg
        ldy #>gcmsiv_pt_text_msg
        jsr print_string
        
        ; ensure uppercase mode
        lda #$8e
        jsr chrout
        
        ; print decrypted text
        ldx #0
@print_loop:
        cpx gcmsiv_pt_len
        beq @print_done
        lda gcmsiv_dec_buf,x
        beq @next_char
        
        ; only print printable characters
        cmp #$20
        bcc @next_char
        cmp #$60
        bcc @do_print
        cmp #$c0
        bcc @next_char
        cmp #$e0
        bcs @next_char
        sec
        sbc #$80
        
@do_print:
        jsr chrout
@next_char:
        inx
        cpx #64
        bcc @print_loop
        
@print_done:
        lda #$0d
        jsr chrout
        
        lda #<gcmsiv_decrypt_done_msg
        ldy #>gcmsiv_decrypt_done_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; gcmsiv_decrypt - perform AES-256-GCM-SIV decryption with tag verification
; Uses the same key derivation and CTR decryption (CTR is symmetric)
; Input: gcmsiv_ct_buf, gcmsiv_pt_len, gcmsiv_nonce, gcmsiv_tag
; Output: gcmsiv_dec_buf, gcmsiv_tag_valid (0=fail, 1=pass)
; =============================================================================
gcmsiv_decrypt:
        ; Initialize tag valid flag
        lda #0
        sta gcmsiv_tag_valid
        
        ; Step 1: Derive keys (same as encryption)
        jsr gcmsiv_derive_keys
        
        ; Step 2: Decrypt ciphertext using AES-CTR with stored tag as IV
        jsr gcmsiv_ctr_decrypt
        
        ; Step 3: Recompute tag over decrypted plaintext and verify
        ; Save the received tag
        ldx #0
@save_tag:
        lda gcmsiv_tag,x
        sta gcmsiv_verify_tag,x
        inx
        cpx #16
        bne @save_tag
        
        ; Copy decrypted data to pt_buf for tag computation
        ldx #0
@copy_dec:
        lda gcmsiv_dec_buf,x
        sta gcmsiv_pt_buf,x
        inx
        cpx gcmsiv_pt_len
        bne @copy_dec
        
        ; Recompute tag (this writes to gcmsiv_tag)
        jsr gcmsiv_compute_tag_base
        jsr gcmsiv_finalize_tag
        
        ; Compare recomputed tag with received tag
        ldx #0
@compare:
        lda gcmsiv_tag,x
        cmp gcmsiv_verify_tag,x
        bne @tag_fail
        inx
        cpx #16
        bne @compare
        
        ; Tag matches
        lda #1
        sta gcmsiv_tag_valid
        
        ; Restore the original tag (so display shows what was received)
        ldx #0
@restore_tag:
        lda gcmsiv_verify_tag,x
        sta gcmsiv_tag,x
        inx
        cpx #16
        bne @restore_tag
        
        rts
        
@tag_fail:
        ; Tag mismatch - clear decrypted data for safety
        lda #0
        sta gcmsiv_tag_valid
        ldx #0
@clear_dec:
        sta gcmsiv_dec_buf,x
        inx
        cpx #64
        bne @clear_dec
        
        ; Restore the original tag
        ldx #0
@restore_tag2:
        lda gcmsiv_verify_tag,x
        sta gcmsiv_tag,x
        inx
        cpx #16
        bne @restore_tag2
        
        rts

; =============================================================================
; gcmsiv_ctr_decrypt - decrypt ciphertext using AES-CTR with tag as IV
; Uses derived encryption key
; =============================================================================
gcmsiv_ctr_decrypt:
        ; Install derived encryption key
        jsr gcmsiv_install_enc_key
        
        ; Copy tag to counter block
        ldx #0
@copy_tag:
        lda gcmsiv_tag,x
        sta gcmsiv_counter,x
        inx
        cpx #16
        bne @copy_tag
        
        ; Set MSB of last byte (counter mode indicator)
        lda gcmsiv_counter+15
        ora #$80
        sta gcmsiv_counter+15
        
        ; Process ciphertext (CTR mode is symmetric - same operation for encrypt/decrypt)
        lda #0
        sta gcmsiv_ct_idx       ; index into ciphertext
        lda #16                 ; force keystream generation on first byte
        sta gcmsiv_ks_idx
        
@decrypt_loop:
        ; Check if done
        lda gcmsiv_ct_idx
        cmp gcmsiv_pt_len
        bcs @decrypt_done
        
        ; Check if we need new keystream block
        lda gcmsiv_ks_idx
        cmp #16
        bcc @have_keystream
        
        ; Generate new keystream block
        jsr gcmsiv_gen_keystream
        lda #0
        sta gcmsiv_ks_idx
        
@have_keystream:
        ; XOR ciphertext with keystream to get plaintext
        ldx gcmsiv_ct_idx
        ldy gcmsiv_ks_idx
        lda gcmsiv_ct_buf,x
        eor gcmsiv_keystream,y
        sta gcmsiv_dec_buf,x
        
        ; Advance indices
        inc gcmsiv_ct_idx
        inc gcmsiv_ks_idx
        
        jmp @decrypt_loop
        
@decrypt_done:
        ; Restore original key
        jsr gcmsiv_restore_orig_key
        rts

; =============================================================================
; do_save_gcm_siv - save GCM-SIV encrypted data to disk
; File format: nonce (12 bytes) || tag (16 bytes) || ciphertext length (1 byte) || ciphertext
; =============================================================================
do_save_gcm_siv:
        lda #$0d
        jsr chrout
        
        ; check if there's GCM-SIV data
        lda gcmsiv_pt_len
        bne @has_data
        
        lda #<gcmsiv_no_data_msg
        ldy #>gcmsiv_no_data_msg
        jsr print_string
        jmp @done
        
@has_data:
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<gcm_filename_prompt_msg
        ldy #>gcm_filename_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        jsr set_default_gcm_filename
        lda #1
        sta using_default_name
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        beq @do_save
        
        lda #<file_exists_msg
        ldy #>file_exists_msg
        jsr print_string
        
        lda using_default_name
        beq @prompt_new_name
        
        jsr increment_gcm_filename
        bcs @names_exhausted
        
        lda #<incremented_msg
        ldy #>incremented_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @got_filename

@names_exhausted:
        lda #<names_exhausted_msg
        ldy #>names_exhausted_msg
        jsr print_string
        jmp @done
        
@prompt_new_name:
        lda #<enter_new_name_msg
        ldy #>enter_new_name_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @do_save
        jsr copy_input_to_filename
        jmp @got_filename
        
@do_save:
        ; --- show what we're saving ---
        lda #<saving_gcm_msg
        ldy #>saving_gcm_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        ; show nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; show tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; show ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; --- save to disk ---
        jsr save_gcmsiv_to_disk
        bcs @save_error
        
        lda #<save_success_msg
        ldy #>save_success_msg
        jsr print_string
        jmp @done
        
@save_error:
        lda #<save_error_msg
        ldy #>save_error_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; do_load_gcm_siv - load GCM-SIV encrypted data from disk
; =============================================================================
do_load_gcm_siv:
        lda #$0d
        jsr chrout
        
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<load_gcm_filename_prompt
        ldy #>load_gcm_filename_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        jsr set_default_gcm_filename
        lda #1
        sta using_default_name
        
        lda #<loading_default_gcm_msg
        ldy #>loading_default_gcm_msg
        jsr print_string
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        bne @do_load
        
        lda #<file_not_found_msg
        ldy #>file_not_found_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @done
        
@do_load:
        lda #<loading_gcm_msg
        ldy #>loading_gcm_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        ; --- load from disk ---
        jsr load_gcmsiv_from_disk
        bcs @load_error
        
        ; show loaded nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; show loaded tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; show loaded ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        lda #<gcm_load_success_msg
        ldy #>gcm_load_success_msg
        jsr print_string
        jmp @done
        
@load_error:
        lda #<load_error_msg
        ldy #>load_error_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; set_default_gcm_filename - set filename to "AESGCM"
; =============================================================================
set_default_gcm_filename:
        ldx #0
@loop:
        lda default_gcm_filename,x
        sta actual_filename,x
        beq @done
        inx
        cpx #7
        bne @loop
@done:
        lda #0
        sta actual_filename,x
        lda #6
        sta filename_len
        lda #0
        sta gcm_filename_suffix
        rts

; =============================================================================
; increment_gcm_filename - increment the numeric suffix for GCM files
; returns: carry set if exhausted (reached 9)
; =============================================================================
increment_gcm_filename:
        lda gcm_filename_suffix
        cmp #10
        bcs @exhausted
        
        inc gcm_filename_suffix
        lda gcm_filename_suffix
        
        clc
        adc #$2F                ; convert to ASCII digit
        ldx #6
        sta actual_filename,x
        lda #0
        sta actual_filename+7
        lda #7
        sta filename_len
        
        clc
        rts
        
@exhausted:
        sec
        rts

; =============================================================================
; save_gcmsiv_to_disk - save nonce, tag, length, and ciphertext as hex
; =============================================================================
save_gcmsiv_to_disk:
        jsr build_write_filename
        
        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam
        
        lda #3
        ldx drive_number
        ldy #3
        jsr setlfs
        
        jsr open
        bcc @open_ok
        jmp @error
@open_ok:
        
        ldx #3
        jsr chkout
        bcc @chkout_ok
        jmp @close_error
@chkout_ok:
        
        ; write nonce (12 bytes as hex)
        lda #0
        sta save_byte_index
@write_nonce:
        ldx save_byte_index
        cpx #12
        beq @nonce_done
        lda gcmsiv_nonce,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$20
        jsr chrout
        inc save_byte_index
        jmp @write_nonce
@nonce_done:
        lda #$0d
        jsr chrout
        
        ; write tag (16 bytes as hex)
        lda #0
        sta save_byte_index
@write_tag:
        ldx save_byte_index
        cpx #16
        beq @tag_done
        lda gcmsiv_tag,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$20
        jsr chrout
        inc save_byte_index
        jmp @write_tag
@tag_done:
        lda #$0d
        jsr chrout
        
        ; write length (1 byte as hex)
        lda gcmsiv_pt_len
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$0d
        jsr chrout
        
        ; write ciphertext
        lda #0
        sta save_byte_index
@write_ct:
        ldx save_byte_index
        cpx gcmsiv_pt_len
        beq @ct_done
        lda gcmsiv_ct_buf,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$20
        jsr chrout
        ; newline every 8 bytes
        lda save_byte_index
        and #$07
        cmp #$07
        bne @no_newline
        lda #$0d
        jsr chrout
@no_newline:
        inc save_byte_index
        jmp @write_ct
@ct_done:
        
        jsr readst
        bne @close_error
        
        jsr clrchn
        lda #3
        jsr close
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #3
        jsr close
@error:
        sec
        rts

; =============================================================================
; load_gcmsiv_from_disk - load nonce, tag, length, and ciphertext
; =============================================================================
load_gcmsiv_from_disk:
        jsr build_read_filename
        
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        lda #4
        ldx drive_number
        ldy #4
        jsr setlfs
        
        jsr open
        bcc @open_ok
        jmp @error
@open_ok:
        
        ldx #4
        jsr chkin
        bcc @chkin_ok
        jmp @close_error
@chkin_ok:
        
        ; read nonce (12 bytes)
        lda #0
        sta read_byte_index
@read_nonce:
        lda read_byte_index
        cmp #12
        beq @nonce_done
        jsr read_hex_char
        bcc @nonce_ok1
        jmp @close_error
@nonce_ok1:
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcc @nonce_ok2
        jmp @close_error
@nonce_ok2:
        ora read_temp_byte
        ldx read_byte_index
        sta gcmsiv_nonce,x
        inc read_byte_index
        jmp @read_nonce
@nonce_done:
        
        ; read tag (16 bytes)
        lda #0
        sta read_byte_index
@read_tag:
        lda read_byte_index
        cmp #16
        beq @tag_done
        jsr read_hex_char
        bcc @tag_ok1
        jmp @close_error
@tag_ok1:
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcc @tag_ok2
        jmp @close_error
@tag_ok2:
        ora read_temp_byte
        ldx read_byte_index
        sta gcmsiv_tag,x
        inc read_byte_index
        jmp @read_tag
@tag_done:
        
        ; read length (1 byte)
        jsr read_hex_char
        bcc @len_ok1
        jmp @close_error
@len_ok1:
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcc @len_ok2
        jmp @close_error
@len_ok2:
        ora read_temp_byte
        sta gcmsiv_pt_len
        
        ; read ciphertext
        lda #0
        sta read_byte_index
@read_ct:
        lda read_byte_index
        cmp gcmsiv_pt_len
        beq @ct_done
        jsr read_hex_char
        bcs @ct_done            ; EOF is ok here
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcs @ct_done
        ora read_temp_byte
        ldx read_byte_index
        sta gcmsiv_ct_buf,x
        inc read_byte_index
        jmp @read_ct
@ct_done:
        
        jsr clrchn
        lda #4
        jsr close
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec
        rts

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
        !byte $00, $01, $02, $03, $04, $05, $06, $07
        !byte $08, $09, $0a, $0b, $0c, $0d, $0e, $0f
        !byte $10, $11, $12, $13, $14, $15, $16, $17
        !byte $18, $19, $1a, $1b, $1c, $1d, $1e, $1f

; IV: 00000000000000000000000000000000 (all zeros for ECB test)
nist_test_iv:
        !byte $00, $00, $00, $00, $00, $00, $00, $00
        !byte $00, $00, $00, $00, $00, $00, $00, $00

; Plaintext: 00112233445566778899aabbccddeeff
nist_test_plaintext:
        !byte $00, $11, $22, $33, $44, $55, $66, $77
        !byte $88, $99, $aa, $bb, $cc, $dd, $ee, $ff

; Expected Ciphertext: 8ea2b7ca516745bfeafc49904b496089
nist_test_ciphertext:
        !byte $8e, $a2, $b7, $ca, $51, $67, $45, $bf
        !byte $ea, $fc, $49, $90, $4b, $49, $60, $89


; =============================================================================
; do_show_reu_status - display REU presence and size
; =============================================================================
do_show_reu_status:
        lda #$0d
        jsr chrout
        
        lda #<reu_status_msg
        ldy #>reu_status_msg
        jsr print_string
        
        ; Run REU detection now
        lda #<reu_detecting_msg
        ldy #>reu_detecting_msg
        jsr print_string
        
        jsr detect_reu
        
        ; Check result
        lda reu_present
        bne @show_present
        
        lda #<reu_not_present_msg
        ldy #>reu_not_present_msg
        jsr print_string
        jmp @done
        
@show_present:
        lda #<reu_present_msg
        ldy #>reu_present_msg
        jsr print_string
        
        ; display size in decimal KB
        lda #<reu_size_is_msg
        ldy #>reu_size_is_msg
        jsr print_string
        
        ; print reu_size_kb as decimal
        lda reu_size_kb
        sta zp_temp
        lda reu_size_kb+1
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<reu_kb_suffix
        ldy #>reu_kb_suffix
        jsr print_string
        
        ; Ask if user wants to fill the REU
        lda #<reu_fill_prompt
        ldy #>reu_fill_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'N'
        beq @done
        cmp #'n'
        beq @done
        ; Enter or Y = yes, continue to ask zero or random
        
        ; Ask zero or random fill
        lda #<reu_fill_type_prompt
        ldy #>reu_fill_type_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'R'
        beq @random_fill
        cmp #'r'
        beq @random_fill
        ; Enter or 0 = zero fill
        
        ; Zero-fill the REU
        lda #0
        sta reu_fill_random
        jsr fill_reu
        jmp @done
        
@random_fill:
        lda #1
        sta reu_fill_random
        jsr fill_reu
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; =============================================================================
; fill_reu - fill entire REU with zeros or random, showing progress
; reu_fill_random: 0=zeros, 1=random
; Exit if user presses space bar
;
; Zero fill optimization: uses REU "fix C64 address" mode ($DF0A bit 7)
; to DMA a single zero byte across an entire 64KB bank in one operation.
; This is ~256x faster than the per-page approach since the REC reads
; the same C64 byte repeatedly while incrementing the REU address.
; DMA rate is ~1 byte/cycle = ~65ms per 64KB bank.
;
; Random fill: must use per-page stashes since each page needs unique
; random data generated by the PRNG.
; =============================================================================
fill_reu:
        ; Show appropriate message
        lda reu_fill_random
        beq @zero_msg
        lda #<reu_random_msg
        ldy #>reu_random_msg
        jmp @print_msg
@zero_msg:
        lda #<reu_zeroing_msg
        ldy #>reu_zeroing_msg
@print_msg:
        jsr print_string
        
        ; Do the actual fill
        jsr refill_reu_core
        bcs @aborted            ; carry set = user aborted
        
        ; Fill complete
        lda #$0d
        jsr chrout
        lda #<reu_fill_done_msg
        ldy #>reu_fill_done_msg
        jsr print_string
        
        ; Only offer save for random fill
        lda reu_fill_random
        beq @fill_exit
        jsr offer_save_reu_to_disk
        
@fill_exit:
        ; Restore address control to normal (increment both)
        lda #0
        sta $df0a
        rts
        
@aborted:
        lda #$0d
        jsr chrout
        lda #<reu_aborted_msg
        ldy #>reu_aborted_msg
        jsr print_string
        ; Restore address control
        lda #0
        sta $df0a
        rts

; =============================================================================
; refill_reu_core - raw REU fill without UI prompts or save offer
; Used by fill_reu (full UI) and by the multi-pass disk writer (silent)
; Returns: carry clear = completed, carry set = user aborted (space bar)
; =============================================================================
refill_reu_core:
        ; Initialize counters
        lda #0
        sta reu_fill_bank
        sta reu_fill_addr_hi
        sta reu_kb_counter
        sta reu_kb_counter+1
        
        ; reu_banks = (number of 64KB banks) - 1
        ; For 128KB: reu_banks = 1 (banks 0-1)
        ; For 512KB: reu_banks = 7 (banks 0-7)
        ; For 16MB:  reu_banks = 0 (meaning 256, banks 0-255, wraps)
        ; We fill banks 0 through reu_banks inclusive.
        ; Completion: after incrementing fill_bank, if it equals
        ; (reu_banks + 1) we're done. For the 256-bank case,
        ; reu_banks + 1 wraps to 0, and fill_bank also wraps to 0
        ; after bank 255, so the comparison still works.
        
        ; Branch based on fill mode
        lda reu_fill_random
        bne @random_fill_path
        jmp @fast_zero_fill
        
; ---- Random fill path (per-page stash, same as before) ----
@random_fill_path:
        jsr prepare_fill_buffer
        
@rand_fill_loop:
        ; Check for space bar to abort
        jsr getin
        cmp #$20
        bne @rand_not_aborted
        jmp @aborted
@rand_not_aborted:
        
        ; Refill buffer with new random data each page
        jsr prepare_fill_buffer
        
        ; Stash 256-byte buffer to REU
        lda #<reu_zero_buffer
        sta $df02
        lda #>reu_zero_buffer
        sta $df03
        
        lda #0
        sta $df04               ; REU address low
        lda reu_fill_addr_hi
        sta $df05               ; REU address high
        lda reu_fill_bank
        sta $df06               ; REU bank
        
        lda #0
        sta $df07               ; length low (0 = 256)
        lda #1
        sta $df08               ; length high
        lda #0
        sta $df0a               ; increment both addresses
        
        lda #$90                ; stash with execute
        sta $df01
        
        ; Show progress every 1KB (4 x 256 bytes)
        lda reu_fill_addr_hi
        and #$03
        cmp #$03
        bne @rand_advance
        
        ; Increment KB counter
        inc reu_kb_counter
        bne +
        inc reu_kb_counter+1
+       jsr show_fill_progress
        
@rand_advance:
        inc reu_fill_addr_hi
        beq @rand_bank_wrap
        jmp @rand_fill_loop
        
@rand_bank_wrap:
        inc reu_fill_bank
        beq @complete           ; wrapped 255->0: all 256 banks done (16MB)
        
        ; For reu_banks=0 (256 banks), only the wrap above terminates
        lda reu_banks
        beq @rand_continue      ; 0 means 256 banks, keep going
        
        ; Normal case: check if we've passed the last bank
        lda reu_fill_bank
        cmp reu_banks
        beq @rand_continue      ; fill_bank == reu_banks: still need this bank
        bcc @rand_continue      ; fill_bank < reu_banks: more banks to go
        jmp @complete           ; fill_bank > reu_banks: done
        
@rand_continue:
        jmp @rand_fill_loop

; ---- Fast zero fill path (one DMA per 64KB bank) ----
@fast_zero_fill:
        ; Store a zero byte in a known location for the fixed-address DMA
        lda #0
        sta reu_zero_byte
        
@zero_bank_loop:
        ; Check for space bar to abort
        jsr getin
        cmp #$20
        bne @zero_not_aborted
        jmp @aborted
@zero_not_aborted:
        
        ; Set up DMA: fixed C64 address -> incrementing REU address
        ; C64 address: point to our zero byte
        lda #<reu_zero_byte
        sta $df02
        lda #>reu_zero_byte
        sta $df03
        
        ; REU address: start of current bank
        lda #0
        sta $df04               ; REU address low = 0
        sta $df05               ; REU address high = 0
        lda reu_fill_bank
        sta $df06               ; REU bank
        
        ; Transfer length: 0 = 64KB (entire bank)
        lda #0
        sta $df07               ; length low
        sta $df08               ; length high (0,0 = 65536 bytes)
        
        ; Address control: fix C64 address (bit 7), increment REU (bit 6=0)
        lda #$80
        sta $df0a
        
        ; Execute stash: the REC will read our single zero byte 65536 times
        ; while incrementing through the entire REU bank at ~1 byte/cycle
        lda #$90                ; stash with execute
        sta $df01
        
        ; Update KB counter: one bank = 64KB
        lda reu_kb_counter
        clc
        adc #64
        sta reu_kb_counter
        lda reu_kb_counter+1
        adc #0
        sta reu_kb_counter+1
        
        ; Show progress
        jsr show_fill_progress
        
        ; Next bank
        inc reu_fill_bank
        beq @complete           ; wrapped 255->0: all 256 banks done (16MB)
        
        ; For reu_banks=0 (256 banks), only the wrap above terminates
        lda reu_banks
        beq @zero_bank_cont     ; 0 means 256 banks, keep going
        
        ; Normal case: check if we've passed the last bank
        lda reu_fill_bank
        cmp reu_banks
        beq @zero_bank_cont     ; fill_bank == reu_banks: still need this bank
        bcc @zero_bank_cont     ; fill_bank < reu_banks: more banks to go
        jmp @complete           ; fill_bank > reu_banks: done
        
@zero_bank_cont:
        jmp @zero_bank_loop

@complete:
        ; Fill completed successfully
        clc                     ; carry clear = success
        rts
        
@aborted:
        ; User pressed space bar
        sec                     ; carry set = aborted
        rts

; =============================================================================
; show_fill_progress - display current KB / total KB progress
; =============================================================================
show_fill_progress:
        lda #$0d
        jsr chrout
        lda #<reu_progress_msg
        ldy #>reu_progress_msg
        jsr print_string
        
        lda reu_kb_counter
        sta zp_temp
        lda reu_kb_counter+1
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<reu_kb_of_msg
        ldy #>reu_kb_of_msg
        jsr print_string
        
        lda reu_size_kb
        sta zp_temp
        lda reu_size_kb+1
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<reu_kb_suffix2
        ldy #>reu_kb_suffix2
        jsr print_string
        rts

; Single zero byte for fixed-address DMA source
reu_zero_byte:
        !byte 0

; =============================================================================
; =============================================================================
; offer_save_reu_to_disk - prompt and save REU random data to disk
; Features:
;   - Prompts for drive number (default 8) and filename (default RNGFILL)
;   - Checks disk free blocks and whether file already exists
;   - If file exists: appends more random data until disk full
;   - If file doesn't exist: creates new sequential file
;   - If REU is smaller than disk: refills REU and continues writing
;   - Optimized write loop: checks I/O status once per 254-byte block
;     instead of per byte (~2x throughput vs per-byte status check)
; =============================================================================
offer_save_reu_to_disk:
        lda #<reu_save_prompt
        ldy #>reu_save_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'N'
        bne +
        jmp @no_save
+       cmp #'n'
        bne +
        jmp @no_save
+
        ; --- Prompt for drive number ---
        lda #<reu_drive_prompt
        ldy #>reu_drive_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #$0d                ; Enter = default 8
        beq @use_drive_8
        cmp #'9'
        beq @use_drive_9
        cmp #'1'
        beq @use_drive_10p
        ; Default to 8 for anything else
@use_drive_8:
        lda #8
        jmp @store_drive
@use_drive_9:
        lda #9
        jmp @store_drive
@use_drive_10p:
        ; Might be 10 or 11 -- read next digit
        jsr getin_wait
        cmp #'0'
        beq @drive_10
        cmp #'1'
        beq @drive_11
        lda #8                  ; fallback
        jmp @store_drive
@drive_10:
        lda #10
        jmp @store_drive
@drive_11:
        lda #11
@store_drive:
        sta save_drive_num
        
        ; Echo drive number
        pha
        lda save_drive_num
        jsr print_byte_decimal
        lda #$0d
        jsr chrout
        pla
        
        ; --- Prompt for filename ---
        lda #<reu_filename_prompt
        ldy #>reu_filename_prompt
        jsr print_string
        
        jsr get_input_line
        
        ; Check if empty input - use default "RNGFILL"
        lda input_index
        bne @have_filename
        
        ldx #0
@copy_default:
        lda default_save_filename,x
        beq @default_done
        sta filename_buf,x
        inx
        jmp @copy_default
@default_done:
        stx input_index
        
@have_filename:
        ; Copy filename for reuse (save the clean name before we modify it)
        ldx #0
@save_name:
        lda filename_buf,x
        sta rng_save_filename,x
        inx
        cpx input_index
        bne @save_name
        lda #0
        sta rng_save_filename,x
        lda input_index
        sta rng_save_namelen
        
        ; Echo filename
        lda #<rng_save_filename
        ldy #>rng_save_filename
        jsr print_string
        lda #$0d
        jsr chrout
        
        ; --- Check disk free blocks ---
        lda #<reu_checking_disk_msg
        ldy #>reu_checking_disk_msg
        jsr print_string
        
        jsr get_disk_free_blocks
        bcc @have_free_info
        jmp @disk_error
        
@have_free_info:
        ; Display free blocks
        lda #<reu_free_blocks_msg
        ldy #>reu_free_blocks_msg
        jsr print_string
        
        lda disk_free_lo
        sta zp_temp
        lda disk_free_hi
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<reu_blocks_suffix
        ldy #>reu_blocks_suffix
        jsr print_string
        
        ; Check if any free space
        lda disk_free_lo
        ora disk_free_hi
        bne @have_space
        jmp @no_space
@have_space:
        
        ; --- Check if file already exists ---
        jsr rng_check_file
        lda rng_file_exists
        beq @create_new_file
        
        ; File exists - offer to append
        lda #<rng_file_exists_msg
        ldy #>rng_file_exists_msg
        jsr print_string
        
        lda #<rng_append_prompt
        ldy #>rng_append_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'N'
        bne +
        jmp @no_save
+       cmp #'n'
        bne +
        jmp @no_save
+
        ; Open for append
        jsr open_append_file
        bcc @file_open
        jmp @open_error
        
@create_new_file:
        jsr open_new_file
        bcc @file_open
        jmp @open_error
        
@file_open:
        ; --- Main write loop: write REU to disk, refilling as needed ---
        lda #0
        sta reu_read_bank
        sta reu_read_addr_hi
        sta blocks_written_lo
        sta blocks_written_hi
        sta rng_pass_num
        sta rng_reu_exhausted
        
        lda #<reu_writing_msg
        ldy #>reu_writing_msg
        jsr print_string
        
@write_main_loop:
        ; Check for space bar to abort
        jsr getin
        cmp #$20
        bne +
        jmp @write_aborted_close
+
        ; Check if disk free blocks exhausted
        lda blocks_written_hi
        cmp disk_free_hi
        bcc @still_space
        bne +
        lda blocks_written_lo
        cmp disk_free_lo
        bcc @still_space
+       jmp @write_complete
        
@still_space:
        ; Check if REU is exhausted (read through all banks)
        lda rng_reu_exhausted
        beq @reu_has_data
        
        ; REU exhausted — refill with random and reset read pointer
        inc rng_pass_num
        
        lda #$0d
        jsr chrout
        lda #<rng_refilling_msg
        ldy #>rng_refilling_msg
        jsr print_string
        
        lda rng_pass_num
        clc
        adc #1
        jsr print_byte_decimal
        lda #<rng_pass_suffix
        ldy #>rng_pass_suffix
        jsr print_string
        
        ; Close file temporarily during REU fill (long operation)
        jsr close_save_file
        
        ; Refill REU with fresh random data (silent - no prompts)
        lda #1
        sta reu_fill_random
        jsr refill_reu_core
        ; Ignore abort during refill - we still need to reopen and continue
        
        ; Reopen file for append
        jsr open_append_file
        bcc +
        jmp @open_error
+
        ; Reset REU read pointer
        lda #0
        sta reu_read_bank
        sta reu_read_addr_hi
        sta rng_reu_exhausted
        
        jmp @write_main_loop
        
@reu_has_data:
        ; Fetch 254 bytes from REU to C64 buffer
        jsr fetch_block_from_reu
        
        ; Write buffer to file (optimized: status check once per block)
        jsr write_block_to_file
        bcs @write_error_close
        
        ; Increment block counter
        inc blocks_written_lo
        bne @show_write_progress
        inc blocks_written_hi
        
@show_write_progress:
        ; Show progress every 16 blocks to reduce screen I/O overhead
        lda blocks_written_lo
        and #$0f
        bne @write_main_loop
        
        lda #$0d
        jsr chrout
        lda #<reu_progress_msg
        ldy #>reu_progress_msg
        jsr print_string
        
        lda blocks_written_lo
        sta zp_temp
        lda blocks_written_hi
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<reu_of_msg
        ldy #>reu_of_msg
        jsr print_string
        
        lda disk_free_lo
        sta zp_temp
        lda disk_free_hi
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<reu_blocks_suffix
        ldy #>reu_blocks_suffix
        jsr print_string
        
        jmp @write_main_loop
        
@write_complete:
        jsr close_save_file
        lda #$0d
        jsr chrout
        lda #<reu_save_done_msg
        ldy #>reu_save_done_msg
        jsr print_string
        
        ; Show total written
        lda blocks_written_lo
        sta zp_temp
        lda blocks_written_hi
        sta zp_temp+1
        jsr print_decimal_word
        lda #<rng_blocks_written_msg
        ldy #>rng_blocks_written_msg
        jsr print_string
        
@no_save:
        rts
        
@write_aborted_close:
        jsr close_save_file
        lda #$0d
        jsr chrout
        lda #<reu_write_aborted_msg
        ldy #>reu_write_aborted_msg
        jsr print_string
        rts

@write_error_close:
        jsr close_save_file
        lda #$0d
        jsr chrout
        lda #<reu_write_error_msg
        ldy #>reu_write_error_msg
        jsr print_string
        rts
        
@disk_error:
        lda #<reu_disk_error_msg
        ldy #>reu_disk_error_msg
        jsr print_string
        rts
        
@no_space:
        lda #<reu_no_space_msg
        ldy #>reu_no_space_msg
        jsr print_string
        rts
        
@open_error:
        lda #<reu_open_error_msg
        ldy #>reu_open_error_msg
        jsr print_string
        rts

; =============================================================================
; rng_check_file - check if rng_save_filename exists on disk
; Sets rng_file_exists: 0=no, 1=yes
; Opens file for reading, then checks drive error channel (#15)
; =============================================================================
rng_check_file:
        lda #0
        sta rng_file_exists
        
        ; Ensure clean state
        jsr clrchn
        lda #4
        jsr close
        lda #15
        jsr close
        
        ; Build "0:filename,s,r"
        lda #$30                ; '0'
        sta chk_fname_buf
        lda #$3a                ; ':'
        sta chk_fname_buf+1
        
        ldx #0
@copy_name:
        cpx rng_save_namelen
        beq @add_suffix
        lda rng_save_filename,x
        sta chk_fname_buf+2,x
        inx
        cpx #16
        bne @copy_name
        
@add_suffix:
        txa
        clc
        adc #2
        tay
        lda #','
        sta chk_fname_buf,y
        iny
        lda #'S'
        sta chk_fname_buf,y
        iny
        lda #','
        sta chk_fname_buf,y
        iny
        lda #'R'
        sta chk_fname_buf,y
        iny
        sty chk_fname_len
        
        ; Try to open file for reading
        lda chk_fname_len
        ldx #<chk_fname_buf
        ldy #>chk_fname_buf
        jsr setnam
        
        lda #4                  ; file number 4
        ldx save_drive_num
        ldy #4                  ; secondary address
        jsr setlfs
        
        jsr open
        bcs @not_found          ; KERNAL-level open failed
        
        ; Open command channel to check drive error status
        lda #0                  ; no filename for command channel
        ldx #<chk_fname_buf    ; dummy pointer (length 0 means ignored)
        ldy #>chk_fname_buf
        jsr setnam
        
        lda #15                 ; file number 15
        ldx save_drive_num
        ldy #15                 ; secondary address 15 = command channel
        jsr setlfs
        
        jsr open
        bcs @close_file_not_found
        
        ; Read error code from command channel
        ldx #15
        jsr chkin
        bcs @close_all_not_found
        
        ; Read first two characters (error number, e.g. "00" or "62")
        jsr chrin
        sta chk_err_tens
        jsr chrin
        sta chk_err_ones
        
        ; Close command channel
        jsr clrchn
        lda #15
        jsr close
        
        ; Close data file
        lda #4
        jsr close
        
        ; Check error code: "00" = OK (file found), anything else = not found
        lda chk_err_tens
        cmp #$30                ; '0'
        bne @not_found_clean
        lda chk_err_ones
        cmp #$30                ; '0'
        bne @not_found_clean
        
        ; File exists
        lda #1
        sta rng_file_exists
        rts
        
@close_all_not_found:
        jsr clrchn
        lda #15
        jsr close
@close_file_not_found:
        jsr clrchn
        lda #4
        jsr close
@not_found:
@not_found_clean:
        lda #0
        sta rng_file_exists
        rts

chk_fname_buf:
        !fill 32, 0
chk_fname_len:
        !byte 0
chk_err_tens:
        !byte 0
chk_err_ones:
        !byte 0

; =============================================================================
; open_new_file - open new sequential file for writing
; =============================================================================
open_new_file:
        ; Ensure clean I/O state
        jsr clrchn
        lda #2
        jsr close
        
        ; Build "0:filename,s,w"
        lda #$30                ; '0'
        sta write_fname_buf2
        lda #$3a                ; ':'
        sta write_fname_buf2+1
        
        ldx #0
@copy:
        cpx rng_save_namelen
        beq @add_suffix
        lda rng_save_filename,x
        sta write_fname_buf2+2,x
        inx
        cpx #16
        bne @copy
        
@add_suffix:
        txa
        clc
        adc #2
        tay
        lda #','
        sta write_fname_buf2,y
        iny
        lda #'S'
        sta write_fname_buf2,y
        iny
        lda #','
        sta write_fname_buf2,y
        iny
        lda #'W'
        sta write_fname_buf2,y
        iny
        sty write_fname_len2
        
        lda #2                  ; file number
        ldx save_drive_num
        ldy #2                  ; secondary address for write
        jsr setlfs
        
        lda write_fname_len2
        ldx #<write_fname_buf2
        ldy #>write_fname_buf2
        jsr setnam
        
        jsr open
        bcs @error
        
        ldx #2
        jsr chkout
        bcs @close_error
        
        clc
        rts
        
@close_error:
        lda #2
        jsr close
@error:
        sec
        rts

write_fname_buf2:
        !fill 32, 0
write_fname_len2:
        !byte 0

; =============================================================================
; open_append_file - open existing sequential file for append
; Uses DOS command "0:filename,s,a"
; =============================================================================
open_append_file:
        ; Ensure clean I/O state
        jsr clrchn
        lda #2
        jsr close
        
        ; Build "0:filename,s,a"
        lda #$30                ; '0'
        sta write_fname_buf2
        lda #$3a                ; ':'
        sta write_fname_buf2+1
        
        ldx #0
@copy:
        cpx rng_save_namelen
        beq @add_suffix
        lda rng_save_filename,x
        sta write_fname_buf2+2,x
        inx
        cpx #16
        bne @copy
        
@add_suffix:
        txa
        clc
        adc #2
        tay
        lda #','
        sta write_fname_buf2,y
        iny
        lda #'S'
        sta write_fname_buf2,y
        iny
        lda #','
        sta write_fname_buf2,y
        iny
        lda #'A'                ; Append mode
        sta write_fname_buf2,y
        iny
        sty write_fname_len2
        
        lda #2                  ; file number
        ldx save_drive_num
        ldy #2                  ; secondary address
        jsr setlfs
        
        lda write_fname_len2
        ldx #<write_fname_buf2
        ldy #>write_fname_buf2
        jsr setnam
        
        jsr open
        bcs @error
        
        ldx #2
        jsr chkout
        bcs @close_error
        
        clc
        rts
        
@close_error:
        lda #2
        jsr close
@error:
        sec
        rts

; =============================================================================
; print_byte_decimal - print A as 1-3 digit decimal number
; =============================================================================
print_byte_decimal:
        sta pb_val
        lda #0
        sta pb_leading
        
        ; Hundreds
        ldx #0
        lda pb_val
@hundreds:
        cmp #100
        bcc @tens
        sec
        sbc #100
        inx
        jmp @hundreds
@tens:
        sta pb_val
        cpx #0
        beq @skip_hundreds
        txa
        clc
        adc #'0'
        jsr chrout
        lda #1
        sta pb_leading
@skip_hundreds:
        
        ; Tens
        ldx #0
        lda pb_val
@tens_loop:
        cmp #10
        bcc @ones
        sec
        sbc #10
        inx
        jmp @tens_loop
@ones:
        sta pb_val
        cpx #0
        bne @print_tens
        lda pb_leading
        beq @skip_tens
@print_tens:
        txa
        clc
        adc #'0'
        jsr chrout
@skip_tens:
        
        ; Ones (always print)
        lda pb_val
        clc
        adc #'0'
        jsr chrout
        rts

pb_val:     !byte 0
pb_leading: !byte 0

; =============================================================================
; get_disk_free_blocks - read directory to get free blocks
; Robust version: clears channels, closes stale handles before starting
; =============================================================================
get_disk_free_blocks:
        ; Ensure clean KERNAL I/O state
        jsr clrchn
        
        ; Close any stale file #1 (ignore errors)
        lda #1
        jsr close
        
        ; Open directory
        lda #1                  ; file number
        ldx save_drive_num
        ldy #0                  ; secondary address
        jsr setlfs
        
        lda #1
        ldx #<dir_name
        ldy #>dir_name
        jsr setnam
        
        jsr open
        bcs @error
        
        ldx #1
        jsr chkin
        bcs @close_error
        
        ; Skip first two bytes (load address)
        jsr chrin
        jsr chrin
        
        ; Read directory lines
        ; Format: link_lo, link_hi, blk_lo, blk_hi, text..., $00
        ; Last useful line is "BLOCKS FREE" whose block count = free blocks
@read_loop:
        ; Read link bytes
        jsr chrin
        sta dir_link_lo
        jsr readst
        and #$40
        bne @use_last           ; EOF before we got link = use last count
        
        jsr chrin
        sta dir_link_hi
        jsr readst
        and #$40
        bne @use_last
        
        ; Read block count (16-bit little-endian line number)
        jsr chrin
        sta disk_free_lo        ; overwrite each time; final = free blocks
        jsr readst
        and #$40
        bne @use_last
        
        jsr chrin
        sta disk_free_hi
        jsr readst
        and #$40
        bne @use_last
        
        ; Skip rest of line until null terminator
@skip_line:
        jsr chrin
        pha
        jsr readst
        and #$40
        bne @eof_in_line
        pla
        cmp #0
        bne @skip_line
        jmp @read_loop
        
@eof_in_line:
        pla                     ; discard stacked byte

@use_last:
        ; disk_free_lo/hi holds the last line's block count = free blocks
        jsr clrchn
        lda #1
        jsr close
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #1
        jsr close
@error:
        sec
        rts

dir_name:
        !text "$"

dir_link_lo:
        !byte 0
dir_link_hi:
        !byte 0

; =============================================================================
; close_save_file - close the output file and clear channel
; =============================================================================
close_save_file:
        jsr clrchn
        lda #2
        jsr close
        rts

; =============================================================================
; fetch_block_from_reu - DMA fetch 254 bytes from REU to buffer
; Sets rng_reu_exhausted=1 when all banks have been read
; =============================================================================
fetch_block_from_reu:
        ; Set up DMA transfer
        lda #<reu_zero_buffer
        sta $df02               ; C64 address low
        lda #>reu_zero_buffer
        sta $df03               ; C64 address high
        
        lda #0
        sta $df04               ; REU address low
        lda reu_read_addr_hi
        sta $df05               ; REU address high
        lda reu_read_bank
        sta $df06               ; REU bank
        
        lda #254                ; block size (1541 sector data = 254 bytes)
        sta $df07
        lda #0
        sta $df08
        sta $df0a               ; increment both addresses
        
        lda #$91                ; fetch with execute
        sta $df01
        
        ; Advance REU read pointer by one page (256 bytes, wastes 2)
        inc reu_read_addr_hi
        bne @no_bank_wrap
        
        ; Wrapped past end of bank
        inc reu_read_bank
        beq @reu_done           ; wrapped 255->0: all 256 banks read (16MB)
        
        ; For reu_banks=0 (256 banks), only the wrap above exhausts
        lda reu_banks
        beq @no_bank_wrap       ; 0 means 256 banks, keep going
        
        ; Normal case: check if we've read past the last bank
        lda reu_read_bank
        cmp reu_banks
        beq @no_bank_wrap       ; read_bank == reu_banks: still valid
        bcc @no_bank_wrap       ; read_bank < reu_banks: still valid
        
@reu_done:
        ; REU exhausted
        lda #1
        sta rng_reu_exhausted
        
@no_bank_wrap:
        rts

; =============================================================================
; write_block_to_file - write 254 bytes from buffer to file
; Status check: only bit 7 (device not present) is fatal.
; Bits 0/1 (serial bus timeout) are transient — KERNAL chrout handles
; retries internally. These bits accumulate across the 254 chrout calls
; and will eventually trigger false errors during extended writes,
; especially on 1581 which has variable seek times.
; =============================================================================
write_block_to_file:
        ldx #2                  ; reselect output channel
        jsr chkout
        bcs @error
        
        ldx #0
@write_byte:
        lda reu_zero_buffer,x
        jsr chrout
        inx
        cpx #254
        bne @write_byte
        
        ; Check status — only device-not-present is fatal
        jsr readst
        and #$80                ; bit 7 only: device not present
        bne @error
        
        clc
        rts
        
@error:
        sec
        rts

; Variables for disk save
save_drive_num:
        !byte 8
disk_free_lo:
        !byte 0
disk_free_hi:
        !byte 0
blocks_written_lo:
        !byte 0
blocks_written_hi:
        !byte 0
reu_read_bank:
        !byte 0
reu_read_addr_hi:
        !byte 0
rng_file_exists:
        !byte 0
rng_reu_exhausted:
        !byte 0
rng_pass_num:
        !byte 0
rng_save_namelen:
        !byte 0
rng_save_filename:
        !fill 18, 0

default_save_filename:
        !text "RNGFILL"
        !byte 0

; =============================================================================
; prepare_fill_buffer - fill 256-byte buffer with zeros or random
; Buffer size of 256 bytes is optimal: DMA setup overhead is ~30 cycles
; per stash vs ~100 cycles/byte for PRNG generation, so DMA cost is <2%
; regardless of buffer size. 256 bytes also aligns with REU page size.
; =============================================================================
prepare_fill_buffer:
        lda reu_fill_random
        bne @random_fill
        
        ; Zero fill
        ldx #0
        lda #0
@zero_loop:
        sta reu_zero_buffer,x
        inx
        bne @zero_loop
        rts
        
@random_fill:
        ; Random fill using PRNG - optimized loop
        ; lfsr_random returns byte in A, doesn't need X preserved
        lda #0
        sta fill_buf_idx
@random_loop:
        jsr lfsr_random         ; returns random byte in A
        ldx fill_buf_idx
        sta reu_zero_buffer,x
        inc fill_buf_idx
        bne @random_loop
        rts

fill_buf_idx:
        !byte 0

; Variables for REU fill
reu_fill_bank:
        !byte 0
reu_fill_addr_hi:
        !byte 0
reu_total_banks:
        !byte 0
reu_fill_random:
        !byte 0
reu_kb_counter:
        !word 0

; 256-byte buffer for REU operations
reu_zero_buffer:
        !fill 256, 0

; =============================================================================
; getin_wait - wait for a keypress
; =============================================================================
getin_wait:
        jsr getin
        cmp #0
        beq getin_wait
        rts

; =============================================================================
; do_config_sid - configure additional SID chips for PRNG
; =============================================================================
do_config_sid:
        lda #$0d
        jsr chrout
        
        lda #<sid_config_header
        ldy #>sid_config_header
        jsr print_string
        
        ; Show current config
        lda #<sid_current_msg
        ldy #>sid_current_msg
        jsr print_string
        
        lda extra_sid_count
        clc
        adc #1                  ; +1 for main SID
        clc
        adc #$30
        jsr chrout
        
        lda #<sid_chips_msg
        ldy #>sid_chips_msg
        jsr print_string
        
        ; Ask about extra SIDs
        lda #<sid_extra_prompt
        ldy #>sid_extra_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'N'
        beq @no_extra
        cmp #'n'
        beq @no_extra
        
        ; User wants extra SIDs - ask for addresses
        lda #$0d
        jsr chrout
        lda #<sid_addr_prompt
        ldy #>sid_addr_prompt
        jsr print_string
        
        ; Get input line
        jsr get_input_line
        
        ; Check if empty - use default $D420
        lda input_index
        bne @parse_addresses
        
        ; Default: one extra SID at $D420
        lda #1
        sta extra_sid_count
        lda #$20
        sta extra_sid_lo
        lda #$d4
        sta extra_sid_hi
        jmp @init_extra_sids
        
@parse_addresses:
        ; Parse comma-delimited hex addresses
        jsr parse_sid_addresses
        jmp @init_extra_sids
        
@no_extra:
        lda #0
        sta extra_sid_count
        jmp @done
        
@init_extra_sids:
        ; Play trumpet sound for each SID before initializing
        jsr play_sid_trumpets
        
        ; Initialize extra SID chips for noise
        jsr init_extra_sids
        
@done:
        lda #$0d
        jsr chrout
        lda #<sid_configured_msg
        ldy #>sid_configured_msg
        jsr print_string
        
        ; Show configured count
        lda extra_sid_count
        clc
        adc #1
        clc
        adc #$30
        jsr chrout
        
        lda #<sid_chips_msg
        ldy #>sid_chips_msg
        jsr print_string
        
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; play_sid_trumpets - play trumpet sound on each SID
; Quarter second sound with quarter second pause, incrementing pitch
; =============================================================================
play_sid_trumpets:
        ; Play 1 note on main SID
        lda #0
        sta trumpet_sid_num
        lda #1
        sta trumpet_note_count
        jsr play_trumpet_notes_main
        
        ; Play N+1 notes on each extra SID (2 on SID2, 3 on SID3, 4 on SID4)
        ldx #0
@trumpet_loop:
        cpx extra_sid_count
        bcs @trumpets_done
        
        stx trumpet_sid_num
        
        ; Note count = sid_num + 2 (SID 2 gets 2 notes, SID 3 gets 3, etc)
        txa
        clc
        adc #2
        sta trumpet_note_count
        
        txa
        pha
        jsr play_trumpet_notes_extra
        pla
        tax
        inx
        jmp @trumpet_loop
        
@trumpets_done:
        rts

; =============================================================================
; play_trumpet_notes_main - play multiple trumpet notes on main SID
; trumpet_note_count = number of notes to play
; =============================================================================
play_trumpet_notes_main:
        lda #0
        sta trumpet_current_note
        
@note_loop:
        lda trumpet_current_note
        cmp trumpet_note_count
        bcs @notes_done
        
        ; Set up voice 1 for trumpet-like sound
        lda #$09                ; attack=0, decay=9
        sta $d405
        lda #$a0                ; sustain=10, release=0
        sta $d406
        
        ; Set frequency - higher for each note
        lda trumpet_current_note
        asl
        asl
        asl
        asl
        asl                     ; * 32
        sta $d400               ; freq lo
        
        lda trumpet_current_note
        lsr
        lsr
        lsr
        clc
        adc #$10                ; base frequency high
        sta $d401               ; freq hi
        
        ; Pulse width for brass sound
        lda #$00
        sta $d402
        lda #$08
        sta $d403
        
        ; Volume
        lda #$0f
        sta $d418
        
        ; Gate on with pulse waveform
        lda #$41
        sta $d404
        
        ; Wait quarter second
        jsr wait_quarter_sec
        
        ; Gate off
        lda #$40
        sta $d404
        
        ; Wait quarter second pause
        jsr wait_quarter_sec
        
        inc trumpet_current_note
        jmp @note_loop
        
@notes_done:
        rts

; =============================================================================
; play_trumpet_notes_extra - play multiple trumpet notes on extra SID
; trumpet_sid_num = which extra SID (0-2)
; trumpet_note_count = number of notes to play
; =============================================================================
play_trumpet_notes_extra:
        ; Get SID base address
        ldx trumpet_sid_num
        lda extra_sid_lo,x
        sta zp_ptr
        lda extra_sid_hi,x
        sta zp_ptr+1
        
        lda #0
        sta trumpet_current_note
        
@note_loop:
        lda trumpet_current_note
        cmp trumpet_note_count
        bcs @notes_done
        
        ; Set up voice 1 for trumpet-like sound
        ldy #$05                ; Attack/Decay
        lda #$09
        sta (zp_ptr),y
        
        ldy #$06                ; Sustain/Release
        lda #$a0
        sta (zp_ptr),y
        
        ; Set frequency - higher for each note
        lda trumpet_current_note
        asl
        asl
        asl
        asl
        asl
        ldy #$00
        sta (zp_ptr),y          ; freq lo
        
        lda trumpet_current_note
        lsr
        lsr
        lsr
        clc
        adc #$10
        ldy #$01
        sta (zp_ptr),y          ; freq hi
        
        ; Pulse width
        ldy #$02
        lda #$00
        sta (zp_ptr),y
        ldy #$03
        lda #$08
        sta (zp_ptr),y
        
        ; Volume
        ldy #$18
        lda #$0f
        sta (zp_ptr),y
        
        ; Gate on
        ldy #$04
        lda #$41
        sta (zp_ptr),y
        
        ; Wait quarter second
        jsr wait_quarter_sec
        
        ; Gate off
        ldy #$04
        lda #$40
        sta (zp_ptr),y
        
        ; Wait quarter second pause
        jsr wait_quarter_sec
        
        inc trumpet_current_note
        jmp @note_loop
        
@notes_done:
        rts

; =============================================================================
; wait_quarter_sec - wait approximately 250ms (15 jiffies at 60Hz)
; =============================================================================
wait_quarter_sec:
        lda $a2
        clc
        adc #15
        sta wait_target
@wait_loop:
        lda $a2
        cmp wait_target
        bne @wait_loop
        rts

wait_target:
        !byte 0
trumpet_sid_num:
        !byte 0
trumpet_note_count:
        !byte 0
trumpet_current_note:
        !byte 0

; =============================================================================
; parse_sid_addresses - parse up to 3 hex addresses from input
; Format: D420,D440,D460 or just D420
; =============================================================================
parse_sid_addresses:
        lda #0
        sta extra_sid_count
        sta parse_idx
        
@parse_loop:
        ; Check if we have 3 already
        lda extra_sid_count
        cmp #3
        bcs @parse_done
        
        ; Skip spaces and commas
@skip_delim:
        ldx parse_idx
        cpx input_index
        bcs @parse_done
        lda filename_buf,x
        cmp #' '
        beq @next_char
        cmp #','
        beq @next_char
        jmp @got_hex_start
        
@next_char:
        inc parse_idx
        jmp @skip_delim
        
@got_hex_start:
        ; Parse 4-digit hex address
        ; First two digits = high byte
        jsr parse_hex_byte
        bcs @parse_done         ; error
        sta zp_temp+1           ; high byte
        
        ; Next two digits = low byte
        jsr parse_hex_byte
        bcs @parse_done
        sta zp_temp             ; low byte
        
        ; Store in extra_sid arrays
        ldx extra_sid_count
        lda zp_temp
        sta extra_sid_lo,x
        lda zp_temp+1
        sta extra_sid_hi,x
        
        inc extra_sid_count
        jmp @parse_loop
        
@parse_done:
        rts

; =============================================================================
; parse_hex_byte - parse 2 hex digits from filename_buf at parse_idx
; Returns: A = byte value, carry clear on success
; =============================================================================
parse_hex_byte:
        ldx parse_idx
        cpx input_index
        bcs @error
        
        ; First digit
        lda filename_buf,x
        jsr hex_digit_value
        bcs @error
        asl
        asl
        asl
        asl
        sta zp_temp
        inc parse_idx
        
        ; Second digit
        ldx parse_idx
        cpx input_index
        bcs @error
        lda filename_buf,x
        jsr hex_digit_value
        bcs @error
        ora zp_temp
        inc parse_idx
        clc
        rts
        
@error:
        sec
        rts

; =============================================================================
; hex_digit_value - convert hex digit to value
; Input: A = ASCII character
; Output: A = 0-15, carry clear on success
; =============================================================================
hex_digit_value:
        cmp #'0'
        bcc @not_digit
        cmp #'9'+1
        bcs @try_upper
        sec
        sbc #'0'
        clc
        rts
        
@try_upper:
        cmp #'A'
        bcc @try_lower
        cmp #'F'+1
        bcs @try_lower
        sec
        sbc #'A'-10
        clc
        rts
        
@try_lower:
        cmp #'a'
        bcc @not_digit
        cmp #'f'+1
        bcs @not_digit
        sec
        sbc #'a'-10
        clc
        rts
        
@not_digit:
        sec
        rts

; =============================================================================
; init_extra_sids - initialize extra SID chips for noise generation
; =============================================================================
init_extra_sids:
        ldx #0
@init_loop:
        cpx extra_sid_count
        bcs @init_done
        
        ; Get SID base address
        lda extra_sid_lo,x
        sta zp_ptr
        lda extra_sid_hi,x
        sta zp_ptr+1
        
        ; Set voice 3 to noise waveform
        ldy #$0e                ; voice 3 freq low
        lda #$ff
        sta (zp_ptr),y
        iny                     ; voice 3 freq high
        sta (zp_ptr),y
        
        ldy #$12                ; voice 3 control
        lda #$80                ; noise waveform
        sta (zp_ptr),y
        
        inx
        jmp @init_loop
        
@init_done:
        rts

; =============================================================================
; do_random_stream - measure and display PRNG throughput
; Shows actual bytes generated per second from PRNG
; =============================================================================
do_random_stream:
        lda #$0d
        jsr chrout
        
        ; Clear screen
        lda #$93
        jsr chrout
        
        lda #<random_stream_header
        ldy #>random_stream_header
        jsr print_string
        
        ; Show SID configuration
        lda #<stream_sids_msg
        ldy #>stream_sids_msg
        jsr print_string
        
        lda extra_sid_count
        clc
        adc #1                  ; +1 for main SID
        clc
        adc #'0'
        jsr chrout
        
        lda #<stream_sids_suffix
        ldy #>stream_sids_suffix
        jsr print_string
        
        ; Initialize counters
        lda #0
        sta stream_bytes_lo
        sta stream_bytes_mid
        sta stream_rate_lo
        sta stream_rate_hi
        sta stream_jiffy_count
        
        ; Show header
        lda #$0d
        jsr chrout
        lda #<stream_live_header
        ldy #>stream_live_header
        jsr print_string
        
        ; Record start jiffy
        lda $a2
        sta stream_rate_jiffy
        
@stream_loop:
        ; Check for space bar
        jsr getin
        cmp #$20
        beq @stream_done
        
        ; Generate one random byte
        jsr lfsr_random
        
        ; Increment 16-bit counter
        inc stream_bytes_lo
        bne @check_jiffy
        inc stream_bytes_mid
        
@check_jiffy:
        ; Check if jiffy changed
        lda $a2
        cmp stream_rate_jiffy
        beq @stream_loop
        
        ; Jiffy changed - update
        sta stream_rate_jiffy
        inc stream_jiffy_count
        
        ; Check if 60 jiffies (1 second)
        lda stream_jiffy_count
        cmp #60
        bcc @stream_loop
        
        ; One second elapsed
        lda #0
        sta stream_jiffy_count
        
        ; Copy bytes to rate
        lda stream_bytes_lo
        sta stream_rate_lo
        lda stream_bytes_mid
        sta stream_rate_hi
        
        ; Display rate
        jsr display_stream_rate
        
        ; Reset byte counter
        lda #0
        sta stream_bytes_lo
        sta stream_bytes_mid
        
        jmp @stream_loop
        
@stream_done:
        lda #$0d
        jsr chrout
        lda #<stream_stopped_msg
        ldy #>stream_stopped_msg
        jsr print_string
        
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

stream_jiffy_count:
        !byte 0

; =============================================================================
; display_stream_rate - show current PRNG rate
; =============================================================================
display_stream_rate:
        ; Position at rate display line
        lda #$13                ; home
        jsr chrout
        ldx #5                  ; line 6
@down:
        lda #$11
        jsr chrout
        dex
        bne @down
        
        ; Print rate label
        lda #<stream_rate_label
        ldy #>stream_rate_label
        jsr print_string
        
        ; Print rate value
        lda stream_rate_lo
        sta zp_temp
        lda stream_rate_hi
        sta zp_temp+1
        jsr print_decimal_word
        
        lda #<stream_bps_msg
        ldy #>stream_bps_msg
        jsr print_string
        
        ; Clear rest of line
        lda #' '
        jsr chrout
        jsr chrout
        jsr chrout
        jsr chrout
        jsr chrout
        jsr chrout
        
        ; Show sample bytes on next line
        lda #$0d
        jsr chrout
        lda #<stream_sample_msg
        ldy #>stream_sample_msg
        jsr print_string
        
        jsr lfsr_random
        jsr print_hex_byte
        
        lda #' '
        jsr chrout
        jsr lfsr_random
        jsr print_hex_byte
        
        lda #' '
        jsr chrout
        jsr lfsr_random
        jsr print_hex_byte
        
        lda #' '
        jsr chrout
        jsr lfsr_random
        jsr print_hex_byte
        
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
; multi_sid_random - get random byte using all configured SIDs
; Combines output from main SID and extra SIDs via XOR
; =============================================================================
multi_sid_random:
        ; Start with main LFSR random
        jsr lfsr_random
        sta zp_temp
        
        ; XOR with extra SID oscillators if configured
        ldx extra_sid_count
        beq @done
        
        dex
@extra_loop:
        ; Get extra SID base
        lda extra_sid_lo,x
        sta zp_ptr
        lda extra_sid_hi,x
        sta zp_ptr+1
        
        ; Read oscillator 3 output ($1B offset)
        ldy #$1b
        lda (zp_ptr),y
        eor zp_temp
        sta zp_temp
        
        dex
        bpl @extra_loop
        
@done:
        lda zp_temp
        rts

; Variables for SID config
extra_sid_count:
        !byte 0                 ; number of extra SIDs (0-3)
extra_sid_lo:
        !byte 0, 0, 0           ; low bytes of extra SID addresses
extra_sid_hi:
        !byte 0, 0, 0           ; high bytes of extra SID addresses
parse_idx:
        !byte 0

; Variables for random stream
stream_bytes_lo:
        !byte 0
stream_bytes_mid:
        !byte 0
stream_rate_jiffy:
        !byte 0
stream_rate_lo:
        !byte 0
stream_rate_hi:
        !byte 0

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
        !byte 0
dec_print_started:
        !byte 0

; =============================================================================
; do_calc_sha256 - calculate SHA-256 hash of input text
; =============================================================================
do_calc_sha256:
        lda #$0d
        jsr chrout
        
        ; check if there's input text
        lda input_length
        bne @has_input
        
        lda #<no_input_hash_msg
        ldy #>no_input_hash_msg
        jsr print_string
        jmp @done
        
@has_input:
        ; show what we're hashing
        lda #<hashing_msg
        ldy #>hashing_msg
        jsr print_string
        
        ; display input text
        ldx #0
@print_input:
        cpx input_length
        beq @print_done
        lda input_buffer,x
        jsr chrout
        inx
        cpx #40                 ; max display width
        bcc @print_input
@print_done:
        lda #$0d
        jsr chrout
        
        ; calculate SHA-256
        lda #<calculating_msg
        ldy #>calculating_msg
        jsr print_string
        
        jsr sha256_init
        jsr sha256_update
        jsr sha256_final
        
        ; display the hash
        lda #<hash_result_msg
        ldy #>hash_result_msg
        jsr print_string
        
        lda #<sha256_hash
        sta zp_ptr
        lda #>sha256_hash
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; SHA-256 Implementation
; =============================================================================

; SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
sha256_h0_init:
        !byte $6a, $09, $e6, $67
sha256_h1_init:
        !byte $bb, $67, $ae, $85
sha256_h2_init:
        !byte $3c, $6e, $f3, $72
sha256_h3_init:
        !byte $a5, $4f, $f5, $3a
sha256_h4_init:
        !byte $51, $0e, $52, $7f
sha256_h5_init:
        !byte $9b, $05, $68, $8c
sha256_h6_init:
        !byte $1f, $83, $d9, $ab
sha256_h7_init:
        !byte $5b, $e0, $cd, $19

; SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
sha256_k:
        !byte $42, $8a, $2f, $98, $71, $37, $44, $91, $b5, $c0, $fb, $cf, $e9, $b5, $db, $a5
        !byte $39, $56, $c2, $5b, $59, $f1, $11, $f1, $92, $3f, $82, $a4, $ab, $1c, $5e, $d5
        !byte $d8, $07, $aa, $98, $12, $83, $5b, $01, $24, $31, $85, $be, $55, $0c, $7d, $c3
        !byte $72, $be, $5d, $74, $80, $de, $b1, $fe, $9b, $dc, $06, $a7, $c1, $9b, $f1, $74
        !byte $e4, $9b, $69, $c1, $ef, $be, $47, $86, $0f, $c1, $9d, $c6, $24, $0c, $a1, $cc
        !byte $2d, $e9, $2c, $6f, $4a, $74, $84, $aa, $5c, $b0, $a9, $dc, $76, $f9, $88, $da
        !byte $98, $3e, $51, $52, $a8, $31, $c6, $6d, $b0, $03, $27, $c8, $bf, $59, $7f, $c7
        !byte $c6, $e0, $0b, $f3, $d5, $a7, $91, $47, $06, $ca, $63, $51, $14, $29, $29, $67
        !byte $27, $b7, $0a, $85, $2e, $1b, $21, $38, $4d, $2c, $6d, $fc, $53, $38, $0d, $13
        !byte $65, $0a, $73, $54, $76, $6a, $0a, $bb, $81, $c2, $c9, $2e, $92, $72, $2c, $85
        !byte $a2, $bf, $e8, $a1, $a8, $1a, $66, $4b, $c2, $4b, $8b, $70, $c7, $6c, $51, $a3
        !byte $d1, $92, $e8, $19, $d6, $99, $06, $24, $f4, $0e, $35, $85, $10, $6a, $a0, $70
        !byte $19, $a4, $c1, $16, $1e, $37, $6c, $08, $27, $48, $77, $4c, $34, $b0, $bc, $b5
        !byte $39, $1c, $0c, $b3, $4e, $d8, $aa, $4a, $5b, $9c, $ca, $4f, $68, $2e, $6f, $f3
        !byte $74, $8f, $82, $ee, $78, $a5, $63, $6f, $84, $c8, $78, $14, $8c, $c7, $02, $08
        !byte $90, $be, $ff, $fa, $a4, $50, $6c, $eb, $be, $f9, $a3, $f7, $c6, $71, $78, $f2

; =============================================================================
; sha256_init - initialize hash state
; =============================================================================
sha256_init:
        ; copy initial hash values to working state
        ldx #0
@copy_h:
        lda sha256_h0_init,x
        sta sha256_h0,x
        lda sha256_h1_init,x
        sta sha256_h1,x
        lda sha256_h2_init,x
        sta sha256_h2,x
        lda sha256_h3_init,x
        sta sha256_h3,x
        lda sha256_h4_init,x
        sta sha256_h4,x
        lda sha256_h5_init,x
        sta sha256_h5,x
        lda sha256_h6_init,x
        sta sha256_h6,x
        lda sha256_h7_init,x
        sta sha256_h7,x
        inx
        cpx #4
        bne @copy_h
        
        ; clear message length
        lda #0
        sta sha256_len
        sta sha256_len+1
        rts

; =============================================================================
; sha256_update - process input_buffer with input_length bytes
; =============================================================================
sha256_update:
        ; store message length in bits (length * 8)
        lda input_length
        sta sha256_len
        lda #0
        sta sha256_len+1
        
        ; multiply by 8 (shift left 3)
        asl sha256_len
        rol sha256_len+1
        asl sha256_len
        rol sha256_len+1
        asl sha256_len
        rol sha256_len+1
        
        ; copy input to message block and pad
        ; clear block first
        ldx #0
        lda #0
@clear_block:
        sta sha256_block,x
        inx
        cpx #64
        bne @clear_block
        
        ; copy input data
        ldx #0
@copy_input:
        cpx input_length
        beq @add_padding
        lda input_buffer,x
        sta sha256_block,x
        inx
        cpx #64
        bcc @copy_input
        
@add_padding:
        ; add 0x80 byte after message
        lda #$80
        sta sha256_block,x
        
        ; if message is 55 bytes or less, length fits in this block
        ; otherwise we'd need two blocks (not implemented for simplicity)
        lda input_length
        cmp #56
        bcs @need_extra_block
        
        ; add length at end of block (big endian, 64-bit)
        ; we only support up to 255 bytes, so just use low 16 bits
        lda sha256_len+1
        sta sha256_block+62
        lda sha256_len
        sta sha256_block+63
        
        ; process the block
        jsr sha256_process_block
        rts
        
@need_extra_block:
        ; for messages >= 56 bytes, need two blocks
        ; process first block (message + padding)
        jsr sha256_process_block
        
        ; clear second block
        ldx #0
        lda #0
@clear_block2:
        sta sha256_block,x
        inx
        cpx #64
        bne @clear_block2
        
        ; add length at end
        lda sha256_len+1
        sta sha256_block+62
        lda sha256_len
        sta sha256_block+63
        
        ; process second block
        jsr sha256_process_block
        rts

; =============================================================================
; sha256_final - copy hash state to output
; =============================================================================
sha256_final:
        ; copy hash values to output (big endian)
        ldx #0
@copy:
        lda sha256_h0,x
        sta sha256_hash,x
        lda sha256_h1,x
        sta sha256_hash+4,x
        lda sha256_h2,x
        sta sha256_hash+8,x
        lda sha256_h3,x
        sta sha256_hash+12,x
        lda sha256_h4,x
        sta sha256_hash+16,x
        lda sha256_h5,x
        sta sha256_hash+20,x
        lda sha256_h6,x
        sta sha256_hash+24,x
        lda sha256_h7,x
        sta sha256_hash+28,x
        inx
        cpx #4
        bne @copy
        rts

; =============================================================================
; sha256_process_block - process one 64-byte block
; =============================================================================
sha256_process_block:
        ; prepare message schedule W[0..63]
        ; W[0..15] = block words (big endian)
        ldx #0
@copy_w:
        lda sha256_block,x
        sta sha256_w,x
        inx
        cpx #64
        bne @copy_w
        
        ; W[16..63] = computed from previous words
        lda #16
        sta sha256_round
        
@compute_w:
        ; w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16]
        
        ; get w[i-2] and compute sig1
        lda sha256_round
        sec
        sbc #2
        asl
        asl
        tax
        jsr sha256_load_word    ; load w[i-2] to sha_temp1
        jsr sha256_sig1         ; result in sha_temp1
        
        ; add w[i-7]
        lda sha256_round
        sec
        sbc #7
        asl
        asl
        tax
        jsr sha256_load_word_to_temp2
        jsr sha256_add_temp2_to_temp1
        
        ; add sig0(w[i-15])
        lda sha256_round
        sec
        sbc #15
        asl
        asl
        tax
        jsr sha256_load_word    ; to sha_temp1... wait, that overwrites
        ; need to save current sum first
        ldx #0
@save_sum:
        lda sha_temp1,x
        sta sha_temp3,x
        inx
        cpx #4
        bne @save_sum
        
        lda sha256_round
        sec
        sbc #15
        asl
        asl
        tax
        jsr sha256_load_word
        jsr sha256_sig0
        
        ; add saved sum back
        ldx #0
@add_sum:
        lda sha_temp3,x
        sta sha_temp2,x
        inx
        cpx #4
        bne @add_sum
        jsr sha256_add_temp2_to_temp1
        
        ; add w[i-16]
        lda sha256_round
        sec
        sbc #16
        asl
        asl
        tax
        jsr sha256_load_word_to_temp2
        jsr sha256_add_temp2_to_temp1
        
        ; store result as w[i]
        lda sha256_round
        asl
        asl
        tax
        ldy #0
@store_w:
        lda sha_temp1,y
        sta sha256_w,x
        inx
        iny
        cpy #4
        bne @store_w
        
        inc sha256_round
        lda sha256_round
        cmp #64
        bcs @w_done
        jmp @compute_w
@w_done:
        
        ; initialize working variables
        ldx #0
@init_working:
        lda sha256_h0,x
        sta sha_a,x
        lda sha256_h1,x
        sta sha_b,x
        lda sha256_h2,x
        sta sha_c,x
        lda sha256_h3,x
        sta sha_d,x
        lda sha256_h4,x
        sta sha_e,x
        lda sha256_h5,x
        sta sha_f,x
        lda sha256_h6,x
        sta sha_g,x
        lda sha256_h7,x
        sta sha_h,x
        inx
        cpx #4
        bne @init_working
        
        ; main compression loop (64 rounds)
        lda #0
        sta sha256_round
        
@main_loop:
        ; T1 = h + Sig1(e) + Ch(e,f,g) + k[i] + w[i]
        ; T2 = Sig0(a) + Maj(a,b,c)
        ; h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2
        
        ; compute Sig1(e)
        ldx #0
@load_e:
        lda sha_e,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @load_e
        jsr sha256_big_sig1
        
        ; add h
        ldx #0
@add_h:
        lda sha_h,x
        sta sha_temp2,x
        inx
        cpx #4
        bne @add_h
        jsr sha256_add_temp2_to_temp1
        
        ; add Ch(e,f,g)
        jsr sha256_ch
        jsr sha256_add_temp2_to_temp1
        
        ; add k[i]
        lda sha256_round
        asl
        asl
        tax
        ldy #0
@add_k:
        lda sha256_k,x
        sta sha_temp2,y
        inx
        iny
        cpy #4
        bne @add_k
        jsr sha256_add_temp2_to_temp1
        
        ; add w[i]
        lda sha256_round
        asl
        asl
        tax
        ldy #0
@add_w:
        lda sha256_w,x
        sta sha_temp2,y
        inx
        iny
        cpy #4
        bne @add_w
        jsr sha256_add_temp2_to_temp1
        
        ; save T1
        ldx #0
@save_t1:
        lda sha_temp1,x
        sta sha_t1,x
        inx
        cpx #4
        bne @save_t1
        
        ; compute Sig0(a)
        ldx #0
@load_a:
        lda sha_a,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @load_a
        jsr sha256_big_sig0
        
        ; add Maj(a,b,c)
        jsr sha256_maj
        jsr sha256_add_temp2_to_temp1
        
        ; T2 is now in sha_temp1
        
        ; update working variables
        ; h = g
        ldx #0
@update_h:
        lda sha_g,x
        sta sha_h,x
        inx
        cpx #4
        bne @update_h
        
        ; g = f
        ldx #0
@update_g:
        lda sha_f,x
        sta sha_g,x
        inx
        cpx #4
        bne @update_g
        
        ; f = e
        ldx #0
@update_f:
        lda sha_e,x
        sta sha_f,x
        inx
        cpx #4
        bne @update_f
        
        ; e = d + T1
        ldx #0
@copy_d:
        lda sha_d,x
        sta sha_temp2,x
        lda sha_t1,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @copy_d
        jsr sha256_add_temp2_to_temp1
        ldx #0
@update_e:
        lda sha_temp1,x
        sta sha_e,x
        inx
        cpx #4
        bne @update_e
        
        ; d = c
        ldx #0
@update_d:
        lda sha_c,x
        sta sha_d,x
        inx
        cpx #4
        bne @update_d
        
        ; c = b
        ldx #0
@update_c:
        lda sha_b,x
        sta sha_c,x
        inx
        cpx #4
        bne @update_c
        
        ; b = a
        ldx #0
@update_b:
        lda sha_a,x
        sta sha_b,x
        inx
        cpx #4
        bne @update_b
        
        ; a = T1 + T2 (T2 still in sha_temp1 from Sig0+Maj)
        ; wait, we need to recalculate - T2 was in temp1 but we used temp1 for e=d+T1
        ; let me fix this - save T2 first
        
        ; actually let's load T1 and add the saved T2
        ; we need to re-load T2... this is getting complex
        ; for now, recalculate T2
        ldx #0
@load_a2:
        lda sha_b,x             ; b now has old a
        sta sha_temp1,x
        inx
        cpx #4
        bne @load_a2
        jsr sha256_big_sig0
        jsr sha256_maj_from_b   ; maj using b(old a), c(old b), d(old c)
        jsr sha256_add_temp2_to_temp1
        ; add T1
        ldx #0
@add_t1:
        lda sha_t1,x
        sta sha_temp2,x
        inx
        cpx #4
        bne @add_t1
        jsr sha256_add_temp2_to_temp1
        ldx #0
@update_a:
        lda sha_temp1,x
        sta sha_a,x
        inx
        cpx #4
        bne @update_a
        
        inc sha256_round
        lda sha256_round
        cmp #64
        beq @done_rounds
        jmp @main_loop
        
@done_rounds:
        ; add working variables to hash state
        jsr sha256_add_to_hash
        rts

; =============================================================================
; sha256_load_word - load 4 bytes from sha256_w+X to sha_temp1
; =============================================================================
sha256_load_word:
        ldy #0
@loop:
        lda sha256_w,x
        sta sha_temp1,y
        inx
        iny
        cpy #4
        bne @loop
        rts

; =============================================================================
; sha256_load_word_to_temp2 - load 4 bytes from sha256_w+X to sha_temp2
; =============================================================================
sha256_load_word_to_temp2:
        ldy #0
@loop:
        lda sha256_w,x
        sta sha_temp2,y
        inx
        iny
        cpy #4
        bne @loop
        rts

; =============================================================================
; sha256_add_temp2_to_temp1 - 32-bit addition
; =============================================================================
sha256_add_temp2_to_temp1:
        clc
        lda sha_temp1+3
        adc sha_temp2+3
        sta sha_temp1+3
        lda sha_temp1+2
        adc sha_temp2+2
        sta sha_temp1+2
        lda sha_temp1+1
        adc sha_temp2+1
        sta sha_temp1+1
        lda sha_temp1
        adc sha_temp2
        sta sha_temp1
        rts

; =============================================================================
; sha256_sig0 - lowercase sigma 0: rotr7 ^ rotr18 ^ shr3
; =============================================================================
sha256_sig0:
        ; save input
        ldx #0
@save:
        lda sha_temp1,x
        sta sha_temp3,x
        inx
        cpx #4
        bne @save
        
        ; rotr7
        jsr sha256_rotr7
        ldx #0
@save_r7:
        lda sha_temp1,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @save_r7
        
        ; rotr18
        jsr sha256_rotr18
        ldx #0
@xor_r18:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_r18
        
        ; shr3
        jsr sha256_shr3
        ldx #0
@xor_final:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_final
        rts

; =============================================================================
; sha256_sig1 - lowercase sigma 1: rotr17 ^ rotr19 ^ shr10
; =============================================================================
sha256_sig1:
        ldx #0
@save:
        lda sha_temp1,x
        sta sha_temp3,x
        inx
        cpx #4
        bne @save
        
        jsr sha256_rotr17
        ldx #0
@save_r17:
        lda sha_temp1,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @save_r17
        
        jsr sha256_rotr19
        ldx #0
@xor_r19:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_r19
        
        jsr sha256_shr10
        ldx #0
@xor_final:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_final
        rts

; =============================================================================
; sha256_big_sig0 - uppercase Sigma 0: rotr2 ^ rotr13 ^ rotr22
; =============================================================================
sha256_big_sig0:
        ldx #0
@save:
        lda sha_temp1,x
        sta sha_temp3,x
        inx
        cpx #4
        bne @save
        
        jsr sha256_rotr2
        ldx #0
@save_r2:
        lda sha_temp1,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @save_r2
        
        jsr sha256_rotr13
        ldx #0
@xor_r13:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_r13
        
        jsr sha256_rotr22
        ldx #0
@xor_final:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_final
        rts

; =============================================================================
; sha256_big_sig1 - uppercase Sigma 1: rotr6 ^ rotr11 ^ rotr25
; =============================================================================
sha256_big_sig1:
        ldx #0
@save:
        lda sha_temp1,x
        sta sha_temp3,x
        inx
        cpx #4
        bne @save
        
        jsr sha256_rotr6
        ldx #0
@save_r6:
        lda sha_temp1,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @save_r6
        
        jsr sha256_rotr11
        ldx #0
@xor_r11:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp2,x
        lda sha_temp3,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_r11
        
        jsr sha256_rotr25
        ldx #0
@xor_final:
        lda sha_temp1,x
        eor sha_temp2,x
        sta sha_temp1,x
        inx
        cpx #4
        bne @xor_final
        rts

; =============================================================================
; sha256_ch - Ch(e,f,g) = (e AND f) XOR (NOT e AND g), result in sha_temp2
; =============================================================================
sha256_ch:
        ldx #0
@loop:
        lda sha_e,x
        and sha_f,x
        sta sha_temp2,x
        lda sha_e,x
        eor #$ff
        and sha_g,x
        eor sha_temp2,x
        sta sha_temp2,x
        inx
        cpx #4
        bne @loop
        rts

; =============================================================================
; sha256_maj - Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c), result in sha_temp2
; =============================================================================
sha256_maj:
        ldx #0
@loop:
        lda sha_a,x
        and sha_b,x
        sta sha_temp2,x
        lda sha_a,x
        and sha_c,x
        eor sha_temp2,x
        sta sha_temp2,x
        lda sha_b,x
        and sha_c,x
        eor sha_temp2,x
        sta sha_temp2,x
        inx
        cpx #4
        bne @loop
        rts

; =============================================================================
; sha256_maj_from_b - Maj using b,c,d (after rotation), result in sha_temp2
; =============================================================================
sha256_maj_from_b:
        ldx #0
@loop:
        lda sha_b,x
        and sha_c,x
        sta sha_temp2,x
        lda sha_b,x
        and sha_d,x
        eor sha_temp2,x
        sta sha_temp2,x
        lda sha_c,x
        and sha_d,x
        eor sha_temp2,x
        sta sha_temp2,x
        inx
        cpx #4
        bne @loop
        rts

; =============================================================================
; sha256_add_to_hash - add working variables to hash state
; =============================================================================
sha256_add_to_hash:
        ; h0 += a
        clc
        lda sha256_h0+3
        adc sha_a+3
        sta sha256_h0+3
        lda sha256_h0+2
        adc sha_a+2
        sta sha256_h0+2
        lda sha256_h0+1
        adc sha_a+1
        sta sha256_h0+1
        lda sha256_h0
        adc sha_a
        sta sha256_h0
        
        ; h1 += b
        clc
        lda sha256_h1+3
        adc sha_b+3
        sta sha256_h1+3
        lda sha256_h1+2
        adc sha_b+2
        sta sha256_h1+2
        lda sha256_h1+1
        adc sha_b+1
        sta sha256_h1+1
        lda sha256_h1
        adc sha_b
        sta sha256_h1
        
        ; h2 += c
        clc
        lda sha256_h2+3
        adc sha_c+3
        sta sha256_h2+3
        lda sha256_h2+2
        adc sha_c+2
        sta sha256_h2+2
        lda sha256_h2+1
        adc sha_c+1
        sta sha256_h2+1
        lda sha256_h2
        adc sha_c
        sta sha256_h2
        
        ; h3 += d
        clc
        lda sha256_h3+3
        adc sha_d+3
        sta sha256_h3+3
        lda sha256_h3+2
        adc sha_d+2
        sta sha256_h3+2
        lda sha256_h3+1
        adc sha_d+1
        sta sha256_h3+1
        lda sha256_h3
        adc sha_d
        sta sha256_h3
        
        ; h4 += e
        clc
        lda sha256_h4+3
        adc sha_e+3
        sta sha256_h4+3
        lda sha256_h4+2
        adc sha_e+2
        sta sha256_h4+2
        lda sha256_h4+1
        adc sha_e+1
        sta sha256_h4+1
        lda sha256_h4
        adc sha_e
        sta sha256_h4
        
        ; h5 += f
        clc
        lda sha256_h5+3
        adc sha_f+3
        sta sha256_h5+3
        lda sha256_h5+2
        adc sha_f+2
        sta sha256_h5+2
        lda sha256_h5+1
        adc sha_f+1
        sta sha256_h5+1
        lda sha256_h5
        adc sha_f
        sta sha256_h5
        
        ; h6 += g
        clc
        lda sha256_h6+3
        adc sha_g+3
        sta sha256_h6+3
        lda sha256_h6+2
        adc sha_g+2
        sta sha256_h6+2
        lda sha256_h6+1
        adc sha_g+1
        sta sha256_h6+1
        lda sha256_h6
        adc sha_g
        sta sha256_h6
        
        ; h7 += h
        clc
        lda sha256_h7+3
        adc sha_h+3
        sta sha256_h7+3
        lda sha256_h7+2
        adc sha_h+2
        sta sha256_h7+2
        lda sha256_h7+1
        adc sha_h+1
        sta sha256_h7+1
        lda sha256_h7
        adc sha_h
        sta sha256_h7
        rts

; =============================================================================
; Rotation functions - rotate sha_temp1 right by N bits
; =============================================================================

sha256_rotr2:
        ldy #2
        jmp sha256_rotr_n

sha256_rotr6:
        ldy #6
        jmp sha256_rotr_n

sha256_rotr7:
        ldy #7
        jmp sha256_rotr_n

sha256_rotr11:
        ldy #11
        jmp sha256_rotr_n

sha256_rotr13:
        ldy #13
        jmp sha256_rotr_n

sha256_rotr17:
        ldy #17
        jmp sha256_rotr_n

sha256_rotr18:
        ldy #18
        jmp sha256_rotr_n

sha256_rotr19:
        ldy #19
        jmp sha256_rotr_n

sha256_rotr22:
        ldy #22
        jmp sha256_rotr_n

sha256_rotr25:
        ldy #25
        jmp sha256_rotr_n

; rotate right by Y bits
sha256_rotr_n:
@loop:
        cpy #0
        beq @done
        ; rotate right by 1
        lsr sha_temp1
        ror sha_temp1+1
        ror sha_temp1+2
        ror sha_temp1+3
        bcc @no_carry
        ; wrap carry to top
        lda sha_temp1
        ora #$80
        sta sha_temp1
@no_carry:
        dey
        jmp @loop
@done:
        rts

; =============================================================================
; Shift right functions
; =============================================================================

sha256_shr3:
        ldy #3
        jmp sha256_shr_n

sha256_shr10:
        ldy #10
        jmp sha256_shr_n

sha256_shr_n:
@loop:
        cpy #0
        beq @done
        lsr sha_temp1
        ror sha_temp1+1
        ror sha_temp1+2
        ror sha_temp1+3
        dey
        jmp @loop
@done:
        rts

; =============================================================================
; init_sid - initialize main SID chip for noise generation on voice 3
; Uses CIA timer XOR for variable delay before setting frequency
; =============================================================================
init_sid:
        ; Get entropy from CIA timers for delay
        lda cia1_ta_lo
        eor cia1_tb_lo
        eor cia1_ta_hi
        eor cia1_tb_hi
        and #$3f                ; limit to 0-63
        tax
        
        ; Variable delay based on CIA entropy
@delay_init:
        ldy #10
@inner_delay:
        dey
        bne @inner_delay
        dex
        bpl @delay_init
        
        ; Initialize main SID voice 3 for noise
        lda #$ff
        sta sid_v3_freq_lo
        sta sid_v3_freq_hi
        lda #$80                ; noise waveform
        sta sid_v3_ctrl
        lda #$0f
        sta sid_volume
        
        ; Record last reseed time
        lda $a2
        sta prng_last_reseed
        
        rts

; =============================================================================
; init_all_sids - initialize all configured SIDs with RNG-offset delays
; Each SID gets a unique delay derived from lfsr_random to decorrelate
; the noise generator phase between SIDs
; =============================================================================
init_all_sids:
        ; Initialize main SID first
        jsr init_sid
        
        ; Initialize extra SIDs sequentially
        ldx #0
@init_loop:
        cpx extra_sid_count
        bcs @init_done
        
        stx prng_current_sid
        
        ; Use LFSR RNG + CIA timers for a unique delay per SID
        ; This ensures each SID's noise generator is phase-offset
        jsr lfsr_random         ; get RNG value in A
        eor cia1_ta_lo          ; mix with CIA for additional jitter
        and #$3f                ; limit to 0-63 iterations
        ora #$08                ; ensure minimum 8 iterations (~416 cycles)
        tay
        
        ; Delay: Y iterations × ~52 cycles
@delay2:
        ldx #10
@inner2:
        dex
        bne @inner2
        dey
        bne @delay2
        
        ; Get SID base address
        ldx prng_current_sid
        lda extra_sid_lo,x
        sta zp_ptr
        lda extra_sid_hi,x
        sta zp_ptr+1
        
        ; Initialize this SID's voice 3
        ldy #$0e                ; voice 3 freq low
        lda #$ff
        sta (zp_ptr),y
        iny                     ; voice 3 freq high
        sta (zp_ptr),y
        
        ldy #$12                ; voice 3 control
        lda #$80                ; noise waveform
        sta (zp_ptr),y
        
        ldy #$18                ; volume
        lda #$0f
        sta (zp_ptr),y
        
        ldx prng_current_sid
        inx
        jmp @init_loop
        
@init_done:
        rts

prng_current_sid:
        !byte 0
prng_sid_idx:
        !byte 0

; =============================================================================
; seed_lfsr - seed the 16-bit LFSR using SID + CIA entropy
; =============================================================================
seed_lfsr:
        ; Gather entropy from all sources
        lda sid_osc3
        eor cia1_ta_lo
        eor cia1_tb_hi
        sta lfsr_lo
        
        ; Small delay for new SID sample
        ldx #30
@delay1:
        dex
        bne @delay1
        
        lda sid_osc3
        eor cia1_ta_hi
        eor cia1_tb_lo
        sta lfsr_hi
        
        ; XOR with extra SIDs if available
        lda extra_sid_count
        beq @check_zero
        
        lda #0
        sta prng_sid_idx        ; start at SID index 0
        
@extra_seed:
        ldx prng_sid_idx
        cpx extra_sid_count
        bcs @check_zero         ; done all extra SIDs
        
        lda extra_sid_lo,x
        sta zp_ptr
        lda extra_sid_hi,x
        sta zp_ptr+1
        
        ldy #$1b                ; OSC3 offset
        lda (zp_ptr),y
        eor lfsr_lo
        sta lfsr_lo
        
        ; Delay for fresh SID sample (>= 26 cycles at max freq)
        ; 5 iterations × (2+3) = 25, plus ldx(2) + final dex(2) + bne-not(2) = 31
        ldx #5
@delay2:
        dex
        bne @delay2
        
        ldy #$1b                ; OSC3 offset
        lda (zp_ptr),y
        eor lfsr_hi
        sta lfsr_hi
        
        inc prng_sid_idx
        jmp @extra_seed
        
@check_zero:
        ; Ensure LFSR is not zero
        lda lfsr_lo
        ora lfsr_hi
        bne @done
        
        lda #$01
        sta lfsr_lo
@done:
        ; Update last reseed time
        lda $a2
        sta prng_last_reseed
        rts

prng_last_reseed:
        !byte 0

; =============================================================================
; check_prng_reseed - check if ~30 seconds elapsed, reseed if needed
; Uses jiffy clock ($A2 wraps every 256/60 = 4.27 seconds)
; Count 7 wraps of $A2 = ~30 seconds
; =============================================================================
check_prng_reseed:
        lda $a2
        cmp prng_last_jiffy
        beq @no_increment       ; same jiffy, nothing to do
        sta prng_last_jiffy
        
        ; detect wrap of $A2 (new value < old value)
        bcs @no_increment       ; no wrap if new >= old (carry still set from cmp)
        
        ; $A2 wrapped — one ~4.27 second period elapsed
        inc prng_reseed_counter
        lda prng_reseed_counter
        cmp #7                  ; 7 wraps * 4.27 sec = ~30 seconds
        bcc @no_increment
        
        ; Time to reseed
        lda #0
        sta prng_reseed_counter
        
        jsr init_all_sids       ; reinitialize all SIDs with CIA delays
        jsr seed_lfsr           ; reseed LFSR
        
@no_increment:
        rts

prng_last_jiffy:
        !byte 0
prng_reseed_counter:
        !byte 0

; =============================================================================
; generate_bytes - generate random bytes into buffer
; input: zp_ptr = destination address, a = count
; =============================================================================
generate_bytes:
        sta zp_count
@loop:
        jsr lfsr_random
        ldy #0
        sta (zp_ptr),y
        
        inc zp_ptr
        bne @no_carry
        inc zp_ptr+1
@no_carry:
        
        dec zp_count
        bne @loop
        rts

; =============================================================================
; lfsr_random - 16-bit LFSR PRNG with SID and CIA mixing
; Returns random byte in A
; Uses Galois LFSR with polynomial x^16+x^14+x^13+x^11+1
; Taps at bits 16,14,13,11 = mask $B400 applied when bit 0 is set
; =============================================================================
lfsr_random:
        ; Galois LFSR: if bit 0 is set, shift right and XOR with taps
        ; taps at 16,14,13,11 -> mask $B400 (bits 15,13,12,10 in 0-indexed)
        lda lfsr_lo
        lsr                     ; bit 0 -> carry
        bcc @no_taps
        
        ; Shift right the full 16-bit register
        lda lfsr_hi
        lsr                     ; high byte shift right
        sta lfsr_hi
        lda lfsr_lo
        ror                     ; low byte with carry from high
        sta lfsr_lo
        
        ; XOR with tap mask $B400
        lda lfsr_hi
        eor #$b4
        sta lfsr_hi
        ; lfsr_lo XOR $00 = no change
        jmp @mix_entropy
        
@no_taps:
        ; Just shift right the full 16-bit register
        lsr lfsr_hi
        ror lfsr_lo
        
@mix_entropy:
        ; XOR with main SID oscillator 3 for continuous entropy
        lda sid_osc3
        eor lfsr_lo
        
        ; Also mix in CIA timer low bits for additional entropy
        eor cia1_ta_lo
        
        sta lfsr_lo
        
        ; Guard against zero-state lockup (LFSR is stuck at 0 forever)
        ora lfsr_hi
        bne @not_zero
        ; Both bytes zero — escape by forcing lfsr_lo to 1
        lda #$01
        sta lfsr_lo
@not_zero:
        
        ; Return the random byte
        lda lfsr_lo
        rts

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

; =============================================================================
; data section
; =============================================================================

; lfsr state
lfsr_lo:
        !byte $01
lfsr_hi:
        !byte $01

; storage for generated values
iv_data:
        !fill 16, 0

key_data:
        !fill 32, 0

; aes working data
aes_state:
        !fill 16, 0

cbc_vector:
        !fill 16, 0

expanded_key:
        !fill 240, 0            ; 15 round keys * 16 bytes

; encryption buffers
input_buffer:
        !fill input_buf_size, 0

encrypt_buffer:
        !fill encrypt_buf_size, 0

decrypt_data:
        !fill input_buf_size, 0

input_length:
        !byte 0

encrypt_length:
        !byte 0

decrypt_length:
        !byte 0

block_count:
        !byte 0

current_block:
        !byte 0

pkcs7_pad_value:
        !byte 0

input_index:
        !byte 0

; disk save variables
drive_number:
        !byte 8

filename_buf:
        !fill 17, 0             ; input buffer for filename

actual_filename:
        !fill 17, 0             ; actual filename to use

filename_len:
        !byte 0

filename_suffix:
        !byte 0

using_default_name:
        !byte 0

file_exists_flag:
        !byte 0

cmd_buffer:
        !fill 24, 0

cmd_len:
        !byte 0

write_fname_buf:
        !fill 32, 0

write_fname_len:
        !byte 0

read_fname_buf:
        !fill 32, 0

read_fname_len:
        !byte 0

key_read_buf:
        !fill 32, 0

decimal_flag:
        !byte 0

save_byte_index:
        !byte 0

read_byte_index:
        !byte 0

read_temp_byte:
        !byte 0

disk_error_code:
        !byte 0, 0              ; two bytes for error code digits

msg_filename_suffix:
        !byte 0

enc_read_buf:
        !fill 64, 0             ; buffer for reading encrypted data back

enc_read_length:
        !byte 0

iv_read_buf:
        !fill 16, 0             ; buffer for reading IV back

; SHA-256 working variables
sha256_h0:      !fill 4, 0
sha256_h1:      !fill 4, 0
sha256_h2:      !fill 4, 0
sha256_h3:      !fill 4, 0
sha256_h4:      !fill 4, 0
sha256_h5:      !fill 4, 0
sha256_h6:      !fill 4, 0
sha256_h7:      !fill 4, 0

sha_a:          !fill 4, 0
sha_b:          !fill 4, 0
sha_c:          !fill 4, 0
sha_d:          !fill 4, 0
sha_e:          !fill 4, 0
sha_f:          !fill 4, 0
sha_g:          !fill 4, 0
sha_h:          !fill 4, 0

sha_temp1:      !fill 4, 0
sha_temp2:      !fill 4, 0
sha_temp3:      !fill 4, 0
sha_t1:         !fill 4, 0

sha256_block:   !fill 64, 0
sha256_w:       !fill 256, 0    ; message schedule (64 words * 4 bytes)
sha256_hash:    !fill 32, 0     ; final hash output
sha256_len:     !fill 2, 0      ; message length in bits
sha256_round:   !byte 0

; GCM-SIV variables
gcmsiv_nonce:       !fill 12, 0     ; 96-bit nonce
gcmsiv_pt_buf:      !fill 64, 0     ; plaintext buffer
gcmsiv_pt_len:      !byte 0         ; plaintext length
gcmsiv_ct_buf:      !fill 64, 0     ; ciphertext buffer
gcmsiv_dec_buf:     !fill 64, 0     ; decrypted plaintext buffer
gcmsiv_tag:         !fill 16, 0     ; authentication tag
gcmsiv_tag_acc:     !fill 16, 0     ; tag accumulator
gcmsiv_auth_key:    !fill 16, 0     ; derived auth key
gcmsiv_enc_key:     !fill 32, 0     ; derived encryption key (256-bit for AES-256)
gcmsiv_counter:     !fill 16, 0     ; CTR mode counter
gcmsiv_keystream:   !fill 16, 0     ; keystream block
gcmsiv_block_idx:   !byte 0         ; block processing index
gcmsiv_ct_idx:      !byte 0         ; ciphertext index
gcmsiv_ks_idx:      !byte 0         ; keystream index
gcmsiv_tag_valid:   !byte 0         ; tag verification: 0=fail, 1=pass
gcmsiv_verify_tag:  !fill 16, 0     ; saved received tag for verification
gcmsiv_saved_key:   !fill 32, 0     ; saved original key during derivation
gcmsiv_exp_enc_key: !fill 256, 0    ; expanded derived encryption key
gcmsiv_saved_exp:   !fill 256, 0    ; saved original expanded key

default_filename:
        !text "AESKEY"
        !byte 0

default_msg_filename:
        !text "AESMSG"
        !byte 0

default_gcm_filename:
        !text "AESGCM"
        !byte 0

gcm_filename_suffix:
        !byte 0

; benchmark variables
bench_iterations:   !word 0
timer_start_lo:     !byte 0
timer_start_hi:     !byte 0
timer_end_lo:       !byte 0
timer_end_hi:       !byte 0
timer_elapsed:      !word 0

; REU variables
reu_present:        !byte 0     ; 0=no REU, 1=REU detected
reu_size_kb:        !word 0     ; REU size in KB

cbc_temp:
        !fill 16, 0             ; temp storage for cbc decryption

; mix columns temp storage
mc_a0:  !byte 0
mc_a1:  !byte 0
mc_a2:  !byte 0
mc_a3:  !byte 0
mc_b0:  !byte 0
mc_b1:  !byte 0
mc_b2:  !byte 0
mc_b3:  !byte 0

; =============================================================================
; aes s-box (256 bytes)
; =============================================================================
aes_sbox:
        !byte $63,$7c,$77,$7b,$f2,$6b,$6f,$c5,$30,$01,$67,$2b,$fe,$d7,$ab,$76
        !byte $ca,$82,$c9,$7d,$fa,$59,$47,$f0,$ad,$d4,$a2,$af,$9c,$a4,$72,$c0
        !byte $b7,$fd,$93,$26,$36,$3f,$f7,$cc,$34,$a5,$e5,$f1,$71,$d8,$31,$15
        !byte $04,$c7,$23,$c3,$18,$96,$05,$9a,$07,$12,$80,$e2,$eb,$27,$b2,$75
        !byte $09,$83,$2c,$1a,$1b,$6e,$5a,$a0,$52,$3b,$d6,$b3,$29,$e3,$2f,$84
        !byte $53,$d1,$00,$ed,$20,$fc,$b1,$5b,$6a,$cb,$be,$39,$4a,$4c,$58,$cf
        !byte $d0,$ef,$aa,$fb,$43,$4d,$33,$85,$45,$f9,$02,$7f,$50,$3c,$9f,$a8
        !byte $51,$a3,$40,$8f,$92,$9d,$38,$f5,$bc,$b6,$da,$21,$10,$ff,$f3,$d2
        !byte $cd,$0c,$13,$ec,$5f,$97,$44,$17,$c4,$a7,$7e,$3d,$64,$5d,$19,$73
        !byte $60,$81,$4f,$dc,$22,$2a,$90,$88,$46,$ee,$b8,$14,$de,$5e,$0b,$db
        !byte $e0,$32,$3a,$0a,$49,$06,$24,$5c,$c2,$d3,$ac,$62,$91,$95,$e4,$79
        !byte $e7,$c8,$37,$6d,$8d,$d5,$4e,$a9,$6c,$56,$f4,$ea,$65,$7a,$ae,$08
        !byte $ba,$78,$25,$2e,$1c,$a6,$b4,$c6,$e8,$dd,$74,$1f,$4b,$bd,$8b,$8a
        !byte $70,$3e,$b5,$66,$48,$03,$f6,$0e,$61,$35,$57,$b9,$86,$c1,$1d,$9e
        !byte $e1,$f8,$98,$11,$69,$d9,$8e,$94,$9b,$1e,$87,$e9,$ce,$55,$28,$df
        !byte $8c,$a1,$89,$0d,$bf,$e6,$42,$68,$41,$99,$2d,$0f,$b0,$54,$bb,$16

; =============================================================================
; aes inverse s-box (256 bytes)
; =============================================================================
aes_inv_sbox:
        !byte $52,$09,$6a,$d5,$30,$36,$a5,$38,$bf,$40,$a3,$9e,$81,$f3,$d7,$fb
        !byte $7c,$e3,$39,$82,$9b,$2f,$ff,$87,$34,$8e,$43,$44,$c4,$de,$e9,$cb
        !byte $54,$7b,$94,$32,$a6,$c2,$23,$3d,$ee,$4c,$95,$0b,$42,$fa,$c3,$4e
        !byte $08,$2e,$a1,$66,$28,$d9,$24,$b2,$76,$5b,$a2,$49,$6d,$8b,$d1,$25
        !byte $72,$f8,$f6,$64,$86,$68,$98,$16,$d4,$a4,$5c,$cc,$5d,$65,$b6,$92
        !byte $6c,$70,$48,$50,$fd,$ed,$b9,$da,$5e,$15,$46,$57,$a7,$8d,$9d,$84
        !byte $90,$d8,$ab,$00,$8c,$bc,$d3,$0a,$f7,$e4,$58,$05,$b8,$b3,$45,$06
        !byte $d0,$2c,$1e,$8f,$ca,$3f,$0f,$02,$c1,$af,$bd,$03,$01,$13,$8a,$6b
        !byte $3a,$91,$11,$41,$4f,$67,$dc,$ea,$97,$f2,$cf,$ce,$f0,$b4,$e6,$73
        !byte $96,$ac,$74,$22,$e7,$ad,$35,$85,$e2,$f9,$37,$e8,$1c,$75,$df,$6e
        !byte $47,$f1,$1a,$71,$1d,$29,$c5,$89,$6f,$b7,$62,$0e,$aa,$18,$be,$1b
        !byte $fc,$56,$3e,$4b,$c6,$d2,$79,$20,$9a,$db,$c0,$fe,$78,$cd,$5a,$f4
        !byte $1f,$dd,$a8,$33,$88,$07,$c7,$31,$b1,$12,$10,$59,$27,$80,$ec,$5f
        !byte $60,$51,$7f,$a9,$19,$b5,$4a,$0d,$2d,$e5,$7a,$9f,$93,$c9,$9c,$ef
        !byte $a0,$e0,$3b,$4d,$ae,$2a,$f5,$b0,$c8,$eb,$bb,$3c,$83,$53,$99,$61
        !byte $17,$2b,$04,$7e,$ba,$77,$d6,$26,$e1,$69,$14,$63,$55,$21,$0c,$7d

; =============================================================================
; aes round constants
; =============================================================================
aes_rcon:
        !byte $01,$02,$04,$08,$10,$20,$40,$80,$1b,$36

; =============================================================================
; messages
; =============================================================================
title_msg:
        !byte $93
        !text "*** AES-256 ENCRYPTION DEMO ***"
        !byte $0d
        !text "USING SID LFSR PRNG"
        !byte $0d
        !text "FOR DEMONSTRATION ONLY"
        !byte $0d, $0d, 0

gen_iv_msg:
        !text "GENERATING IV (16 BYTES)..."
        !byte $0d, 0

gen_key_msg:
        !text "GENERATING KEY (32 BYTES)..."
        !byte $0d, 0

expanding_msg:
        !text "EXPANDING KEY..."
        !byte $0d, $0d, 0

iv_header_msg:
        !text "*** INITIALIZATION VECTOR ***"
        !byte $0d
        !text "(16 BYTES / 128 BITS)"
        !byte $0d, $0d, 0

key_header_msg:
        !byte $0d
        !text "*** AES-256 ENCRYPTION KEY ***"
        !byte $0d
        !text "(32 BYTES / 256 BITS)"
        !byte $0d, $0d, 0

done_msg:
        !byte $0d
        !text "*** READY ***"
        !byte $0d, 0

instructions_msg:
        !byte $0d
        !text "1=KEY 2=ENC 3=SHOW 4=DEC 5=SAVE KEY"
        !byte $0d
        !text "6=LOAD KEY 7=SAVE 8=LOAD 9=SHA256"
        !byte $0d
        !text "A=GCM-ENC B=GCM-DEC C=GCM-SAVE"
        !byte $0d
        !text "D=GCM-LOAD E=BENCH F=NIST G=REU"
        !byte $0d
        !text "H=RNG STREAM I=SID CONFIG J=CSR"
        !byte $0d
        !text "Q=QUIT"
        !byte $0d, 0

input_prompt_msg:
        !byte $0d
        !text "ENTER TEXT TO ENCRYPT:"
        !byte $0d, 0

encrypting_msg:
        !byte $0d
        !text "ENCRYPTING..."
        !byte $0d, 0

encrypt_done_msg:
        !text "ENCRYPTION COMPLETE."
        !byte $0d, 0

decrypting_msg:
        !text "DECRYPTING..."
        !byte $0d, 0

decrypted_header_msg:
        !byte $0d
        !text "*** DECRYPTED (HEX) ***"
        !byte $0d, 0

as_text_msg:
        !byte $0d
        !text "AS TEXT: "
        !byte 0

no_input_msg:
        !text "NO INPUT PROVIDED."
        !byte $0d, 0

no_encrypted_msg:
        !text "NO ENCRYPTED DATA YET."
        !byte $0d
        !text "PRESS 2 TO ENCRYPT TEXT."
        !byte $0d, 0

encrypted_header_msg:
        !text "*** ENCRYPTED OUTPUT ***"
        !byte $0d, $0d, 0

exit_msg:
        !byte $0d
        !text "*** PROGRAM ENDED ***"
        !byte $0d, 0

drive_prompt_msg:
        !text "DRIVE NUMBER (8): "
        !byte 0

using_drive_msg:
        !text "USING DRIVE "
        !byte 0

filename_prompt_msg:
        !text "FILENAME (AESKEY): "
        !byte 0

file_exists_msg:
        !byte $0d
        !text "FILE ALREADY EXISTS!"
        !byte $0d, 0

incremented_msg:
        !text "TRYING: "
        !byte 0

enter_new_name_msg:
        !text "ENTER NEW FILENAME: "
        !byte 0

saving_key_msg:
        !byte $0d
        !text "SAVING KEY TO: "
        !byte 0

key_value_msg:
        !text "KEY VALUE:"
        !byte $0d, 0

save_success_msg:
        !text "FILE SAVED SUCCESSFULLY."
        !byte $0d, 0

save_error_msg:
        !text "ERROR SAVING FILE!"
        !byte $0d, 0

reading_back_msg:
        !byte $0d
        !text "READING KEY BACK..."
        !byte $0d, 0

reading_enc_back_msg:
        !byte $0d
        !text "READING DATA BACK..."
        !byte $0d, 0

key_read_msg:
        !text "KEY READ FROM DISK:"
        !byte $0d, 0

read_error_msg:
        !text "ERROR READING FILE!"
        !byte $0d, 0

verify_ok_msg:
        !text "VERIFICATION OK!"
        !byte $0d, 0

verify_fail_msg:
        !text "VERIFICATION FAILED!"
        !byte $0d, 0

names_exhausted_msg:
        !byte $0d
        !text "ALL DEFAULT NAMES TAKEN (0-9)!"
        !byte $0d
        !text "PLEASE SPECIFY A CUSTOM NAME."
        !byte $0d, 0

load_filename_prompt_msg:
        !text "FILENAME TO LOAD (AESKEY): "
        !byte 0

loading_default_msg:
        !text "USING DEFAULT FILENAME: AESKEY"
        !byte $0d, 0

file_not_found_msg:
        !byte $0d
        !text "FILE NOT FOUND: "
        !byte 0

loading_key_msg:
        !byte $0d
        !text "LOADING KEY FROM: "
        !byte 0

key_loaded_msg:
        !text "KEY LOADED FROM DISK:"
        !byte $0d, 0

reexpanding_msg:
        !text "EXPANDING KEY FOR AES..."
        !byte $0d, 0

load_success_msg:
        !text "KEY LOADED SUCCESSFULLY!"
        !byte $0d
        !text "READY FOR ENCRYPTION/DECRYPTION."
        !byte $0d, 0

load_error_msg:
        !text "ERROR LOADING KEY FILE!"
        !byte $0d, 0

msg_filename_prompt_msg:
        !text "FILENAME (AESMSG): "
        !byte 0

saving_msg_msg:
        !byte $0d
        !text "SAVING ENCRYPTED DATA TO: "
        !byte 0

enc_value_msg:
        !text "ENCRYPTED DATA:"
        !byte $0d, 0

enc_read_msg:
        !text "DATA READ FROM DISK:"
        !byte $0d, 0

load_msg_filename_prompt:
        !text "FILENAME TO LOAD (AESMSG): "
        !byte 0

loading_default_msg_msg:
        !text "USING DEFAULT FILENAME: AESMSG"
        !byte $0d, 0

loading_enc_msg:
        !byte $0d
        !text "LOADING ENCRYPTED DATA FROM: "
        !byte 0

enc_loaded_msg:
        !text "ENCRYPTED DATA LOADED:"
        !byte $0d, 0

loaded_iv_msg:
        !text "LOADED IV:"
        !byte $0d, 0

enc_load_success_msg:
        !text "ENCRYPTED DATA LOADED SUCCESSFULLY!"
        !byte $0d
        !text "USE OPTION 4 TO DECRYPT."
        !byte $0d, 0

enc_load_error_msg:
        !text "ERROR LOADING ENCRYPTED FILE!"
        !byte $0d, 0

saving_iv_msg:
        !text "IV BEING SAVED:"
        !byte $0d, 0

iv_read_back_msg:
        !text "IV READ BACK:"
        !byte $0d, 0

no_input_hash_msg:
        !text "NO INPUT TEXT TO HASH."
        !byte $0d
        !text "USE OPTION 2 TO ENTER TEXT FIRST."
        !byte $0d, 0

hashing_msg:
        !text "HASHING: "
        !byte 0

bytes_msg:
        !text " BYTES"
        !byte $0d, 0

calculating_msg:
        !text "CALCULATING SHA-256..."
        !byte $0d, 0

hash_result_msg:
        !text "SHA-256 HASH:"
        !byte $0d, 0

gcmsiv_prompt_msg:
        !byte $0d
        !text "ENTER TEXT FOR GCM-SIV ENCRYPTION:"
        !byte $0d, 0

gcmsiv_encrypting_msg:
        !text "ENCRYPTING "
        !byte 0

gcmsiv_nonce_msg:
        !text "NONCE (12 BYTES):"
        !byte $0d, 0

gcmsiv_ciphertext_msg:
        !text "CIPHERTEXT:"
        !byte $0d, 0

gcmsiv_tag_msg:
        !text "AUTH TAG (16 BYTES):"
        !byte $0d, 0

gcmsiv_done_msg:
        !byte $0d
        !text "GCM-SIV ENCRYPTION COMPLETE."
        !byte $0d, 0

gcmsiv_no_data_msg:
        !text "NO GCM-SIV CIPHERTEXT TO DECRYPT."
        !byte $0d
        !text "USE OPTION A TO ENCRYPT FIRST."
        !byte $0d, 0

gcmsiv_decrypting_msg:
        !text "DECRYPTING GCM-SIV CIPHERTEXT..."
        !byte $0d, 0

gcmsiv_pt_hex_msg:
        !text "DECRYPTED (HEX):"
        !byte $0d, 0

gcmsiv_pt_text_msg:
        !text "DECRYPTED (TEXT):"
        !byte $0d, 0

gcmsiv_decrypt_done_msg:
        !byte $0d
        !text "GCM-SIV DECRYPTION COMPLETE."
        !byte $0d, 0

gcmsiv_tag_ok_msg:
        !text "*** TAG VERIFIED OK ***"
        !byte $0d, 0

gcmsiv_tag_fail_msg:
        !byte $0d
        !text "*** TAG VERIFICATION FAILED! ***"
        !byte $0d
        !text "DATA MAY BE CORRUPTED/TAMPERED!"
        !byte $0d, 0

gcm_filename_prompt_msg:
        !text "FILENAME (AESGCM): "
        !byte 0

saving_gcm_msg:
        !byte $0d
        !text "SAVING GCM-SIV DATA TO: "
        !byte 0

load_gcm_filename_prompt:
        !text "FILENAME TO LOAD (AESGCM): "
        !byte 0

loading_default_gcm_msg:
        !text "USING DEFAULT FILENAME: AESGCM"
        !byte $0d, 0

loading_gcm_msg:
        !byte $0d
        !text "LOADING GCM-SIV DATA FROM: "
        !byte 0

gcm_load_success_msg:
        !text "GCM-SIV DATA LOADED SUCCESSFULLY!"
        !byte $0d
        !text "USE OPTION B TO DECRYPT."
        !byte $0d, 0

benchmark_header_msg:
        !text "=== AES BENCHMARK ==="
        !byte $0d
        !text "ENCRYPTING 64 BYTES X 256 ITERS"
        !byte $0d, $0d, 0

bench_cbc_msg:
        !text "AES-256-CBC (4 BLOCKS):"
        !byte $0d, 0

bench_gcm_msg:
        !byte $0d
        !text "AES-256-GCM-SIV (64 BYTES):"
        !byte $0d, 0

bench_block_msg:
        !byte $0d
        !text "SINGLE AES BLOCK:"
        !byte $0d, 0

bench_iters_msg:
        !text "  ITERATIONS: $"
        !byte 0

bench_time_msg:
        !text "  TIME: $"
        !byte 0

bench_jiffies_msg:
        !text " JIFFIES (1/60 SEC)"
        !byte $0d, 0

bench_done_msg:
        !byte $0d
        !text "BENCHMARK COMPLETE."
        !byte $0d, 0

nist_header_msg:
        !text "=== NIST FIPS 197 TEST VECTORS ==="
        !byte $0d
        !text "AES-256 APPENDIX C.3"
        !byte $0d, $0d, 0

nist_expanding_msg:
        !text "EXPANDING KEY..."
        !byte $0d, 0

nist_key_msg:
        !text "KEY (32 BYTES):"
        !byte $0d, 0

nist_iv_msg:
        !text "IV (16 BYTES):"
        !byte $0d, 0

nist_pt_msg:
        !text "EXPECTED PLAINTEXT:"
        !byte $0d, 0

nist_ct_msg:
        !text "EXPECTED CIPHERTEXT:"
        !byte $0d, 0

nist_verify_msg:
        !byte $0d
        !text "VERIFYING ENCRYPTION..."
        !byte $0d, 0

nist_result_msg:
        !text "ACTUAL RESULT:"
        !byte $0d, 0

nist_pass_msg:
        !byte $0d
        !text "*** NIST TEST PASSED! ***"
        !byte $0d, 0

nist_fail_msg:
        !byte $0d
        !text "*** NIST TEST FAILED! ***"
        !byte $0d, 0

nist_cbc_test_msg:
        !byte $0d
        !text "TESTING CBC MODE (ZERO IV)..."
        !byte $0d, 0

nist_cbc_result_msg:
        !text "CBC RESULT:"
        !byte $0d, 0

nist_cbc_pass_msg:
        !text "*** CBC TEST PASSED! ***"
        !byte $0d, 0

nist_cbc_fail_msg:
        !text "*** CBC TEST FAILED! ***"
        !byte $0d, 0

nist_note_msg:
        !byte $0d
        !text "NOTE: OPTION 2 ENCRYPTS ASCII TEXT,"
        !byte $0d
        !text "NOT RAW HEX. TYPING '00' ENCRYPTS"
        !byte $0d
        !text "$30,$30 NOT $00,$00."
        !byte $0d, 0

; REU status messages
reu_detected_msg:
        !text "REU DETECTED: "
        !byte 0

reu_kb_msg:
        !text " KB"
        !byte $0d, 0

reu_not_found_msg:
        !text "NO REU DETECTED"
        !byte $0d, 0

reu_status_msg:
        !text "=== REU STATUS ==="
        !byte $0d, 0

reu_not_present_msg:
        !text "REU: NOT PRESENT"
        !byte $0d, 0

reu_present_msg:
        !text "REU: PRESENT"
        !byte $0d, 0

reu_size_is_msg:
        !text "SIZE: "
        !byte 0

reu_kb_suffix:
        !text " KB"
        !byte $0d, 0

reu_detecting_msg:
        !text "DETECTING REU..."
        !byte $0d, 0

reu_fill_prompt:
        !text "FILL REU? (Y/N, ENTER=YES) "
        !byte 0

reu_fill_type_prompt:
        !byte $0d
        !text "0=ZERO R=RANDOM (ENTER=ZERO) "
        !byte 0

reu_zeroing_msg:
        !text "ZEROING REU (SPACE TO ABORT)..."
        !byte $0d, 0

reu_random_msg:
        !text "RANDOM FILL (SPACE TO ABORT)..."
        !byte $0d, 0

reu_progress_msg:
        !text "PROGRESS: "
        !byte 0

reu_kb_of_msg:
        !text " OF "
        !byte 0

reu_kb_suffix2:
        !text " KB"
        !byte 0

reu_aborted_msg:
        !text "ABORTED BY USER."
        !byte $0d, 0

reu_fill_done_msg:
        !text "REU FILL COMPLETE."
        !byte $0d, 0

reu_save_prompt:
        !text "SAVE TO DISK? (Y/N, ENTER=YES) "
        !byte 0

reu_drive_prompt:
        !text "DRIVE NUMBER (ENTER=8): "
        !byte 0

reu_filename_prompt:
        !text "FILENAME (ENTER=RNGFILL): "
        !byte 0

reu_checking_disk_msg:
        !text "CHECKING DISK..."
        !byte $0d, 0

reu_free_blocks_msg:
        !text "FREE: "
        !byte 0

reu_blocks_suffix:
        !text " BLOCKS"
        !byte $0d, 0

reu_no_space_msg:
        !text "NO SPACE ON DISK!"
        !byte $0d, 0

reu_disk_error_msg:
        !text "DISK ERROR!"
        !byte $0d, 0

reu_open_error_msg:
        !text "CANNOT OPEN FILE!"
        !byte $0d, 0

reu_writing_msg:
        !text "WRITING TO DISK..."
        !byte $0d, 0

reu_of_msg:
        !text " OF "
        !byte 0

reu_write_aborted_msg:
        !text "WRITE ABORTED."
        !byte $0d, 0

reu_write_error_msg:
        !text "WRITE ERROR!"
        !byte $0d, 0

reu_save_done_msg:
        !byte $0d
        !text "SAVE COMPLETE. "
        !byte 0

rng_file_exists_msg:
        !text "FILE ALREADY EXISTS."
        !byte $0d, 0

rng_append_prompt:
        !text "APPEND MORE DATA? (Y/N, ENTER=YES) "
        !byte 0

rng_refilling_msg:
        !text "REFILLING REU (PASS "
        !byte 0

rng_pass_suffix:
        !text ")..."
        !byte $0d, 0

rng_blocks_written_msg:
        !text " BLOCKS WRITTEN."
        !byte $0d, 0

; SID configuration messages
sid_config_header:
        !text "=== SID CONFIGURATION ==="
        !byte $0d, 0

sid_current_msg:
        !text "CURRENT: "
        !byte 0

sid_chips_msg:
        !text " SID CHIP(S) CONFIGURED"
        !byte $0d, 0

sid_extra_prompt:
        !text "EXTRA SID CHIPS? (Y/N, ENTER=YES) "
        !byte 0

sid_addr_prompt:
        !text "ENTER ADDRESSES (E.G. D420,D440):"
        !byte $0d
        !text "(ENTER FOR DEFAULT D420) "
        !byte 0

sid_configured_msg:
        !text "CONFIGURED: "
        !byte 0

; Random stream messages
random_stream_header:
        !text "=== PRNG SPEED TEST ==="
        !byte $0d
        !text "PRESS SPACE TO STOP"
        !byte $0d, $0d, 0

stream_sids_msg:
        !text "CONFIGURED SIDS: "
        !byte 0

stream_sids_suffix:
        !byte $0d, 0

stream_live_header:
        !byte $0d
        !text "MEASURING THROUGHPUT..."
        !byte $0d, 0

stream_sample_msg:
        !text "SAMPLE: "
        !byte 0

stream_stopped_msg:
        !byte $0d
        !text "STREAM STOPPED."
        !byte $0d, 0

stream_stats_header:
        !byte $0d
        !text "STATISTICS:"
        !byte $0d, 0

stream_total_msg:
        !text "TOTAL: "
        !byte 0

stream_bytes_msg:
        !text " BYTES"
        !byte 0

stream_rate_label:
        !text "RATE:  "
        !byte 0

stream_bps_msg:
        !text " BYTES/SEC"
        !byte 0

stream_stats_msg:
        !text "GENERATED: "
        !byte 0

stream_kb_msg:
        !text " KB"
        !byte 0

stream_rate_msg:
        !text "  RATE: "
        !byte 0

stream_kbsec_msg:
        !text " KB/SEC"
        !byte 0

sid_label_main:
        !text "SID 1 ($D400): "
        !byte 0

sid_label_extra:
        !text "SID "
        !byte 0

; =============================================================================
; CSR (Certificate Signing Request) Generation
; =============================================================================
; Generates a text-format CSR containing the AES-256 key and X.509
; subject fields entered by the user. Output is a human-readable
; sequential text file suitable for submission to a CA or for use
; with external tools that convert to PKCS#10 DER/PEM format.
;
; CSR format:
;   -----BEGIN CERTIFICATE REQUEST-----
;   Key-Type: AES-256
;   Key: <64 hex digits>
;   Subject: /C=xx/ST=xx/L=xx/O=xx/OU=xx/CN=xx
;   Email: xx
;   -----END CERTIFICATE REQUEST-----
; =============================================================================

; =============================================================================
; do_generate_csr - CSR/ECDSA sub-menu handler
; =============================================================================
do_generate_csr:
        lda #$0d
        jsr chrout
        lda #<csr_submenu_msg
        ldy #>csr_submenu_msg
        jsr print_string

        jsr getin_wait
        cmp #'1'
        beq @do_csr
        cmp #'2'
        beq @do_ecdsa_test
        ; Any other key = return
        rts

@do_ecdsa_test:
        jsr do_ecdsa_test
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

@do_csr:
        lda #<csr_header_msg
        ldy #>csr_header_msg
        jsr print_string
        
        ; --- Prompt for each CSR field ---
        
        ; Country (C) - 2 letter code
        lda #<csr_country_prompt
        ldy #>csr_country_prompt
        jsr print_string
        lda #<csr_country
        sta csr_field_ptr
        lda #>csr_country
        sta csr_field_ptr+1
        lda #2                  ; max 2 chars
        jsr csr_get_field
        sta csr_country_len
        
        ; State/Province (ST)
        lda #<csr_state_prompt
        ldy #>csr_state_prompt
        jsr print_string
        lda #<csr_state
        sta csr_field_ptr
        lda #>csr_state
        sta csr_field_ptr+1
        lda #32                 ; max 32 chars
        jsr csr_get_field
        sta csr_state_len
        
        ; Locality/City (L)
        lda #<csr_city_prompt
        ldy #>csr_city_prompt
        jsr print_string
        lda #<csr_city
        sta csr_field_ptr
        lda #>csr_city
        sta csr_field_ptr+1
        lda #32
        jsr csr_get_field
        sta csr_city_len
        
        ; Organization (O)
        lda #<csr_org_prompt
        ldy #>csr_org_prompt
        jsr print_string
        lda #<csr_org
        sta csr_field_ptr
        lda #>csr_org
        sta csr_field_ptr+1
        lda #32
        jsr csr_get_field
        sta csr_org_len
        
        ; Organizational Unit (OU)
        lda #<csr_ou_prompt
        ldy #>csr_ou_prompt
        jsr print_string
        lda #<csr_ou
        sta csr_field_ptr
        lda #>csr_ou
        sta csr_field_ptr+1
        lda #32
        jsr csr_get_field
        sta csr_ou_len
        
        ; Common Name (CN) - required
        lda #<csr_cn_prompt
        ldy #>csr_cn_prompt
        jsr print_string
        lda #<csr_cn
        sta csr_field_ptr
        lda #>csr_cn
        sta csr_field_ptr+1
        lda #40                 ; max 40 chars
        jsr csr_get_field
        sta csr_cn_len
        
        ; Check CN is not empty
        lda csr_cn_len
        bne @cn_ok
        lda #<csr_cn_required_msg
        ldy #>csr_cn_required_msg
        jsr print_string
        rts
        
@cn_ok:
        ; Email address
        lda #<csr_email_prompt
        ldy #>csr_email_prompt
        jsr print_string
        lda #<csr_email
        sta csr_field_ptr
        lda #>csr_email
        sta csr_field_ptr+1
        lda #40
        jsr csr_get_field
        sta csr_email_len
        
        ; --- Preview CSR on screen ---
        lda #$0d
        jsr chrout
        lda #<csr_preview_msg
        ldy #>csr_preview_msg
        jsr print_string
        
        jsr csr_print_content
        
        ; --- Prompt to save ---
        lda #<csr_save_prompt
        ldy #>csr_save_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'N'
        bne +
        jmp @csr_exit
+       cmp #'n'
        bne +
        jmp @csr_exit
+
        ; --- Get drive number ---
        lda #<csr_drive_prompt
        ldy #>csr_drive_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @csr_default_drive
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @csr_default_drive
        sta csr_drive_num
        jmp @csr_got_drive
        
@csr_default_drive:
        lda #8
        sta csr_drive_num
        
@csr_got_drive:
        lda #<csr_using_drive_msg
        ldy #>csr_using_drive_msg
        jsr print_string
        lda csr_drive_num
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- Get filename ---
        lda #<csr_fname_prompt
        ldy #>csr_fname_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        bne @csr_user_fname
        
        ; Use default "MYCSR"
        ldx #0
@copy_default_csr:
        lda csr_default_fname,x
        beq @default_csr_done
        sta actual_filename,x
        inx
        jmp @copy_default_csr
@default_csr_done:
        stx filename_len
        jmp @csr_got_fname
        
@csr_user_fname:
        jsr copy_input_to_filename
        
@csr_got_fname:
        ; --- Write CSR to disk ---
        lda #<csr_saving_msg
        ldy #>csr_saving_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        jsr csr_save_to_disk
        bcs @csr_save_error
        
        lda #<csr_save_ok_msg
        ldy #>csr_save_ok_msg
        jsr print_string
        jmp @csr_exit
        
@csr_save_error:
        lda #<csr_save_fail_msg
        ldy #>csr_save_fail_msg
        jsr print_string
        
@csr_exit:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; csr_get_field - read user input into a CSR field buffer
; csr_field_ptr = destination pointer (set by caller)
; A = max length
; Returns: A = length of input
; =============================================================================
csr_get_field:
        sta csr_max_len
        lda #0
        sta csr_input_len
        
        ; Clear destination buffer
        ldy #0
        lda #0
@clear:
        cpy csr_max_len
        beq @input_loop
        sta (csr_field_ptr),y
        iny
        jmp @clear
        
@input_loop:
        jsr getin
        beq @input_loop
        
        cmp #petscii_return
        beq @input_done
        
        cmp #$14                ; delete
        beq @input_del
        
        ; Check max length
        ldx csr_input_len
        cpx csr_max_len
        bcs @input_loop         ; at max, ignore
        
        ; Store character
        ldy csr_input_len
        sta (csr_field_ptr),y
        inc csr_input_len
        jsr chrout              ; echo
        jmp @input_loop
        
@input_del:
        ldx csr_input_len
        beq @input_loop         ; nothing to delete
        dex
        stx csr_input_len
        txa
        tay
        lda #0
        sta (csr_field_ptr),y
        lda #$14                ; backspace on screen
        jsr chrout
        jmp @input_loop
        
@input_done:
        lda #$0d
        jsr chrout
        lda csr_input_len
        rts

; =============================================================================
; csr_print_content - output the CSR content via chrout
; Works for both screen display and file output (after chkout)
; =============================================================================
csr_print_content:
        ; -----BEGIN CERTIFICATE REQUEST-----
        lda #<csr_begin_line
        ldy #>csr_begin_line
        jsr csr_write_string
        
        ; Key-Type: AES-256
        lda #<csr_keytype_line
        ldy #>csr_keytype_line
        jsr csr_write_string
        
        ; Key: <hex>
        lda #<csr_key_label
        ldy #>csr_key_label
        jsr csr_write_string
        
        ; Write 32 key bytes as 64 hex chars (no spaces)
        lda #0
        sta csr_byte_idx
@key_loop:
        ldx csr_byte_idx
        lda key_data,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr csr_write_hex_nibble
        pla
        and #$0f
        jsr csr_write_hex_nibble
        inc csr_byte_idx
        lda csr_byte_idx
        cmp #32
        bne @key_loop
        lda #$0d
        jsr chrout
        
        ; Subject: /C=xx/ST=xx/L=xx/O=xx/OU=xx/CN=xx
        lda #<csr_subject_label
        ldy #>csr_subject_label
        jsr csr_write_string
        
        ; /C=
        lda csr_country_len
        beq @skip_c
        lda #<csr_tag_c
        ldy #>csr_tag_c
        jsr csr_write_string
        lda #<csr_country
        ldy #>csr_country
        ldx csr_country_len
        jsr csr_write_field
@skip_c:
        ; /ST=
        lda csr_state_len
        beq @skip_st
        lda #<csr_tag_st
        ldy #>csr_tag_st
        jsr csr_write_string
        lda #<csr_state
        ldy #>csr_state
        ldx csr_state_len
        jsr csr_write_field
@skip_st:
        ; /L=
        lda csr_city_len
        beq @skip_l
        lda #<csr_tag_l
        ldy #>csr_tag_l
        jsr csr_write_string
        lda #<csr_city
        ldy #>csr_city
        ldx csr_city_len
        jsr csr_write_field
@skip_l:
        ; /O=
        lda csr_org_len
        beq @skip_o
        lda #<csr_tag_o
        ldy #>csr_tag_o
        jsr csr_write_string
        lda #<csr_org
        ldy #>csr_org
        ldx csr_org_len
        jsr csr_write_field
@skip_o:
        ; /OU=
        lda csr_ou_len
        beq @skip_ou
        lda #<csr_tag_ou
        ldy #>csr_tag_ou
        jsr csr_write_string
        lda #<csr_ou
        ldy #>csr_ou
        ldx csr_ou_len
        jsr csr_write_field
@skip_ou:
        ; /CN= (always present)
        lda #<csr_tag_cn
        ldy #>csr_tag_cn
        jsr csr_write_string
        lda #<csr_cn
        ldy #>csr_cn
        ldx csr_cn_len
        jsr csr_write_field
        
        lda #$0d
        jsr chrout
        
        ; Email: (if provided)
        lda csr_email_len
        beq @skip_email
        lda #<csr_email_label
        ldy #>csr_email_label
        jsr csr_write_string
        lda #<csr_email
        ldy #>csr_email
        ldx csr_email_len
        jsr csr_write_field
        lda #$0d
        jsr chrout
@skip_email:
        
        ; -----END CERTIFICATE REQUEST-----
        lda #<csr_end_line
        ldy #>csr_end_line
        jsr csr_write_string
        
        rts

; =============================================================================
; csr_write_string - write null-terminated string via chrout
; =============================================================================
csr_write_string:
        sta csr_ws_lo
        sty csr_ws_hi
        ldy #0
@loop:
        lda (csr_ws_lo),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts
csr_ws_lo = zp_ptr              ; reuse zp_ptr

; Alias for high byte
csr_ws_hi = zp_ptr+1

; =============================================================================
; csr_write_field - write field buffer of known length via chrout
; A/Y = buffer address low/high, X = length
; =============================================================================
csr_write_field:
        sta csr_wf_lo
        sty csr_wf_hi
        stx csr_wf_len
        ldy #0
@loop:
        cpy csr_wf_len
        beq @done
        lda (csr_wf_lo),y
        jsr chrout
        iny
        jmp @loop
@done:
        rts

csr_wf_lo = zp_ptr2            ; reuse zp_ptr2
csr_wf_hi = zp_ptr2+1
csr_wf_len:
        !byte 0

; =============================================================================
; csr_write_hex_nibble - write a single hex nibble via chrout
; A = value 0-15
; =============================================================================
csr_write_hex_nibble:
        cmp #10
        bcc @digit
        clc
        adc #($41 - 10)         ; 'A'
        jmp chrout
@digit:
        clc
        adc #$30                ; '0'
        jmp chrout

; =============================================================================
; csr_save_to_disk - write CSR content to sequential file
; Returns: carry clear = success, carry set = error
; =============================================================================
csr_save_to_disk:
        ; Ensure clean I/O state
        jsr clrchn
        lda #3
        jsr close
        
        ; Build "0:filename,s,w"
        jsr build_write_filename
        
        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam
        
        lda #3
        ldx csr_drive_num
        ldy #3
        jsr setlfs
        
        jsr open
        bcs @error
        
        ldx #3
        jsr chkout
        bcs @close_error
        
        ; Write CSR content (chrout now directed to file)
        jsr csr_print_content
        
        ; Check status
        jsr readst
        and #$83
        bne @close_error
        
        jsr clrchn
        lda #3
        jsr close
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #3
        jsr close
@error:
        sec
        rts

; --- CSR field pointer (reuses zp_ptr2) ---
csr_field_ptr   = zp_ptr2

; --- CSR variables ---
csr_max_len:    !byte 0
csr_input_len:  !byte 0
csr_byte_idx:   !byte 0
csr_drive_num:  !byte 8

csr_country:    !fill 3, 0
csr_country_len: !byte 0
csr_state:      !fill 33, 0
csr_state_len:  !byte 0
csr_city:       !fill 33, 0
csr_city_len:   !byte 0
csr_org:        !fill 33, 0
csr_org_len:    !byte 0
csr_ou:         !fill 33, 0
csr_ou_len:     !byte 0
csr_cn:         !fill 41, 0
csr_cn_len:     !byte 0
csr_email:      !fill 41, 0
csr_email_len:  !byte 0

csr_default_fname:
        !text "MYCSR"
        !byte 0

; --- CSR prompt messages ---
csr_submenu_msg:
        !text "J: CSR/ECDSA"
        !byte $0d
        !text "1=GENERATE CSR  2=ECDSA TEST"
        !byte $0d, 0

csr_header_msg:
        !text "=== CSR GENERATION ==="
        !byte $0d
        !text "ENTER CSR SUBJECT FIELDS."
        !byte $0d
        !text "PRESS RETURN TO SKIP OPTIONAL FIELDS."
        !byte $0d, 0

csr_country_prompt:
        !text "COUNTRY (2 LETTER CODE): "
        !byte 0

csr_state_prompt:
        !text "STATE/PROVINCE: "
        !byte 0

csr_city_prompt:
        !text "CITY/LOCALITY: "
        !byte 0

csr_org_prompt:
        !text "ORGANIZATION: "
        !byte 0

csr_ou_prompt:
        !text "ORG UNIT: "
        !byte 0

csr_cn_prompt:
        !text "COMMON NAME (REQUIRED): "
        !byte 0

csr_email_prompt:
        !text "EMAIL ADDRESS: "
        !byte 0

csr_cn_required_msg:
        !text "COMMON NAME IS REQUIRED."
        !byte $0d, 0

csr_preview_msg:
        !text "--- CSR PREVIEW ---"
        !byte $0d, 0

csr_save_prompt:
        !byte $0d
        !text "SAVE CSR TO DISK? (Y/N, ENTER=YES) "
        !byte 0

csr_drive_prompt:
        !text "DRIVE NUMBER (ENTER=8): "
        !byte 0

csr_using_drive_msg:
        !text "USING DRIVE "
        !byte 0

csr_fname_prompt:
        !text "FILENAME (ENTER=MYCSR): "
        !byte 0

csr_saving_msg:
        !text "SAVING CSR TO "
        !byte 0

csr_save_ok_msg:
        !text "CSR SAVED SUCCESSFULLY."
        !byte $0d, 0

csr_save_fail_msg:
        !text "ERROR SAVING CSR!"
        !byte $0d, 0

; --- CSR file content strings ---
csr_begin_line:
        !text "-----BEGIN CERTIFICATE REQUEST-----"
        !byte $0d, 0

csr_end_line:
        !text "-----END CERTIFICATE REQUEST-----"
        !byte $0d, 0

csr_keytype_line:
        !text "KEY-TYPE: AES-256"
        !byte $0d, 0

csr_key_label:
        !text "KEY: "
        !byte 0

csr_subject_label:
        !text "SUBJECT: "
        !byte 0

csr_tag_c:
        !text "/C="
        !byte 0

csr_tag_st:
        !text "/ST="
        !byte 0

csr_tag_l:
        !text "/L="
        !byte 0

csr_tag_o:
        !text "/O="
        !byte 0

csr_tag_ou:
        !text "/OU="
        !byte 0

csr_tag_cn:
        !text "/CN="
        !byte 0

csr_email_label:
        !text "EMAIL: "
        !byte 0

; =============================================================================
; Debug messages
; =============================================================================

; Include ECDSA P-256 implementation
!source "ecdsa_p256.asm"

debug_len_msg:
        !text "ENC LEN: "
        !byte 0

debug_blk_msg:
        !text "BLOCKS: "
        !byte 0

debug_cur_msg:
        !text "CUR BLK: "
        !byte 0

debug_state_msg:
        !text "STATE: "
        !byte 0

debug_after_dec_msg:
        !text "AFTER DEC: "
        !byte 0

debug_after_xor_msg:
        !text "AFTER XOR: "
        !byte 0

debug_cbc_msg:
        !text "CBC VEC: "
        !byte 0

debug_iv_msg:
        !text "IV DATA: "
        !byte 0

dbg_ark14_msg:
        !text "ARK14: "
        !byte 0

dbg_mainrnd_msg:
        !text "MAINRND: "
        !byte 0

dbg_inlen_msg:
        !text "IN LEN: "
        !byte 0

dbg_inbuf_msg:
        !text "IN BUF: "
        !byte 0

dbg_blocks_msg:
        !text "BLOCKS: "
        !byte 0

dbg_enclen_msg:
        !text "ENC LEN: "
        !byte 0

dbg_expkey_msg:
        !text "EXP KEY: "
        !byte 0
