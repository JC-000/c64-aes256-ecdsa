; =============================================================================
; constants.s - System equates, zero page, hardware addresses, AES constants
; No code emitted - pure equates only
; =============================================================================

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
;chrin          = $ffcf         ; input character (duplicate of line 11 - ca65 errors on redefining
                                ; a '=' constant even with an identical value; see
                                ; docs/ca65_translation_notes.md)
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
sha_temp1       = $0a           ; SHA-256 temp (4 bytes: $0A-$0D)
sha_temp2       = $0e           ; SHA-256 temp (4 bytes: $0E-$11)
sha256_round    = $12           ; SHA-256 round counter
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
