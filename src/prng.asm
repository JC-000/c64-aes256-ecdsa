; =============================================================================
; prng.asm - SID hardware initialization: init_sid, init_all_sids
; Related: sid_config.asm (multi-SID configuration), hmac_drbg.asm (DRBG PRNG)
; =============================================================================

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

        rts

; =============================================================================
; init_all_sids - initialize all configured SIDs with entropy-offset delays
; Each SID gets a unique delay derived from SID+CIA entropy to decorrelate
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
        
        ; Use SID+CIA entropy for a unique delay per SID
        ; This ensures each SID's noise generator is phase-offset
        lda sid_osc3            ; read SID oscillator 3
        eor cia1_ta_lo          ; mix with CIA timer
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

