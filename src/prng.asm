; =============================================================================
; prng.asm - SID-based PRNG: init_sid, init_all_sids, seed_lfsr, generate_bytes, lfsr_random
; Related: sid_config.asm (multi-SID configuration)
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

