; =============================================================================
; sid_config.asm - SID configuration UI, trumpet player, random stream, address parsing
; Related: prng.asm (init_sid, init_all_sids)
; =============================================================================

.segment "CODE"

.importzp zp_ptr, zp_temp
.import chrout, getin
.import filename_buf, input_index
.import sid_config_header, sid_current_msg, sid_chips_msg, sid_extra_prompt
.import sid_addr_prompt, sid_configured_msg, instructions_msg
.import random_stream_header, stream_sids_msg, stream_sids_suffix
.import stream_live_header, stream_stopped_msg, stream_rate_label
.import stream_bps_msg, stream_sample_msg
.import print_string, print_hex_byte, print_decimal_word
.import get_input_line
.import drbg_random_byte
.import getin_wait

.export do_config_sid, do_random_stream
.export extra_sid_count, extra_sid_lo, extra_sid_hi

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
        .byte 0
trumpet_sid_num:
        .byte 0
trumpet_note_count:
        .byte 0
trumpet_current_note:
        .byte 0

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
        jsr drbg_random_byte

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
        .byte 0

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

        jsr drbg_random_byte
        jsr print_hex_byte

        lda #' '
        jsr chrout
        jsr drbg_random_byte
        jsr print_hex_byte

        lda #' '
        jsr chrout
        jsr drbg_random_byte
        jsr print_hex_byte

        lda #' '
        jsr chrout
        jsr drbg_random_byte
        jsr print_hex_byte

        rts

; Variables for SID config
extra_sid_count:
        .byte 0                 ; number of extra SIDs (0-3)
extra_sid_lo:
        .byte 0, 0, 0           ; low bytes of extra SID addresses
extra_sid_hi:
        .byte 0, 0, 0           ; high bytes of extra SID addresses
parse_idx:
        .byte 0

; Variables for random stream
stream_bytes_lo:
        .byte 0
stream_bytes_mid:
        .byte 0
stream_rate_jiffy:
        .byte 0
stream_rate_lo:
        .byte 0
stream_rate_hi:
        .byte 0
