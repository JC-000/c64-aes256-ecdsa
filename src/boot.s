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
.export restore_system

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

; =============================================================================
; basic stub: 10 SYS 2061
;
; 2061 = $080D = `start`, which is basic_stub ($0801) + this stub's 12 bytes:
;   .word basic_end (2) + .word 10 (2) + $9e (1) + "2061" (4) + $00 (1)
;   + .word 0 (2)  =  12
;
; It said "2064" ($0810) from the ACME days until 2026-08-23, three bytes PAST
; `start`. SYS therefore landed on the `lda #$8e` below and skipped the
; `jsr clrscr` entirely -- which is why this program never cleared the screen
; on RUN, a symptom nobody chased because the test suites only wait for
; "Q=QUIT" to appear and do not care what else is on screen.
;
; ***  IF YOU ADD CODE AT THE TOP OF `start`, THE DIGITS ABOVE MUST STILL  ***
; ***  NAME IT.  Getting this wrong is SILENT.  Under the old off-by-3, a  ***
; ***  four-byte insert at `start` would have put SYS's landing point in   ***
; ***  the MIDDLE of an instruction; a smaller one would simply have been  ***
; ***  jumped over -- build green, boot gate green, feature dead.  That is ***
; ***  exactly how the $01 banking below could have been "added" without   ***
; ***  ever executing.  tools/check_boot_position.py now parses these      ***
; ***  digits and compares them against the real `start` label, so the     ***
; ***  mismatch is caught at build time rather than at a head-scratch.     ***
; =============================================================================
basic_stub:
        .word basic_end         ; pointer to next basic line
        .word 10                ; line number 10
        .byte $9e               ; sys token
        .byte "2061"            ; SYS target as ascii digits == `start` ($080D)
        .byte 0                 ; end of line
basic_end:
        .word 0                 ; end of basic program

; =============================================================================
; main program entry point ($0810)
; =============================================================================
start:
        ; ---------------------------------------------------------------------
        ; RESTORE-key (NMI) safety -- installed FIRST, before BASIC is banked
        ; out, so there is never an instant where a RESTORE could take the
        ; KERNAL's default path while $A000 is RAM.
        ;
        ; Hardware NMI -> $FFFA -> $FE43 (KERNAL) -> JMP ($0318). The default
        ; ($0318) = $FE47 ends by jumping through ($A002), BASIC's warm-start
        ; vector. With BASIC banked out that address holds POLYVAL CODE BYTES,
        ; which would be read as a pointer and jumped to -- an undefined crash
        ; on a keypress that today merely drops back to READY. Our handler
        ; below swallows the NMI instead.
        ;
        ; The two-store vector update is not atomic and an NMI landing between
        ; them would use a half-written pointer. That is a ~4-cycle window in
        ; the first instructions after RUN, and NMI cannot be masked by SEI,
        ; so there is no cheap way to close it; noted rather than papered over.
        ; ---------------------------------------------------------------------
        lda $0318
        sta saved_nmi_vec
        lda $0319
        sta saved_nmi_vec+1
        lda #<nmi_handler
        sta $0318
        lda #>nmi_handler
        sta $0319

        ; ---------------------------------------------------------------------
        ; Bank BASIC ROM out: $01 = $36 (LORAM=0, HIRAM=1, CHAREN=1).
        ;
        ; REQUIRED, not an optimisation. Since the c64-polyval swap the program
        ; image spans $0801-$CCFF, and LIB_POLYVAL_SHORT_CODE at $9602-$CB2F has
        ; 8,192 of its 13,614 bytes (60%) sitting under the BASIC ROM window at
        ; $A000-$BFFF. The KERNAL loader writes those bytes to RAM correctly, so
        ; the PRG loads fine -- the CPU just cannot SEE them: reading $A25E
        ; (polyval_multiply) returns BASIC's "GAL QUAN" text instead of code,
        ; and polyval_precompute_table wedges at $A005. Relocation cannot fix
        ; it; the image needs ~48 KB of read-only space and only ~38 KB exists
        ; below $A000.
        ;
        ; $36 leaves HIRAM=1 and CHAREN=1, so KERNAL ($E000-$FFFF) and I/O
        ; ($D000-$DFFF) both stay mapped. Every KERNAL call this program makes
        ; (chrout/chrin/getin/open/close/chkin/chkout/clrchn/readst/setlfs/
        ; setnam, and clrscr at $E544), the SID entropy source, the CIA timers,
        ; the REU registers at $DF00 and the default $EA31 IRQ are all
        ; unaffected. Nothing in this program uses BASIC ROM at all: no
        ; floating point, no BASIC entry points, no equate anywhere in
        ; $A000-$BFFF.
        ;
        ; Whole-program rather than per-call because this is a property of the
        ; memory MAP, not of POLYVAL: any future module placed above $A000
        ; needs the same thing, and a per-call overlay would make "caller must
        ; bank BASIC out" an unwritten precondition of the POLYVAL ABI that
        ; wedges instead of erroring when violated.
        ;
        ; Undone by restore_system below. Related trap, since it looks like
        ; this one and is NOT: benchmark.s:258-275 reads $A0/$A1/$A2 inside
        ; sei/cli. Those are the KERNAL jiffy clock in ZERO PAGE, not the ROM
        ; window, and banking does not touch them.
        ; ---------------------------------------------------------------------
        lda #$36
        sta $01

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

; =============================================================================
; restore_system - undo both global machine changes `start` made, so a program
; that has exited leaves the C64 exactly as it found it. Called from
; main_loop.s's @quit path immediately before its `rts` back to BASIC.
;
; ORDER MATTERS: $01 first, THEN the NMI vector. Reinstating the KERNAL's
; default handler while BASIC is still banked out would re-open the very
; ($A002)-into-polyval-bytes hole this pair exists to close, for however many
; cycles the rest of this routine takes. Restoring $01 first means BASIC ROM is
; already back under $A000 before anything can jump through it again.
;
; Returning to BASIC without the $37 restore would be worse than a crash-on-
; RESTORE: the `rts` lands in the BASIC interpreter, which is not there.
; =============================================================================
restore_system:
        lda #$37                ; LORAM=1: BASIC ROM back at $A000-$BFFF
        sta $01

        lda saved_nmi_vec
        sta $0318
        lda saved_nmi_vec+1
        sta $0319
        rts

; =============================================================================
; nmi_handler - minimal RESTORE-key swallower. See the install site in `start`.
;
; $FE43 does SEI then JMP ($0318) WITHOUT saving any register, so a handler
; reached this way must preserve whatever it touches itself. This one clobbers
; only A (RTI restores P from the stack), hence the single pha/pla pair.
;
; The $DD0D read acknowledges and clears any CIA2 interrupt source. A RESTORE
; keypress is edge-triggered straight onto the NMI line and does not latch, so
; strictly it needs no acknowledge -- but a CIA2-sourced NMI would re-fire
; forever without one, and this program never programs CIA2's ICR to say which
; it will be. $DD0D is I/O, mapped under both $36 and $37.
; =============================================================================
nmi_handler:
        pha
        lda $dd0d               ; ack/clear any CIA2 NMI source
        pla
        rti

; Saved KERNAL ($0318) NMI vector. In LIB_AES256ECDSA_CODE like every other
; buffer this project keeps (see src/data.s) -- the segment is `type = ro` to
; ld65 only in the sense that it is loaded from the PRG; it is ordinary RAM at
; runtime.
saved_nmi_vec:
        .res 2, 0
