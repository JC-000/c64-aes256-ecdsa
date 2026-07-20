; =============================================================================
; main.s - AES-256 / ECDSA P-256 for Commodore 64 (ca65 port)
; Build with ca65/ld65 - see linker config (.cfg) for the equivalent of
; ACME's '!to "aes256keygen.prg", cbm' output format and the '* = $0801' /
; '* = $7C00' origin directives (see notes below).
;
; Phase 5 (docs/modular_restructure_plan.md): this file used to be the
; single .include manifest for the whole program. As of Phase 5's final
; batch, every src/*.s module (all 34, including zp_config.s/lib_version.s
; added in earlier phases) is a real, standalone ca65 object — see the
; Makefile's MODULES list for the full inventory and object order.
; src/remainder.s (the incremental scaffolding file used during Phase 5's
; batches) no longer exists; it was deleted once the last two modules
; (boot.s, main_loop.s) were extracted. This file now contains only the
; LOADADDR segment stub.
; =============================================================================

        .setcpu "6502"

; --- 2-byte PRG load-address header (ld65 LOADADDR segment, see linker.cfg).
; Equivalent to ACME's cbm output format prepending $0801. ---
.segment "LOADADDR"
        .word $0801

; --- Program origin ---
; ACME: * = $0801  (standard C64 BASIC-stub load address)
; NOTE: address placement is a LINKER CONFIG concern under ca65/ld65, not an
; in-source '.org'. The segment(s) holding the code below must be placed at
; $0801 by the ld65 linker configuration (equivalent to ACME's cbm output
; format, which prepends the 2-byte $0801 load-address header).
