; =============================================================================
; main.asm - AES-256 / ECDSA P-256 for Commodore 64
; Top-level assembly file. Build with:
;   acme -f cbm -o build/aes256keygen.prg --vicelabels build/labels.txt src/main.asm
; =============================================================================

        !cpu 6502
        !to "aes256keygen.prg", cbm

; --- Constants and equates (no code emitted) ---
!source "constants.asm"

; --- Program origin ---
        * = $0801

; --- Code modules (order = binary layout, DO NOT reorder) ---
!source "boot.asm"
!source "main_loop.asm"
!source "reu_core.asm"
!source "aes_encrypt.asm"
!source "aes_decrypt.asm"
!source "disk_io.asm"
!source "gcm_siv.asm"
!source "benchmark.asm"
!source "reu_advanced.asm"
!source "sid_config.asm"
!source "sha256.asm"
!source "prng.asm"
!source "display.asm"

; --- Data and tables ---
!source "data.asm"
!source "tables.asm"
!source "strings.asm"

; --- CSR and ECDSA ---
!source "csr.asm"
!source "ecdsa_p256.asm"
!source "debug_strings.asm"
