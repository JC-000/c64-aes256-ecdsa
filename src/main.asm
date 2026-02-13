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
; --- ECDSA P-256 (split into layers) ---
!source "ecdsa_fp.asm"
!source "ecdsa_mod.asm"
!source "ecdsa_curve.asm"
!source "ecdsa_points.asm"
!source "ecdsa_sign.asm"
!source "ecdsa_test.asm"

; --- PKCS#10 CSR generation ---
; Skip over quarter-square table region ($7800-$7BFF) used by fp_init_sqtab
        * = $7C00
!source "hmac_drbg.asm"
!source "der_encode.asm"
!source "base64.asm"
!source "pkcs10_build.asm"
!source "pkcs10.asm"

!source "debug_strings.asm"
