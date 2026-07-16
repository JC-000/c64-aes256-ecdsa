; =============================================================================
; main.s - AES-256 / ECDSA P-256 for Commodore 64 (ca65 port)
; Top-level assembly file. Build with ca65/ld65 - see linker config (.cfg)
; for the equivalent of ACME's '!to "aes256keygen.prg", cbm' output format
; and the '* = $0801' / '* = $7C00' origin directives (see notes below).
; =============================================================================

        .setcpu "6502"

; --- 2-byte PRG load-address header (ld65 LOADADDR segment, see linker.cfg).
; Equivalent to ACME's cbm output format prepending $0801. ---
.segment "LOADADDR"
        .word $0801

.segment "CODE"

; --- Constants and equates (no code emitted) ---
.include "constants.s"

; --- Program origin ---
; ACME: * = $0801  (standard C64 BASIC-stub load address)
; NOTE: address placement is a LINKER CONFIG concern under ca65/ld65, not an
; in-source '.org'. The segment(s) holding the code below must be placed at
; $0801 by the ld65 linker configuration (equivalent to ACME's cbm output
; format, which prepends the 2-byte $0801 load-address header).

; --- Code modules (order = binary layout, DO NOT reorder) ---
.include "boot.s"
.include "main_loop.s"
.include "reu_core.s"
.include "aes_encrypt.s"
.include "aes_decrypt.s"
.include "disk_io.s"
.include "gcm_siv.s"
.include "polyval.s"
.include "benchmark.s"
.include "reu_advanced.s"
.include "sid_config.s"
.include "sha256.s"
.include "prng.s"
.include "display.s"

; --- Data and tables ---
.include "data.s"
.include "tables.s"
.include "strings.s"

; --- CSR and ECDSA ---
.include "csr.s"
; --- ECDSA P-256 (split into layers) ---
.include "ecdsa_fp.s"
.include "ecdsa_mod.s"
.include "ecdsa_curve.s"
.include "ecdsa_points.s"
.include "ecdsa_sign.s"

; --- PKCS#10 CSR generation ---
; ACME: * = $7C00 -- skip over quarter-square table region ($7800-$7BFF)
; used by fp_init_sqtab.
; NOTE: as above, this is a LINKER CONFIG concern, not an in-source directive.
; The segment containing the modules below must be placed starting at $7C00
; by the ld65 config so it does not collide with the page-aligned,
; runtime-built $7800-$7BFF (1KB, two 256-byte-aligned halves) quarter-square
; multiplication lookup table referenced directly by fp_mul (see ecdsa_fp.s).
; ca65 port note: the ca65/ld65 codebase grew slightly larger than the
; original ACME build (extra exported labels, section alignment), so the
; HICODE cutover point was moved a few hundred bytes earlier than ACME's
; historical '* = $7C00' to keep everything clear of the $7800 quarter-square
; table region; ecdsa_test.s (diagnostic/debug UI, not on the hot path) now
; lives in HICODE alongside the PKCS#10 modules instead of in MAIN.
.segment "HICODE"
.include "ecdsa_test.s"
.include "hmac_drbg.s"
.include "der_encode.s"
.include "base64.s"
.include "pkcs10_build.s"
.include "pkcs10.s"

.include "debug_strings.s"
