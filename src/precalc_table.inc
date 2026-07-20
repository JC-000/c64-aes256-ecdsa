; precalc_table.inc — canonical per c64-lib-contract SPEC §8.0 catch-loop.
;
; CANONICAL SOURCE. The fenced code block in SPEC.md §8.0 is shown for
; readability; this file is the byte-for-byte source adopters copy into
; their own src/precalc_table.inc. Updates land via coordinated cross-repo
; PR; do not edit your local copy.
;
; Smoke-tested in examples/precalc_table_smoke.s and exercised by `make verify`
; at this repo's root.

.ifndef PRECALC_TABLE_INC_INCLUDED
PRECALC_TABLE_INC_INCLUDED = 1

PRECALC_REGION_RAM     = $01
PRECALC_REGION_REU     = $02
PRECALC_REGION_RODATA  = $03

PRECALC_SHARED_NO      = $00
PRECALC_SHARED_YES     = $01

; LIB_PRECALC_TABLE "name", size_bytes, region, shared
;
;   "name":       quoted string literal (becomes the symbol suffix;
;                 use lower_snake_case, no leading digit)
;   size_bytes:   total bytes claimed by the table
;   region:       PRECALC_REGION_RAM | _REU | _RODATA
;   shared:       PRECALC_SHARED_YES | PRECALC_SHARED_NO
;
; Emits three exported equates per invocation. The macro preserves the
; case of the `name` argument verbatim (ca65 has no built-in toupper),
; so `LIB_PRECALC_TABLE "sqtab", ...` emits the symbols below in their
; lower-case form. The normative §8.x canonical names use
; lower_snake_case throughout, so cross-adopter audits grep on a single
; case convention:
;
;   LIB_PRECALC_<name>_SIZE     = size_bytes
;   LIB_PRECALC_<name>_REGION   = region
;   LIB_PRECALC_<name>_SHARED   = shared
;
; SIZE is exported without an address-size hint so values > 16 bits
; (e.g. the 131072-byte REU mul table) export cleanly as 'far'
; without a "far but exported absolute" warning. REGION and SHARED
; are byte-valued and exported without a hint for consistency.

.macro LIB_PRECALC_TABLE name, size_bytes, region, shared
    .ident (.sprintf("LIB_PRECALC_%s_SIZE",   name)) = size_bytes
    .ident (.sprintf("LIB_PRECALC_%s_REGION", name)) = region
    .ident (.sprintf("LIB_PRECALC_%s_SHARED", name)) = shared

    .export .ident (.sprintf("LIB_PRECALC_%s_SIZE",   name))
    .export .ident (.sprintf("LIB_PRECALC_%s_REGION", name))
    .export .ident (.sprintf("LIB_PRECALC_%s_SHARED", name))
.endmacro

.endif ; PRECALC_TABLE_INC_INCLUDED
