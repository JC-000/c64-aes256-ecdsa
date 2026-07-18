# ca65 translation notes

Several module headers in `src/*.s` reference "the translation report" /
`manual_attention_needed` for addressing-mode and linkage caveats found during the
ACME-to-ca65 port. That report was generated during the port's Translate phase (one
agent per module) but was never committed to the repository, leaving those header
comments pointing at a document that didn't exist. This file restores the entries for
the modules that reference it, recovered from the original per-module translation
records. It is not a full re-derivation of notes for all 26 ported modules - only the
ones whose headers cite it, plus `constants.s` (directly relevant to the zero-page
layout note in `build_ca65/linker.cfg`).

## constants.s

Pure equates (no code, no `!byte`/`!text`/`!source`/`!zone`/`* =` directives), almost a
verbatim copy. One real issue found: the original ACME source defines `chrin = $ffcf`
twice (once documented "kernal: input character", once "input character") - ACME
tolerates redefining a symbol via `=` as long as the value is unchanged, but ca65's `=`
defines a true constant and errors on any redefinition, even with an identical value
(ca65's redefinable form is `.set`, not `=`). The second occurrence was commented out
rather than silently dropped or converted to `.set`, with an inline note pointing here.
Zero-page symbols defined in this file ($02-$09, $0A-$12, $FB/$FD/$FE) were cross-checked
and are consistent with the ranges used elsewhere; the $22-$2B and $39-$3C ranges are not
referenced/defined in this file (see `ecdsa_fp.s`).

**Note (found during a later review, 2026-07-16):** HANDOFF.md's documented zero-page map
does not list `zp_ptr2`($02-03), `zp_round`($04), `zp_col`($05), or `zp_tmp1`-`zp_tmp4`
($06-09) at all, even though `constants.s` (and the original `constants.asm`) has always
defined them. This is a pre-existing gap in HANDOFF.md's documentation, not something the
port introduced - `build_ca65/linker.cfg`'s original zero-page layout was designed against
HANDOFF.md's incomplete table and consequently mis-declared $02-$09 as free ("ZP1"), which
has since been corrected (see the linker.cfg header comment for the full, source-verified
occupancy map). HANDOFF.md's own zero-page table should be corrected separately.

## display.s

Zero ACME-specific directives (no `!byte`/`!word`/`!fill`/`!text`/`!pet`/`!source`/`!zone`,
no `* =`). Every line is a plain 6502 mnemonic, global label, or `@local` cheap label - all
already valid ca65 syntax verbatim. Flagged for Integrate (addressed there, not here):
zero-page symbols `zp_ptr`, `zp_count`, `zp_temp` are referenced throughout via both direct
and indirect-indexed (`(zp_ptr),y`) addressing. The indirect-indexed form is unambiguous
(6502 only has a zero-page form for it), but direct references (`sta zp_ptr`, `dec
zp_count`, etc.) have both zero-page and absolute encodings - ca65 will silently choose the
3-byte absolute form if it can't prove the symbol resolves into zero page at assemble time.
Resolved by keeping the whole project as one `.include`-chained assembly unit (mirroring
ACME's `!source` model), so all symbols are defined in-unit before any reference assembles.

## aes_encrypt.s

No ACME-specific directives anywhere in the file; translation is a verbatim mnemonic/label
port (header comment and whitespace only differ). Two things flagged for Integrate:
1. Zero-page temps (`zp_tmp1-4`, `zp_round`, `zp_col`, `zp_count`, `zp_temp`) are used with
   non-indexed addressing and are defined in another module - same zero-page/absolute
   addressing-mode risk as `display.s` above, resolved the same way (single assembly unit).
2. Indexed-absolute references with negative label offsets (`expanded_key-4,x` through
   `expanded_key-1,x`, and `expanded_key-32,x` through `-29,x`) inside `aes_key_expansion`
   depend on `expanded_key` resolving as an absolute label at assembly time. No issue
   observed once linked as a single unit.

## aes_decrypt.s

No ACME-specific directives; verbatim translation (only the header comment changed).
Same zero-page/absolute addressing-mode consideration as `aes_encrypt.s`/`display.s` for
its external references to `zp_ptr`, `zp_count`, `zp_round`, `zp_col`, `zp_tmp1`, `zp_temp`
- resolved by the single-assembly-unit model.

## sha256.s

One real syntax translation: ACME's `+` forward-reference anonymous labels (in
`sha256_rotr1`/`sha256_rotl1`) became ca65's anonymous-label syntax (`:` to define, `:+` to
reference forward) - verified to assemble correctly with a standalone smoke test. No
`* =`, `!zone`, `!text`, `!pet`, `!if`/`!ifdef`, or `!fill` directives anywhere; all data
was plain `!byte` mapping 1:1 to `.byte`. References many symbols defined elsewhere
(`sha256_h0..h7`, `sha_a..sha_h`, `zp_ptr`, `zp_count`, etc.) - resolved via the
single-assembly-unit model, same as above. Verified the translated file assembles cleanly
standalone with `ca65 -U` (auto-import flag used only for this isolated syntax check, not
a statement about the real linker config).

## disk_io.s

The most mechanical of the modules - genuinely zero ACME-specific pseudo-ops (verified by
grep), pure 6502 mnemonics/labels/`@`-locals, verbatim port apart from the header comment.
Cross-checked against the original ACME build's own "oversized addressing mode" warnings:
this file produced zero such warnings (all of ACME's warnings were in `csr.asm`/`base64.asm`,
untouched by this file), so no instruction here needs an explicit ca65 absolute-addressing
override. `zp_ptr`/`zp_count` are referenced only via direct (non-indexed) addressing in
this file, never `(zp),y`, so nothing zero-page-specific needed disambiguating here.

## ecdsa_mod.s

Three anonymous-label sites (`bne +` ... standalone `+`) converted to ca65's `bne :+` ...
`:` syntax - each is a self-contained triplet with no ambiguity, though anonymous-label
scoping is easy to break if code is inserted between reference and target later. Character
literals (`.`, `H`, `V`, `C`, `U`) used in `fp_mod_inv`'s debug trace output translated as
bare ca65 char literals with the same values (debug-only, not part of any cryptographic
computation). References external zero-page symbols `fp_misc`, `fp_src1`, `fp_src2`,
`fp_dst`, `fp_carry`, `fp_wide` (defined in `ecdsa_fp.s`) - correctness for the
indirect-indexed `(fp_misc),y` addressing in `fp_mod_reduce` depends on `fp_misc` actually
landing in zero page, confirmed via the single-assembly-unit model and the linker.cfg
zero-page reservations.

## data.s (referenced here for context, not in the dangling-reference list)

Not cited by any module header, but worth preserving: `!fill n, 0` (ACME) maps to
`.res n, 0` (ca65) for buffer zero-initialization. This is only equivalent if the segment
these buffers land in is a real initialized-data segment - if the linker config ever maps
this file's default segment to a BSS-type segment (common for "uninitialized" scratch RAM),
the fill value is dropped silently and the C64 will not actually zero this memory on load.
`build_ca65/linker.cfg` keeps `data.s`'s buffers in the `DATA`/`BSS` split under the `MAIN`
memory area with `fill = yes` on `MAIN` itself - confirmed this preserves the zero-init
guarantee for the file-backed portion of the PRG.
