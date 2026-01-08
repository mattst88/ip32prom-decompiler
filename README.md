# ip32prom-decompiler

Decompile the PROM firmware for the Silicon Graphics O2 (IP32) and reassemble into a bit-identical image.

## Background

The [Silicon Graphics O2](https://en.wikipedia.org/wiki/SGI_O2) is a Unix workstation with a MIPS CPU.

There are two families of CPUs available for the O2:

- in-order [R5000](https://en.wikipedia.org/wiki/R5000) / RM7000 CPUs, from 180-350 MHz
- out-of-order [R10000](https://en.wikipedia.org/wiki/R10000) / [R12000](https://en.wikipedia.org/wiki/R12000) CPUs, from 150-400 MHz

In the early 2000s, members of the Nekochan community replaced the 300 MHz RM5200 and 350 MHz RM7000A CPUs with a faster 600 MHz RM7000C model. The 600 MHz CPU, though in-order, is faster than the out-of-order 400 MHz R12000 CPU in most cases.

This modification is documented by [SGI Depot](http://www.sgidepot.co.uk/) in the article [Upgrading an O2 to 600MHz (and beyond!)](http://www.sgidepot.co.uk/o2cpumod.html). While replacing a BGA-mounted CPU takes significant tooling and expertise, the modification does not require any firmware or software changes.

## The Problem

As the title ("Upgrading an O2 to 600MHz (and beyond!)") of the article might suggest, there were hopes of further upgrades. The article notes

> Meanwhile, Joe unfortunately did not have any success with the PMC 866Mhz CPU - apparently it is not quite as compatible with R5200 as PMC thought. Meanwhile, any ideas about a 900 are somewhat hampered by the need to have a distinctly modified IP32 PROM image, which would need some assistance from SGI. Who knows if they would be willing to help; one can but ask!
>
> Watch this space!!

The 900 MHz CPU referred to is the RM7900 from PMC-Sierra. The RM7900 uses a newer E9000 CPU core but in a 304-pin BGA package compatible with earlier RM7000 CPUs. It is not clear to me what the 866 MHz CPU is — I can find no evidence of an 866 MHz MIPS CPU, RM7000 or otherwise.

Presumably any attempts to use an RM7900 failed without support in the O2's PROM firmware.

At the time, Silicon Graphics still existed and there remained some faint hope for access to the source code of the PROM — the boot firmware — but today Silicon Graphics is long gone and with it the source code for the PROM. (as well as any concerns about legal issues from reverse engineering!)

## The (partial) Solution

I reverse engineered the PROM firmware and wrote a program to decompile it into modifiable assembly (`.S`) files. The assembly files can be reassembled into a bit-identical PROM image, thus verifying that the decompilation was accurate.

With the PROM firmware now decompiled into modifiable assembly, the "distinctly modified IP32 PROM image" needed for RM7900 support is possible — no assistance from SGI required.

See [doc/reverse-engineering.md](doc/reverse-engineering.md) for details on the process.

### External Annotations

The assembly files are made more comprehensible with various annotations and other improvements to readability.

| Filename | Purpose |
| -------- | ------- |
| [labels.json](annotations/labels.json) | Named addresses for branch targets and data |
| [comments.json](annotations/comments.json) | Per-instruction documentation |
| [functions.json](annotations/functions.json) | Function boundaries and descriptions |
| [operands.json](annotations/operands.json) | Instruction operand replacements |
| [relocations.json](annotations/relocations.json) | Code that executes at different addresses than stored |
| [bss.json](annotations/bss.json) | Named BSS (uninitialized data) symbols |

The resulting assembly:

<table>
<tr>
<th>Without improvements</th>
<th>With improvements</th>
</tr>

<tr>
<td>

```




L_0xbfc019b0:
	lui	    $t1, 0xbfc0
	lui	    $t0, 0xa000
	addiu	$t1, $t1, 0x19c8
	or	    $t0, $t0, $t1
	jr	    $t0
	nop



L_0xbfc019c8:
	mtc0	$zero, 5
	mtc0	$zero, 29
	addiu	$t1, $zero, 0x23
	nop
	mfc0	$t0, $t7
	andi	$t0, $t0, 0xff00
	srl	    $t0, $t0, 8
	beq	    $t0, $t1, 0xbfc01ae4
	nop
	addiu	$t1, $zero, 0x28
	beq	    $t0, $t1, 0xbfc01ae4
	nop
	addiu	$t1, $zero, 0x27
	bne	    $t0, $t1, 0xbfc01bbc
	nop
	addiu	$t0, $zero, 0x2f
	lui	    $t1, 0x1000
L_0xbfc01a0c:
	addiu	$at, $zero, 0x1fff
	not	    $t2, $at
	and	    $t2, $t2, $t1
	lui	    $at, 0x8000
	mtc0	$t0, 0
	or	    $t2, $t2, $at
	mtc0	$t2, 10
	srl	    $at, $t1, 0xc
	sll	    $at, $at, 6
	ori	    $at, $at, 0x11
	mtc0	$at, 2
	addiu	$t2, $at, 0x40
	mtc0	$at, 3
	addi	$t0, $t0, -1
	addiu	$t1, $t1, -0x2000
	bgtz	$t0, 0xbfc01a0c
	tlbwi
	mfc0	$t0, $s0
	addiu	$at, $zero, -0x1001
	and	    $t0, $t0, $at
	addiu	$at, $zero, -9
	and	    $t0, $t0, $at
	mtc0	$t0, 16
	mfc0	$t0, $s0
	srl	    $t0, $t0, 9
	addiu	$t1, $zero, 0x1000
	andi	$t0, $t0, 7
	sllv	$t0, $t1, $t0
	addi	$t0, $t0, -0x20
	lui	    $t1, 0x8000
	addu	$t2, $t0, $t1
L_0xbfc01a88:
	cache	0, ($t2)
	addi	$t0, $t0, -0x20
	bgez	$t0, 0xbfc01a88
	addu	$t2, $t0, $t1
	mfc0	$t0, $s0
	srl	    $t0, $t0, 6
	addiu	$t1, $zero, 0x1000
	andi	$t0, $t0, 7
	sllv	$t0, $t1, $t0
	addi	$t0, $t0, -0x20
	lui	    $t1, 0x8000
	lui	    $at, 0x1000
L_0xbfc01ab8:
	addu	$at, $at, $t0
	srl	    $at, $at, 0xc
	sll	    $at, $at, 8
	mtc0	$at, 29
	addu	$t2, $t0, $t1
	addi	$t0, $t0, -0x20
	cache	9, ($t2)
	bgez	$t0, 0xbfc01ab8
	lui	    $at, 0x1000
	jr	    $ra
	nop
[...]
```
</td>
<td>

```
/* Function tlb_init_uncached_trampoline [0xbfc019b0 - 0xbfc019c8)
 *
 * Jump to tlb_init through uncached KSEG1
 */
tlb_init_uncached_trampoline: /* 0xbfc019b0 */
	lui	    $t1, %hi(tlb_init)
	lui	    $t0, HI(KSEG1)
	addiu	$t1, $t1, %lo(tlb_init)
	or	    $t0, $t0, $t1
	jr	    $t0		# Jump to (KSEG1 | tlb_init)
	 nop

/* Function tlb_init [0xbfc019c8 - 0xbfc01d98)
 */
tlb_init: /* 0xbfc019c8 */
	mtc0	$zero, $CP0_PAGEMASK
	mtc0	$zero, $CP0_TAGHI
	li	    $t1, PRID_IMP_R5000
	nop
	mfc0	$t0, $CP0_PRID
	andi	$t0, $t0, PRID_IMP_MASK
	srl	    $t0, $t0, PRID_IMP_SHIFT
	beq	    $t0, $t1, tlb_r5k_init
	 nop
	li	    $t1, PRID_IMP_NEVADA
	beq	    $t0, $t1, tlb_r5k_init
	 nop
	li	    $t1, PRID_IMP_RM7000
	bne	    $t0, $t1, tlb_r10k_init
	 nop
	li	    $t0, RM7000_NUM_TLB_ENTRIES-1
	lui	    $t1, HI(0x0fffe000)
tlb_rm7k_write_tlb_loop: /* 0xbfc01a0c */
	li	    $at, PAGE_OFFSET_MASK
	not	    $t2, $at
	and	    $t2, $t2, $t1
	lui	    $at, HI(KSEG0)
	mtc0	$t0, $CP0_INDEX
	or	    $t2, $t2, $at
	mtc0	$t2, $CP0_ENTRYHI
	srl	    $at, $t1, PAGE_SHIFT
	sll	    $at, $at, ENTRYLO_PFN_SHIFT
	ori	    $at, $at, (ENTRYLO_G|ENTRYLO_C_UNCACHED)
	mtc0	$at, $CP0_ENTRYLO0
	addiu	$t2, $at, 1 << ENTRYLO_PFN_SHIFT
	mtc0	$at, $CP0_ENTRYLO1
	addi	$t0, $t0, -1
	addiu	$t1, $t1, LO(0x0fffe000)
	bgtz	$t0, tlb_rm7k_write_tlb_loop
	 tlbwi
	mfc0	$t0, $CP0_CONFIG
	li	    $at, ~RM7K_CONF_TE
	and	    $t0, $t0, $at
	li	    $at, ~CONF_CU
	and	    $t0, $t0, $at
	mtc0	$t0, $CP0_CONFIG
	mfc0	$t0, $CP0_CONFIG
	srl	    $t0, $t0, CONF_IC_SHIFT
	li	    $t1, 0x1000
	andi	$t0, $t0, CONF_CACHE_SIZE_MASK
	sllv	$t0, $t1, $t0
	addi	$t0, $t0, -CACHE_LINE_SIZE
	lui	    $t1, HI(KSEG0)
	addu	$t2, $t0, $t1
tlb_rm7k_inv_l1i_loop: /* 0xbfc01a88 */
	cache	(CACHE_TYPE_L1I|INDEX_WRITEBACK_INV), 0($t2)
	addi	$t0, $t0, -CACHE_LINE_SIZE
	bgez	$t0, tlb_rm7k_inv_l1i_loop
	 addu	$t2, $t0, $t1
	mfc0	$t0, $CP0_CONFIG
	srl	    $t0, $t0, CONF_DC_SHIFT
	li	    $t1, 0x1000
	andi	$t0, $t0, CONF_CACHE_SIZE_MASK
	sllv	$t0, $t1, $t0
	addi	$t0, $t0, -CACHE_LINE_SIZE
	lui	    $t1, HI(KSEG0)
	lui	    $at, 0x1000
tlb_rm7k_inv_l1d_loop: /* 0xbfc01ab8 */
	addu	$at, $at, $t0
	srl	    $at, $at, PAGE_SHIFT
	sll	    $at, $at, RM7K_TAGHI_PTAG_SHIFT
	mtc0	$at, $CP0_TAGHI
	addu	$t2, $t0, $t1
	addi	$t0, $t0, -CACHE_LINE_SIZE
	cache	(CACHE_TYPE_L1D|INDEX_STORE_TAG), 0($t2)
	bgez	$t0, tlb_rm7k_inv_l1d_loop
	 lui	$at, 0x1000
	jr	    $ra
	 nop
[...]
```
</td>
</tr>
</table>

## Building

### Prerequisites

- Rust toolchain (cargo)
- MIPS cross-compilation toolchain
- C preprocessor (`cpp`)

### Build

With `ip32prom.rev4.18.bin` located one directory up from the project directory, run `make` in the project directory. The path to the PROM image can be overridden with `make PROM_IMAGE=/path/to/prom.bin`.

This project has been tested with PROM version 4.18, but is expected to work with other versions.

#### Output

The decompiled PROM image is in `output/`, complete with:

- a `definitions.h` header containing preprocessor defines used by the assembly sources
- a `macros.inc` file containing GNU GAS macros used by the assembly sources
- assembly sources (`.S`) themselves, one for each section in the PROM image
- linker scripts, needed to set the virtual memory addresses
- a `Makefile` to build the PROM image from these files

In addition, the following ancillary files are generated:

- `.xpm` images that show the structure of each section. `prom.xpm` shows the structure of the sections as combined into the final PROM image.
- `.dot` graphs that show the control flow graph of functions and basic blocks in each section (note that `firmware.dot` is too large to render).

## Testing

Running `make check` builds the decompiler, generates assembly files, reassembles them, and verifies the rebuilt `output/prom.bin` matches the original.
