// SPDX-License-Identifier: GPL-3.0-or-later
//! Header file generation for assembly output.
//!
//! This module generates the definitions.h and macros.inc header files used by
//! the generated assembly code.

use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::annotations::BssNames;

use super::util::create_output_file;

use crate::hardware::constants::{
    ARCS_MAGIC, CTYPE_TOLOWER, ELF_MAGIC, EPOC_1970, GDA_MAGIC, HEXDIGIT_INVALID, RTSB_MAGIC,
    SECONDS_IN_1_DAY, SECONDS_IN_365_DAYS, SECONDS_IN_366_DAYS, SGI_LABEL_MAGIC, SHDR_MAGIC,
    SystemConstants, UART_BASE_CLOCK, WARM_START_COOKIE,
};
use crate::hardware::memmap::{
    BASE_AUDIO, BASE_CRIME, BASE_I2C, BASE_ISA, BASE_KBD_MS, BASE_MACE_PCI, BASE_RENDER, BASE_RTC,
    KSEG0, KSEG1, KSEG2, MACE_ETHERNET, MACE_ISA_EXTERNAL, MACE_PCI, MACE_PERIPHERAL,
    MACE_PERIPHERAL_AUDIO, MACE_PERIPHERAL_I2C, MACE_PERIPHERAL_ISA, MACE_PERIPHERAL_KBD_MS,
    MACE_PERIPHERAL_UST, PHYS_BASE_CRIME, PHYS_BASE_MACE, PHYS_BASE_RENDER, PHYS_SYSTEM_ROM,
    ROM_ALIGN, ROM_SIZE,
};
use crate::mips::format::{CACHE_OP_NAMES, CACHE_TYPE_NAMES};
use crate::mips::regs::{CP0_REG_NAMES, GPR_NAMES};
use crate::shdr::{
    SECTION_TYPE_CODE, SECTION_TYPE_DATA, SECTION_TYPE_LOADABLE, SHDR_OFFSET_CHECKSUM,
    SHDR_OFFSET_MAGIC, SHDR_OFFSET_NAME, SHDR_OFFSET_NAME_LEN, SHDR_OFFSET_SECTION_LEN,
    SHDR_OFFSET_SECTION_TYPE, SHDR_OFFSET_SUBSECTION_HEADER, SHDR_OFFSET_VERSION,
    SHDR_OFFSET_VERSION_LEN, SHDR_SIZE, SUBSECTION_HEADER_OFFSET_ADDR,
    SUBSECTION_HEADER_OFFSET_LEN, SUBSECTION_HEADER_SIZE,
};

/// Emit a #define statement. When given an identifier, uses stringify! to
/// generate the name automatically. Otherwise takes explicit name and value.
///
/// Usage:
///   emit_define!(file, CONST_NAME);              // name from identifier
///   emit_define!(file, CONST_NAME, "comment");   // with comment
///   emit_define!(file, "name", value);           // explicit name/value
///   emit_define!(file, "name", value, "comment"); // explicit with comment
macro_rules! emit_define {
    // Identifier only (no comment)
    ($file:expr, $name:ident) => {
        emit_define_fn($file, stringify!($name), $name, None)
    };
    // Identifier with comment
    ($file:expr, $name:ident, $comment:expr) => {
        emit_define_fn($file, stringify!($name), $name, Some($comment))
    };
    // Explicit name and value (no comment)
    ($file:expr, $name:expr, $value:expr) => {
        emit_define_fn($file, $name, $value, None)
    };
    // Explicit name, value, and comment
    ($file:expr, $name:expr, $value:expr, $comment:expr) => {
        emit_define_fn($file, $name, $value, Some($comment))
    };
}

/// Emit a #define statement with a hex-formatted value (0x prefix, 8 digits).
/// When given an identifier, uses stringify! to generate the name automatically.
///
/// Usage:
///   emit_define_hex!(file, CONST_NAME);              // name from identifier
///   emit_define_hex!(file, CONST_NAME, "comment");   // with comment
///   emit_define_hex!(file, "name", value);           // explicit name/value
///   emit_define_hex!(file, "name", value, "comment"); // explicit with comment
macro_rules! emit_define_hex {
    // Identifier only (no comment)
    ($file:expr, $name:ident) => {
        emit_define_fn(
            $file,
            stringify!($name),
            format_args!("0x{:08x}", $name),
            None,
        )
    };
    // Identifier with comment
    ($file:expr, $name:ident, $comment:expr) => {
        emit_define_fn(
            $file,
            stringify!($name),
            format_args!("0x{:08x}", $name),
            Some($comment),
        )
    };
    // Explicit name and value (no comment)
    ($file:expr, $name:expr, $value:expr) => {
        emit_define_fn($file, $name, format_args!("0x{:08x}", $value), None)
    };
    // Explicit name, value, and comment
    ($file:expr, $name:expr, $value:expr, $comment:expr) => {
        emit_define_fn(
            $file,
            $name,
            format_args!("0x{:08x}", $value),
            Some($comment),
        )
    };
}

/// Generate the definitions.h header file
pub fn generate_definitions_header(
    output_path: &Path,
    sys_consts: &SystemConstants,
    bss_names: &BssNames,
) -> Result<()> {
    let mut file = create_output_file(output_path, "definitions header")?;

    writeln!(file, "/* Auto-generated definitions header */")?;
    writeln!(file, "#ifndef _DEFINITIONS_H_")?;
    writeln!(file, "#define _DEFINITIONS_H_")?;
    writeln!(file)?;

    emit_elf_constants(&mut file)?;
    emit_memory_segments(&mut file)?;
    emit_shdr_constants(&mut file)?;
    emit_magic_constants(&mut file)?;
    emit_time_constants(&mut file)?;
    emit_tlb_constants(&mut file)?;
    emit_gpr_definitions(&mut file)?;
    emit_cp0_definitions(&mut file)?;
    emit_cp1_definitions(&mut file)?;
    emit_cache_ops(&mut file)?;
    emit_ip32_definitions(&mut file, sys_consts)?;
    emit_crime_definitions(&mut file, sys_consts)?;
    emit_rtc_definitions(&mut file, sys_consts)?;
    emit_bss_names(&mut file, bss_names)?;

    writeln!(file, "#endif /* _DEFINITIONS_H_ */")?;

    Ok(())
}

/// Emit ELF header constants
fn emit_elf_constants(file: &mut File) -> Result<()> {
    writeln!(file, "/* ELF Header Constants */")?;
    emit_define!(file, "ELFCLASS32", 1)?;
    emit_define!(file, "ELFDATA2MSB", 2)?;
    emit_define!(file, "EV_CURRENT", 1)?;
    emit_define!(file, "ELFOSABI_NONE", 0)?;
    emit_define!(file, "EM_MIPS", 8)?;
    writeln!(file)?;
    writeln!(file, "/* MIPS ELF e_flags */")?;
    emit_define!(file, "EF_MIPS_NOREORDER", "0x00000001")?;
    emit_define!(file, "EF_MIPS_PIC", "0x00000002")?;
    emit_define!(file, "EF_MIPS_ARCH_2", "0x10000000")?;
    writeln!(file)?;
    Ok(())
}

/// Emit memory segment definitions (KSEG0/1/2)
#[rustfmt::skip]
fn emit_memory_segments(file: &mut File) -> Result<()> {
    writeln!(file, "/* Memory Segments */")?;
    emit_define!(file, "KUSEG", "0x00000000")?;
    emit_define_hex!(file, KSEG0)?;
    emit_define_hex!(file, KSEG1)?;
    emit_define_hex!(file, KSEG2)?;
    writeln!(file)?;
    writeln!(file, "/* Register Access */")?;
    emit_define!(file, "LO32_OFFSET", "0x04", "Offset to low 32 bits of 64-bit register (big-endian)")?;
    writeln!(file)?;
    Ok(())
}

/// Emit SHDR constants and section types
fn emit_shdr_constants(file: &mut File) -> Result<()> {
    writeln!(file, "/* SHDR Constants */")?;
    emit_define!(file, SHDR_SIZE)?;
    emit_define!(file, SHDR_OFFSET_MAGIC)?;
    emit_define!(file, SHDR_OFFSET_SECTION_LEN)?;
    emit_define!(file, SHDR_OFFSET_NAME_LEN)?;
    emit_define!(file, SHDR_OFFSET_VERSION_LEN)?;
    emit_define!(file, SHDR_OFFSET_SECTION_TYPE)?;
    emit_define!(file, SHDR_OFFSET_NAME)?;
    emit_define!(file, SHDR_OFFSET_VERSION)?;
    emit_define!(file, SHDR_OFFSET_CHECKSUM)?;
    emit_define!(file, SHDR_OFFSET_SUBSECTION_HEADER)?;
    emit_define!(file, SUBSECTION_HEADER_SIZE)?;
    emit_define!(file, SUBSECTION_HEADER_OFFSET_ADDR)?;
    emit_define!(file, SUBSECTION_HEADER_OFFSET_LEN)?;
    writeln!(file)?;
    writeln!(file, "/* Section Types */")?;
    emit_define!(file, SECTION_TYPE_DATA)?;
    emit_define!(file, SECTION_TYPE_CODE)?;
    emit_define!(file, SECTION_TYPE_LOADABLE)?;
    writeln!(file)?;
    Ok(())
}

/// Emit magic number constants
#[rustfmt::skip]
fn emit_magic_constants(file: &mut File) -> Result<()> {
    writeln!(file, "/* Magic Numbers */")?;
    emit_define_hex!(file, ARCS_MAGIC, "\"ARCS\"")?;
    emit_define_hex!(file, ELF_MAGIC, "\"\\x7fELF\"")?;
    emit_define_hex!(file, GDA_MAGIC, "\"XFER\"")?;
    emit_define_hex!(file, RTSB_MAGIC, "\"RTSB\" (Restart Block)")?;
    emit_define_hex!(file, SGI_LABEL_MAGIC, "SGI disk partition label")?;
    emit_define_hex!(file, SHDR_MAGIC, "\"SHDR\"")?;
    writeln!(file)?;

    emit_define_hex!(file, WARM_START_COOKIE)?;
    writeln!(file)?;

    writeln!(file, "/* Sentinel Values */")?;
    emit_define!(file, "HEXDIGIT_INVALID", format_args!("{}\t/* 0x{:08x} */", HEXDIGIT_INVALID, HEXDIGIT_INVALID))?;
    writeln!(file)?;

    writeln!(file, "/* Hardware Constants */")?;
    emit_define!(file, "UART_BASE_CLOCK", format_args!("{}", UART_BASE_CLOCK), "1.8432 MHz")?;
    writeln!(file)?;

    writeln!(file, "/* Global Data Area address */")?;
    emit_define!(file, "GDA_ADDR", "(KSEG0 | 0x400)")?;
    writeln!(file)?;

    writeln!(file, "/* ctype Table Offsets */")?;
    emit_define!(file, "CTYPE_TOLOWER", format_args!("0x{:03x}", CTYPE_TOLOWER))?;
    writeln!(file)?;
    Ok(())
}

/// Emit time constants
fn emit_time_constants(file: &mut File) -> Result<()> {
    writeln!(file, "/* Time Constants */")?;
    emit_define!(file, SECONDS_IN_1_DAY)?;
    emit_define!(file, SECONDS_IN_365_DAYS)?;
    emit_define!(file, SECONDS_IN_366_DAYS)?;
    emit_define!(file, EPOC_1970)?;
    writeln!(file)?;
    Ok(())
}

/// Emit TLB constants
#[rustfmt::skip]
fn emit_tlb_constants(file: &mut File) -> Result<()> {
    writeln!(file, "/* TLB Constants */")?;
    emit_define!(file, "PAGE_SIZE", 4096)?;
    emit_define!(file, "PAGE_SHIFT", 12)?;
    emit_define!(file, "PAGE_OFFSET_MASK", "0x1fff", "TLB entry offset mask (covers two 4KB pages)")?;
    emit_define!(file, "R5000_NUM_TLB_ENTRIES", 48)?;
    emit_define!(file, "RM7000_NUM_TLB_ENTRIES", 48)?;
    emit_define!(file, "R10000_NUM_TLB_ENTRIES", 64)?;
    writeln!(file)?;
    Ok(())
}

/// Emit GPR register definitions
fn emit_gpr_definitions(file: &mut File) -> Result<()> {
    writeln!(file, "/* General Purpose Registers */")?;
    emit_register_defines(
        file,
        GPR_NAMES.iter().map(|&(name, num)| (name, num as usize)),
    )?;
    writeln!(file)?;
    Ok(())
}

/// Emit CP0 register definitions
#[rustfmt::skip]
fn emit_cp0_definitions(file: &mut File) -> Result<()> {
    // https://en.wikichip.org/wiki/mips/coprocessor_0
    writeln!(file, "/* CP0 (System Control Coprocessor) Registers */")?;
    emit_register_defines(
        file,
        CP0_REG_NAMES
            .iter()
            .enumerate()
            .map(|(num, &name)| (name, num)),
    )?;
    writeln!(file)?;

    // CP0_STATUS bits
    writeln!(file, "/* CP0_STATUS bits */")?;
    emit_define!(file, "ST0_IE", "(1 <<  0)")?;
    emit_define!(file, "ST0_EXL", "(1 <<  1)")?;
    emit_define!(file, "ST0_KX", "(1 <<  7)")?;
    emit_define!(file, "ST0_IM", "0x0000ff00")?;
    emit_define!(file, "ST0_DE", "(1 << 16)")?;
    emit_define!(file, "ST0_CH", "(1 << 18)")?;
    emit_define!(file, "ST0_NMI", "(1 << 19)")?;
    emit_define!(file, "ST0_SR", "(1 << 20)")?;
    emit_define!(file, "ST0_BEV", "(1 << 22)")?;
    emit_define!(file, "ST0_FR", "(1 << 26)")?;
    emit_define!(file, "ST0_CU0", "(1 << 28)")?;
    emit_define!(file, "ST0_CU1", "(1 << 29)")?;
    writeln!(file)?;

    // CP0_CAUSE bits
    writeln!(file, "/* CP0_CAUSE bits */")?;
    emit_define!(file, "CAUSE_EXCCODE", "0x7c")?;
    writeln!(file)?;
    writeln!(file, "/* Exception codes (ExcCode field values, already shifted) */")?;
    emit_define!(file, "EXC_BP", "0x24", "Breakpoint")?;
    writeln!(file)?;

    // CP0_ENTRYLO bits
    writeln!(file, "/* CP0_ENTRYLO0/1 bits */")?;
    emit_define!(file, "ENTRYLO_G", "(1 << 0)", "Global")?;
    emit_define!(file, "ENTRYLO_C_UNCACHED", "(2 << 3)")?;
    emit_define!(file, "ENTRYLO_PFN_SHIFT", 6, "Page frame number shift")?;
    writeln!(file)?;

    // CP0_CONFIG bits
    writeln!(file, "/* CP0_CONFIG bits */")?;
    emit_define!(file, "CONF_CM_CACHABLE_NONCOHERENT", 3)?;
    emit_define!(file, "CONF_CM_CMASK", 7)?;
    emit_define!(file, "CONF_CU", "( 1u <<  3)")?;
    emit_define!(file, "CONF_DB", "( 1u <<  4)")?;
    emit_define!(file, "CONF_IB", "( 1u <<  5)")?;
    emit_define!(file, "CONF_DC", "( 7u <<  6)")?;
    emit_define!(file, "CONF_DC_SHIFT", 6)?;
    emit_define!(file, "CONF_IC", "( 7u <<  9)")?;
    emit_define!(file, "CONF_IC_SHIFT", 9)?;
    emit_define!(file, "CONF_CACHE_SIZE_MASK", 7)?;
    emit_define!(file, "CONF_SC", "( 1u << 17)")?;
    emit_define!(file, "CONF_SB", "( 3u << 22)")?;
    writeln!(file)?;

    // R5000-specific CONFIG bits
    writeln!(file, "/* R5000-specific CONFIG bits */")?;
    emit_define!(file, "R5K_CONF_SE", "( 1u << 12)")?;
    emit_define!(file, "R5K_CONF_SS", "( 3u << 20)")?;
    writeln!(file)?;

    // R5000-specific TAGLO bits
    writeln!(file, "/* R5000-specific CP0_TAGLO bits */")?;
    emit_define!(file, "R5K_TAGLO_PTAG_SHIFT", 8)?;
    emit_define!(file, "R5K_TAGLO_DIRTY", "0xc0")?;
    writeln!(file)?;

    // RM7000-specific CONFIG bits
    writeln!(file, "/* RM7000-specific CONFIG bits */")?;
    emit_define!(file, "RM7K_CONF_TE", "( 1u << 12)")?;
    writeln!(file)?;

    // RM7000-specific TAGLO bits
    writeln!(file, "/* RM7000-specific CP0_TAGLO bits */")?;
    emit_define!(file, "RM7K_TAGLO_DIRTY", "0xc0")?;
    writeln!(file)?;

    // RM7000-specific TAGHI bits
    writeln!(file, "/* RM7000-specific CP0_TAGHI bits */")?;
    emit_define!(file, "RM7K_TAGHI_PTAG_SHIFT", 8)?;
    writeln!(file)?;

    // R10000-specific CONFIG bits
    writeln!(file, "/* R10000-specific CONFIG bits */")?;
    emit_define!(file, "R10K_CONF_SS_SHIFT", 16)?;
    writeln!(file)?;

    // R10000 cache block sizes (for CACHE instruction indexing)
    writeln!(file, "/* R10000 cache block sizes */")?;
    emit_define!(file, "R10K_L1I_BLOCK_SIZE", "0x40")?;
    emit_define!(file, "R10K_L1D_BLOCK_SIZE", "0x20")?;
    emit_define!(file, "R10K_L2_BLOCK_SIZE", "0x10")?;
    writeln!(file)?;

    // R10000-specific TAGLO bits
    writeln!(file, "/* R10000-specific CP0_TAGLO bits */")?;
    emit_define!(file, "R10K_TAGLO_DIRTY", "0xc8")?;
    emit_define!(file, "R10K_L2_TAGLO_DIRTY", "0xc00")?;
    writeln!(file)?;

    // CP0_PRID constants
    // https://en.wikichip.org/wiki/mips/prid_register
    writeln!(file, "/* CP0_PRID constants */")?;
    emit_define!(file, "PRID_REV_MASK", "0x00ff")?;
    emit_define!(file, "PRID_IMP_MASK", "0xff00")?;
    emit_define!(file, "PRID_IMP_SHIFT", 8)?;
    emit_define!(file, "PRID_IMP_R4000", "0x04")?;
    emit_define!(file, "PRID_IMP_R4600", "0x20")?;
    emit_define!(file, "PRID_IMP_R4700", "0x21")?;
    emit_define!(file, "PRID_IMP_R5000", "0x23")?;
    emit_define!(file, "PRID_IMP_RM7000", "0x27")?;
    emit_define!(file, "PRID_IMP_NEVADA", "0x28")?;
    writeln!(file)?;

    Ok(())
}

/// Emit CP1 (FPU) control register definitions
fn emit_cp1_definitions(file: &mut File) -> Result<()> {
    // Only emit the CP1 control registers that are actually used
    writeln!(file, "/* CP1 (FPU) Control Registers */")?;
    emit_define!(file, "CP1_FEIR", 30)?;
    emit_define!(file, "CP1_FCSR", 31)?;
    writeln!(file)?;

    Ok(())
}

/// Calculate tabs needed to align to a target column (assuming 8-char tab stops)
fn tabs_to_align(current_col: usize, target_col: usize) -> String {
    let mut col = current_col;
    let mut count = 0;
    while col < target_col {
        col = (col + 8) & !7;
        count += 1;
    }
    "\t".repeat(count.max(1))
}

/// Column width for #define alignment (target column for values)
const DEFINE_TARGET_COL: usize = 40;
/// Length of "#define " prefix
const DEFINE_PREFIX_LEN: usize = 8;

/// Emit a #define statement with aligned value and optional comment.
fn emit_define_fn<V: std::fmt::Display>(
    file: &mut File,
    name: &str,
    value: V,
    comment: Option<&str>,
) -> Result<()> {
    let tabs = tabs_to_align(DEFINE_PREFIX_LEN + name.len(), DEFINE_TARGET_COL);
    match comment {
        Some(c) => writeln!(file, "#define {}{}{}\t/* {} */", name, tabs, value, c),
        None => writeln!(file, "#define {}{}{}", name, tabs, value),
    }?;
    Ok(())
}

/// Emit #define statements for register names with numeric values.
/// Takes an iterator of (name, number) pairs.
fn emit_register_defines<'a>(
    file: &mut File,
    registers: impl Iterator<Item = (&'a str, usize)>,
) -> Result<()> {
    for (name, num) in registers {
        emit_define_fn(file, name, num, None)?;
    }
    Ok(())
}

/// Emit cache operation constants
fn emit_cache_ops(file: &mut File) -> Result<()> {
    writeln!(file, "/* Cache Operation Constants */")?;
    for (i, name) in CACHE_TYPE_NAMES.iter().enumerate() {
        emit_define_fn(file, name, format_args!("0x{:02x}", i), None)?;
    }
    writeln!(file)?;
    for (i, name) in CACHE_OP_NAMES.iter().enumerate() {
        emit_define_fn(file, name, format_args!("0x{:02x}", i << 2), None)?;
    }
    writeln!(file)?;
    emit_define!(file, "CACHE_LINE_SIZE", "0x20")?;
    writeln!(file)?;
    Ok(())
}

/// Emit IP32 device address definitions
#[rustfmt::skip]
fn emit_ip32_definitions(file: &mut File, sys_consts: &SystemConstants) -> Result<()> {
    writeln!(file, "/* IP32 Physical Addresses */")?;
    emit_define_hex!(file, PHYS_BASE_CRIME)?;
    emit_define_hex!(file, PHYS_BASE_RENDER)?;
    emit_define_hex!(file, PHYS_BASE_MACE)?;
    // Hierarchical sub-entries for MACE
    writeln!(file, "#define  MACE_PCI\t\t\t  0x{:06x}", MACE_PCI)?;
    writeln!(file, "#define  MACE_ETHERNET\t\t\t  0x{:06x}", MACE_ETHERNET)?;
    writeln!(file, "#define  MACE_PERIPHERAL\t\t  0x{:06x}", MACE_PERIPHERAL)?;
    writeln!(file, "#define   MACE_PERIPHERAL_AUDIO\t\t   0x{:05x}", MACE_PERIPHERAL_AUDIO)?;
    writeln!(file, "#define   MACE_PERIPHERAL_ISA\t\t   0x{:05x}", MACE_PERIPHERAL_ISA)?;
    writeln!(file, "#define   MACE_PERIPHERAL_KBD_MS\t   0x{:05x}", MACE_PERIPHERAL_KBD_MS)?;
    writeln!(file, "#define   MACE_PERIPHERAL_I2C\t\t   0x{:05x}", MACE_PERIPHERAL_I2C)?;
    writeln!(file, "#define   MACE_PERIPHERAL_UST\t\t   0x{:05x}", MACE_PERIPHERAL_UST)?;
    writeln!(file, "#define  MACE_ISA_EXTERNAL\t\t  0x{:06x}", MACE_ISA_EXTERNAL)?;
    writeln!(file, "#define   MACE_ISA_UART_1\t\t   0x10000")?;
    writeln!(file, "#define   MACE_ISA_UART_2\t\t   0x18000")?;
    writeln!(file, "#define   MACE_ISA_RTC\t\t\t   0x20000")?;
    emit_define_hex!(file, PHYS_SYSTEM_ROM)?;
    writeln!(file)?;

    writeln!(file, "/* ROM Addresses */")?;
    emit_define!(file, "ROM_SIZE", format_args!("0x{:x}", ROM_SIZE))?;
    emit_define!(file, "ROM_START", "(KSEG1 | PHYS_SYSTEM_ROM)")?;
    emit_define!(file, "ROM_END", "(KSEG1 | (PHYS_SYSTEM_ROM + ROM_SIZE))")?;
    emit_define!(file, ROM_ALIGN)?;
    writeln!(file)?;

    writeln!(file, "/* IP32 Device Base Addresses */")?;
    emit_define!(file, "BASE_CRIME", "(KSEG1 | PHYS_BASE_CRIME)")?;
    emit_define!(file, "BASE_RENDER", "(KSEG1 | PHYS_BASE_RENDER)")?;
    emit_define!(file, "BASE_MACE_PCI", "(KSEG1 | PHYS_BASE_MACE | MACE_PCI)")?;
    emit_define!(file, "BASE_MEC", "(KSEG1 | PHYS_BASE_MACE | MACE_ETHERNET)")?;
    emit_define!(file, "BASE_AUDIO", "(KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_AUDIO)")?;
    emit_define!(file, "BASE_ISA", "(KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_ISA)")?;
    emit_define!(file, "BASE_KBD_MS", "(KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_KBD_MS)")?;
    emit_define!(file, "BASE_I2C", "(KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_I2C)")?;
    emit_define!(file, "BASE_UST", "(KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_UST)")?;
    emit_define!(file, "BASE_UART_1", "(KSEG1 | PHYS_BASE_MACE | MACE_ISA_EXTERNAL | MACE_ISA_UART_1)")?;
    emit_define!(file, "BASE_UART_2", "(KSEG1 | PHYS_BASE_MACE | MACE_ISA_EXTERNAL | MACE_ISA_UART_2)")?;
    emit_define!(file, "BASE_RTC", "(KSEG1 | PHYS_BASE_MACE | MACE_ISA_EXTERNAL | MACE_ISA_RTC)")?;
    writeln!(file)?;

    // ISA Interface Registers
    // mace.pdf, page 122, TABLE 52. ISA Interface Registers
    writeln!(file, "/* ISA Interface Registers */")?;
    emit_device_registers(file, sys_consts, BASE_ISA, 2, true)?;
    // mace.pdf, TABLE 53. Peripheral ring base and reset register
    emit_define!(file, "ISA_RESET", "0x01")?;
    // mace.pdf, TABLE 54. Flash-ROM/NIC control register
    emit_define!(file, "ISA_FLASH_ROM_WRITE_ENABLE", "(1 << 0)")?;
    emit_define!(file, "ISA_RED_LED", "(1 << 4)")?;
    emit_define!(file, "ISA_GREEN_LED", "(1 << 5)")?;
    writeln!(file)?;

    // PCI Host Bridge Registers
    // mace.pdf, page 162, TABLE 82. PCI Host Bridge Internal Registers
    writeln!(file, "/* MACE PCI Host Bridge Registers */")?;
    emit_device_registers(file, sys_consts, BASE_MACE_PCI, 2, true)?;
    writeln!(file)?;

    // Audio Interface Registers
    // mace.pdf, page 62, TABLE 26. Audio Interface Registers
    writeln!(file, "/* MACE Audio Interface Registers */")?;
    emit_device_registers(file, sys_consts, BASE_AUDIO, 2, true)?;
    emit_define!(file, "MACE_AUDIO_RING_CTRL_CHAN(x)", "(0x20 * (x) + 0x8 * 0)")?;
    emit_define!(file, "MACE_AUDIO_RD_PTR_CHAN(x)", "(0x20 * (x) + 0x8 * 1)")?;
    emit_define!(file, "MACE_AUDIO_WR_PTR_CHAN(x)", "(0x20 * (x) + 0x8 * 2)")?;
    emit_define!(file, "MACE_AUDIO_RING_DEPTH_CHAN(x)", "(0x20 * (x) + 0x8 * 3)")?;
    writeln!(file)?;

    // I2C Interface Registers
    // mace.pdf, page 150, TABLE 76. I2C Interface Registers
    writeln!(file, "/* MACE I2C Interface Registers */")?;
    emit_device_registers(file, sys_consts, BASE_I2C, 2, true)?;
    writeln!(file)?;

    // UART Registers
    writeln!(file, "/* UART Registers */")?;
    emit_define!(file, "BYTE_OFFSET", 7)?;
    emit_define!(file, "UART_REG(x)", "(((x) << 8) + BYTE_OFFSET)")?;
    emit_define!(file, "UART_DATA", "UART_REG(0x00)")?;
    emit_define!(file, "UART_IER", "UART_REG(0x01)")?;
    emit_define!(file, "UART_IIR", "UART_REG(0x02)")?;
    emit_define!(file, "UART_LCR", "UART_REG(0x03)")?;
    emit_define!(file, "UART_MCR", "UART_REG(0x04)")?;
    emit_define!(file, "UART_LSR", "UART_REG(0x05)")?;
    emit_define!(file, "UART_MSR", "UART_REG(0x06)")?;
    emit_define!(file, "UART_SCR", "UART_REG(0x07)")?;
    writeln!(file)?;

    // Ethernet Interface Registers
    // mace.pdf, page 70, TABLE 37. Ethernet Interface Registers
    writeln!(file, "/* MACE Ethernet Interface Registers */")?;
    emit_define!(file, "MACE_ETH_MAC_CONTROL", "0x00")?;
    emit_define!(file, "MACE_ETH_INTR_STATUS", "0x08")?;
    emit_define!(file, "MACE_ETH_RX_MCL_WR_PTR", "0x45")?;
    emit_define!(file, "MACE_ETH_RX_MCL_RD_PTR", "0x46")?;
    emit_define!(file, "MACE_ETH_RX_MCL_DEPTH", "0x47")?;
    emit_define!(file, "MACE_ETH_MCL_RECEIVE_FIFO(x)", "((x) + 0x100)")?;
    writeln!(file)?;

    // PS/2 Interface Registers
    // mace.pdf, page 140, TABLE 70. PS/2 Interface Registers
    writeln!(file, "/* MACE PS/2 Interface Registers */")?;
    emit_device_registers(file, sys_consts, BASE_KBD_MS, 2, true)?;
    writeln!(file)?;

    Ok(())
}

/// Helper to emit device register definitions from the SystemConstants HashMap.
/// `hex_width` controls the minimum hex digit width (e.g., 2 for `0x0a`, 4 for `0x000a`).
/// `skip_parameterized` skips entries containing `(` (parameterized macros).
fn emit_device_registers(
    file: &mut File,
    sys_consts: &SystemConstants,
    base: u32,
    hex_width: usize,
    skip_parameterized: bool,
) -> Result<()> {
    for (offset, name) in sys_consts.registers_for_base(base) {
        // Skip derived offsets (those containing "+")
        if name.contains('+') {
            continue;
        }
        if skip_parameterized && name.contains('(') {
            continue;
        }
        let tabs = tabs_to_align(DEFINE_PREFIX_LEN + name.len(), DEFINE_TARGET_COL);
        writeln!(
            file,
            "#define {}{}0x{:0width$x}",
            name,
            tabs,
            offset,
            width = hex_width
        )?;
    }
    Ok(())
}

/// Emit CRIME memory controller definitions
fn emit_crime_definitions(file: &mut File, sys_consts: &SystemConstants) -> Result<()> {
    // crime.pdf, page 113, Register Map
    writeln!(file, "/* CRIME Registers */")?;
    emit_device_registers(file, sys_consts, BASE_CRIME, 4, false)?;
    writeln!(file)?;

    writeln!(file, "/* CRIME ID Register Bits */")?;
    emit_define!(file, "CRIME_ID_REV", "0x0f")?;
    writeln!(file)?;

    writeln!(file, "/* CRIME Control Register Bits */")?;
    emit_define!(file, "CRIME_CONTROL_TRITON_SYSADC", "0x2000")?;
    emit_define!(file, "CRIME_CONTROL_CRIME_SYSADC", "0x1000")?;
    emit_define!(file, "CRIME_CONTROL_HARD_RESET", "0x0800")?;
    emit_define!(file, "CRIME_CONTROL_SOFT_RESET", "0x0400")?;
    writeln!(file)?;

    // crmfbreg.h register offsets
    writeln!(file, "/* CRIME Rendering Engine Registers */")?;
    emit_device_registers(file, sys_consts, BASE_RENDER, 4, false)?;
    emit_define!(file, "CRIME_DE_START", "0x0800")?;
    writeln!(file)?;

    Ok(())
}

/// Emit RTC register definitions
#[rustfmt::skip]
fn emit_rtc_definitions(file: &mut File, sys_consts: &SystemConstants) -> Result<()> {
    writeln!(file, "/* RTC Register Definitions */")?;
    emit_define!(file, "RTC_REG(x)", "((x) << 8)")?;
    writeln!(file)?;

    for (offset, name) in sys_consts.registers_for_base(BASE_RTC) {
        // Skip BYTE_OFFSET which is emitted elsewhere
        if name == "BYTE_OFFSET" {
            continue;
        }
        // RTC registers use the RTC_REG macro which shifts by 8
        let reg_index = offset >> 8;
        emit_define_fn(file, name, format_args!("RTC_REG(0x{:02x})", reg_index), None)?;
    }
    writeln!(file)?;

    emit_define!(file, "RTC_NVRAM_BASE", "0x0E")?;
    emit_define!(file, "RTC_NVRAM(x)", "RTC_REG(RTC_NVRAM_BASE + (x))")?;
    writeln!(file)?;

    Ok(())
}

/// Emit BSS variable name definitions.
/// Maps symbolic names to numeric offsets from BSS_BASE.
fn emit_bss_names(file: &mut File, bss_names: &BssNames) -> Result<()> {
    if bss_names.is_empty() {
        return Ok(());
    }

    writeln!(file, "/* BSS Variable Names */")?;

    // Collect and sort by offset
    let mut entries: Vec<(u32, &str)> = bss_names
        .keys()
        .filter_map(|k| Some((k, bss_names.get(k)?)))
        .collect();
    entries.sort_by_key(|(offset, _)| *offset);

    for (offset, name) in entries {
        emit_define_fn(file, name, format_args!("{:#x}", offset), None)?;
    }
    writeln!(file)?;

    Ok(())
}

/// The complete macros.inc content as a raw string literal.
///
/// This contains all SHDR assembly macros: HI/LO address construction,
/// BSS access, section/subsection tracking, SHDR header emission,
/// checksum placeholders, and string padding.
const MACROS_TEMPLATE: &str = r#"/* Auto-generated assembly macros */

.altmacro

/*
 * Macros for constructing 32-bit addresses from lui + addiu/load/store patterns.
 * Use HI and LO when the low bits come from ADDIU or load/store displacement
 * (sign-extended). These match the GNU assembler's %hi/%lo operators.
 *
 * When the low 16 bits have bit 15 set (>= 0x8000), they will be sign-extended
 * to a negative value. To compensate, HI adds 1 to the high bits.
 */
#define LO(x) (((x) & 0xffff) - (((x) & 0x8000) << 1))
#define HI(x) (((x) >> 16) + (((x) & 0x8000) >> 15))

/*
 * Macros for constructing 32-bit values from lui + ori patterns.
 * Use HI_UNSIGNED and LO_UNSIGNED when the low bits come from ORI (zero-extended).
 * WARNING: Do not use these with %hi/%lo assembler operators.
 */
#define LO_UNSIGNED(x) ((x) & 0xffff)
#define HI_UNSIGNED(x) ((x) >> 16)

/*
 * Macros for accessing BSS (uninitialized data).
 * BSS_BASE is automatically calculated as the end of rwdata.
 * Use BSS_HI and BSS_LO with offsets relative to BSS_BASE.
 * These use %%hi/%%lo relocations to allow forward reference to BSS_BASE.
 */
#define BSS_HI(offset) %hi(BSS_BASE + (offset))
#define BSS_LO(offset) %lo(BSS_BASE + (offset))

/*
 * Mark the start of a section for automatic length calculation.
 * Call this immediately after the first two instructions.
 * The section start is 8 bytes before the current position
 * (accounting for the two instructions already emitted).
 */
.macro section_start name
\name\()_start = . - 8
.endm

/*
 * Mark the end of a section for automatic length calculation.
 * Call this as the last directive in the section.
 */
.macro section_end name
\name\()_end = .
.endm

/*
 * Track the size of an ELF section.
 * Use elfsect_start at the beginning and elfsect_end at the end.
 * The size is: __elfsect_<name>_end - __elfsect_<name>_start
 */
.macro elfsect_start name
__elfsect_\name\()_start = .
.endm

.macro elfsect_end name
__elfsect_\name\()_end = .
.endm

/* Shorthand for section size */
#define ELFSECT_SIZE(name) (__elfsect_ ## name ## _end - __elfsect_ ## name ## _start)

/*
 * Emit an SHDR header (56 bytes).
 * This macro emits the header starting at the "SHDR" magic.
 * The first two instructions should be emitted as code before this macro.
 * String lengths and section length are calculated automatically
 * using label arithmetic (requires section_start before and section_end after).
 * The SHDR checksum is set to zero; use the checksum tool to set it.
 *
 * Usage: shdr <name>, <version>, <type>
 *
 * Parameters:
 *   name          - Section name string (max 31 chars)
 *   version       - Version string (max 7 chars)
 *   type          - Section type (SECTION_TYPE_*)
 */
.macro shdr name, version, type
	/* Magic "SHDR" */
	.ascii "SHDR"
	/* Section length (calculated from section_start/section_end labels) */
	.int \name\()_end - \name\()_start
	/* name_len, version_len, section_type, padding */
	.byte \name\()_name_end - \name\()_name_start
	.byte \name\()_version_end - \name\()_version_start
	.byte \type
	.byte 0
	/* Name field (32 bytes) */
\name\()_name_start:
	.ascii "\name"
\name\()_name_end:
	.fill 32 - (\name\()_name_end - \name\()_name_start), 1, 0
	/* Version field (8 bytes) */
\name\()_version_start:
	.ascii "\version"
\name\()_version_end:
	.fill 8 - (\name\()_version_end - \name\()_version_start), 1, 0
	/* SHDR Checksum (placeholder, set by checksum tool) */
	shdr_checksum
.endm

/*
 * Emit a placeholder SHDR checksum (4 bytes of zeros).
 * The checksum tool will calculate and set the correct value.
 */
.macro shdr_checksum
	.int 0x00000000
.endm

/*
 * Emit an SHDR header with explicit length (for multi-section loadable firmware).
 * Use this instead of 'shdr' when section content spans multiple ELF sections.
 * The length should be the sum of all ELF section sizes.
 */
.macro shdr_with_len name, version, type, length
	.ascii "SHDR"
	.int \length
	.byte \name\()_name_end - \name\()_name_start
	.byte \name\()_version_end - \name\()_version_start
	.byte \type
	.byte 0
\name\()_name_start:
	.ascii "\name"
\name\()_name_end:
	.fill 32 - (\name\()_name_end - \name\()_name_start), 1, 0
\name\()_version_start:
	.ascii "\version"
\name\()_version_end:
	.fill 8 - (\name\()_version_end - \name\()_version_start), 1, 0
	shdr_checksum
.endm

/*
 * Emit a placeholder section checksum (4 bytes of zeros).
 * This should be the last 4 bytes of the section.
 * The checksum tool will calculate and set the correct value.
 */
.macro section_checksum
	.int 0x00000000
.endm

/*
 * Mark the start of a subsection for automatic length calculation.
 * The subsection length is calculated from subsect_start to subsect_end.
 */
.macro subsect_start addr
subsection_\addr\()_start = .
.endm

/*
 * Emit a subsection header (8 bytes).
 * Contains the load address and subsection length.
 * The length is calculated automatically using label arithmetic.
 */
.macro subsect_header addr
	.int \addr
	.int subsection_\addr\()_end - subsection_\addr\()_start
.endm

/*
 * Mark the end of a subsection.
 */
.macro subsect_end addr
subsection_\addr\()_end = .
.endm

/*
 * Emit a sentinel marker (8 bytes) at the end of all subsections.
 * The sentinel has a load address and zero length.
 */
.macro sentinel addr
	.int \addr
	.int 0x00000000
.endm

/*
 * Emit a string with automatic zero-padding to pad_to boundary.
 * The padding fills from the end of the string to the next multiple of pad_to.
 * Use pad_to=4 for code sections (4-byte alignment).
 * Use pad_to=1 for data sections (no padding).
 */
.macro string pad_to, str
LOCAL start
LOCAL end
start = .
.ascii \str
end = .
/* Always emit at least 1 byte (NUL terminator), plus padding to pad_to */
.fill (\pad_to - ((end - start) & (\pad_to - 1))), 1, 0
.endm
"#;

/// Generate the macros.inc file with SHDR assembly macros
pub fn generate_macros_header(output_path: &Path) -> Result<()> {
    let mut file = create_output_file(output_path, "macros header")?;
    write!(file, "{}", MACROS_TEMPLATE)?;
    Ok(())
}
