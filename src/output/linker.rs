// SPDX-License-Identifier: GPL-3.0-or-later
//! Linker script generation for firmware sections.
//!
//! This module generates linker scripts (.lds files) for code sections,
//! handling both simple code sections and loadable sections with multiple
//! subsections (text, rodata, rwdata), as well as virtual subsections
//! (relocated code that executes at different addresses).

use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use std::io::Write;
use std::path::Path;

use super::util::create_output_file;
use crate::section::Section;
use crate::shdr::{SHDR_SIZE, SUBSECTION_HEADER_SIZE, SUBSECTION_RODATA, SUBSECTION_RWDATA};

/// Generate a linker script for a section
pub fn generate_linker_script(section: &Section, output_path: &Path) -> Result<()> {
    let mut file = create_output_file(output_path, "linker script")?;

    // For loadable sections, the start address comes from the load header
    // For regular code sections, it's ROM_START + section offset
    let start_addr =
        if section.shdr.is_loadable() && section.data.len() >= SHDR_SIZE + SUBSECTION_HEADER_SIZE {
            // Read the load address from struct load following the SHDR
            BigEndian::read_u32(&section.data[SHDR_SIZE..SHDR_SIZE + 4])
        } else {
            section.start_addr
        };

    // Define program headers - main segment and one for each virtual subsection
    write!(file, "PHDRS {{ {} PT_LOAD;", section.shdr.name)?;
    for vsub in section.virtual_subsections.iter() {
        let elf_section = vsub.elf_section.as_deref().unwrap_or("text_ram");
        write!(
            file,
            " {} PT_LOAD AT({:#010x});",
            elf_section, vsub.rom_addr
        )?;
    }
    writeln!(file, " }}")?;
    writeln!(file, "SECTIONS")?;
    writeln!(file, "{{")?;

    // For loadable sections with multiple subsections, use VMA/LMA separation
    // so that labels resolve to runtime addresses while the binary remains contiguous
    if section.subsections.len() > 1 {
        // First subsection (.text) - VMA and LMA both at the load address
        writeln!(file, "  . = {:#010x};", start_addr)?;
        writeln!(file, "  .text : {{ *(.text) }} :{}", section.shdr.name)?;
        writeln!(file)?;

        // Track LMA position for chaining
        writeln!(file, "  __lma_pos = {:#010x} + SIZEOF(.text);", start_addr)?;
        writeln!(file)?;

        // rodata header - VMA doesn't matter (no symbols), LMA chained
        writeln!(
            file,
            "  .rodata_header : AT(__lma_pos) {{ *(.rodata_header) }} :{}",
            section.shdr.name
        )?;
        writeln!(file, "  __lma_pos = __lma_pos + SIZEOF(.rodata_header);")?;
        writeln!(file)?;

        // rodata section - VMA at runtime address, LMA chained
        let rodata_addr = section
            .subsections
            .get(SUBSECTION_RODATA)
            .map(|s| s.load_addr)
            .unwrap_or(0);
        writeln!(file, "  . = {:#010x};", rodata_addr)?;
        writeln!(
            file,
            "  .rodata : AT(__lma_pos) {{ *(.rodata) }} :{}",
            section.shdr.name
        )?;
        writeln!(file, "  __lma_pos = __lma_pos + SIZEOF(.rodata);")?;
        writeln!(file)?;

        // rwdata header - LMA chained
        writeln!(
            file,
            "  .rwdata_header : AT(__lma_pos) {{ *(.rwdata_header) }} :{}",
            section.shdr.name
        )?;
        writeln!(file, "  __lma_pos = __lma_pos + SIZEOF(.rwdata_header);")?;
        writeln!(file)?;

        // rwdata section - VMA at runtime address, LMA chained
        let data_addr = section
            .subsections
            .get(SUBSECTION_RWDATA)
            .map(|s| s.load_addr)
            .unwrap_or(0);
        writeln!(file, "  . = {:#010x};", data_addr)?;
        writeln!(
            file,
            "  .rwdata : AT(__lma_pos) {{ *(.rwdata) }} :{}",
            section.shdr.name
        )?;
        writeln!(file, "  __lma_pos = __lma_pos + SIZEOF(.rwdata);")?;
        writeln!(file)?;

        // sentinel - LMA chained
        writeln!(
            file,
            "  .sentinel : AT(__lma_pos) {{ *(.sentinel) }} :{}",
            section.shdr.name
        )?;
        writeln!(file)?;

        // Discard unwanted sections
        writeln!(
            file,
            "  /DISCARD/ : {{ *(.MIPS.options) *(.MIPS.abiflags) *(.gnu.attributes) *(.reginfo) }}"
        )?;
    } else if !section.virtual_subsections.is_empty() {
        // Section with virtual (relocated) subsections
        // We need to emit .text at ROM address, then virtual subsections with VMA/LMA separation,
        // and .text_after_N sections for code after each virtual subsection

        // Main .text section at ROM address
        writeln!(file, "  . = {:#010x};", start_addr)?;
        writeln!(file, "  .text : {{ *(.text) }} :{}", section.shdr.name)?;
        writeln!(file)?;

        // Virtual subsections - each has VMA (execution address) and LMA (ROM storage address)
        for (i, vsub) in section.virtual_subsections.iter().enumerate() {
            let elf_section = vsub.elf_section.as_deref().unwrap_or("text_ram");
            let segment_index = i + 1;

            writeln!(
                file,
                "  /* Relocated code: VMA={:#010x}, LMA={:#010x}, len={:#x} */",
                vsub.load_addr, vsub.rom_addr, vsub.length
            )?;
            writeln!(file, "  . = {:#010x};", vsub.load_addr)?;
            // Define LMA symbol for code that needs to reference the ROM address
            // The data_0xROMaddr symbol should point to ROM address (LMA) for copy operations
            writeln!(file, "  __{}_lma = {:#010x};", elf_section, vsub.rom_addr)?;
            writeln!(
                file,
                "  data_{:#010x} = {:#010x};",
                vsub.rom_addr, vsub.rom_addr
            )?;
            // Use explicit LMA with AT() and assign to the virtual subsection's program header
            writeln!(
                file,
                "  .{} {:#010x} : AT({:#010x}) {{ *(.{}) }} :{}",
                elf_section, vsub.load_addr, vsub.rom_addr, elf_section, elf_section
            )?;
            writeln!(file)?;

            // Code after this virtual subsection (LMA continues from end of virtual subsection)
            let lma_after = vsub.rom_addr + vsub.length as u32;
            writeln!(
                file,
                "  /* Code after relocated section {} */",
                segment_index
            )?;
            writeln!(file, "  . = {:#010x};", lma_after)?;
            writeln!(
                file,
                "  .text_after_{} : AT({:#010x}) {{ *(.text_after_{}) }} :{}",
                segment_index, lma_after, segment_index, section.shdr.name
            )?;
            writeln!(file)?;
        }

        // Discard unwanted sections
        writeln!(
            file,
            "  /DISCARD/ : {{ *(.MIPS.options) *(.MIPS.abiflags) *(.gnu.attributes) *(.reginfo) }}"
        )?;
    } else {
        // Simple section - no subsections or virtual subsections
        writeln!(file, "  . = {:#010x};", start_addr)?;
        writeln!(file, "  .text : {{ *(.text) }} :{}", section.shdr.name)?;
    }

    writeln!(file, "}}")?;

    Ok(())
}
