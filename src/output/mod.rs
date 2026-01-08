// SPDX-License-Identifier: GPL-3.0-or-later
//! Output generation for assembly files, linker scripts, and headers.

use anyhow::{Context, Result};
use capstone::Capstone;
use std::path::Path;

use crate::annotations::Annotations;
use crate::hardware::SystemConstants;
use crate::section::Section;
use crate::shdr::Shdr;

pub mod assembly;
pub mod dot;
pub mod headers;
pub mod linker;
pub mod makefile;
pub mod trailing;
pub mod util;
pub mod writer;
pub mod xpm;

pub use assembly::generate_assembly;
pub use dot::generate_dot;
pub use headers::{generate_definitions_header, generate_macros_header};
pub use linker::generate_linker_script;
pub use makefile::generate_makefile;
pub use trailing::generate_trailing;
pub use xpm::{generate_prom_xpm, generate_xpm};

/// Generate common header files (definitions.h and macros.inc).
/// Returns the list of generated file paths.
pub fn generate_headers(
    output_dir: &Path,
    sys_consts: &SystemConstants,
    bss_names: &crate::annotations::BssNames,
) -> Result<Vec<std::path::PathBuf>> {
    let mut generated = Vec::new();

    let definitions_file = output_dir.join("definitions.h");
    generate_definitions_header(&definitions_file, sys_consts, bss_names)?;
    generated.push(definitions_file);

    let macros_file = output_dir.join("macros.inc");
    generate_macros_header(&macros_file)?;
    generated.push(macros_file);

    Ok(generated)
}

/// Generate all output files for a section (assembly, linker script, XPM visualization).
/// Returns the list of generated file paths.
pub fn generate_section_outputs(
    cs: &Capstone,
    section: &Section,
    output_dir: &Path,
    annotations: &mut Annotations,
    sys_consts: &SystemConstants,
) -> Result<Vec<std::path::PathBuf>> {
    let mut generated = Vec::new();
    let name = &section.shdr.name;

    // Generate assembly file
    let asm_file = output_dir.join(format!("{}.S", name));
    generate_assembly(cs, section, &asm_file, annotations, sys_consts)?;
    generated.push(asm_file);

    // Generate linker script for code sections
    if section.shdr.is_code() {
        let lds_file = output_dir.join(format!("{}.lds", name));
        generate_linker_script(section, &lds_file)?;
        generated.push(lds_file);
    }

    // Generate XPM visualization
    let xpm_file = output_dir.join(format!("{}.xpm", name));
    generate_xpm(section, &xpm_file)?;
    generated.push(xpm_file);

    // Generate DOT control-flow graph for code sections
    if section.shdr.is_code() {
        let dot_file = output_dir.join(format!("{}.dot", name));
        generate_dot(cs, section, &dot_file, &annotations.labels)?;
        generated.push(dot_file);
    }

    Ok(generated)
}

/// Process all sections: analyze each section and generate all output files.
/// Returns the list of all generated file paths and the analyzed Section objects.
pub fn process_all_sections(
    cs: &Capstone,
    shdrs: &[Shdr],
    firmware: &[u8],
    output_dir: &Path,
    annotations: &mut Annotations,
    sys_consts: &SystemConstants,
) -> Result<(Vec<std::path::PathBuf>, Vec<Section>)> {
    let mut all_generated = Vec::new();
    let mut sections = Vec::new();

    for shdr in shdrs {
        println!("Processing section: {}", shdr.name);
        let mut section = Section::from_firmware(shdr, firmware);

        // Add virtual subsections from relocation config
        section.add_relocations(&annotations.relocations);

        section.analyze(cs, &annotations.funcs, &mut annotations.labels);

        let generated =
            generate_section_outputs(cs, &section, output_dir, annotations, sys_consts)?;
        for path in &generated {
            println!("  Generated: {:?}", path);
        }
        all_generated.extend(generated);
        sections.push(section);
    }

    Ok((all_generated, sections))
}

/// Create the output directory if it doesn't exist.
pub fn create_output_dir(output_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {:?}", output_dir))
}

/// Generate trailing data output if there is data after the last section.
/// Returns the path to the generated file, or None if there was no trailing data.
pub fn generate_trailing_output(
    firmware: &[u8],
    trailing_start: usize,
    output_dir: &Path,
) -> Result<Option<std::path::PathBuf>> {
    if trailing_start >= firmware.len() {
        return Ok(None);
    }

    let trailing_data = &firmware[trailing_start..];
    println!(
        "\nTrailing data: {} bytes at offset {:#x}",
        trailing_data.len(),
        trailing_start
    );

    let trailing_file = output_dir.join("trailing.S");
    generate_trailing(trailing_data, trailing_start, &trailing_file)?;

    Ok(Some(trailing_file))
}
