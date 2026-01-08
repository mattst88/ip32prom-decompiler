// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use ip32prom_decompiler::{
    annotations::Annotations,
    hardware::SystemConstants,
    mips::create_capstone,
    output::{
        create_output_dir, generate_headers, generate_makefile, generate_prom_xpm,
        generate_trailing_output, process_all_sections,
    },
    shdr::{find_shdrs, last_section_end, load_firmware, print_section_summaries},
};

#[derive(Parser)]
#[command(name = "ip32prom-decompiler")]
#[command(about = "Decompile MIPS firmware images to assembly")]
struct Args {
    /// Path to the firmware image
    firmware: PathBuf,

    /// Output directory for assembly files
    #[arg(short, long, default_value = ".")]
    output: PathBuf,

    /// Directory containing annotation JSON files
    #[arg(short, long, default_value = "annotations")]
    annotations: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let firmware_data = load_firmware(&args.firmware)?;
    println!(
        "Loaded firmware: {} bytes ({:#x})",
        firmware_data.len(),
        firmware_data.len()
    );

    let shdrs = find_shdrs(&firmware_data);
    println!("Found {} sections:\n", shdrs.len());

    let cs = create_capstone()?;
    print_section_summaries(&shdrs);

    create_output_dir(&args.output)?;

    // Load annotations from JSON files
    let mut annotations = Annotations::load_from_dir(&args.annotations)?;
    annotations.print_stats(&args.annotations);

    // Initialize system constants lookup tables
    let sys_consts = SystemConstants::new();

    // Generate common header files
    for path in generate_headers(&args.output, &sys_consts, &annotations.bss_names)? {
        println!("Generated: {:?}", path);
    }

    // Process all sections
    let (_generated_paths, sections) = process_all_sections(
        &cs,
        &shdrs,
        &firmware_data,
        &args.output,
        &mut annotations,
        &sys_consts,
    )?;

    // Handle trailing data after the last section
    let has_trailing = last_section_end(&shdrs) < firmware_data.len();
    if let Some(path) =
        generate_trailing_output(&firmware_data, last_section_end(&shdrs), &args.output)?
    {
        println!("  Generated: {:?}", path);
    }

    // Generate Makefile
    let makefile_path = args.output.join("Makefile");
    generate_makefile(&makefile_path, &sections, has_trailing)?;
    println!("Generated: {:?}", makefile_path);

    // Generate combined PROM XPM visualization (excluding trailing data)
    let prom_xpm_path = args.output.join("prom.xpm");
    generate_prom_xpm(&sections, &prom_xpm_path)?;
    println!("Generated: {:?}", prom_xpm_path);

    // Verify all annotations were used
    annotations.verify_all_used();

    println!("\nDone!");
    Ok(())
}
