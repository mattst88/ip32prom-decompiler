// SPDX-License-Identifier: GPL-3.0-or-later
//! SHDR and Section checksum calculator/verifier for IP32 PROM sections
//!
//! This tool can verify or set checksums in individual section binary files.
//!
//! Usage:
//!   checksum --verify <file>    Verify checksums in file
//!   checksum --set <file>       Calculate and set checksums in file

use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use clap::{ArgGroup, Parser};
use ip32prom_decompiler::shdr::{SHDR_SIZE, Shdr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};

#[derive(Parser, Debug)]
#[command(name = "checksum")]
#[command(about = "Calculate and verify SHDR and Section checksums")]
#[command(group(ArgGroup::new("mode").required(true).args(["verify", "set"])))]
struct Args {
    /// Verify checksums in the file
    #[arg(long)]
    verify: bool,

    /// Calculate and set checksums in the file
    #[arg(long)]
    set: bool,

    /// Input file (section binary)
    file: String,
}

/// Calculate the SHDR checksum
///
/// Sum all 32-bit big-endian words in the first 60 bytes (excluding the checksum field),
/// then negate the result.
fn calculate_shdr_checksum(data: &[u8]) -> u32 {
    assert!(data.len() >= SHDR_SIZE);

    let num_words = (SHDR_SIZE - 4) / 4; // 15 words (60 bytes, excluding checksum)
    let mut sum: u32 = 0;

    for i in 0..num_words {
        let word = BigEndian::read_u32(&data[i * 4..(i + 1) * 4]);
        sum = sum.wrapping_add(word);
    }

    sum.wrapping_neg()
}

/// Get the stored SHDR checksum from the data
fn get_shdr_checksum(data: &[u8]) -> u32 {
    BigEndian::read_u32(&data[60..64])
}

/// Calculate the section checksum
///
/// Sum all 32-bit big-endian words from byte 64 (after SHDR) to 4 bytes before the end
/// (excluding the section checksum field), then negate the result.
fn calculate_section_checksum(data: &[u8], section_len: usize) -> u32 {
    let start_offset = SHDR_SIZE;
    let end_offset = section_len - 4; // Exclude the final checksum word

    let mut sum: u32 = 0;

    for offset in (start_offset..end_offset).step_by(4) {
        if offset + 4 <= data.len() {
            let word = BigEndian::read_u32(&data[offset..offset + 4]);
            sum = sum.wrapping_add(word);
        }
    }

    sum.wrapping_neg()
}

/// Get the stored section checksum from the data
fn get_section_checksum(data: &[u8], section_len: usize) -> u32 {
    let checksum_offset = section_len - 4;
    BigEndian::read_u32(&data[checksum_offset..checksum_offset + 4])
}

/// Load a section file, parse SHDR, and validate sizes.
/// Returns the data, SHDR, and section length.
fn load_and_validate_section(filename: &str) -> Result<(Vec<u8>, Shdr, usize)> {
    let mut file = File::open(filename).with_context(|| format!("Failed to open {}", filename))?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read {}", filename))?;

    if data.len() < SHDR_SIZE {
        bail!("File too small to contain SHDR header");
    }

    let shdr = Shdr::parse(&data, 0)?;
    let section_len = shdr.len();

    if data.len() < section_len {
        bail!(
            "File size ({}) is smaller than section length ({})",
            data.len(),
            section_len
        );
    }

    println!(
        "Section: \"{}\", version \"{}\", type: {}, length: {} bytes",
        shdr.name,
        shdr.version,
        shdr.section_type_expr(),
        section_len
    );
    println!();

    Ok((data, shdr, section_len))
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verify {
        verify_checksums(&args.file)
    } else {
        set_checksums(&args.file)
    }
}

fn verify_checksums(filename: &str) -> Result<()> {
    let (data, _shdr, section_len) = load_and_validate_section(filename)?;

    // Verify SHDR checksum
    let shdr_expected = get_shdr_checksum(&data);
    let shdr_calculated = calculate_shdr_checksum(&data);

    println!("SHDR checksum:");
    println!("  Stored:     {:#010x}", shdr_expected);
    println!("  Calculated: {:#010x}", shdr_calculated);

    let shdr_ok = shdr_expected == shdr_calculated;
    if shdr_ok {
        println!("  Status:     OK");
    } else {
        println!("  Status:     MISMATCH");
    }
    println!();

    // Verify section checksum
    let sect_expected = get_section_checksum(&data, section_len);
    let sect_calculated = calculate_section_checksum(&data, section_len);

    println!("Section checksum:");
    println!("  Stored:     {:#010x}", sect_expected);
    println!("  Calculated: {:#010x}", sect_calculated);

    let sect_ok = sect_expected == sect_calculated;
    if sect_ok {
        println!("  Status:     OK");
    } else {
        println!("  Status:     MISMATCH");
    }
    println!();

    if shdr_ok && sect_ok {
        println!("All checksums are correct!");
        Ok(())
    } else {
        bail!("Checksum verification failed");
    }
}

fn set_checksums(filename: &str) -> Result<()> {
    let (mut data, _shdr, section_len) = load_and_validate_section(filename)?;

    // Re-open file for writing
    let mut file = OpenOptions::new()
        .write(true)
        .open(filename)
        .with_context(|| format!("Failed to open {} for writing", filename))?;

    // Calculate and set SHDR checksum
    let shdr_checksum = calculate_shdr_checksum(&data);
    println!("Setting SHDR checksum: {:#010x}", shdr_checksum);

    file.seek(SeekFrom::Start(60))?;
    file.write_u32::<BigEndian>(shdr_checksum)?;

    // Update data buffer for section checksum calculation
    BigEndian::write_u32(&mut data[60..64], shdr_checksum);

    // Calculate and set section checksum
    let sect_checksum = calculate_section_checksum(&data, section_len);
    println!("Setting section checksum: {:#010x}", sect_checksum);

    let sect_checksum_offset = section_len - 4;
    file.seek(SeekFrom::Start(sect_checksum_offset as u64))?;
    file.write_u32::<BigEndian>(sect_checksum)?;

    println!();
    println!("Checksums updated successfully!");

    Ok(())
}
