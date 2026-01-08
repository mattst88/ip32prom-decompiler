// SPDX-License-Identifier: GPL-3.0-or-later
//! Trailing data generation for firmware images.
//!
//! This module generates assembly output for any data that appears
//! after the last firmware section.

use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use std::path::Path;

use super::util::{count_consecutive_words, create_output_file};
use super::writer::AssemblyWriter;

/// Minimum number of words to use .fill directive (otherwise emit individual .int)
const MIN_FILL_WORDS: usize = 5;

/// Generate assembly output for trailing data after all sections
pub fn generate_trailing(
    trailing_data: &[u8],
    trailing_offset: usize,
    output_path: &Path,
) -> Result<()> {
    let trailing_len = trailing_data.len();

    let file = create_output_file(output_path, "trailing data file")?;
    let mut w = AssemblyWriter::new(file);

    w.comment("Trailing data after all sections")?;
    w.comment(&format!(
        "Offset: {:#x}, Length: {} bytes",
        trailing_offset, trailing_len
    ))?;
    w.blank_line()?;
    w.raw(".set noreorder")?;
    w.raw(".set noat")?;
    w.blank_line()?;

    // Emit trailing data as words or fill directives
    let mut offset = 0;
    while offset < trailing_len {
        if offset + 4 <= trailing_len {
            let word = BigEndian::read_u32(&trailing_data[offset..offset + 4]);

            // For padding values (0x00000000 or 0xffffffff), check for runs
            if word == 0 || word == 0xffffffff {
                let run_count = count_consecutive_words(trailing_data, offset, trailing_len, word);
                if run_count >= MIN_FILL_WORDS {
                    w.fill_words(run_count, word)?;
                    offset += run_count * 4;
                    continue;
                }
            }

            w.int_hex(word)?;
            offset += 4;
        } else {
            // Emit remaining bytes
            while offset < trailing_len {
                w.byte_hex(trailing_data[offset])?;
                offset += 1;
            }
        }
    }

    Ok(())
}
