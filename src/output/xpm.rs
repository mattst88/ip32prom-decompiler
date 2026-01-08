// SPDX-License-Identifier: GPL-3.0-or-later
//! XPM visualization generation for firmware sections.
//!
//! This module generates XPM image files that visualize the data types
//! in each firmware section, making it easy to see code vs data regions.

use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use super::util::create_output_file;
use crate::hardware::memmap::ROM_ALIGN;
use crate::section::{DataType, Section};

/// Width of XPM images in pixels (each pixel = one 4-byte word)
const XPM_WIDTH: usize = 128;

/// All data types in the order they appear in the XPM color table
const DATA_TYPES: [DataType; 7] = [
    DataType::Header,
    DataType::Code,
    DataType::Data,
    DataType::String,
    DataType::PadZero,
    DataType::PadOnes,
    DataType::Unknown,
];

/// Write an XPM file with the given name, dimensions, and data type lookup function.
fn write_xpm<F>(file: &mut File, name: &str, height: usize, get_dtype: F) -> Result<()>
where
    F: Fn(usize) -> DataType,
{
    // XPM header
    writeln!(file, "/* XPM */")?;
    writeln!(file, "static char *{}_xpm[] = {{", name)?;
    writeln!(file, "\"{} {} 7 1\",", XPM_WIDTH, height)?;

    // Color definitions
    for dt in &DATA_TYPES {
        writeln!(file, "\"{} c {}\",", dt.to_xpm_char(), dt.xpm_color())?;
    }

    // Pixel data - one character per 4-byte word
    for row in 0..height {
        write!(file, "\"")?;
        for col in 0..XPM_WIDTH {
            let byte_offset = (row * XPM_WIDTH + col) * 4;
            write!(file, "{}", get_dtype(byte_offset).to_xpm_char())?;
        }
        if row == height - 1 {
            writeln!(file, "\"")?;
        } else {
            writeln!(file, "\",")?;
        }
    }

    writeln!(file, "}};")?;
    Ok(())
}

/// Generate an XPM visualization image for a section
pub fn generate_xpm(section: &Section, output_path: &Path) -> Result<()> {
    let mut file = create_output_file(output_path, "XPM file")?;

    let aligned_len = section.data.len().next_multiple_of(ROM_ALIGN);
    let height = (aligned_len / 4).div_ceil(XPM_WIDTH);

    write_xpm(&mut file, &section.shdr.name, height, |byte_offset| {
        if byte_offset < section.data.len() {
            *section
                .data_types
                .get(&byte_offset)
                .unwrap_or(&DataType::Unknown)
        } else {
            DataType::PadZero
        }
    })
}

/// Generate an XPM visualization image for the entire PROM (excluding trailing data)
pub fn generate_prom_xpm(sections: &[Section], output_path: &Path) -> Result<()> {
    let mut file = create_output_file(output_path, "PROM XPM file")?;

    let sections_end = sections
        .iter()
        .map(|s| (s.shdr.offset + s.shdr.len()).next_multiple_of(ROM_ALIGN))
        .max()
        .unwrap_or(0);

    let height = (sections_end / 4).div_ceil(XPM_WIDTH);

    write_xpm(&mut file, "prom", height, |byte_offset| {
        if byte_offset < sections_end {
            get_dtype_at_offset(sections, byte_offset)
        } else {
            DataType::PadZero
        }
    })
}

/// Get the data type at a given firmware offset by finding the containing section
fn get_dtype_at_offset(sections: &[Section], firmware_offset: usize) -> DataType {
    for section in sections {
        let section_start = section.shdr.offset;
        let section_end = section_start + section.shdr.len();
        let aligned_end = section_end.next_multiple_of(ROM_ALIGN);

        if firmware_offset >= section_start && firmware_offset < section_end {
            let offset_in_section = firmware_offset - section_start;
            return *section
                .data_types
                .get(&offset_in_section)
                .unwrap_or(&DataType::Unknown);
        } else if firmware_offset >= section_end && firmware_offset < aligned_end {
            return DataType::PadZero;
        }
    }

    DataType::Unknown
}
