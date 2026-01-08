// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared utility functions for assembly output generation.

use anyhow::{Context, Result};
use byteorder::{BigEndian, ByteOrder};
use std::fs::File;
use std::path::Path;

/// Create an output file with a standardized error message.
pub fn create_output_file(path: &Path, description: &str) -> Result<File> {
    File::create(path).with_context(|| format!("Failed to create {} {:?}", description, path))
}

/// Read a 32-bit big-endian word from a byte slice at the given offset.
/// Panics if there aren't enough bytes.
pub fn read_word(data: &[u8], offset: usize) -> u32 {
    BigEndian::read_u32(&data[offset..offset + 4])
}

/// Count consecutive 4-byte words matching a fill value in a byte slice.
/// Starts at `start_offset` (which must already match `fill_value`) and counts
/// how many consecutive words match up to `end_offset` or end of data.
/// Returns at least 1 (the starting word).
pub fn count_consecutive_words(
    data: &[u8],
    start_offset: usize,
    end_offset: usize,
    fill_value: u32,
) -> usize {
    let mut count = 1;
    let mut check_offset = start_offset + 4;
    let bound = end_offset.min(data.len());

    while check_offset + 4 <= bound {
        let next_word = BigEndian::read_u32(&data[check_offset..check_offset + 4]);
        if next_word != fill_value {
            break;
        }
        count += 1;
        check_offset += 4;
    }

    count
}
