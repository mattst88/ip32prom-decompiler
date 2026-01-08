// SPDX-License-Identifier: GPL-3.0-or-later
//! String detection and manipulation for firmware sections.

use super::{DataType, DetectedString, Section};
use crate::shdr::{SHDR_SIZE, SUBSECTION_RODATA};

/// Compute the next search position based on section alignment rules.
/// For `env` section: advance by 1 byte (no alignment).
/// For other sections: align to 4-byte boundary.
fn next_aligned_pos(pos: usize, is_env_section: bool) -> usize {
    if is_env_section {
        pos
    } else {
        pos.next_multiple_of(4)
    }
}

/// Check if a byte is a valid string character.
/// Includes printable ASCII, whitespace, and ESC (for ANSI sequences).
pub fn is_string_char(b: u8) -> bool {
    // isgraph: printable non-space characters (0x21-0x7e)
    // isspace: whitespace characters (space, tab, newline, etc.)
    // 0x1b: ESC character (used in ANSI escape sequences)
    b.is_ascii_graphic() || b.is_ascii_whitespace() || b == 0x1b
}

/// Escape a string for assembly output.
/// If `escape_altmacro` is true, escapes '!' as '!!' for .altmacro compatibility.
pub fn escape_string(data: &[u8], escape_altmacro: bool) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &b in data {
        match b {
            b'!' if escape_altmacro => result.push_str("!!"),
            b'\r' => result.push_str("\\r"),
            b'\n' => result.push_str("\\n"),
            b'\x0c' => result.push_str("\\f"),
            b'\x0b' => result.push_str("\\v"),
            b'\t' => result.push_str("\\t"),
            b'\\' => result.push_str("\\\\"),
            b'"' => result.push_str("\\\""),
            0x1b => result.push_str("\\x1b"),
            _ => result.push(b as char),
        }
    }
    result
}

/// Discover strings in a section and mark them in data_types
///
/// For code sections and version: strings are 4-byte aligned and zero-padded to 4-byte boundary
/// For env section: strings are 1-byte aligned with no padding requirement
pub fn discover_strings(section: &mut Section) {
    // Only env uses 1-byte alignment; version uses 4-byte alignment like code sections
    let is_env_section = section.shdr.name == "env";

    // For loadable sections, only search in data subsections (not the code subsection)
    // The first subsection contains code, subsequent subsections contain data with strings
    let (start, end) = if !section.subsections.is_empty() && section.subsections.len() > 1 {
        // Start searching from the rodata subsection (first data subsection)
        let rodata = &section.subsections[SUBSECTION_RODATA];
        (rodata.code_offset, section.data.len())
    } else if section.subsections.is_empty() {
        // Non-loadable sections: search from SHDR to end
        (SHDR_SIZE, section.data.len())
    } else {
        // Loadable section with only one subsection: no data subsections to search
        return;
    };

    // Collect subsection header ranges to skip during string search
    let subsection_headers: Vec<(usize, usize)> = section
        .subsections
        .iter()
        .map(|s| (s.header_offset, s.header_offset + 8))
        .collect();

    let mut prev_was_string = false;
    let mut i = start;

    while i < end {
        // Skip subsection headers (8 bytes each)
        if let Some(&(_header_start, header_end)) = subsection_headers
            .iter()
            .find(|&&(start, end)| i >= start && i < end)
        {
            prev_was_string = false;
            i = header_end;
            continue;
        }

        // Skip code areas (code discovery runs before string discovery)
        if section.data_types.get(&i) == Some(&DataType::Code) {
            prev_was_string = false;
            i = next_aligned_pos(i + 4, is_env_section);
            continue;
        }

        // Find the end of this potential string
        let mut j = i;
        while j < section.data.len() && is_string_char(section.data[j]) {
            j += 1;
        }

        // No string characters at this position
        if i == j {
            prev_was_string = false;
            i = next_aligned_pos(i + 1, is_env_section);
            continue;
        }

        let len = j - i;

        // Require minimum length of 3 characters, unless previous was also a string
        // (This allows short strings that follow other strings)
        if len < 3 && !prev_was_string {
            prev_was_string = false;
            i = next_aligned_pos(i + 1, is_env_section);
            continue;
        }

        // Must end with NUL terminator
        if j >= section.data.len() || section.data[j] != 0 {
            prev_was_string = false;
            i = if is_env_section {
                j
            } else {
                (j + 1).next_multiple_of(4)
            };
            continue;
        }

        // Include the NUL terminator in length
        let string_len = len + 1;

        // For non-env sections, verify zero-padding to 4-byte boundary AFTER the NUL
        // The padding check uses string_len (including NUL) to match C++ behavior
        if !is_env_section {
            let padding_needed = (4 - (string_len & 0x3)) & 0x3;
            let padding_ok = if padding_needed > 0 && j + 1 + padding_needed <= section.data.len() {
                // Check bytes after the NUL terminator (at j+1) up to the 4-byte boundary
                section.data[j + 1..j + 1 + padding_needed]
                    .iter()
                    .all(|&b| b == 0)
            } else {
                padding_needed == 0
            };

            if !padding_ok {
                prev_was_string = false;
                i = (i + 1).next_multiple_of(4);
                continue;
            }
        }

        // Extract and escape the string content (without NUL)
        let escaped = escape_string(&section.data[i..j], true);

        // Mark data types for this string
        if is_env_section {
            // For env section, mark each byte
            for offset in i..i + string_len {
                section.data_types.insert(offset, DataType::String);
            }
        } else {
            // For code and version sections, mark 4-byte aligned words
            let lo = i & !0x3;
            let hi = (j + 1).next_multiple_of(4); // +1 for NUL terminator
            for offset in (lo..hi).step_by(4) {
                section.data_types.insert(offset, DataType::String);
            }
        }

        // Store the detected string
        section.strings.insert(
            i,
            DetectedString {
                length: string_len,
                escaped,
            },
        );

        prev_was_string = true;

        // Move to the next position after this string (plus padding for non-env sections)
        i = next_aligned_pos(j + 1, is_env_section);
    }
}
