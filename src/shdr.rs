// SPDX-License-Identifier: GPL-3.0-or-later
//! SHDR (Section Header) parsing for IP32 PROM firmware format.

use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ByteOrder};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::hardware::constants::SHDR_MAGIC;
use crate::hardware::memmap::ROM_ALIGN;

/// SHDR header size in bytes
pub const SHDR_SIZE: usize = 64;

/// SHDR field offsets within the 64-byte header.
/// The SHDR format is overlaid with an ELF header for the "version" section.
pub const SHDR_OFFSET_MAGIC: usize = 8;
pub const SHDR_OFFSET_SECTION_LEN: usize = 12;
pub const SHDR_OFFSET_NAME_LEN: usize = 16;
pub const SHDR_OFFSET_VERSION_LEN: usize = 17;
pub const SHDR_OFFSET_SECTION_TYPE: usize = 18;
pub const SHDR_OFFSET_NAME: usize = 20;
pub const SHDR_OFFSET_VERSION: usize = 52;
pub const SHDR_OFFSET_CHECKSUM: usize = 60;
pub const SHDR_OFFSET_SUBSECTION_HEADER: usize = 64;
pub const SUBSECTION_HEADER_OFFSET_ADDR: usize = 0;
pub const SUBSECTION_HEADER_OFFSET_LEN: usize = 4;

/// ELF header field offsets (for "version" section).
pub const ELF_OFFSET_IDENT_MAGIC: usize = 0;
pub const ELF_OFFSET_IDENT_CLASS: usize = 4;
pub const ELF_OFFSET_PHOFF: usize = 28;
pub const ELF_OFFSET_SHOFF: usize = 32;
pub const ELF_OFFSET_FLAGS: usize = 36;
pub const ELF_OFFSET_EHSIZE: usize = 40;
pub const ELF_OFFSET_PHNUM: usize = 44;
pub const ELF_OFFSET_SHNUM: usize = 48;

/// Section type flag: contains non-executable data
pub const SECTION_TYPE_DATA: u8 = 0;

/// Section type flag: contains executable code
pub const SECTION_TYPE_CODE: u8 = 1;

/// Section type flag: loadable firmware (has subsections)
pub const SECTION_TYPE_LOADABLE: u8 = 2;

/// Subsection header size in bytes (load_addr + length)
pub const SUBSECTION_HEADER_SIZE: usize = 8;

/// Subsection indices for loadable sections.
/// Index 0 is the code (.text) subsection.
/// Index 1 is the read-only data (.rodata) subsection.
/// Index 2 is the read-write data (.rwdata) subsection.
pub const SUBSECTION_TEXT: usize = 0;
pub const SUBSECTION_RODATA: usize = 1;
pub const SUBSECTION_RWDATA: usize = 2;

/// Parsed SHDR (Section Header) structure
#[derive(Debug, Clone)]
pub struct Shdr {
    pub magic: u32,
    pub section_len: u32,
    pub name_len: u8,
    pub version_len: u8,
    pub section_type: u8,
    pub name: String,
    pub version: String,
    pub checksum: u32,
    pub offset: usize,
}

impl Shdr {
    /// Parse an SHDR from raw bytes at the given offset
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        if data.len() < SHDR_SIZE {
            bail!("Not enough data for SHDR at offset {:#x}", offset);
        }

        let magic = BigEndian::read_u32(&data[SHDR_OFFSET_MAGIC..SHDR_OFFSET_MAGIC + 4]);
        if magic != SHDR_MAGIC {
            bail!("Invalid SHDR magic at offset {:#x}", offset);
        }

        let section_len =
            BigEndian::read_u32(&data[SHDR_OFFSET_SECTION_LEN..SHDR_OFFSET_SECTION_LEN + 4]);
        let name_len = data[SHDR_OFFSET_NAME_LEN];
        let version_len = data[SHDR_OFFSET_VERSION_LEN];
        let section_type = data[SHDR_OFFSET_SECTION_TYPE];

        let name =
            std::str::from_utf8(&data[SHDR_OFFSET_NAME..SHDR_OFFSET_NAME + name_len as usize])
                .context("Invalid UTF-8 in section name")?
                .trim_end_matches('\0')
                .to_string();
        let version = std::str::from_utf8(
            &data[SHDR_OFFSET_VERSION..SHDR_OFFSET_VERSION + version_len as usize],
        )
        .context("Invalid UTF-8 in section version")?
        .trim_end_matches('\0')
        .to_string();
        let checksum = BigEndian::read_u32(&data[SHDR_OFFSET_CHECKSUM..SHDR_OFFSET_CHECKSUM + 4]);

        Ok(Shdr {
            magic,
            section_len,
            name_len,
            version_len,
            section_type,
            name,
            version,
            checksum,
            offset,
        })
    }

    /// Check if this section contains executable code
    pub fn is_code(&self) -> bool {
        (self.section_type & SECTION_TYPE_CODE) != 0
    }

    /// Check if this section is loadable (has subsections)
    pub fn is_loadable(&self) -> bool {
        (self.section_type & SECTION_TYPE_LOADABLE) != 0
    }

    /// Check if this is a pure data section (no executable code)
    pub fn is_data(&self) -> bool {
        !self.is_code()
    }

    /// Get the section type as an assembly expression (for SHDR macro)
    pub fn section_type_expr(&self) -> &'static str {
        match self.section_type {
            0 => "SECTION_TYPE_DATA",
            1 => "SECTION_TYPE_CODE",
            2 => "(SECTION_TYPE_DATA | SECTION_TYPE_LOADABLE)",
            3 => "(SECTION_TYPE_CODE | SECTION_TYPE_LOADABLE)",
            _ => "0",
        }
    }

    /// Get the section length as usize
    pub fn len(&self) -> usize {
        self.section_len as usize
    }

    /// Check if section has zero length
    pub fn is_empty(&self) -> bool {
        self.section_len == 0
    }

    /// Get the offset of the checksum (last 4 bytes of section)
    pub fn checksum_offset(&self) -> usize {
        self.len().saturating_sub(4)
    }
}

impl fmt::Display for Shdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Section: {}", self.name)?;
        writeln!(f, "  Offset:       {:#x}", self.offset)?;
        writeln!(
            f,
            "  Length:       {:#x} ({} bytes)",
            self.section_len, self.section_len
        )?;
        writeln!(
            f,
            "  Type:         {} ({:#x})",
            self.section_type_expr(),
            self.section_type
        )?;
        writeln!(f, "  Version:      {}", self.version)?;
        write!(f, "  Checksum:     {:#010x}", self.checksum)
    }
}

/// Find all SHDR sections in firmware data
pub fn find_shdrs(firmware: &[u8]) -> Vec<Shdr> {
    let mut shdrs = Vec::new();
    let mut offset = 0;

    while offset < firmware.len() {
        if let Ok(shdr) = Shdr::parse(&firmware[offset..], offset) {
            let next_offset = (offset + shdr.len()).next_multiple_of(ROM_ALIGN);
            shdrs.push(shdr);
            offset = next_offset;
        } else {
            break;
        }
    }

    shdrs
}

/// Load firmware from a file path.
/// Returns the firmware data as a byte vector.
pub fn load_firmware(path: &Path) -> Result<Vec<u8>> {
    let mut firmware_data = Vec::new();
    File::open(path)
        .with_context(|| format!("Failed to open firmware file {:?}", path))?
        .read_to_end(&mut firmware_data)
        .context("Failed to read firmware file")?;
    Ok(firmware_data)
}

/// Calculate the aligned end offset of the last section.
/// Returns the offset where trailing data begins, or 0 if no sections.
pub fn last_section_end(shdrs: &[Shdr]) -> usize {
    shdrs
        .iter()
        .map(|shdr| (shdr.offset + shdr.len()).next_multiple_of(ROM_ALIGN))
        .max()
        .unwrap_or(0)
}

/// Print summaries for all sections.
pub fn print_section_summaries(shdrs: &[Shdr]) {
    for shdr in shdrs {
        println!("{}", shdr);
        println!();
    }
}
