// SPDX-License-Identifier: GPL-3.0-or-later
//! Section representation and manipulation for firmware sections.

pub mod code;
pub mod strings;
pub mod types;

pub use code::discover_code;
pub use strings::{discover_strings, escape_string, is_string_char};
pub use types::*;

use crate::annotations::{Functions, Labels, Relocations, make_label};
use crate::hardware::memmap::ROM_START;
use crate::mips::format::label_for_addr;
use crate::shdr::{
    SHDR_SIZE, SUBSECTION_HEADER_SIZE, SUBSECTION_RODATA, SUBSECTION_RWDATA, SUBSECTION_TEXT, Shdr,
};
use byteorder::{BigEndian, ByteOrder};
use capstone::Capstone;
use std::collections::{HashMap, HashSet};

/// Returns the smallest value in `set` that is strictly greater than `threshold`.
fn next_after(set: &HashSet<usize>, threshold: usize) -> Option<usize> {
    set.iter().filter(|&&v| v > threshold).min().copied()
}

/// A firmware section with parsed structure and analysis data
pub struct Section {
    pub shdr: Shdr,
    pub data: Vec<u8>,
    pub data_types: HashMap<usize, DataType>,
    pub start_addr: u32,
    /// Control flow information (branch targets, function boundaries, unreachable code)
    pub control_flow: ControlFlowInfo,
    /// Subsections for loadable sections (empty for non-loadable sections)
    pub subsections: Vec<Subsection>,
    /// Virtual subsections from relocation config (code that executes at different addresses)
    pub virtual_subsections: Vec<Subsection>,
    /// Code discovery results (constructed addresses, known accesses, indirect jumps)
    pub discovery: DiscoveryResults,
    /// Detected strings in this section (maps offset to string info)
    pub strings: HashMap<usize, DetectedString>,
    /// Exception vector offsets for non-loadable sections (BEV=1 mode)
    pub exception_vectors: Vec<usize>,
    /// Maps function start offset to end offset (exclusive).
    /// Computed using control flow reachability analysis.
    pub function_bounds: HashMap<usize, usize>,
}

impl Section {
    /// Create a new Section with the given header, data, and start address.
    /// Initializes data types based on the raw data content.
    pub fn new(shdr: Shdr, data: Vec<u8>, start_addr: u32) -> Self {
        let mut data_types = HashMap::new();

        for offset in (0..SHDR_SIZE).step_by(4) {
            data_types.insert(offset, DataType::Header);
        }

        for offset in (SHDR_SIZE..data.len()).step_by(4) {
            if offset + 4 <= data.len() {
                let word = BigEndian::read_u32(&data[offset..offset + 4]);
                let dtype = if word == 0 {
                    DataType::PadZero
                } else if word == 0xffff_ffff {
                    DataType::PadOnes
                } else {
                    DataType::Unknown
                };
                data_types.insert(offset, dtype);
            }
        }

        // Parse subsections for loadable sections
        let subsections = if shdr.is_loadable() {
            Self::parse_subsections(&data, start_addr)
        } else {
            Vec::new()
        };

        // Mark subsection headers as Header type
        for subsection in &subsections {
            for offset in (subsection.header_offset
                ..subsection.header_offset + SUBSECTION_HEADER_SIZE)
                .step_by(4)
            {
                data_types.insert(offset, DataType::Header);
            }
        }

        // Mark the sentinel header (after the last subsection) as Header type
        if let Some(last_subsection) = subsections.last() {
            let sentinel_offset = last_subsection.code_offset + last_subsection.length;
            for offset in (sentinel_offset..sentinel_offset + SUBSECTION_HEADER_SIZE).step_by(4) {
                if offset + 4 <= data.len() {
                    data_types.insert(offset, DataType::Header);
                }
            }
        }

        // Mark the section checksum (last 4 bytes) as Header type
        let checksum_offset = shdr.checksum_offset();
        if checksum_offset + 4 <= data.len() {
            data_types.insert(checksum_offset, DataType::Header);
        }

        Section {
            shdr,
            data,
            data_types,
            start_addr,
            control_flow: ControlFlowInfo::default(),
            subsections,
            virtual_subsections: Vec::new(),
            discovery: DiscoveryResults::default(),
            strings: HashMap::new(),
            exception_vectors: Vec::new(),
            function_bounds: HashMap::new(),
        }
    }

    /// Create a Section from an Shdr and firmware data.
    /// Extracts the section data from the firmware and calculates the start address.
    pub fn from_firmware(shdr: &Shdr, firmware: &[u8]) -> Self {
        let section_end = shdr.offset + shdr.len();
        let section_data = firmware[shdr.offset..section_end.min(firmware.len())].to_vec();
        let start_addr = ROM_START + shdr.offset as u32;
        Self::new(shdr.clone(), section_data, start_addr)
    }

    /// Parse subsection headers from a loadable section
    fn parse_subsections(data: &[u8], start_addr: u32) -> Vec<Subsection> {
        let mut subsections = Vec::new();
        let mut is_first = true;
        let mut header_offset = SHDR_SIZE;

        while header_offset + SUBSECTION_HEADER_SIZE <= data.len() {
            let load_addr = BigEndian::read_u32(&data[header_offset..header_offset + 4]);
            let length_in_header = BigEndian::read_u32(
                &data[header_offset + 4..header_offset + SUBSECTION_HEADER_SIZE],
            ) as usize;

            if length_in_header == 0 {
                break;
            }

            let code_offset = header_offset + SUBSECTION_HEADER_SIZE;

            let (code_length, next_header_offset) = if is_first {
                let actual_code_length = length_in_header - code_offset;
                (actual_code_length, length_in_header)
            } else {
                (length_in_header, code_offset + length_in_header)
            };

            // For firmware-defined subsections, rom_addr = start_addr + code_offset
            let rom_addr = start_addr + code_offset as u32;

            subsections.push(Subsection {
                load_addr,
                rom_addr,
                header_offset,
                code_offset,
                length: code_length,
                is_first,
                is_virtual: false,
                elf_section: None,
            });

            header_offset = next_header_offset;
            is_first = false;
        }

        subsections
    }

    /// Add virtual subsections from relocation configuration
    pub fn add_relocations(&mut self, relocations: &Relocations) {
        for reloc in relocations.for_section(&self.shdr.name) {
            // Convert ROM addresses to section offsets
            let rom_start_offset = if reloc.rom_start >= self.start_addr {
                (reloc.rom_start - self.start_addr) as usize
            } else {
                continue; // ROM address is before this section
            };

            let length = (reloc.rom_end - reloc.rom_start) as usize;

            // Verify the range is within this section
            if rom_start_offset + length > self.data.len() {
                eprintln!(
                    "Warning: Relocation for section {} extends beyond section data",
                    self.shdr.name
                );
                continue;
            }

            self.virtual_subsections.push(Subsection {
                load_addr: reloc.vma,
                rom_addr: reloc.rom_start,
                header_offset: rom_start_offset, // No header for virtual subsections
                code_offset: rom_start_offset,
                length,
                is_first: false,
                is_virtual: true,
                elf_section: Some(reloc.elf_section.clone()),
            });
        }
    }

    /// Check if an offset is in a valid code area (not inside the SHDR header content).
    /// Valid offsets are: 0-7 (initial instructions) or >= SHDR_SIZE (after header).
    pub fn is_valid_code_offset(&self, offset: usize) -> bool {
        offset < self.data.len() && !(SUBSECTION_HEADER_SIZE..SHDR_SIZE).contains(&offset)
    }

    /// Check if an offset falls within any subsection header.
    pub fn in_subsection_header(&self, offset: usize) -> bool {
        self.subsections
            .iter()
            .any(|s| offset >= s.header_offset && offset < s.header_offset + SUBSECTION_HEADER_SIZE)
    }

    /// Mark an offset as a branch target, requiring a label in output.
    /// Offsets in the SHDR header area are silently ignored.
    pub fn mark_branch_target(&mut self, offset: usize) {
        if self.is_valid_code_offset(offset) {
            self.control_flow.branch_targets.insert(offset);
        }
    }

    /// Mark an offset as a function entry point.
    /// Also marks it as a branch target. Invalid offsets are silently ignored.
    pub fn mark_function_start(&mut self, offset: usize) {
        if self.is_valid_code_offset(offset) {
            self.control_flow.function_starts.insert(offset);
            self.control_flow.branch_targets.insert(offset);
        }
    }

    /// Mark an offset as immediately after a function return.
    /// Used for calculating function bounds.
    pub fn mark_function_end(&mut self, offset: usize) {
        if offset <= self.data.len() {
            self.control_flow.function_ends.insert(offset);
        }
    }

    /// Mark an offset as containing a branch/jump instruction.
    /// Used to avoid re-disassembly during CFG construction.
    pub fn mark_branch_instruction(&mut self, offset: usize) {
        self.control_flow.branch_offsets.insert(offset);
    }

    /// Get the end address of a function given its start offset.
    /// Returns None if the function bounds cannot be determined.
    pub fn get_function_end_addr(&self, start_offset: usize) -> Option<u32> {
        // Use pre-computed function bounds if available
        if let Some(&end_offset) = self.function_bounds.get(&start_offset) {
            return Some(self.offset_to_end_addr(end_offset));
        }

        // Fallback to simple heuristic (next function end or start)
        let end_offset = next_after(&self.control_flow.function_ends, start_offset);
        let next_start = next_after(&self.control_flow.function_starts, start_offset);
        let end = [end_offset, next_start].into_iter().flatten().min();

        end.map(|offset| self.offset_to_end_addr(offset))
    }

    fn offset_to_end_addr(&self, offset: usize) -> u32 {
        let addr = self.offset_to_addr(offset);

        if self.shdr.is_loadable()
            && !self.subsections.is_empty()
            && addr >= self.start_addr
            && addr < self.start_addr + self.data.len() as u32
        {
            for subsection in &self.subsections {
                let subsect_end = subsection.code_offset + subsection.length;
                if offset == subsect_end {
                    if subsection.is_first {
                        return subsection.load_addr + subsect_end as u32;
                    } else {
                        return subsection.load_addr + subsection.length as u32;
                    }
                }
            }
        }

        addr
    }

    /// Get the data type at a given offset, defaulting to Unknown.
    pub fn data_type_at(&self, offset: usize) -> DataType {
        self.data_types
            .get(&offset)
            .copied()
            .unwrap_or(DataType::Unknown)
    }

    /// Mark an offset as containing code (an instruction).
    pub fn mark_code(&mut self, offset: usize) {
        if offset + 4 <= self.data.len() {
            self.data_types.insert(offset, DataType::Code);
        }
    }

    /// Iterate all subsections: virtual (relocated) first, then firmware-defined.
    /// Virtual subsections have priority so that relocated code uses VMA addresses.
    fn all_subsections(&self) -> impl Iterator<Item = &Subsection> {
        self.virtual_subsections
            .iter()
            .chain(self.subsections.iter())
    }

    /// Convert an offset within this section to its runtime address.
    /// Checks virtual subsections first, then firmware subsections, then falls back to ROM address.
    pub fn offset_to_addr(&self, offset: usize) -> u32 {
        self.all_subsections()
            .find_map(|s| s.offset_to_addr(offset))
            .unwrap_or(self.start_addr + offset as u32)
    }

    /// Convert an address to section offset.
    /// Checks VMA space (virtual subsections) first, then firmware subsections, then ROM space.
    pub fn addr_to_offset(&self, addr: u32) -> Option<usize> {
        self.all_subsections()
            .find_map(|s| s.addr_to_offset(addr))
            .or_else(|| {
                if addr >= self.start_addr && addr < self.start_addr + self.data.len() as u32 {
                    Some((addr - self.start_addr) as usize)
                } else {
                    None
                }
            })
    }

    /// Check if an offset falls within a virtual (relocated) subsection
    pub fn is_in_virtual_subsection(&self, offset: usize) -> bool {
        self.virtual_subsections
            .iter()
            .any(|s| s.contains_offset(offset))
    }

    /// Check if an address falls within a virtual (relocated) subsection
    pub fn is_addr_in_virtual_subsection(&self, addr: u32) -> bool {
        self.virtual_subsections
            .iter()
            .any(|s| s.contains_addr(addr))
    }

    /// Get the virtual subsection containing the given offset, if any
    pub fn get_virtual_subsection(&self, offset: usize) -> Option<&Subsection> {
        self.virtual_subsections
            .iter()
            .find(|s| s.contains_offset(offset))
    }

    /// Get the load address of the first subsection (used for sentinel macros).
    /// Returns 0 if there are no subsections.
    pub fn sentinel_addr(&self) -> u32 {
        self.subsections.first().map(|s| s.load_addr).unwrap_or(0)
    }

    /// Check if an address falls within this section's data range.
    /// Handles virtual subsections and loadable subsections correctly.
    pub fn addr_in_data_range(&self, addr: u32) -> bool {
        if self.all_subsections().any(|s| s.contains_addr(addr)) {
            return true;
        }
        // Non-loadable sections (or those without subsections): check ROM address space
        if !self.shdr.is_loadable() || self.subsections.is_empty() {
            return addr >= self.start_addr && addr < self.start_addr + self.data.len() as u32;
        }
        false
    }

    /// Get the label prefix for an address based on which subsection it falls in.
    /// Returns None for code/text, or a prefix like "rodata_" or "rwdata_" for data sections.
    pub fn label_prefix_for_addr(&self, addr: u32) -> Option<&'static str> {
        // Check virtual subsections first - they use no prefix (like code)
        if self.is_addr_in_virtual_subsection(addr) {
            return None;
        }

        if self.shdr.is_loadable() && !self.subsections.is_empty() {
            for (i, subsection) in self.subsections.iter().enumerate() {
                if subsection.contains_addr(addr) {
                    return match i {
                        SUBSECTION_TEXT => None,
                        SUBSECTION_RODATA => Some("rodata_"),
                        SUBSECTION_RWDATA => Some("rwdata_"),
                        _ => Some("data_"),
                    };
                }
            }
        }
        Some("data_")
    }

    /// Generate a default data label for an address (e.g., "data_0xbfc00000" or "rodata_0x80100000").
    /// Uses the subsection-appropriate prefix, defaulting to "data_" for code sections.
    pub fn data_label_for_addr(&self, addr: u32) -> String {
        let prefix = self.label_prefix_for_addr(addr).unwrap_or("data_");
        make_label(prefix, addr)
    }

    /// Get the label for an offset if it should have one (branch target or explicitly labeled).
    /// Returns the label string, using label_for_addr for branch targets or falling back to labels.
    pub fn get_label_at_offset(&self, offset: usize, labels: &Labels) -> Option<String> {
        let addr = self.offset_to_addr(offset);
        if self.control_flow.branch_targets.contains(&offset) {
            Some(label_for_addr(addr, self, offset, labels))
        } else {
            labels.get(addr).map(|s| s.to_string())
        }
    }

    /// Get the label for a pointer value if it points to a known target.
    /// Returns the label string if the value points to a branch target or has an explicit label.
    pub fn get_label_for_pointer(&self, value: u32, labels: &Labels) -> Option<String> {
        if let Some(target_offset) = self.addr_to_offset(value)
            && self.control_flow.branch_targets.contains(&target_offset)
        {
            return Some(label_for_addr(value, self, target_offset, labels));
        }
        labels.get(value).map(|s| s.to_string())
    }

    /// Get the start address of the BSS section (uninitialized data).
    /// This is the address immediately after the last subsection.
    /// Returns None for non-loadable sections.
    pub fn bss_start(&self) -> Option<u32> {
        if self.shdr.is_loadable()
            && !self.subsections.is_empty()
            && let Some(last_subsect) = self.subsections.last()
        {
            return Some(last_subsect.load_addr + last_subsect.length as u32);
        }
        None
    }

    /// Find the next exception vector offset at or after the given offset.
    pub fn next_exception_vector(&self, offset: usize) -> Option<usize> {
        self.exception_vectors
            .iter()
            .find(|&&v| v >= offset)
            .copied()
    }

    /// Check if all offsets in the range are unreachable nops.
    /// A nop is encoded as 0x00000000.
    pub fn is_unreachable_nop_range(&self, start: usize, end: usize) -> bool {
        (start..end).step_by(4).all(|offset| {
            self.control_flow.unreachable_code.contains(&offset)
                && self
                    .data
                    .get(offset..offset + 4)
                    .is_some_and(|bytes| bytes == [0, 0, 0, 0])
        })
    }

    /// Discover unreachable code: Unknown data between Code blocks that can be disassembled.
    /// This should be called after discover_code() to find gaps that are likely dead code.
    pub fn discover_unreachable_code(&mut self, cs: &Capstone) {
        // Get all Code offsets, sorted
        let mut code_offsets: Vec<usize> = self
            .data_types
            .iter()
            .filter(|(_, dtype)| **dtype == DataType::Code)
            .map(|(offset, _)| *offset)
            .collect();
        code_offsets.sort_unstable();

        if code_offsets.len() < 2 {
            return;
        }

        // Look for gaps between consecutive Code blocks
        let mut gaps_to_mark = Vec::new();

        for pair in code_offsets.windows(2) {
            let (prev_code, next_code) = (pair[0], pair[1]);

            // Check if there's a gap (more than 4 bytes between them)
            if next_code <= prev_code + 4 {
                continue;
            }

            // Skip gaps that lead to exception vectors (handled by .org directives)
            if self.exception_vectors.contains(&next_code) {
                continue;
            }

            // Check if all entries in the gap are unclassified (Unknown or PadZero)
            let gap_start = prev_code + 4;
            let all_unclassified = (gap_start..next_code)
                .step_by(4)
                .all(|offset| self.data_type_at(offset).is_unclassified());

            if !all_unclassified {
                continue;
            }

            // Try to disassemble each word in the gap
            for offset in (gap_start..next_code).step_by(4) {
                if offset + 4 > self.data.len() {
                    break;
                }

                let code_slice = &self.data[offset..offset + 4];
                let addr = self.offset_to_addr(offset);

                // Try to disassemble
                if let Ok(insns) = cs.disasm_all(code_slice, addr.into())
                    && insns.iter().next().is_some()
                {
                    // Successfully disassembled - mark as unreachable code
                    gaps_to_mark.push(offset);
                }
            }
        }

        // Mark all gaps as Code and unreachable
        for offset in gaps_to_mark {
            self.data_types.insert(offset, DataType::Code);
            self.control_flow.unreachable_code.insert(offset);
        }
    }

    /// Mark memory access targets from constructed addresses as Data type.
    /// This should be called after discover_code() to identify data locations
    /// referenced by load/store instructions.
    pub fn mark_memory_access_targets(&mut self) {
        // Collect targets first to avoid borrow issues
        let targets: Vec<(usize, u8)> = self
            .discovery
            .constructed_addrs
            .values()
            .filter(|addr_info| addr_info.is_memory_access)
            .filter_map(|addr_info| {
                let addr = addr_info.address();
                self.addr_to_offset(addr)
                    .map(|offset| (offset, addr_info.access_size))
            })
            .collect();

        for (offset, access_size) in targets {
            let slots = (access_size as usize).div_ceil(4);
            for i in 0..slots {
                let slot_offset = offset + i * 4;
                if slot_offset + 4 > self.data.len() {
                    break;
                }
                if self.strings.contains_key(&slot_offset) {
                    continue;
                }
                let dtype = self.data_type_at(slot_offset);
                if dtype == DataType::Code || dtype == DataType::String {
                    continue;
                }
                self.data_types.insert(slot_offset, DataType::Data);
            }
        }
    }

    /// Scan data areas for pointer values that point within the section.
    /// Returns a set of addresses that appear to be pointer targets.
    /// This handles pointers stored in data (not constructed via lui/addiu).
    pub fn collect_pointer_targets(&self) -> HashSet<u32> {
        (0..self.data.len())
            .step_by(4)
            .filter_map(|offset| {
                // Only scan Data, Unknown, PadZero, PadOnes - not Code, String, or Header
                let is_data = self.data_type_at(offset).is_data_like();
                if is_data && offset + 4 <= self.data.len() {
                    let word = BigEndian::read_u32(&self.data[offset..offset + 4]);
                    // Check if this looks like a pointer to data within the section
                    if self.addr_in_data_range(word) {
                        return Some(word);
                    }
                }
                None
            })
            .collect()
    }

    /// Collect addresses from constructed address targets that are within the section's data range.
    /// Returns a set of addresses that need labels.
    pub fn collect_constructed_addr_targets(&self) -> HashSet<u32> {
        self.discovery
            .constructed_addrs
            .values()
            .map(|addr_info| addr_info.address())
            .filter(|addr| self.addr_in_data_range(*addr))
            .collect()
    }

    /// Check if an address corresponds to a branch target offset.
    fn is_branch_target_addr(&self, addr: u32) -> bool {
        self.addr_to_offset(addr)
            .is_some_and(|offset| self.control_flow.branch_targets.contains(&offset))
    }

    /// Generate labels for all discovered targets in this section.
    /// This adds labels for:
    /// - Discovered strings
    /// - Pointer targets found in data areas
    /// - Constructed address targets (from lui/addiu patterns)
    pub fn generate_labels(&self, labels: &mut Labels) {
        // Add labels for discovered strings
        for &offset in self.strings.keys() {
            let addr = self.offset_to_addr(offset);
            labels.insert_generated(addr, self.label_prefix_for_addr(addr).or(Some("data_")));
        }

        // Add labels for pointer and constructed address targets
        // Skip addresses that are branch targets - they'll get F_/L_ labels from label_for_addr
        for addr in self
            .collect_pointer_targets()
            .into_iter()
            .chain(self.collect_constructed_addr_targets())
        {
            if !self.is_branch_target_addr(addr) {
                labels.insert_generated(addr, self.label_prefix_for_addr(addr));
            }
        }
    }

    /// Perform full analysis of this section.
    /// This discovers code, strings, memory access targets, and generates labels.
    pub fn analyze(&mut self, cs: &Capstone, funcs: &Functions, labels: &mut Labels) {
        discover_code(cs, self, funcs);
        // Compute function bounds using CFG analysis
        let blocks = crate::cfg::build_basic_blocks(cs, self, false);
        self.function_bounds = crate::cfg::compute_function_bounds(&blocks, self)
            .into_iter()
            .collect();
        discover_strings(self); // After code discovery so we skip code areas
        self.discover_unreachable_code(cs); // After strings so we skip string areas
        self.mark_memory_access_targets();
        self.generate_labels(labels);
    }

    /// Returns the list of ELF section names needed for objcopy to extract the binary.
    /// This must match the sections defined in the linker script.
    pub fn elf_sections_for_objcopy(&self) -> Vec<String> {
        if self.subsections.len() > 1 {
            // Loadable section with multiple subsections (like firmware)
            vec![
                ".text".to_string(),
                ".rodata_header".to_string(),
                ".rodata".to_string(),
                ".rwdata_header".to_string(),
                ".rwdata".to_string(),
                ".sentinel".to_string(),
            ]
        } else if !self.virtual_subsections.is_empty() {
            // Section with virtual (relocated) subsections (like post1)
            let mut sections = vec![".text".to_string()];
            for (i, vsub) in self.virtual_subsections.iter().enumerate() {
                let elf_section = vsub.elf_section.as_deref().unwrap_or("text_ram");
                sections.push(format!(".{}", elf_section));
                sections.push(format!(".text_after_{}", i + 1));
            }
            sections
        } else {
            // Simple section (like sloader)
            vec![".text".to_string()]
        }
    }
}
