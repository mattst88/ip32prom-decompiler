// SPDX-License-Identifier: GPL-3.0-or-later
//! Annotation loading and management for labels, comments, functions, operands, and relocations.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Generate a label string from a prefix and address (e.g., "data_0xbfc00000").
pub fn make_label(prefix: &str, addr: u32) -> String {
    format!("{}{:#010x}", prefix, addr)
}

/// Strip a "0x" or "0X" prefix from a string, if present.
pub fn strip_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// Parse a hex address string with optional 0x/0X prefix
fn parse_hex_addr(s: &str) -> Option<u32> {
    u32::from_str_radix(strip_hex_prefix(s), 16).ok()
}

/// Load and deserialize a JSON file with standardized error context.
fn load_json_file<T: serde::de::DeserializeOwned>(path: &PathBuf, description: &str) -> Result<T> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open {} file {:?}", description, path))?;
    serde_json::from_reader(file)
        .with_context(|| format!("Failed to parse {} file {:?}", description, path))
}

/// Generic map from addresses to values, loaded from JSON.
/// JSON format: [{ "0xaddr": value }, ...]
#[derive(Debug, Default)]
pub struct AddrMap<T>(HashMap<u32, T>);

impl<T: serde::de::DeserializeOwned> AddrMap<T> {
    pub fn load(path: &PathBuf, description: &str) -> Result<Self> {
        let json: Vec<HashMap<String, T>> = load_json_file(path, description)?;

        let mut map = HashMap::new();
        for entry in json {
            for (addr_str, value) in entry {
                if let Some(addr) = parse_hex_addr(&addr_str) {
                    map.insert(addr, value);
                }
            }
        }
        Ok(AddrMap(map))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn get(&self, addr: u32) -> Option<&T> {
        self.0.get(&addr)
    }
    pub fn remove(&mut self, addr: u32) -> Option<T> {
        self.0.remove(&addr)
    }
    pub fn insert(&mut self, addr: u32, value: T) {
        self.0.insert(addr, value);
    }
    pub fn contains_key(&self, addr: u32) -> bool {
        self.0.contains_key(&addr)
    }
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.keys().copied()
    }
}

impl AddrMap<String> {
    pub fn get_str(&self, addr: u32) -> Option<&str> {
        self.0.get(&addr).map(|s| s.as_str())
    }
}

/// A newtype wrapper for `AddrMap<String>` that provides common string map operations.
/// Types can wrap this and use Deref to get the common methods.
#[derive(Debug, Default)]
pub struct StringAddrMap(AddrMap<String>);

impl StringAddrMap {
    fn load(path: &PathBuf, description: &str) -> Result<Self> {
        Ok(Self(AddrMap::load(path, description)?))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, addr: u32) -> Option<&str> {
        self.0.get_str(addr)
    }

    pub fn remove(&mut self, addr: u32) -> Option<String> {
        self.0.remove(addr)
    }

    pub fn insert(&mut self, addr: u32, value: String) {
        self.0.insert(addr, value);
    }

    pub fn contains_key(&self, addr: u32) -> bool {
        self.0.contains_key(addr)
    }

    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.keys()
    }
}

/// Named labels for addresses (branch targets, function names, data labels)
#[derive(Debug, Default)]
pub struct Labels(StringAddrMap);

impl Labels {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        Ok(Self(StringAddrMap::load(path, "labels")?))
    }

    /// Insert a generated label if one doesn't already exist.
    pub fn insert_generated(&mut self, addr: u32, prefix: Option<&str>) {
        if self.0.contains_key(addr) {
            return;
        }
        let label = make_label(prefix.unwrap_or("F_"), addr);
        self.0.insert(addr, label);
    }

    /// Check if any label exists in the given address range (exclusive of start)
    pub fn has_any_in_range(&self, start: u32, end: u32) -> bool {
        ((start + 1)..end).any(|addr| self.0.contains_key(addr))
    }
}

impl std::ops::Deref for Labels {
    type Target = StringAddrMap;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Comments for addresses
#[derive(Debug, Default)]
pub struct Comments(StringAddrMap);

impl Comments {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        Ok(Self(StringAddrMap::load(path, "comments")?))
    }

    pub fn remove(&mut self, addr: u32) -> Option<String> {
        self.0.remove(addr)
    }
}

impl std::ops::Deref for Comments {
    type Target = StringAddrMap;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Function descriptions for addresses
#[derive(Debug, Default)]
pub struct Functions(StringAddrMap);

impl Functions {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        Ok(Self(StringAddrMap::load(path, "functions")?))
    }

    pub fn addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.keys()
    }

    pub fn remove(&mut self, addr: u32) -> Option<String> {
        self.0.remove(addr)
    }
}

impl std::ops::Deref for Functions {
    type Target = StringAddrMap;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// BSS variable names for offsets
#[derive(Debug, Default)]
pub struct BssNames(StringAddrMap);

impl BssNames {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        Ok(Self(StringAddrMap::load(path, "bss names")?))
    }
}

impl std::ops::Deref for BssNames {
    type Target = StringAddrMap;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Operand replacements for addresses: address -> (search -> replacement)
#[derive(Debug, Default)]
pub struct Operands(AddrMap<HashMap<String, String>>);

impl Operands {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        Ok(Operands(AddrMap::load(path, "operands")?))
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.keys()
    }

    /// Apply replacements to an operand string for a given address and remove the entry
    pub fn apply_and_remove(&mut self, addr: u32, op_str: &str) -> String {
        if let Some(rules) = self.0.remove(addr) {
            let mut result = op_str.to_string();
            for (search, replace) in &rules {
                result = replace_token(&result, search, replace);
            }
            result
        } else {
            op_str.to_string()
        }
    }
}

/// Replace a token in a string only when it appears as a complete token
/// A token boundary is defined as: start/end of string, comma, space, parentheses
pub fn replace_token(s: &str, search: &str, replace: &str) -> String {
    if search.is_empty() {
        return s.to_string();
    }

    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let search_chars: Vec<char> = search.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Check if we're at a potential match
        if chars[i..].starts_with(&search_chars) {
            // Check if this is a complete token (not part of a larger number/identifier)
            let before_ok = i == 0 || is_token_boundary(chars[i - 1]);
            let after_ok = i + search_chars.len() >= chars.len()
                || is_token_boundary(chars[i + search_chars.len()]);

            if before_ok && after_ok {
                result.push_str(replace);
                i += search_chars.len();
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Check if a character is a token boundary for operand replacement
fn is_token_boundary(c: char) -> bool {
    matches!(c, ' ' | ',' | '(' | ')' | '\t')
}

/// A single relocation entry defining a region that executes at a different address
#[derive(Debug, Clone, Deserialize)]
pub struct RelocationEntry {
    /// Section name this relocation applies to
    pub section: String,
    /// Start offset within the section (ROM storage location)
    pub rom_start: String,
    /// End offset within the section (ROM storage location, exclusive)
    pub rom_end: String,
    /// Virtual memory address where this code executes
    pub vma: String,
    /// Name for the ELF section (e.g., "text_ram")
    pub elf_section: String,
}

/// Parsed relocation with addresses converted to u32
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Section name this relocation applies to
    pub section: String,
    /// Start address in ROM
    pub rom_start: u32,
    /// End address in ROM (exclusive)
    pub rom_end: u32,
    /// Virtual memory address where code executes
    pub vma: u32,
    /// Name for the ELF section
    pub elf_section: String,
}

impl Relocation {
    /// Check if a ROM address falls within this relocation's range
    pub fn contains_rom_addr(&self, addr: u32) -> bool {
        addr >= self.rom_start && addr < self.rom_end
    }

    /// Convert a ROM address to the corresponding VMA
    pub fn rom_to_vma(&self, rom_addr: u32) -> Option<u32> {
        if self.contains_rom_addr(rom_addr) {
            Some(self.vma + (rom_addr - self.rom_start))
        } else {
            None
        }
    }

    /// Convert a VMA to the corresponding ROM address
    pub fn vma_to_rom(&self, vma_addr: u32) -> Option<u32> {
        if vma_addr >= self.vma && vma_addr < self.vma_end() {
            Some(self.rom_start + (vma_addr - self.vma))
        } else {
            None
        }
    }

    /// Get the length of this relocated region
    pub fn length(&self) -> u32 {
        self.rom_end - self.rom_start
    }

    /// Get the end of the VMA range (exclusive)
    pub fn vma_end(&self) -> u32 {
        self.vma + self.length()
    }
}

/// Relocations for code that executes at different addresses than where it's stored
#[derive(Debug, Default)]
pub struct Relocations(Vec<Relocation>);

impl Relocations {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let entries: Vec<RelocationEntry> = load_json_file(path, "relocations")?;

        let relocations = entries
            .into_iter()
            .filter_map(|entry| {
                let rom_start = parse_hex_addr(&entry.rom_start)?;
                let rom_end = parse_hex_addr(&entry.rom_end)?;
                let vma = parse_hex_addr(&entry.vma)?;
                Some(Relocation {
                    section: entry.section,
                    rom_start,
                    rom_end,
                    vma,
                    elf_section: entry.elf_section,
                })
            })
            .collect();

        Ok(Relocations(relocations))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get all relocations for a specific section
    pub fn for_section(&self, section_name: &str) -> Vec<&Relocation> {
        self.0
            .iter()
            .filter(|r| r.section == section_name)
            .collect()
    }

    /// Find a relocation that contains the given ROM address for a section
    pub fn find_by_rom_addr(&self, section_name: &str, rom_addr: u32) -> Option<&Relocation> {
        self.0
            .iter()
            .find(|r| r.section == section_name && r.contains_rom_addr(rom_addr))
    }

    /// Find a relocation that contains the given VMA for a section
    pub fn find_by_vma(&self, section_name: &str, vma: u32) -> Option<&Relocation> {
        self.0
            .iter()
            .find(|r| r.section == section_name && vma >= r.vma && vma < r.vma_end())
    }
}

/// All annotations bundled together for convenience
pub struct Annotations {
    pub labels: Labels,
    pub comments: Comments,
    pub funcs: Functions,
    pub operands: Operands,
    pub relocations: Relocations,
    pub bss_names: BssNames,
}

impl Annotations {
    /// Load all annotations from a directory containing labels.json, comments.json,
    /// functions.json, operands.json, and optionally relocations.json.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let labels = Labels::load_from_file(&dir.join("labels.json"))?;
        let comments = Comments::load_from_file(&dir.join("comments.json"))?;
        let funcs = Functions::load_from_file(&dir.join("functions.json"))?;
        let operands = Operands::load_from_file(&dir.join("operands.json"))?;

        // Relocations are optional - use empty if file doesn't exist
        let relocations_path = dir.join("relocations.json");
        let relocations = if relocations_path.exists() {
            Relocations::load_from_file(&relocations_path)?
        } else {
            Relocations::default()
        };

        // BSS names are optional - use empty if file doesn't exist
        let bss_names_path = dir.join("bss.json");
        let bss_names = if bss_names_path.exists() {
            BssNames::load_from_file(&bss_names_path)?
        } else {
            BssNames::default()
        };

        Ok(Annotations {
            labels,
            comments,
            funcs,
            operands,
            relocations,
            bss_names,
        })
    }

    /// Print loading statistics
    pub fn print_stats(&self, dir: &Path) {
        println!(
            "Loaded {} labels from {:?}",
            self.labels.len(),
            dir.join("labels.json")
        );
        println!(
            "Loaded {} comments from {:?}",
            self.comments.len(),
            dir.join("comments.json")
        );
        println!(
            "Loaded {} functions from {:?}",
            self.funcs.len(),
            dir.join("functions.json")
        );
        println!(
            "Loaded {} operands from {:?}",
            self.operands.len(),
            dir.join("operands.json")
        );
        if !self.relocations.is_empty() {
            println!(
                "Loaded {} relocations from {:?}",
                self.relocations.len(),
                dir.join("relocations.json")
            );
        }
        if !self.bss_names.is_empty() {
            println!(
                "Loaded {} BSS names from {:?}",
                self.bss_names.len(),
                dir.join("bss.json")
            );
        }
    }

    /// Verify that all annotations have been used.
    /// Returns true if all annotations were consumed, false otherwise.
    /// Prints warnings for any unused annotations.
    pub fn verify_all_used(&self) -> bool {
        let mut all_used = true;

        if !self.comments.is_empty() {
            eprintln!("\nWarning: {} unused comments:", self.comments.len());
            for addr in self.comments.keys() {
                eprintln!("  {:#010x}: {:?}", addr, self.comments.get(addr));
            }
            all_used = false;
        }

        if !self.funcs.is_empty() {
            eprintln!(
                "\nWarning: {} unused function descriptions:",
                self.funcs.len()
            );
            for addr in self.funcs.keys() {
                eprintln!("  {:#010x}: {:?}", addr, self.funcs.get(addr));
            }
            all_used = false;
        }

        if !self.operands.is_empty() {
            eprintln!(
                "\nWarning: {} unused operand replacements:",
                self.operands.len()
            );
            for addr in self.operands.keys() {
                eprintln!("  {:#010x}", addr);
            }
            all_used = false;
        }

        all_used
    }
}
