// SPDX-License-Identifier: GPL-3.0-or-later
//! Data types and supporting structures for section representation.

use std::collections::{HashMap, HashSet};

use crate::shdr::SUBSECTION_HEADER_SIZE;

/// Classification of data at a given offset
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Header,
    Code,
    Data,
    String,
    PadZero,
    PadOnes,
    Unknown,
}

impl DataType {
    /// Returns true if this is a padding type (PadZero or PadOnes).
    pub fn is_padding(self) -> bool {
        matches!(self, DataType::PadZero | DataType::PadOnes)
    }

    /// Returns true if this is unclassified data (Unknown or PadZero).
    /// Used to identify gaps that might contain unreachable code.
    pub fn is_unclassified(self) -> bool {
        matches!(self, DataType::Unknown | DataType::PadZero)
    }

    /// Returns true if this is a data-like type that should be emitted as data
    /// (Data, Unknown, PadZero, or PadOnes).
    pub fn is_data_like(self) -> bool {
        matches!(
            self,
            DataType::Data | DataType::Unknown | DataType::PadZero | DataType::PadOnes
        )
    }

    /// Returns the single-character identifier for this data type in XPM images.
    /// XPM (X PixMap) is used for visualizing the section layout.
    pub fn to_xpm_char(self) -> char {
        match self {
            DataType::Header => 'h',
            DataType::Code => 'c',
            DataType::Data => 'd',
            DataType::String => 's',
            DataType::PadZero => '0',
            DataType::PadOnes => '1',
            DataType::Unknown => 'u',
        }
    }

    /// Returns the hex color code for this data type in XPM visualization.
    pub fn xpm_color(self) -> &'static str {
        match self {
            DataType::Header => "#1e90ff",  // Blue
            DataType::Code => "#dc143c",    // Red
            DataType::Data => "#ffff00",    // Yellow
            DataType::String => "#00ff00",  // Green
            DataType::PadZero => "#000000", // Black
            DataType::PadOnes => "#ffffff", // White
            DataType::Unknown => "#808080", // Gray
        }
    }
}

/// Signedness for the low 16 bits of a constructed address
/// - Unsigned: for ORI instruction (bitwise OR, zero-extended)
/// - Signed: for ADDIU and load/store instructions (sign-extended)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signedness {
    Unsigned,
    Signed,
}

impl Signedness {
    /// Returns the macro suffix for HI/LO macros.
    /// Signed uses no suffix (default), unsigned uses "_UNSIGNED" suffix.
    pub fn macro_suffix(self) -> &'static str {
        match self {
            Signedness::Signed => "",
            Signedness::Unsigned => "_UNSIGNED",
        }
    }
}

/// Represents a fully constructed 32-bit address from lui + addiu/ori/load/store pattern
#[derive(Debug, Clone, Copy)]
pub struct ConstructedAddr {
    /// Upper 16 bits (from lui instruction)
    pub hi_bits: u32,
    /// Lower 16 bits (from addiu/ori/displacement)
    pub lo_bits: i32,
    /// Whether the low bits are sign-extended or zero-extended
    pub signedness: Signedness,
    /// Whether this address is used for a memory access (load/store)
    pub is_memory_access: bool,
    /// Size of the memory access in bytes (1, 2, 4, or 8)
    pub access_size: u8,
}

impl ConstructedAddr {
    pub fn new(hi_bits: u32, lo_bits: i32, signedness: Signedness) -> Self {
        Self {
            hi_bits,
            lo_bits,
            signedness,
            is_memory_access: false,
            access_size: 4,
        }
    }

    pub fn new_memory_access(
        hi_bits: u32,
        lo_bits: i32,
        signedness: Signedness,
        access_size: u8,
    ) -> Self {
        Self {
            hi_bits,
            lo_bits,
            signedness,
            is_memory_access: true,
            access_size,
        }
    }

    /// Create a ConstructedAddr from a full 32-bit address.
    /// Decomposes the address into hi/lo bits based on the signedness.
    pub fn new_from_full_addr(full_addr: u32, signedness: Signedness) -> Self {
        let hi_bits = (full_addr >> 16) & 0xffff;
        let lo_bits = (full_addr & 0xffff) as i16 as i32;
        // For signed addresses, if lo_bits is negative, we need to adjust hi_bits
        // so that (hi_bits << 16) + lo_bits = full_addr
        let adjusted_hi = if signedness == Signedness::Signed && lo_bits < 0 {
            hi_bits + 1
        } else {
            hi_bits
        };
        Self {
            hi_bits: adjusted_hi,
            lo_bits,
            signedness,
            is_memory_access: true,
            access_size: 4,
        }
    }

    /// Compute the full 32-bit address
    pub fn address(&self) -> u32 {
        match self.signedness {
            Signedness::Unsigned => (self.hi_bits << 16) | (self.lo_bits as u32 & 0xffff),
            Signedness::Signed => ((self.hi_bits << 16) as i32 + self.lo_bits) as u32,
        }
    }
}

/// Trait for register state entries that can be tracked across 32 registers.
pub trait RegStateEntry: Default + Clone + Copy {
    /// Mark this entry as invalid/unset.
    fn invalidate(&mut self);
}

/// Generic register state tracker for all 32 MIPS registers.
/// Provides common operations for get, clear, and copy_from.
#[derive(Debug, Clone, Default)]
pub struct RegisterState<T: RegStateEntry> {
    regs: [T; 32],
}

impl<T: RegStateEntry> RegisterState<T> {
    /// Returns a reference to the state for the given register number.
    /// Register numbers are clamped to 0-31.
    pub fn get(&self, reg: usize) -> &T {
        &self.regs[reg.min(31)]
    }

    /// Invalidates the state for the given register, marking it as unset.
    pub fn clear(&mut self, reg: usize) {
        if reg < 32 {
            self.regs[reg].invalidate();
        }
    }

    /// Copies the state from one register to another.
    /// Protects `$zero` (register 0) from modification.
    pub fn copy_from(&mut self, src_reg: usize, dst_reg: usize) {
        if dst_reg < 32 && dst_reg != 0 && src_reg < 32 {
            self.regs[dst_reg] = self.regs[src_reg];
        }
    }

    /// Set a register's state directly. Protects $zero from modification.
    pub fn set_entry(&mut self, reg: usize, entry: T) {
        if reg < 32 && reg != 0 {
            self.regs[reg] = entry;
        }
    }
}

/// Tracks lui state for a single register
#[derive(Debug, Clone, Copy, Default)]
pub struct LuiState {
    /// Offset of the lui instruction that set this register
    pub lui_offset: usize,
    /// Upper 16 bits from the lui immediate
    pub bits: u32,
    /// Whether this register has valid lui state
    pub is_set: bool,
}

impl LuiState {
    /// Returns `Some(self)` if this state is valid, `None` otherwise.
    pub fn as_option(&self) -> Option<&Self> {
        if self.is_set { Some(self) } else { None }
    }
}

impl RegStateEntry for LuiState {
    fn invalidate(&mut self) {
        self.is_set = false;
    }
}

/// Tracks lui state for all 32 MIPS registers
pub type RegisterLuiState = RegisterState<LuiState>;

impl RegisterLuiState {
    pub fn set(&mut self, reg: usize, lui_offset: usize, bits: u32) {
        self.set_entry(
            reg,
            LuiState {
                lui_offset,
                bits,
                is_set: true,
            },
        );
    }
}

/// Tracks known constructed addresses in a single register
#[derive(Debug, Clone, Copy, Default)]
pub struct KnownAddrState {
    /// The full constructed address in this register
    pub address: u32,
    /// Offset of the lui instruction that started the construction
    pub lui_offset: usize,
    /// Whether this register has a valid known address
    pub is_set: bool,
}

impl KnownAddrState {
    /// Returns `Some(self)` if this state is valid, `None` otherwise.
    pub fn as_option(&self) -> Option<&Self> {
        if self.is_set { Some(self) } else { None }
    }
}

impl RegStateEntry for KnownAddrState {
    fn invalidate(&mut self) {
        self.is_set = false;
    }
}

/// Tracks known constructed addresses for all 32 MIPS registers.
/// This is used after ADDIU/ORI completes an address construction,
/// so subsequent load/stores with non-zero offsets can still be recognized.
pub type RegisterKnownAddrs = RegisterState<KnownAddrState>;

impl RegisterKnownAddrs {
    pub fn set(&mut self, reg: usize, address: u32, lui_offset: usize) {
        self.set_entry(
            reg,
            KnownAddrState {
                address,
                lui_offset,
                is_set: true,
            },
        );
    }
}

/// A subsection within a loadable section
#[derive(Debug, Clone)]
pub struct Subsection {
    /// Load address where this subsection is relocated at runtime (VMA)
    pub load_addr: u32,
    /// ROM address where this subsection is stored (LMA).
    /// For firmware-defined subsections, this is calculated from section start + offset.
    /// For virtual (relocation-defined) subsections, this comes from the relocation config.
    pub rom_addr: u32,
    /// Offset within the section data where the subsection header starts
    pub header_offset: usize,
    /// Offset within the section data where the code starts (after 8-byte header)
    pub code_offset: usize,
    /// Length of the subsection code (not including the header)
    pub length: usize,
    /// Whether this is the first subsection (index 0), which has special
    /// handling for the header area at load_addr
    pub is_first: bool,
    /// Whether this is a virtual subsection from relocation config (no firmware header)
    pub is_virtual: bool,
    /// ELF section name for virtual subsections (e.g., "text_ram")
    pub elf_section: Option<String>,
}

impl Subsection {
    /// Check if an address is within this subsection's mapped range (VMA space).
    pub fn contains_addr(&self, addr: u32) -> bool {
        if self.is_first {
            // First subsection: header area OR code area
            let in_header =
                addr >= self.load_addr && addr < self.load_addr + SUBSECTION_HEADER_SIZE as u32;
            let code_load_addr = self.load_addr + self.code_offset as u32;
            let in_code = addr >= code_load_addr && addr < code_load_addr + self.length as u32;
            in_header || in_code
        } else {
            // Virtual and non-first subsections: simple range check
            addr >= self.load_addr && addr < self.load_addr + self.length as u32
        }
    }

    /// Convert an address (VMA) to an offset within the section data, if the address
    /// is within this subsection's mapped range.
    pub fn addr_to_offset(&self, addr: u32) -> Option<usize> {
        if !self.contains_addr(addr) {
            return None;
        }
        if self.is_first {
            // First subsection uses direct mapping: offset = addr - load_addr
            Some((addr - self.load_addr) as usize)
        } else {
            // Other subsections: offset = code_offset + (addr - load_addr)
            Some(self.code_offset + (addr - self.load_addr) as usize)
        }
    }

    /// Convert a section data offset to an address (VMA), if the offset is within
    /// this subsection's range.
    pub fn offset_to_addr(&self, offset: usize) -> Option<u32> {
        let in_range = if self.is_first {
            offset < SUBSECTION_HEADER_SIZE
                || (offset >= self.code_offset && offset < self.code_offset + self.length)
        } else {
            offset >= self.code_offset && offset < self.code_offset + self.length
        };
        if !in_range {
            return None;
        }
        if self.is_first {
            // First subsection uses direct mapping: addr = load_addr + offset
            Some(self.load_addr + offset as u32)
        } else {
            // Other subsections: addr = load_addr + (offset - code_offset)
            Some(self.load_addr + (offset - self.code_offset) as u32)
        }
    }

    /// Check if an offset falls within this subsection's code region
    pub fn contains_offset(&self, offset: usize) -> bool {
        offset >= self.code_offset && offset < self.code_offset + self.length
    }
}

/// A detected string in the binary
#[derive(Debug, Clone)]
pub struct DetectedString {
    /// Length of the string including NUL terminator (but not padding)
    pub length: usize,
    /// The escaped string content (ready for assembly output)
    pub escaped: String,
}

/// Control flow information discovered during code analysis.
/// Groups together branch targets, function boundaries, and unreachable code markers.
#[derive(Debug, Clone, Default)]
pub struct ControlFlowInfo {
    /// Offsets that are targets of branch/jump instructions (need labels)
    pub branch_targets: HashSet<usize>,
    /// Offsets that contain branch/jump instructions (for CFG construction)
    pub branch_offsets: HashSet<usize>,
    /// Offsets that are targets of function call instructions (jal, bal, etc.)
    /// These get F_ prefix labels instead of L_ prefix
    pub function_starts: HashSet<usize>,
    /// Offsets immediately after function returns (jr + delay slot)
    /// Used to calculate function bounds
    pub function_ends: HashSet<usize>,
    /// Offsets of unreachable code (gaps between code blocks that disassemble)
    /// These are emitted as instructions but marked with an "unreachable" comment
    pub unreachable_code: HashSet<usize>,
}

/// Results accumulated during code discovery.
/// Groups constructed addresses, known memory accesses, and indirect jump targets.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryResults {
    /// Maps instruction offsets to constructed addresses (from lui + addiu/ori/load/store patterns)
    /// Used to emit HI/LO macros in the output
    pub constructed_addrs: HashMap<usize, ConstructedAddr>,
    /// Maps instruction offsets to known memory access info (base_addr, displacement).
    /// These are load/store instructions that use a register with a known constructed address
    /// plus a displacement. Unlike constructed_addrs, these don't trigger label generation.
    pub known_addr_accesses: HashMap<usize, (u32, i64)>,
    /// Maps jr instruction offsets to their resolved target offsets.
    /// This captures indirect jumps where the target register has a known address
    /// (e.g., from KSEG1 OR patterns like: lui+addiu+or(KSEG1)+jr)
    pub indirect_jump_targets: HashMap<usize, usize>,
}
