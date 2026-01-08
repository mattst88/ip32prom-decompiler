// SPDX-License-Identifier: GPL-3.0-or-later
//! MIPS-specific utilities for instruction analysis and register handling.

use anyhow::{Context, Result};
use capstone::prelude::*;

pub mod format;
pub mod insn;
pub mod regs;

pub use format::{format_instruction_for_gas, label_for_addr, replace_magic_constants};
pub use insn::*;
pub use regs::*;

/// MIPS BEV=1 exception vector offsets (relative to ROM_START).
/// These are the entry points when Status.BEV=1 (boot exception vectors).
/// Reference: MIPS64 Architecture For Programmers Volume III, Chapter 6.
pub const EXCEPTION_UNCACHED: usize = 0x100;
pub const EXCEPTION_TLB_REFILL: usize = 0x200;
pub const EXCEPTION_XTLB_REFILL: usize = 0x280;
pub const EXCEPTION_CACHE_ERROR: usize = 0x300;
pub const EXCEPTION_GENERAL: usize = 0x380;

/// Create a Capstone instance configured for MIPS III big-endian disassembly.
///
/// We use `arch::mips::ArchMode::Mips64` because:
/// 1. MIPS III is 64-bit
/// 2. Capstone's CS_MODE_MIPS3 is an ISA extension flag meant to be OR'd with
///    a base mode (MIPS32 or MIPS64), but capstone-rs doesn't expose it as an
///    extra_mode - only as a primary mode where it fails to decode anything
/// 3. Mips64 mode correctly decodes all MIPS III instructions
pub fn create_capstone() -> Result<Capstone> {
    Capstone::new()
        .mips()
        .mode(arch::mips::ArchMode::Mips64)
        .endian(capstone::Endian::Big)
        .detail(true)
        .build()
        .context("Failed to initialize Capstone")
}
