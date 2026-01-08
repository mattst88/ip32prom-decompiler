// SPDX-License-Identifier: GPL-3.0-or-later
//! Instruction formatting for gas output.
//!
//! This module handles converting Capstone disassembly output to GNU assembler (gas)
//! compatible syntax, including CP0 register names, address construction macros,
//! branch target labels, and cache operation formatting.

use capstone::arch::mips::MipsInsn;
use capstone::prelude::*;

use super::insn::{
    get_branch_target, has_immediate_target, insn_in, insn_is, is_absolute_jump, is_load_or_store,
};
use super::regs::{CP0_REG_NAMES, CP1_CTRL_REG_NAMES, gpr_name_to_number};
use crate::annotations::{BssNames, Labels, make_label, strip_hex_prefix};
use crate::hardware::{
    SystemConstants,
    memmap::{BASE_RTC, BYTE_OFFSET, KSEG1},
};
use crate::section::{Section, Signedness};

/// RTC NVRAM base register number (registers 0x0e and above are NVRAM)
const RTC_NVRAM_BASE: i32 = 0x0e;

/// MIPS R-type FUNCT field value for ADDU instruction
const FUNCT_ADDU: u8 = 0x21;

/// MIPS cache instruction field masks
pub const CACHE_TYPE_MASK: u8 = 0x03; // Bits 0-1: cache type (I-cache, D-cache, etc.)
pub const CACHE_OP_MASK: u8 = 0x1c; // Bits 2-4: cache operation

/// Split an operand string into individual comma-separated operands, trimming whitespace.
fn split_operands(op_str: &str) -> Vec<&str> {
    op_str.split(',').map(|s| s.trim()).collect()
}

/// CP0 register transfer instructions
const CP0_INSNS: [MipsInsn; 4] = [
    MipsInsn::MIPS_INS_MTC0,
    MipsInsn::MIPS_INS_MFC0,
    MipsInsn::MIPS_INS_DMTC0,
    MipsInsn::MIPS_INS_DMFC0,
];

/// CP1 control register transfer instructions
const CP1_CTRL_INSNS: [MipsInsn; 2] = [MipsInsn::MIPS_INS_CTC1, MipsInsn::MIPS_INS_CFC1];

/// Cache type names indexed by cache_type field (bits 0-1)
pub const CACHE_TYPE_NAMES: [&str; 4] = [
    "CACHE_TYPE_L1I",
    "CACHE_TYPE_L1D",
    "CACHE_TYPE_L3",
    "CACHE_TYPE_L2",
];

/// Cache operation names indexed by operation field (bits 2-4)
pub const CACHE_OP_NAMES: [&str; 8] = [
    "INDEX_WRITEBACK_INV",
    "INDEX_LOAD_TAG",
    "INDEX_STORE_TAG",
    "CREATE_DIRTY_EXCLUSIVE",
    "HIT_INVALIDATE",
    "HIT_WRITEBACK_INV",
    "HIT_WRITEBACK",
    "HIT_SET_VIRTUAL",
];

/// Generate a label name for an address
/// Uses F_ prefix if the offset is a function start, otherwise L_
pub fn label_for_addr(addr: u32, section: &Section, offset: usize, labels: &Labels) -> String {
    // Check if we have a named label for this address
    if let Some(name) = labels.get(addr) {
        return name.to_string();
    }

    // Generate default label based on whether it's a function start
    if section.control_flow.function_starts.contains(&offset) {
        make_label("F_", addr)
    } else {
        make_label("L_", addr)
    }
}

/// Resolve a label for an address within the section.
/// Checks named labels first, then branch targets (with VMA equality check for relocations).
/// Returns None if the address is not in the section or has no label/branch target.
fn resolve_label_for_addr(addr: u32, section: &Section, labels: &Labels) -> Option<String> {
    let offset = section.addr_to_offset(addr)?;
    // Named label at this address
    if let Some(label) = labels.get(addr) {
        return Some(label.to_string());
    }
    // Branch target (only if addr matches the canonical VMA for this offset,
    // to avoid using labels for LMA/ROM addresses that map via relocation)
    let vma_addr = section.offset_to_addr(offset);
    if section.control_flow.branch_targets.contains(&offset) && addr == vma_addr {
        return Some(label_for_addr(addr, section, offset, labels));
    }
    None
}

/// Check if "move" pseudo-instruction uses non-canonical addu encoding.
/// The "move" can be encoded as either "addu $rd, $rs, $zero" or "or $rd, $rs, $zero".
/// The assembler chooses "or", but the original firmware may use "addu".
/// Returns Some(formatted) if we need to emit "addu" instead of "move".
///
/// Note: We must check raw bits because Capstone reports both encodings as MIPS_INS_MOVE.
fn format_move_pseudo(insn: &capstone::Insn, op_str: &str) -> Option<String> {
    if !insn_is(insn, MipsInsn::MIPS_INS_MOVE) {
        return None;
    }

    let bytes = insn.bytes();
    if bytes.len() == 4 {
        // Big-endian: function field is in the last byte, bits 0-5
        let funct = bytes[3] & 0x3f;
        if funct == FUNCT_ADDU {
            // Non-canonical encoding (addu): emit "addu $rd, $rs, $zero"
            return Some(format!("addu\t{}, $zero", op_str));
        }
    }
    // Canonical encoding (or): the assembler will emit "or" for "move"
    None
}

/// Check if instruction is an "li" pseudo-instruction pattern.
/// "li" can be encoded as:
/// - addiu $rd, $zero, imm (signed 16-bit)
/// - ori $rd, $zero, imm (unsigned 16-bit)
///
/// Returns Some(formatted) if we should emit "li" instead.
fn format_li_pseudo(
    insn: &capstone::Insn,
    op_str: &str,
    section: &Section,
    offset: usize,
) -> Option<String> {
    let is_addiu_or_ori =
        insn_is(insn, MipsInsn::MIPS_INS_ADDIU) || insn_is(insn, MipsInsn::MIPS_INS_ORI);
    if !is_addiu_or_ori || section.discovery.constructed_addrs.contains_key(&offset) {
        return None;
    }

    let parts = split_operands(op_str);
    if parts.len() >= 3 && (parts[1] == "$zero" || parts[1] == "$0") {
        return Some(format!("li\t{}, {}", parts[0], parts[2]));
    }
    None
}

/// Parse load/store operand to extract data register and base register.
/// Input format: "data_reg, offset(base_reg)" or "data_reg, (base_reg)"
/// Returns Some((data_reg, base_reg)) if successfully parsed.
fn parse_mem_operand(op_str: &str) -> Option<(&str, &str)> {
    if !op_str.contains('(') {
        return None;
    }
    let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return None;
    }
    let mem_part = parts[1].trim();
    let base_start = mem_part.find('(')?;
    Some((parts[0], &mem_part[base_start..]))
}

/// Format an address macro (HI/LO or BSS_HI/BSS_LO) with the appropriate value.
/// is_hi: true for HI macro, false for LO macro
/// is_bss: true if address is in BSS range
/// bss_offset: offset from BSS_BASE (only used if is_bss)
/// full_addr: the full constructed address
/// suffix: "" for signed displacement (default), "_UNSIGNED" for unsigned
fn format_addr_macro(
    is_hi: bool,
    is_bss: bool,
    bss_offset: u32,
    full_addr: u32,
    suffix: &str,
    bss_names: &BssNames,
) -> String {
    let hilo = if is_hi { "HI" } else { "LO" };
    if is_bss {
        if let Some(name) = bss_names.get(bss_offset) {
            format!("BSS_{}({})", hilo, name)
        } else {
            format!("BSS_{}({:#x})", hilo, bss_offset)
        }
    } else {
        format!("{}{}({:#010x})", hilo, suffix, full_addr)
    }
}

/// Try to format an instruction with HI/LO address parts.
/// Returns Some(formatted) if the instruction matches one of the address construction patterns.
fn try_format_with_hilo(
    insn: &capstone::Insn,
    mnemonic: &str,
    op_str: &str,
    hi_part: &str,
    lo_part: &str,
) -> Option<String> {
    let is_addiu_or_ori =
        insn_is(insn, MipsInsn::MIPS_INS_ADDIU) || insn_is(insn, MipsInsn::MIPS_INS_ORI);

    // LUI: emit hi_part
    if insn_is(insn, MipsInsn::MIPS_INS_LUI) {
        let comma_idx = op_str.find(',')?;
        let reg_part = &op_str[..comma_idx];
        return Some(format!("{}\t{}, {}", mnemonic, reg_part, hi_part));
    }

    // ADDIU/ORI: emit lo_part
    if is_addiu_or_ori {
        let parts = split_operands(op_str);
        if parts.len() >= 3 {
            return Some(format!(
                "{}\t{}, {}, {}",
                mnemonic, parts[0], parts[1], lo_part
            ));
        }
    }

    // Load/Store: emit lo_part in displacement
    if is_load_or_store(insn) {
        let (data_reg, base_reg) = parse_mem_operand(op_str)?;
        return Some(format!(
            "{}\t{}, {}{}",
            mnemonic, data_reg, lo_part, base_reg
        ));
    }

    None
}

/// Resolve HI and LO macro parts for an address.
/// Returns (hi_part, lo_part) formatted for the address, using either:
/// - %hi/%lo with labels for addresses within the section (both named labels and F_/L_ labels)
/// - BSS_HI/BSS_LO for addresses in BSS range
/// - HI/LO or HI_UNSIGNED/LO_UNSIGNED macros for other addresses
fn resolve_addr_macros(
    full_addr: u32,
    signedness: Signedness,
    section: &Section,
    labels: &Labels,
    bss_names: &BssNames,
) -> (String, String) {
    // Try to get a label for this address - either from named labels or branch targets
    if let Some(label) = resolve_label_for_addr(full_addr, section, labels) {
        return (format!("%hi({})", label), format!("%lo({})", label));
    }

    let suffix = signedness.macro_suffix();

    // Check if address is in BSS range (after rwdata and still in KSEG0)
    // BSS addresses use signed displacement and fall between bss_start and KSEG1
    let (is_bss, bss_offset) = match section.bss_start() {
        Some(bs) if signedness == Signedness::Signed && full_addr >= bs && full_addr < KSEG1 => {
            (true, full_addr - bs)
        }
        _ => (false, 0),
    };

    (
        format_addr_macro(true, is_bss, bss_offset, full_addr, suffix, bss_names),
        format_addr_macro(false, is_bss, bss_offset, full_addr, suffix, bss_names),
    )
}

/// Format HI/LO macros for constructed address patterns.
/// Handles both %hi/%lo with labels for in-section addresses and HI/LO macros for external addresses.
/// Returns Some(formatted) if the instruction is part of an address construction pattern.
fn format_hilo_macros(
    insn: &capstone::Insn,
    mnemonic: &str,
    op_str: &str,
    section: &Section,
    offset: usize,
    labels: &Labels,
    bss_names: &BssNames,
) -> Option<String> {
    let addr_info = section.discovery.constructed_addrs.get(&offset)?;
    let full_addr = addr_info.address();
    let (hi_part, lo_part) =
        resolve_addr_macros(full_addr, addr_info.signedness, section, labels, bss_names);
    try_format_with_hilo(insn, mnemonic, op_str, &hi_part, &lo_part)
}

/// Format load/store instructions that use a known base address plus displacement.
/// This handles the pattern: lui + addiu + load/store where the load/store has a non-zero offset.
/// Returns Some(formatted) if the instruction matches this pattern.
fn format_known_addr_access(
    insn: &capstone::Insn,
    mnemonic: &str,
    op_str: &str,
    section: &Section,
    offset: usize,
    sys_consts: &SystemConstants,
) -> Option<String> {
    if !is_load_or_store(insn) {
        return None;
    }

    let &(base_addr, disp) = section.discovery.known_addr_accesses.get(&offset)?;

    // Try to find a symbolic name for the displacement relative to the base address
    let disp_name = sys_consts.lookup_register(base_addr, disp as i32)?;

    let (data_reg, base_reg) = parse_mem_operand(op_str)?;
    Some(format!(
        "{}\t{}, {}{}",
        mnemonic, data_reg, disp_name, base_reg
    ))
}

/// Format branch/jump instructions by replacing address with label.
/// Returns:
/// - `Some(Some(formatted))` - instruction formatted successfully
/// - `Some(None)` - instruction should fall back to .word output
/// - `None` - not a branch instruction, continue with other processing
fn format_branch_target(
    cs: &Capstone,
    insn: &capstone::Insn,
    mnemonic: &str,
    op_str: &str,
    section: &Section,
    labels: &Labels,
) -> Option<Option<String>> {
    if !has_immediate_target(insn) {
        return None;
    }

    let target = get_branch_target(cs, insn)?;

    // Check if target is within this section and has a label
    if let Some(label) = resolve_label_for_addr(target, section, labels) {
        // Handle beqzl/bnezl pseudo-instructions:
        // beql $rs, $zero, target -> beqzl $rs, target
        // bnel $rs, $zero, target -> bnezl $rs, target
        let is_beql = insn_is(insn, MipsInsn::MIPS_INS_BEQL);
        let is_bnel = insn_is(insn, MipsInsn::MIPS_INS_BNEL);
        if is_beql || is_bnel {
            let parts = split_operands(op_str);
            if parts.len() >= 3 {
                let (rs, rt) = (parts[0], parts[1]);
                // Check if either operand is $zero
                if rt == "$zero" || rt == "$0" {
                    let pseudo = if is_beql { "beqzl" } else { "bnezl" };
                    return Some(Some(format!("{}\t{}, {}", pseudo, rs, label)));
                } else if rs == "$zero" || rs == "$0" {
                    let pseudo = if is_beql { "beqzl" } else { "bnezl" };
                    return Some(Some(format!("{}\t{}, {}", pseudo, rt, label)));
                }
            }
        }

        // op_str format varies:
        // - "b 0xaddr" -> just the address
        // - "beq $reg, $reg, 0xaddr" -> regs then address
        // The address is always the last operand for these instructions
        let formatted_ops = replace_last_immediate_with_label(op_str, &label);
        if formatted_ops.is_empty() {
            return Some(Some(mnemonic.to_string()));
        } else {
            return Some(Some(format!("{}\t{}", mnemonic, formatted_ops)));
        }
    }

    // For j/jal instructions, emit with absolute address even if target
    // is unknown (e.g., in another section). These use pseudo-absolute
    // addressing and will assemble correctly.
    if is_absolute_jump(insn) {
        return Some(Some(format!("{}\t{}", mnemonic, op_str)));
    }

    // For PC-relative branches to unknown targets, fall back to .word
    // since the branch offset might not be representable
    Some(None)
}

/// Format standalone lui instructions with known base address constants.
/// For lui instructions not part of a constructed address pair, check if the
/// immediate value corresponds to the high 16 bits of a known constant.
fn format_standalone_lui(
    insn: &capstone::Insn,
    op_str: &str,
    section: &Section,
    offset: usize,
    sys_consts: &SystemConstants,
) -> Option<String> {
    // Only handle lui instructions
    if !insn_is(insn, MipsInsn::MIPS_INS_LUI) {
        return None;
    }

    // Skip if this lui is part of a constructed address pattern
    if section.discovery.constructed_addrs.contains_key(&offset) {
        return None;
    }

    // Parse operands: "reg, imm"
    let parts = split_operands(op_str);
    if parts.len() != 2 {
        return None;
    }

    // Parse the immediate value (may be hex or decimal)
    let imm_str = parts[1].trim();
    let imm: u32 = u32::from_str_radix(strip_hex_prefix(imm_str), 16).ok()?;

    // Calculate the full address this lui is loading the high part of
    let full_addr = imm << 16;

    // Look up if this is a known constant
    let const_name = sys_consts.lookup_constant(full_addr)?;

    Some(format!("lui\t{}, HI({})", parts[0], const_name))
}

/// Format an instruction for gas output
/// Handles CP0 register names and other syntax differences between Capstone and gas
pub fn format_instruction_for_gas(
    cs: &Capstone,
    insn: &capstone::Insn,
    section: &Section,
    offset: usize,
    labels: &Labels,
    sys_consts: &SystemConstants,
    bss_names: &BssNames,
) -> Option<String> {
    let mnemonic = insn.mnemonic()?;
    let op_str = insn.op_str().unwrap_or("");

    // Handle "move" pseudo-instruction encoding detection
    if let Some(formatted) = format_move_pseudo(insn, op_str) {
        return Some(formatted);
    }

    // Handle "li" pseudo-instruction detection
    if let Some(formatted) = format_li_pseudo(insn, op_str, section, offset) {
        return Some(formatted);
    }

    // Handle constructed address patterns (HI/LO macros)
    if let Some(formatted) =
        format_hilo_macros(insn, mnemonic, op_str, section, offset, labels, bss_names)
    {
        return Some(formatted);
    }

    // Handle load/store with known base address + displacement
    if let Some(formatted) =
        format_known_addr_access(insn, mnemonic, op_str, section, offset, sys_consts)
    {
        return Some(formatted);
    }

    // Handle standalone lui with known base address constants
    if let Some(formatted) = format_standalone_lui(insn, op_str, section, offset, sys_consts) {
        return Some(formatted);
    }

    // Handle branch/jump instructions with immediate targets
    if let Some(result) = format_branch_target(cs, insn, mnemonic, op_str, section, labels) {
        return result;
    }

    // Format CP0 register operands
    let formatted_ops = format_cp0_registers(insn, op_str);

    // Format CP1 control register operands
    let formatted_ops = format_cp1_ctrl_registers(insn, &formatted_ops);

    // Fix zero displacement - Capstone outputs "($reg)" but gas requires "0($reg)"
    let formatted_ops = fix_zero_displacement(&formatted_ops);

    // Format cache operations with symbolic names
    let formatted_ops = format_cache_op(insn, &formatted_ops);

    if formatted_ops.is_empty() {
        Some(mnemonic.to_string())
    } else {
        Some(format!("{}\t{}", mnemonic, formatted_ops))
    }
}

/// Replace the last immediate operand in an operand string with a label
fn replace_last_immediate_with_label(op_str: &str, label: &str) -> String {
    // Find the last "0x" in the string and replace it and everything after with the label
    if let Some(idx) = op_str.rfind("0x") {
        let prefix = op_str[..idx].trim_end_matches([' ', ',']);
        if prefix.is_empty() {
            label.to_string()
        } else {
            format!("{}, {}", prefix, label)
        }
    } else {
        // No hex immediate found, just append label
        if op_str.is_empty() {
            label.to_string()
        } else {
            format!(
                "{}, {}",
                op_str.trim_end_matches(|c: char| c.is_ascii_hexdigit() || c == 'x'),
                label
            )
        }
    }
}

/// Fix zero displacement for memory operands
/// Capstone outputs "($reg)" but we want "0($reg)"
fn fix_zero_displacement(op_str: &str) -> String {
    // Match patterns like ", ($reg)" or start with "($reg)"
    let mut result = op_str.to_string();

    // Handle ", ($reg)" pattern (e.g., "$v0, ($t0)")
    if let Some(idx) = result.find(", (") {
        // Check if there's no displacement before the paren
        let before = &result[..idx + 2]; // includes ", "
        let after = &result[idx + 2..]; // starts with "("
        if after.starts_with('(') {
            result = format!("{}0{}", before, after);
        }
    }

    result
}

/// Format cache instruction operands with symbolic names
/// Cache operations are encoded as: (operation << 2) | cache_type
/// where cache_type is: L1I=0, L1D=1, L3=2, L2=3
/// and operation is: INDEX_WRITEBACK_INV=0, INDEX_LOAD_TAG=1, INDEX_STORE_TAG=2,
///                   CREATE_DIRTY_EXCLUSIVE=3, HIT_INVALIDATE=4, HIT_WRITEBACK_INV=5,
///                   HIT_WRITEBACK=6, HIT_SET_VIRTUAL=7
fn format_cache_op(insn: &capstone::Insn, op_str: &str) -> String {
    if !insn_is(insn, MipsInsn::MIPS_INS_CACHE) {
        return op_str.to_string();
    }

    // Parse the operand: "op_code, offset(base)"
    let parts: Vec<&str> = op_str.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return op_str.to_string();
    }

    // Parse the operation code (may be decimal or hex)
    let op_code_str = parts[0].trim();
    let op_code: u8 = u8::from_str_radix(strip_hex_prefix(op_code_str), 16).unwrap_or(0);

    let cache_type = (op_code & CACHE_TYPE_MASK) as usize;
    let operation = ((op_code & CACHE_OP_MASK) >> 2) as usize;

    format!(
        "({}|{}), {}",
        CACHE_TYPE_NAMES[cache_type], CACHE_OP_NAMES[operation], parts[1]
    )
}

/// Format CP0 register operands.
///
/// Capstone outputs "$rt, $cp0reg, sel" where $cp0reg is shown as a GPR name
/// (like $s1 for register 17). This function:
/// 1. Converts CP0 register to symbolic name (e.g., $s1 -> $CP0_LLADDR) for readability
/// 2. Removes the `sel` operand (MIPS3 gas doesn't accept it)
fn format_cp0_registers(insn: &capstone::Insn, op_str: &str) -> String {
    if !insn_in(insn, &CP0_INSNS) {
        return op_str.to_string();
    }

    let parts = split_operands(op_str);
    if parts.len() < 2 {
        return op_str.to_string();
    }

    let rt = parts[0];
    let cp0_reg_str = parts[1];

    if let Some(reg_num) = gpr_name_to_number(cp0_reg_str) {
        if reg_num < 32 {
            let cp0_name = CP0_REG_NAMES[reg_num as usize];
            format!("{}, ${}", rt, cp0_name)
        } else {
            op_str.to_string()
        }
    } else {
        op_str.to_string()
    }
}

/// Format CP1 control register operands.
///
/// Capstone outputs "$rt, $fs" where $fs is a FPU register number.
/// This function converts standard control registers to symbolic names
/// (e.g., $31 -> $CP1_FCSR) for cfc1/ctc1 instructions.
fn format_cp1_ctrl_registers(insn: &capstone::Insn, op_str: &str) -> String {
    if !insn_in(insn, &CP1_CTRL_INSNS) {
        return op_str.to_string();
    }

    let parts = split_operands(op_str);
    if parts.len() < 2 {
        return op_str.to_string();
    }

    let rt = parts[0];
    let cp1_reg_str = parts[1];

    // CP1 control register is specified as $N (a number)
    let reg_str = cp1_reg_str.trim_start_matches('$');
    if let Ok(reg_num) = reg_str.parse::<u32>() {
        // Only use symbolic names for known registers (0=FIR, 30=FEIR, 31=FCSR)
        if reg_num == 0 || reg_num == 30 || reg_num == 31 {
            let cp1_name = CP1_CTRL_REG_NAMES[reg_num as usize];
            return format!("{}, ${}", rt, cp1_name);
        }
    }

    op_str.to_string()
}

/// Replace magic constants with symbolic names in formatted instructions
/// Handles both full constants (like BASE_CRIME) and base+offset patterns
/// Uses '|' for unsigned (ori/HI_UNSIGNED/LO_UNSIGNED) and '+' for signed (addiu/HI/LO)
pub fn replace_magic_constants(formatted: &str, sys_consts: &SystemConstants) -> String {
    // Look for hex values in the format 0x12345678 (with optional leading -)
    // These appear in HI/LO macros and immediate operands
    let mut result = String::new();
    let input: Vec<char> = formatted.chars().collect();
    let mut i = 0;

    while i < input.len() {
        // Check for potential hex number (0x prefix)
        if i + 1 < input.len() && input[i] == '0' && input[i + 1] == 'x' {
            // Skip hex values that are part of label names (preceded by '_')
            // This prevents turning "data_0xbfc00000" into "data_ROM_START"
            let is_label_part = result.ends_with('_');

            i += 2; // skip "0x"

            // Collect hex digits
            let mut hex_str = String::new();
            while i < input.len() && input[i].is_ascii_hexdigit() {
                hex_str.push(input[i]);
                i += 1;
            }

            if !hex_str.is_empty()
                && !is_label_part
                && let Ok(value) = u32::from_str_radix(&hex_str, 16)
            {
                // Determine the operator based on context
                // Look backwards to see if we're in HI_UNSIGNED/LO_UNSIGNED (unsigned) or HI/LO (signed)
                let use_or = is_unsigned_context(&result);

                // Try to find a symbolic replacement
                if let Some(replacement) = find_constant_replacement(value, sys_consts, use_or) {
                    result.push_str(&replacement);
                    continue;
                }
            }
            // No replacement found (or is part of a label), keep original
            result.push_str("0x");
            result.push_str(&hex_str);
        } else {
            result.push(input[i]);
            i += 1;
        }
    }

    result
}

/// Check if the current context is unsigned (HI_UNSIGNED/LO_UNSIGNED)
/// by looking at what precedes the hex value in the result string
fn is_unsigned_context(preceding: &str) -> bool {
    // Look for HI_UNSIGNED( or LO_UNSIGNED( at the end of preceding text
    preceding.ends_with("HI_UNSIGNED(") || preceding.ends_with("LO_UNSIGNED(")
}

/// Find a symbolic replacement for a constant value
/// Returns the symbolic name or base+offset expression if found
/// use_or: if true, use '|' operator; if false, use '+' operator
fn find_constant_replacement(
    value: u32,
    sys_consts: &SystemConstants,
    use_or: bool,
) -> Option<String> {
    // Try to decompose into base + offset for device registers first
    // This takes priority over raw constants so we get "BASE_ISA + ISA_RING_BASE_AND_RESET"
    // instead of just "BASE_ISA" when offset 0 has a register name
    let op = if use_or { "|" } else { "+" };
    for base_addr in sys_consts.device_base_addrs() {
        if value >= base_addr {
            let offset = (value - base_addr) as i32;
            // Only consider reasonable offsets (positive and not too large)
            if (0..0x10000).contains(&offset) {
                // Try exact match in register table
                if let Some(reg_name) = sys_consts.lookup_register(base_addr, offset) {
                    // Get the base name
                    if let Some(base_name) = sys_consts.lookup_constant(base_addr) {
                        return Some(format!("{} {} {}", base_name, op, reg_name));
                    }
                }

                // For BASE_RTC, try to decompose as RTC_NVRAM(x) + optional BYTE_OFFSET
                // RTC_NVRAM(x) = RTC_REG(0x0e + x) = ((0x0e + x) << 8)
                if base_addr == BASE_RTC
                    && let Some(nvram_expr) = try_rtc_nvram_decomposition(offset, op)
                {
                    return Some(format!("BASE_RTC {} {}", op, nvram_expr));
                }
            }
        }
    }

    // Fall back to direct constant match if no device register match
    if let Some(name) = sys_consts.lookup_constant(value) {
        return Some(name.to_string());
    }

    None
}

/// Try to decompose an RTC offset as RTC_NVRAM(x) + optional BYTE_OFFSET
/// Returns the expression string if successful (e.g., "RTC_NVRAM(0x2a) + BYTE_OFFSET")
fn try_rtc_nvram_decomposition(offset: i32, op: &str) -> Option<String> {
    // RTC_REG(x) = x << 8, so reg_num = offset >> 8
    let reg_num = offset >> 8;
    let byte_part = offset & 0xff;

    // NVRAM starts at register 0x0e (RTC_NVRAM_BASE)
    // Valid NVRAM range is roughly 0x0e to 0x4b (before special registers at 0x47+)
    if (RTC_NVRAM_BASE..0x47).contains(&reg_num) {
        let nvram_idx = reg_num - RTC_NVRAM_BASE;

        // Check if byte_part is BYTE_OFFSET (7) or 0
        if byte_part == BYTE_OFFSET {
            return Some(format!("RTC_NVRAM({:#04x}) {} BYTE_OFFSET", nvram_idx, op));
        } else if byte_part == 0 {
            return Some(format!("RTC_NVRAM({:#04x})", nvram_idx));
        }
        // Other byte_part values don't match the pattern
    }

    None
}
