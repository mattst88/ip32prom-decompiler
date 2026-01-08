// SPDX-License-Identifier: GPL-3.0-or-later
//! Code discovery and analysis for firmware sections.
//!
//! This module handles discovering code regions in firmware sections by following
//! control flow, tracking LUI state for address construction patterns, and marking
//! branch targets and function boundaries.

use capstone::arch::mips::{MipsInsn, MipsOperand};
use capstone::prelude::*;
use std::collections::{HashSet, VecDeque};

use super::{
    ConstructedAddr, DiscoveryResults, RegisterKnownAddrs, RegisterLuiState, Section, Signedness,
};
use crate::annotations::Functions;
use crate::hardware::memmap::{
    BYTE_OFFSET, HI_BASE_RTC, HI_BASE_UART_1, HI_BASE_UART_2, HI_KSEG1, LO_BASE_UART_2,
};
use crate::mips::insn::{
    LOAD_INSNS, get_branch_target, insn_in, insn_is, is_branch, is_branch_likely,
    is_call_instruction, is_function_end, is_load_or_store, is_move_insn, is_unconditional_branch,
    load_store_access_size, with_single_insn,
};
use crate::mips::regs::capstone_reg_to_gpr_num;
use crate::mips::{
    EXCEPTION_CACHE_ERROR, EXCEPTION_GENERAL, EXCEPTION_TLB_REFILL, EXCEPTION_UNCACHED,
    EXCEPTION_XTLB_REFILL,
};
use crate::shdr::{SHDR_SIZE, SUBSECTION_HEADER_SIZE};

/// Check if an ADDIU/ORI immediate should preserve lui_state.
/// Lui state is preserved when the immediate is:
/// - 0 (no modification to base address)
/// - BYTE_OFFSET (7) when base is BASE_RTC or BASE_UART_1
/// - LO(BASE_UART_2) when base is BASE_UART_2
fn should_preserve_lui_state(hi_bits: u32, imm: i32) -> bool {
    if imm == 0 {
        return true;
    }
    if imm == BYTE_OFFSET && (hi_bits == HI_BASE_RTC || hi_bits == HI_BASE_UART_1) {
        return true;
    }
    if imm == LO_BASE_UART_2 && hi_bits == HI_BASE_UART_2 {
        return true;
    }
    false
}

/// Handle ADDIU/ORI address construction pattern (lui + addiu/ori).
/// Returns true if the instruction was handled.
fn handle_addr_construction(
    operands: &[MipsOperand],
    offset: usize,
    lui_state: &mut RegisterLuiState,
    known_addrs: &mut RegisterKnownAddrs,
    results: &mut DiscoveryResults,
    signedness: Signedness,
) -> bool {
    if let (MipsOperand::Reg(dst), MipsOperand::Reg(src), MipsOperand::Imm(imm)) =
        (&operands[0], &operands[1], &operands[2])
    {
        let dst_reg = capstone_reg_to_gpr_num(*dst);
        let src_reg = capstone_reg_to_gpr_num(*src);

        if let (Some(dst_num), Some(src_num)) = (dst_reg, src_reg) {
            // Check if source register has valid lui state
            if src_num != 0
                && let Some(lui_info) = lui_state.get(src_num).as_option()
            {
                // Copy values from lui_info before any mutations
                let lui_offset = lui_info.lui_offset;
                let hi_bits = lui_info.bits;
                let imm_val = *imm as i32;
                let addr = ConstructedAddr::new(hi_bits, imm_val, signedness);

                // Only record constructed addresses when dst == src (true address construction).
                // When dst != src, we're computing a derived value that shouldn't be symbolically
                // formatted (e.g., addiu $at, $t9, 0x7fff to compute an intermediate pointer).
                if dst_num == src_num {
                    // Record for the lui instruction only if not already set (don't overwrite
                    // the first addiu's constructed address with subsequent ones)
                    results.constructed_addrs.entry(lui_offset).or_insert(addr);
                    // Always record for this instruction
                    results.constructed_addrs.insert(offset, addr);
                }

                // Preserve lui state in special cases where subsequent load/stores
                // should still be tracked. This allows patterns like:
                //   lui $t8, HI(BASE_RTC)
                //   addiu $t8, $t8, BYTE_OFFSET
                //   sb $t9, 0x3e00($t8)  <- should be tracked as constructed addr
                if !should_preserve_lui_state(hi_bits, imm_val) {
                    // Clear lui state for destination - address construction is complete
                    lui_state.clear(dst_num);
                    // Track known address for potential future load/stores with displacement
                    known_addrs.set(dst_num, addr.address(), lui_offset);
                }
            } else {
                // No valid lui state, clear any existing state for destination
                lui_state.clear(dst_num);
            }
            return true;
        }
    }
    false
}

/// Process an instruction for lui state tracking
/// Updates the lui_state based on the instruction and records any constructed addresses
fn process_insn_for_lui_state(
    cs: &Capstone,
    insn: &capstone::Insn,
    offset: usize,
    lui_state: &mut RegisterLuiState,
    known_addrs: &mut RegisterKnownAddrs,
    results: &mut DiscoveryResults,
) {
    let Ok(detail) = cs.insn_detail(insn) else {
        return;
    };
    let arch_detail = detail.arch_detail();
    let Some(mips_detail) = arch_detail.mips() else {
        return;
    };

    let operands: Vec<_> = mips_detail.operands().collect();

    // LUI: Set lui state for destination register
    if insn_is(insn, MipsInsn::MIPS_INS_LUI)
        && let (MipsOperand::Reg(dst), MipsOperand::Imm(imm)) = (&operands[0], &operands[1])
        && let Some(dst_reg) = capstone_reg_to_gpr_num(*dst)
    {
        lui_state.set(dst_reg, offset, *imm as u32);
        // Clear known address since we're starting a new construction
        known_addrs.clear(dst_reg);
        return;
    }

    // ADDIU: Check for address construction with signed displacement
    if insn_is(insn, MipsInsn::MIPS_INS_ADDIU) {
        handle_addr_construction(
            &operands,
            offset,
            lui_state,
            known_addrs,
            results,
            Signedness::Signed,
        );
        return;
    }

    // ORI: Check for address construction with unsigned displacement
    if insn_is(insn, MipsInsn::MIPS_INS_ORI) {
        handle_addr_construction(
            &operands,
            offset,
            lui_state,
            known_addrs,
            results,
            Signedness::Unsigned,
        );
        return;
    }

    // Load/Store: Check for address construction with signed displacement
    if is_load_or_store(insn) {
        if let MipsOperand::Mem(mem) = &operands[1]
            && let Some(base_reg) = capstone_reg_to_gpr_num(mem.base())
        {
            if base_reg != 0
                && let Some(lui_info) = lui_state.get(base_reg).as_option()
            {
                // Case 1: Base register has pending LUI state (lui + load/store pattern)
                let addr = ConstructedAddr::new_memory_access(
                    lui_info.bits,
                    mem.disp() as i32,
                    Signedness::Signed,
                    load_store_access_size(insn),
                );
                // Record for the lui instruction only if not already set
                results
                    .constructed_addrs
                    .entry(lui_info.lui_offset)
                    .or_insert(addr);
                // Always record for this instruction
                results.constructed_addrs.insert(offset, addr);
            } else if base_reg != 0
                && let Some(known_info) = known_addrs.get(base_reg).as_option()
                && mem.disp() != 0
            {
                // Case 2: Base register has a known constructed address (lui + addiu + load/store)
                // with a non-zero displacement. Record base address and displacement separately
                // so we can look up symbolic names for the displacement.
                // Record in known_addr_accesses for formatting (not constructed_addrs,
                // which would trigger label generation)
                results
                    .known_addr_accesses
                    .insert(offset, (known_info.address, mem.disp()));
            }
        }
        // Clear lui state and known address for destination register of load instructions
        if let MipsOperand::Reg(dst) = &operands[0]
            && let Some(dst_num) = capstone_reg_to_gpr_num(*dst)
            && insn_in(insn, LOAD_INSNS)
        {
            // Only loads write to the destination; stores read from it
            lui_state.clear(dst_num);
            known_addrs.clear(dst_num);
        }
        return;
    }

    // MOVE: Propagate lui state and known addresses from source to destination
    if is_move_insn(insn)
        && let (MipsOperand::Reg(dst), MipsOperand::Reg(src)) = (&operands[0], &operands[1])
        && let (Some(dst_num), Some(src_num)) =
            (capstone_reg_to_gpr_num(*dst), capstone_reg_to_gpr_num(*src))
    {
        if lui_state.get(src_num).as_option().is_some() {
            lui_state.copy_from(src_num, dst_num);
        } else {
            lui_state.clear(dst_num);
        }
        if known_addrs.get(src_num).as_option().is_some() {
            known_addrs.copy_from(src_num, dst_num);
        } else {
            known_addrs.clear(dst_num);
        }
        return;
    }

    // Ignore ADDU where dst and src0 are the same register.
    // This is used to add an array index offset while preserving the lui state.
    // Example: lui $s1, 0x8105 ... addu $s1, $s1, $t6 ... lw $s1, 0x5250($s1)
    if insn_is(insn, MipsInsn::MIPS_INS_ADDU)
        && let (MipsOperand::Reg(dst), MipsOperand::Reg(src0)) = (&operands[0], &operands[1])
        && dst == src0
    {
        return; // Don't clear lui state for array index calculations
    }

    // OR: Check for KSEG1 conversion pattern (or $dst, $kseg1_reg, $func_reg)
    // This pattern is used to convert a cached (KSEG0) function address to uncached (KSEG1)
    // for execution from uncached memory. The underlying function address is preserved.
    if insn_is(insn, MipsInsn::MIPS_INS_OR)
        && let (MipsOperand::Reg(dst), MipsOperand::Reg(src0), MipsOperand::Reg(src1)) =
            (&operands[0], &operands[1], &operands[2])
        && let (Some(dst_num), Some(src0_num), Some(src1_num)) = (
            capstone_reg_to_gpr_num(*dst),
            capstone_reg_to_gpr_num(*src0),
            capstone_reg_to_gpr_num(*src1),
        )
    {
        // Check both orderings: or $dst, $kseg1, $func OR or $dst, $func, $kseg1
        let (kseg1_reg, func_reg) = if let Some(s) = lui_state.get(src0_num).as_option()
            && s.bits == HI_KSEG1
        {
            (Some(src0_num), Some(src1_num))
        } else if let Some(s) = lui_state.get(src1_num).as_option()
            && s.bits == HI_KSEG1
        {
            (Some(src1_num), Some(src0_num))
        } else {
            (None, None)
        };

        if let (Some(_kseg1), Some(func)) = (kseg1_reg, func_reg)
            && let Some(known_info) = known_addrs.get(func).as_option()
        {
            // Propagate the known address to the destination register
            // The KSEG1 OR doesn't change the underlying function identity
            let func_addr = known_info.address;
            let lui_offset = known_info.lui_offset;
            known_addrs.set(dst_num, func_addr, lui_offset);
            lui_state.clear(dst_num);
            return;
        }

        // Not a KSEG1 pattern we recognize - clear destination state
        lui_state.clear(dst_num);
        known_addrs.clear(dst_num);
        return;
    }

    // For all other instructions, clear lui state for any written registers
    for op in &operands {
        if let MipsOperand::Reg(reg) = op
            && let Some(reg_num) = capstone_reg_to_gpr_num(*reg)
        {
            // Check if this operand is written to (for R-type ALU ops, first operand is dest)
            // For most MIPS instructions, the first register operand is the destination
            // For simplicity, clear lui state for first register operand
            // This is conservative but safe
            lui_state.clear(reg_num);
            break; // Only clear the first (destination) register
        }
    }
}

/// Process a delay slot instruction for lui state tracking
fn process_delay_slot(
    cs: &Capstone,
    section: &Section,
    offset: usize,
    lui_state: &mut RegisterLuiState,
    known_addrs: &mut RegisterKnownAddrs,
    results: &mut DiscoveryResults,
) {
    let delay_offset = offset + 4;
    if delay_offset >= section.data.len() {
        return;
    }
    let delay_code = &section.data[delay_offset..];
    let delay_addr = section.offset_to_addr(delay_offset);
    with_single_insn(cs, delay_code, delay_addr.into(), |insn| {
        process_insn_for_lui_state(cs, insn, delay_offset, lui_state, known_addrs, results);
    });
}

/// Process a visited target for lui state tracking.
/// When we reach an already-visited offset with new lui state, we still need to
/// process the instruction (and its delay slot if it's a branch) to record any
/// constructed addresses that result from pairing our lui state with the target.
fn process_visited_target(
    cs: &Capstone,
    section: &Section,
    offset: usize,
    lui_state: &mut RegisterLuiState,
    known_addrs: &mut RegisterKnownAddrs,
    results: &mut DiscoveryResults,
) {
    if offset >= section.data.len() {
        return;
    }
    let code = &section.data[offset..];
    let addr = section.offset_to_addr(offset);
    with_single_insn(cs, code, addr.into(), |insn| {
        process_insn_for_lui_state(cs, insn, offset, lui_state, known_addrs, results);
        if is_branch(cs, insn) {
            process_delay_slot(cs, section, offset, lui_state, known_addrs, results);
        }
    });
}

/// Initialize the work queue with all known code entry points.
fn init_code_discovery_queue(
    section: &mut Section,
    funcs: &Functions,
    queue: &mut VecDeque<(usize, RegisterLuiState)>,
) {
    // Start at the first instruction in the SHDR header (offset 0)
    queue.push_back((0, RegisterLuiState::default()));

    // For loadable sections, only the first subsection contains code
    // Subsequent subsections contain data
    if let Some(first_subsection) = section.subsections.first() {
        queue.push_back((first_subsection.code_offset, RegisterLuiState::default()));
    } else {
        // For non-loadable sections, start at the code after the SHDR header
        queue.push_back((SHDR_SIZE, RegisterLuiState::default()));
    }

    // Add MIPS BEV=1 exception vector entry points (relative to ROM_START)
    // BEV=1 mode is used during boot when Status.BEV is set
    // Only for non-loadable sections since loadable sections use different addresses
    if section.subsections.is_empty() {
        let exception_vectors = [
            EXCEPTION_UNCACHED,
            EXCEPTION_TLB_REFILL,
            EXCEPTION_XTLB_REFILL,
            EXCEPTION_CACHE_ERROR,
            EXCEPTION_GENERAL,
        ];

        for &vec_offset in &exception_vectors {
            let section_offset = vec_offset.saturating_sub(section.shdr.offset);
            if section_offset >= SHDR_SIZE && section_offset < section.data.len() {
                queue.push_back((section_offset, RegisterLuiState::default()));
                section.exception_vectors.push(section_offset);
            }
        }
    }

    // Add known function addresses from functions.json
    for addr in funcs.addresses() {
        if let Some(offset) = section.addr_to_offset(addr)
            && offset < section.data.len()
        {
            queue.push_back((offset, RegisterLuiState::default()));
            section.mark_function_start(offset);
        }
    }
}

/// Determine the end of the code region for a given offset.
/// For loadable sections, only the first subsection contains code.
fn get_code_end(section: &Section, offset: usize) -> usize {
    if let Some(first_subsection) = section.subsections.first() {
        if offset < SUBSECTION_HEADER_SIZE {
            SUBSECTION_HEADER_SIZE // Initial instructions end at subsection header
        } else if offset >= first_subsection.code_offset
            && offset < first_subsection.code_offset + first_subsection.length
        {
            first_subsection.code_offset + first_subsection.length
        } else {
            section.data.len()
        }
    } else {
        section.data.len()
    }
}

/// Try to resolve a jr instruction's target from known register state.
/// Returns the target address if the register has a known value.
fn resolve_jr_target(
    cs: &Capstone,
    insn: &capstone::Insn,
    current_offset: usize,
    known_addrs: &RegisterKnownAddrs,
    section: &Section,
    results: &mut DiscoveryResults,
) -> Option<u32> {
    if !insn_is(insn, MipsInsn::MIPS_INS_JR) {
        return None;
    }
    let detail = cs.insn_detail(insn).ok()?;
    let arch_detail = detail.arch_detail();
    let mips_detail = arch_detail.mips()?;
    let MipsOperand::Reg(reg) = mips_detail.operands().next()? else {
        return None;
    };
    let reg_num = capstone_reg_to_gpr_num(reg)?;
    let known_info = known_addrs.get(reg_num).as_option()?;
    let addr = known_info.address;
    // Record the indirect jump for DOT generation
    if let Some(offset) = section.addr_to_offset(addr) {
        results.indirect_jump_targets.insert(current_offset, offset);
    }
    Some(addr)
}

/// Process a resolved branch target: mark as function start or branch target
/// and enqueue for discovery.
#[expect(clippy::too_many_arguments)]
fn process_branch_target(
    cs: &Capstone,
    insn: &capstone::Insn,
    target_offset: usize,
    section: &mut Section,
    visited: &HashSet<usize>,
    queue: &mut VecDeque<(usize, RegisterLuiState)>,
    lui_state: &RegisterLuiState,
    results: &mut DiscoveryResults,
) {
    if is_call_instruction(cs, insn) {
        section.mark_function_start(target_offset);
        if !visited.contains(&target_offset) {
            queue.push_back((target_offset, RegisterLuiState::default()));
        }
    } else {
        section.mark_branch_target(target_offset);
        if !visited.contains(&target_offset) {
            queue.push_back((target_offset, lui_state.clone()));
        } else {
            let mut path_lui_state = lui_state.clone();
            let mut path_known_addrs = RegisterKnownAddrs::default();
            process_visited_target(
                cs,
                section,
                target_offset,
                &mut path_lui_state,
                &mut path_known_addrs,
                results,
            );
        }
    }
}

/// Discover code regions in a section by following control flow
///
/// This function walks through the section's code, following branches and jumps,
/// to identify all reachable code. It also tracks LUI state to detect address
/// construction patterns (lui + addiu/ori/load/store).
pub fn discover_code(cs: &Capstone, section: &mut Section, funcs: &Functions) {
    if section.shdr.is_data() {
        return;
    }

    // Queue stores (offset, lui_state) pairs
    let mut queue: VecDeque<(usize, RegisterLuiState)> = VecDeque::new();
    let mut visited: HashSet<usize> = HashSet::new();

    // Accumulated results from code discovery
    let mut results = DiscoveryResults::default();

    init_code_discovery_queue(section, funcs, &mut queue);

    while let Some((offset, mut lui_state)) = queue.pop_front() {
        // Track known constructed addresses for this basic block
        let mut known_addrs = RegisterKnownAddrs::default();

        if visited.contains(&offset) {
            // Offset already visited, but we may have lui state that needs to be paired
            // with instructions at this offset.
            process_visited_target(
                cs,
                section,
                offset,
                &mut lui_state,
                &mut known_addrs,
                &mut results,
            );
            continue;
        }

        let code_end = get_code_end(section, offset);

        let mut current_offset = offset;
        while current_offset < code_end {
            let code_slice = &section.data[current_offset..code_end];
            let addr = section.offset_to_addr(current_offset);

            let Ok(insns) = cs.disasm_count(code_slice, addr.into(), 1) else {
                break;
            };

            let Some(insn) = insns.first() else { break };

            if !visited.insert(current_offset) {
                break;
            }
            section.mark_code(current_offset);

            // Process instruction for lui state tracking
            process_insn_for_lui_state(
                cs,
                insn,
                current_offset,
                &mut lui_state,
                &mut known_addrs,
                &mut results,
            );

            if is_branch(cs, insn) {
                // Record this as a branch instruction for CFG construction
                section.mark_branch_instruction(current_offset);

                // For "branch likely" instructions, the delay slot is only executed if the
                // branch is taken. Save lui state so we can restore it for the fall-through path.
                let branch_likely = is_branch_likely(insn);
                let saved_lui_state = if branch_likely {
                    Some(lui_state.clone())
                } else {
                    None
                };

                // Process delay slot first - it always executes before the branch is completed,
                // so the lui_state at the branch target should include the delay slot's effect
                let delay_slot_offset = current_offset + 4;
                if delay_slot_offset < section.data.len() {
                    section.mark_code(delay_slot_offset);
                    visited.insert(delay_slot_offset);
                    process_delay_slot(
                        cs,
                        section,
                        current_offset,
                        &mut lui_state,
                        &mut known_addrs,
                        &mut results,
                    );
                }

                // Resolve target address: immediate target or indirect via known register
                let target_addr = get_branch_target(cs, insn).or_else(|| {
                    resolve_jr_target(
                        cs,
                        insn,
                        current_offset,
                        &known_addrs,
                        section,
                        &mut results,
                    )
                });

                if let Some(target) = target_addr
                    && let Some(target_offset) = section.addr_to_offset(target)
                {
                    process_branch_target(
                        cs,
                        insn,
                        target_offset,
                        section,
                        &visited,
                        &mut queue,
                        &lui_state,
                        &mut results,
                    );
                }

                // For branch likely, restore lui state for fall-through path since
                // the delay slot is not executed when the branch is not taken
                if let Some(restored) = saved_lui_state {
                    lui_state = restored;
                }

                if is_unconditional_branch(insn) {
                    // Mark function end if this is a jr instruction
                    if is_function_end(insn) {
                        let end_offset = current_offset + 8; // After delay slot
                        section.mark_function_end(end_offset);
                    }
                    break;
                }

                // For conditional branches, skip past the delay slot to continue fall-through
                current_offset += 8;
                continue;
            }

            current_offset += 4;
        }
    }

    // Store results in section
    section.discovery = results;
}
