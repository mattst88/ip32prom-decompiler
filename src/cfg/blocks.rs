// SPDX-License-Identifier: GPL-3.0-or-later
//! Basic block construction for control flow graphs.

use capstone::Capstone;
use std::collections::{BTreeMap, BTreeSet};

use crate::mips::insn::{
    get_branch_target, is_branch, is_call_instruction, is_function_end, is_unconditional_branch,
};
use crate::section::{DataType, Section};

/// Type of edge in the control flow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    /// Unconditional jump or branch taken
    Jump,
    /// Fall-through (branch not taken or sequential)
    FallThrough,
    /// Function call
    Call,
}

impl EdgeType {
    /// Get the DOT color for this edge type.
    pub fn color(&self) -> &'static str {
        match self {
            EdgeType::Jump => "blue",
            EdgeType::FallThrough => "black",
            EdgeType::Call => "red",
        }
    }

    /// Get the DOT style for this edge type.
    pub fn style(&self) -> &'static str {
        match self {
            EdgeType::Jump => "solid",
            EdgeType::FallThrough => "dashed",
            EdgeType::Call => "bold",
        }
    }
}

/// A basic block in the control flow graph.
#[derive(Debug)]
pub struct BasicBlock {
    /// End offset (exclusive) in the section
    pub end_offset: usize,
    /// Address of the first instruction
    pub start_addr: u32,
    /// Successors: (target_offset, edge_type)
    pub successors: Vec<(usize, EdgeType)>,
    /// Whether this block ends with a function return
    pub is_function_return: bool,
}

/// Get the offset of the branch instruction in a block.
///
/// MIPS branches have delay slots, so the branch is typically the second-to-last
/// instruction in a block (with the delay slot being the last).
fn get_block_branch_offset(block_code: &[usize]) -> Option<usize> {
    match block_code.len() {
        0 => None,
        1 => Some(block_code[0]),
        n => Some(block_code[n - 2]),
    }
}

/// Compute successor edges for a branch instruction.
fn compute_branch_successors(
    cs: &Capstone,
    section: &Section,
    branch_offset: usize,
    end_offset: usize,
) -> (Vec<(usize, EdgeType)>, bool) {
    let mut successors = Vec::new();
    let mut is_function_return = false;

    if branch_offset + 4 > section.data.len() {
        return (successors, is_function_return);
    }

    let code_slice = &section.data[branch_offset..];
    let addr = section.offset_to_addr(branch_offset);

    if let Ok(insns) = cs.disasm_count(code_slice, addr.into(), 1)
        && let Some(insn) = insns.iter().next()
    {
        if is_branch(cs, insn) {
            // Check if this is a function return
            if is_function_end(insn) {
                is_function_return = true;
            }

            // Get branch target - first try immediate target, then indirect
            let is_call = is_call_instruction(cs, insn);
            let target_offset = if let Some(target) = get_branch_target(cs, insn) {
                section.addr_to_offset(target)
            } else {
                // Check for indirect jump with known target (e.g., KSEG1 OR pattern)
                section
                    .discovery
                    .indirect_jump_targets
                    .get(&branch_offset)
                    .copied()
            };

            if let Some(target_offset) = target_offset
                && section.data_types.get(&target_offset) == Some(&DataType::Code)
            {
                let edge_type = if is_call {
                    EdgeType::Call
                } else {
                    EdgeType::Jump
                };
                successors.push((target_offset, edge_type));
            }

            // For conditional branches, add fall-through edge
            if !is_unconditional_branch(insn) && !is_call {
                let fall_through = branch_offset + 8; // After delay slot
                if section.data_types.get(&fall_through) == Some(&DataType::Code) {
                    successors.push((fall_through, EdgeType::FallThrough));
                }
            }

            // For calls, add fall-through to return point
            if is_call {
                let return_point = branch_offset + 8;
                if section.data_types.get(&return_point) == Some(&DataType::Code) {
                    successors.push((return_point, EdgeType::FallThrough));
                }
            }
        } else {
            // Non-branch instruction - fall through to next block
            if section.data_types.get(&end_offset) == Some(&DataType::Code) {
                successors.push((end_offset, EdgeType::FallThrough));
            }
        }
    }

    (successors, is_function_return)
}

/// Build basic blocks from the section's code discovery data.
///
/// If `exclude_unreachable` is true, blocks marked as unreachable code are filtered out.
pub fn build_basic_blocks(
    cs: &Capstone,
    section: &Section,
    exclude_unreachable: bool,
) -> BTreeMap<usize, BasicBlock> {
    let mut blocks: BTreeMap<usize, BasicBlock> = BTreeMap::new();

    // Collect all code offsets sorted, optionally excluding unreachable code
    let mut code_offsets: Vec<usize> = section
        .data_types
        .iter()
        .filter(|(offset, dtype)| {
            **dtype == DataType::Code
                && (!exclude_unreachable || !section.control_flow.unreachable_code.contains(offset))
        })
        .map(|(offset, _)| *offset)
        .collect();
    code_offsets.sort_unstable();

    if code_offsets.is_empty() {
        return blocks;
    }

    // Block boundaries: branch targets, function starts, instructions after branches
    let mut block_starts: BTreeSet<usize> = BTreeSet::new();

    // Add known boundaries (optionally excluding unreachable code)
    for &offset in &section.control_flow.branch_targets {
        if section.data_types.get(&offset) == Some(&DataType::Code)
            && (!exclude_unreachable || !section.control_flow.unreachable_code.contains(&offset))
        {
            block_starts.insert(offset);
        }
    }
    for &offset in &section.control_flow.function_starts {
        if section.data_types.get(&offset) == Some(&DataType::Code)
            && (!exclude_unreachable || !section.control_flow.unreachable_code.contains(&offset))
        {
            block_starts.insert(offset);
        }
    }

    // First code offset is always a block start
    if let Some(&first) = code_offsets.first()
        && (!exclude_unreachable || !section.control_flow.unreachable_code.contains(&first))
    {
        block_starts.insert(first);
    }

    // Find instructions after branches (they start new blocks)
    // Use cached branch_offsets to avoid re-disassembling every instruction
    for &offset in &section.control_flow.branch_offsets {
        if exclude_unreachable && section.control_flow.unreachable_code.contains(&offset) {
            continue;
        }
        let after_delay = offset + 8;
        if section.data_types.get(&after_delay) == Some(&DataType::Code)
            && (!exclude_unreachable
                || !section.control_flow.unreachable_code.contains(&after_delay))
        {
            block_starts.insert(after_delay);
        }
    }

    // Build blocks
    let block_starts_vec: Vec<usize> = block_starts.iter().copied().collect();

    for (i, &start_offset) in block_starts_vec.iter().enumerate() {
        let end_offset = block_starts_vec
            .get(i + 1)
            .copied()
            .unwrap_or(code_offsets.last().map(|&o| o + 4).unwrap_or(start_offset));

        // Find code offsets in this block using binary search (code_offsets is sorted)
        let start_idx = code_offsets.partition_point(|&o| o < start_offset);
        let end_idx = code_offsets.partition_point(|&o| o < end_offset);
        let block_code = &code_offsets[start_idx..end_idx];

        let Some(branch_offset) = get_block_branch_offset(block_code) else {
            continue;
        };

        let (successors, is_function_return) =
            compute_branch_successors(cs, section, branch_offset, end_offset);

        blocks.insert(
            start_offset,
            BasicBlock {
                end_offset,
                start_addr: section.offset_to_addr(start_offset),
                successors,
                is_function_return,
            },
        );
    }

    blocks
}
