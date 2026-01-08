// SPDX-License-Identifier: GPL-3.0-or-later
//! Reachability analysis for control flow graphs.

use std::collections::{BTreeMap, BTreeSet};

use super::{BasicBlock, EdgeType};
use crate::section::Section;

/// BFS from a function start to find all blocks reachable via non-call edges,
/// stopping at other function entry points.
fn bfs_function_blocks(
    func_start: usize,
    blocks: &BTreeMap<usize, BasicBlock>,
    section: &Section,
) -> BTreeSet<usize> {
    let mut visited = BTreeSet::new();
    let mut queue = vec![func_start];

    while let Some(offset) = queue.pop() {
        if visited.contains(&offset) {
            continue;
        }
        // Don't cross into another function's entry point
        if offset != func_start && section.control_flow.function_starts.contains(&offset) {
            continue;
        }
        visited.insert(offset);

        if let Some(block) = blocks.get(&offset) {
            for (target_offset, edge_type) in &block.successors {
                if *edge_type != EdgeType::Call
                    && !visited.contains(target_offset)
                    && !section.control_flow.function_starts.contains(target_offset)
                {
                    queue.push(*target_offset);
                }
            }
        }
    }

    visited
}

/// Compute which blocks belong to which function using control flow reachability.
///
/// A block belongs to a function if it's reachable from the function start
/// via non-call edges (jumps, branches, fall-throughs).
///
/// Returns:
/// - `function_blocks`: Map from function start offset to list of block offsets
/// - `block_to_function`: Map from block offset to its containing function
pub fn compute_function_membership(
    blocks: &BTreeMap<usize, BasicBlock>,
    section: &Section,
) -> (BTreeMap<usize, Vec<usize>>, BTreeMap<usize, usize>) {
    let mut function_blocks: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut block_to_function: BTreeMap<usize, usize> = BTreeMap::new();

    // For each function start, do a BFS to find all reachable blocks.
    // Sort function starts for deterministic block ownership when blocks are
    // reachable from multiple functions (HashSet iteration order is arbitrary).
    let mut sorted_func_starts: Vec<usize> = section
        .control_flow
        .function_starts
        .iter()
        .copied()
        .collect();
    sorted_func_starts.sort_unstable();
    for &func_start in &sorted_func_starts {
        if !blocks.contains_key(&func_start) {
            continue;
        }

        let visited = bfs_function_blocks(func_start, blocks, section);

        // Record all visited blocks as belonging to this function
        let func_block_list: Vec<usize> = visited.into_iter().collect();
        for &offset in &func_block_list {
            block_to_function.insert(offset, func_start);
        }
        function_blocks.insert(func_start, func_block_list);
    }

    (function_blocks, block_to_function)
}

/// Compute which functions are transitively reachable from entrypoints.
///
/// Entrypoints are: offset 0 (reset vector) and exception vectors.
///
/// Returns a set of function start offsets that are reachable.
pub fn compute_reachable_functions(
    blocks: &BTreeMap<usize, BasicBlock>,
    block_to_function: &BTreeMap<usize, usize>,
    section: &Section,
) -> BTreeSet<usize> {
    // Build a map from function to the functions it calls
    let mut function_calls: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();

    for (&offset, block) in blocks {
        let caller_func = block_to_function.get(&offset).copied();

        for (target_offset, edge_type) in &block.successors {
            if *edge_type == EdgeType::Call
                && section.control_flow.function_starts.contains(target_offset)
            {
                if let Some(caller) = caller_func {
                    function_calls
                        .entry(caller)
                        .or_default()
                        .insert(*target_offset);
                }
            } else if *edge_type == EdgeType::Jump
                && section.control_flow.function_starts.contains(target_offset)
            {
                // Jump to a function start (e.g., indirect jump via KSEG1 OR pattern)
                // Treat this as a call edge for reachability
                if let Some(caller) = caller_func {
                    function_calls
                        .entry(caller)
                        .or_default()
                        .insert(*target_offset);
                }
            }
        }
    }

    // BFS from entrypoints to find all transitively reachable functions
    let mut reachable_functions: BTreeSet<usize> = BTreeSet::new();
    let mut queue: Vec<usize> = Vec::new();

    // Entrypoints: offset 0 and exception vectors
    if section.control_flow.function_starts.contains(&0) {
        queue.push(0);
    }
    for &ev_offset in &section.exception_vectors {
        if section.control_flow.function_starts.contains(&ev_offset) {
            queue.push(ev_offset);
        }
    }

    while let Some(func_offset) = queue.pop() {
        if !reachable_functions.insert(func_offset) {
            continue;
        }

        // Add all functions called by this function
        if let Some(callees) = function_calls.get(&func_offset) {
            for &callee in callees {
                if !reachable_functions.contains(&callee) {
                    queue.push(callee);
                }
            }
        }
    }

    reachable_functions
}

/// Compute function bounds (end offsets) using control flow reachability.
///
/// For each function, the end offset is the maximum end offset of any
/// basic block reachable from the function start.
pub fn compute_function_bounds(
    blocks: &BTreeMap<usize, BasicBlock>,
    section: &Section,
) -> BTreeMap<usize, usize> {
    let mut function_bounds: BTreeMap<usize, usize> = BTreeMap::new();

    for &func_start in &section.control_flow.function_starts {
        if !blocks.contains_key(&func_start) {
            continue;
        }

        let visited = bfs_function_blocks(func_start, blocks, section);
        let max_end_offset = visited
            .iter()
            .filter_map(|&offset| blocks.get(&offset))
            .map(|block| block.end_offset)
            .max()
            .unwrap_or(0);

        if max_end_offset > 0 {
            function_bounds.insert(func_start, max_end_offset);
        }
    }

    function_bounds
}
