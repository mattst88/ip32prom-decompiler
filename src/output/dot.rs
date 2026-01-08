// SPDX-License-Identifier: GPL-3.0-or-later
//! Control-flow graph output in DOT (Graphviz) format.
//!
//! Generates a call graph with:
//! - Functions as subgraph clusters (boxes)
//! - Basic blocks as nodes within each function
//! - Intra-function control flow edges between basic blocks
//! - Inter-function call edges between function clusters

use anyhow::Result;
use capstone::Capstone;
use std::collections::BTreeSet;
use std::io::{BufWriter, Write};
use std::path::Path;

use super::util::create_output_file;
use crate::annotations::Labels;
use crate::cfg::{
    EdgeType, build_basic_blocks, compute_function_membership, compute_reachable_functions,
};
use crate::section::Section;

/// Get a label for an address, using the labels map or generating one.
fn get_label(addr: u32, labels: &Labels, section: &Section) -> String {
    if let Some(label) = labels.get(addr) {
        label.to_string()
    } else if let Some(offset) = section.addr_to_offset(addr) {
        if section.control_flow.function_starts.contains(&offset) {
            format!("F_{:#x}", addr)
        } else {
            format!("L_{:#x}", addr)
        }
    } else {
        format!("{:#x}", addr)
    }
}

/// Generate DOT output for a section's control-flow graph.
pub fn generate_dot(
    cs: &Capstone,
    section: &Section,
    output_path: &Path,
    labels: &Labels,
) -> Result<()> {
    // Build basic blocks, excluding unreachable code
    let blocks = build_basic_blocks(cs, section, true);

    // Compute function membership using control flow reachability
    let (function_blocks, block_to_function) = compute_function_membership(&blocks, section);

    // Find functions transitively reachable from entrypoints
    let reachable_functions = compute_reachable_functions(&blocks, &block_to_function, section);

    // Find orphan blocks (not in any function)
    let orphan_blocks: Vec<usize> = blocks
        .keys()
        .filter(|offset| !block_to_function.contains_key(offset))
        .copied()
        .collect();

    // Collect control flow edges and call edges
    let mut control_flow_edges: Vec<(usize, usize, EdgeType)> = Vec::new();
    let mut call_edges: BTreeSet<(usize, usize)> = BTreeSet::new();

    for (&offset, block) in &blocks {
        let caller_func = block_to_function.get(&offset).copied();

        for (target_offset, edge_type) in &block.successors {
            if *edge_type == EdgeType::Call {
                if section.control_flow.function_starts.contains(target_offset) {
                    call_edges.insert((offset, *target_offset));
                }
            } else if *edge_type == EdgeType::Jump
                && section.control_flow.function_starts.contains(target_offset)
            {
                // Jump to a function start (e.g., indirect jump via KSEG1 OR pattern)
                call_edges.insert((offset, *target_offset));
            } else {
                // Control flow edge (intra-function or involving orphan blocks)
                let target_func = block_to_function.get(target_offset).copied();
                let is_intra_function = caller_func == target_func && caller_func.is_some();
                let involves_orphan = caller_func.is_none() || target_func.is_none();
                if is_intra_function || involves_orphan {
                    control_flow_edges.push((offset, *target_offset, *edge_type));
                }
            }
        }
    }

    // Write DOT output
    let file = create_output_file(output_path, "DOT file")?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "digraph {} {{", section.shdr.name.replace('-', "_"))?;
    writeln!(writer, "    compound=true;")?;
    writeln!(writer, "    rankdir=TB;")?;
    writeln!(
        writer,
        "    node [shape=box, fontname=\"monospace\", fontsize=10];"
    )?;
    writeln!(writer, "    edge [fontname=\"monospace\", fontsize=8];")?;
    writeln!(writer)?;

    // Output each function as a subgraph cluster (only reachable functions)
    for (&func_start, block_offsets) in &function_blocks {
        if !reachable_functions.contains(&func_start) {
            continue;
        }

        let func_addr = section.offset_to_addr(func_start);
        let func_label = get_label(func_addr, labels, section);

        writeln!(writer, "    subgraph cluster_{:#x} {{", func_addr)?;
        writeln!(writer, "        label=\"{}\";", func_label)?;
        writeln!(writer, "        style=\"rounded,filled\";")?;
        writeln!(writer, "        fillcolor=lightgray;")?;
        writeln!(writer)?;

        // Output nodes for this function
        for &offset in block_offsets {
            if let Some(block) = blocks.get(&offset) {
                let node_label = get_label(block.start_addr, labels, section);
                let node_id = format!("n_{:#x}", block.start_addr);

                // Build block label with address range
                let end_addr = section.offset_to_addr(block.end_offset.saturating_sub(4));
                let block_label = if block.start_addr == end_addr {
                    node_label
                } else {
                    format!("{}\n[{:#x}-{:#x}]", node_label, block.start_addr, end_addr)
                };

                // Style basic blocks by type
                // Section entrypoints (reset vector, exception vectors) are yellow
                // Function entries are green, returns are coral, others are white
                let is_entrypoint = offset == 0 || section.exception_vectors.contains(&offset);
                let style = if is_entrypoint {
                    ", style=filled, fillcolor=yellow"
                } else if section.control_flow.function_starts.contains(&offset) {
                    ", style=filled, fillcolor=lightgreen"
                } else if block.is_function_return {
                    ", style=filled, fillcolor=lightcoral"
                } else {
                    ", style=filled, fillcolor=white"
                };

                writeln!(
                    writer,
                    "        {} [label=\"{}\"{}];",
                    node_id, block_label, style
                )?;
            }
        }

        writeln!(writer, "    }}")?;
        writeln!(writer)?;
    }

    // Output orphan blocks (not in any function)
    if !orphan_blocks.is_empty() {
        writeln!(writer, "    // Orphan blocks (not in any function)")?;
        for &offset in &orphan_blocks {
            if let Some(block) = blocks.get(&offset) {
                let node_label = get_label(block.start_addr, labels, section);
                let node_id = format!("n_{:#x}", block.start_addr);

                let end_addr = section.offset_to_addr(block.end_offset.saturating_sub(4));
                let block_label = if block.start_addr == end_addr {
                    node_label
                } else {
                    format!("{}\n[{:#x}-{:#x}]", node_label, block.start_addr, end_addr)
                };

                let is_entrypoint = offset == 0 || section.exception_vectors.contains(&offset);
                let style = if is_entrypoint {
                    ", style=filled, fillcolor=yellow"
                } else {
                    ", style=filled, fillcolor=white"
                };

                writeln!(
                    writer,
                    "    {} [label=\"{}\"{}];",
                    node_id, block_label, style
                )?;
            }
        }
        writeln!(writer)?;
    }

    // Output control flow edges (only for reachable functions)
    writeln!(writer, "    // Control flow edges")?;
    for (src_offset, dst_offset, edge_type) in &control_flow_edges {
        let src_func = block_to_function.get(src_offset);
        let dst_func = block_to_function.get(dst_offset);
        let src_reachable = src_func.is_none_or(|f| reachable_functions.contains(f));
        let dst_reachable = dst_func.is_none_or(|f| reachable_functions.contains(f));

        if !src_reachable || !dst_reachable {
            continue;
        }

        if let (Some(src_block), Some(dst_block)) = (blocks.get(src_offset), blocks.get(dst_offset))
        {
            let src_id = format!("n_{:#x}", src_block.start_addr);
            let dst_id = format!("n_{:#x}", dst_block.start_addr);

            writeln!(
                writer,
                "    {} -> {} [color={}, style={}];",
                src_id,
                dst_id,
                edge_type.color(),
                edge_type.style()
            )?;
        }
    }

    writeln!(writer)?;

    // Output inter-function call edges
    writeln!(writer, "    // Inter-function call edges")?;
    for (caller_block, callee_func) in &call_edges {
        let caller_func = block_to_function.get(caller_block);
        let caller_reachable = caller_func.is_some_and(|f| reachable_functions.contains(f));
        let callee_reachable = reachable_functions.contains(callee_func);

        if !caller_reachable || !callee_reachable {
            continue;
        }

        let caller_block_addr = section.offset_to_addr(*caller_block);
        let callee_addr = section.offset_to_addr(*callee_func);

        let src_id = format!("n_{:#x}", caller_block_addr);
        let dst_id = format!("n_{:#x}", callee_addr);

        // For recursive calls (caller inside callee's cluster), don't use lhead
        // to avoid "tail is inside head cluster" warnings
        let is_recursive = caller_func == Some(callee_func);
        let lhead = if is_recursive {
            String::new()
        } else {
            format!("lhead=cluster_{:#x}, ", callee_addr)
        };

        writeln!(
            writer,
            "    {} -> {} [{}color={}, style={}];",
            src_id,
            dst_id,
            lhead,
            EdgeType::Call.color(),
            EdgeType::Call.style()
        )?;
    }

    writeln!(writer, "}}")?;

    Ok(())
}
