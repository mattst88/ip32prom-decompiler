// SPDX-License-Identifier: GPL-3.0-or-later
//! Control flow graph analysis for firmware sections.
//!
//! This module provides shared types and functions for building and analyzing
//! control flow graphs from disassembled code.

mod blocks;
mod reachability;

pub use blocks::{BasicBlock, EdgeType, build_basic_blocks};
pub use reachability::{
    compute_function_bounds, compute_function_membership, compute_reachable_functions,
};
