// SPDX-License-Identifier: GPL-3.0-or-later
//! IP32 PROM Decompiler Library
//!
//! This library provides functionality for decompiling SGI O2 (IP32) PROM firmware
//! into reassemblable source code.

pub mod annotations;
pub mod cfg;
pub mod hardware;
pub mod mips;
pub mod output;
pub mod section;
pub mod shdr;
