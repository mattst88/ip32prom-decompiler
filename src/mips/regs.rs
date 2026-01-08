// SPDX-License-Identifier: GPL-3.0-or-later
//! MIPS register name and number conversion utilities.

use capstone::arch::mips::MipsReg::*;

/// CP0 (System Control Coprocessor) register names indexed by register number
pub const CP0_REG_NAMES: [&str; 32] = [
    "CP0_INDEX",       // 0
    "CP0_RANDOM",      // 1
    "CP0_ENTRYLO0",    // 2
    "CP0_ENTRYLO1",    // 3
    "CP0_CONTEXT",     // 4
    "CP0_PAGEMASK",    // 5
    "CP0_WIRED",       // 6
    "CP0_INFO",        // 7
    "CP0_BADVADDR",    // 8
    "CP0_COUNT",       // 9
    "CP0_ENTRYHI",     // 10
    "CP0_COMPARE",     // 11
    "CP0_STATUS",      // 12
    "CP0_CAUSE",       // 13
    "CP0_EPC",         // 14
    "CP0_PRID",        // 15
    "CP0_CONFIG",      // 16
    "CP0_LLADDR",      // 17
    "CP0_WATCHLO",     // 18
    "CP0_WATCHHI",     // 19
    "CP0_XCONTEXT",    // 20
    "CP0_FRAMEMASK",   // 21
    "CP0_DIAGNOSTIC",  // 22
    "CP0_DEBUG",       // 23
    "CP0_DEPC",        // 24
    "CP0_PERFORMANCE", // 25
    "CP0_ECC",         // 26
    "CP0_CACHEERR",    // 27
    "CP0_TAGLO",       // 28
    "CP0_TAGHI",       // 29
    "CP0_ERROREPC",    // 30
    "CP0_DESAVE",      // 31
];

/// CP1 (FPU) control register names indexed by register number
/// Only registers 0 (FIR) and 31 (FCSR) are standard; others are reserved
pub const CP1_CTRL_REG_NAMES: [&str; 32] = [
    "CP1_FIR", // 0 - FPU Implementation/Revision
    "CP1_1",   // 1 - reserved
    "CP1_2",   // 2 - reserved
    "CP1_3",   // 3 - reserved
    "CP1_4",   // 4 - reserved
    "CP1_5",   // 5 - reserved
    "CP1_6",   // 6 - reserved
    "CP1_7",   // 7 - reserved
    "CP1_8",   // 8 - reserved
    "CP1_9",   // 9 - reserved
    "CP1_10",  // 10 - reserved
    "CP1_11",  // 11 - reserved
    "CP1_12",  // 12 - reserved
    "CP1_13",  // 13 - reserved
    "CP1_14",  // 14 - reserved
    "CP1_15",  // 15 - reserved
    "CP1_16",  // 16 - reserved
    "CP1_17",  // 17 - reserved
    "CP1_18",  // 18 - reserved
    "CP1_19",  // 19 - reserved
    "CP1_20",  // 20 - reserved
    "CP1_21",  // 21 - reserved
    "CP1_22",  // 22 - reserved
    "CP1_23",  // 23 - reserved
    "CP1_24",  // 24 - reserved
    "CP1_25",  // 25 - reserved
    "CP1_26",  // 26 - reserved
    "CP1_27",  // 27 - reserved
    "CP1_28",  // 28 - reserved
    "CP1_29",  // 29 - reserved
    // The "IDT MIPS Microprocessor Family Software Reference Manual"
    // (https://psx.arthus.net/docs/3715.pdf) contains example code in Chapter 4 Exception Handling
    // that saves CP1 control register $30 in a field named `R_FEIR`:
    // ```
    // cfc1 v0,$30
    // cfc1 v1,$31
    // sw v0,R_FEIR*4(AT)
    // sw v1,R_FCSR*4(AT)
    // ```
    // but I can find no documentation that definitively states that this register existed. In
    // fact, multiple documents (e.g. "MIPS R4000 Microprocessor User's Manual, Second Edition" and
    // "MIPS IV Instruction Set") say that only $0 and $31 are defined.
    "CP1_FEIR", // 30 - FPU Exception Instruction Register
    "CP1_FCSR", // 31 - FPU Control/Status Register
];

/// MIPS General Purpose Register names and their corresponding numbers.
pub const GPR_NAMES: &[(&str, u32)] = &[
    ("zero", 0),
    ("at", 1),
    ("v0", 2),
    ("v1", 3),
    ("a0", 4),
    ("a1", 5),
    ("a2", 6),
    ("a3", 7),
    ("t0", 8),
    ("t1", 9),
    ("t2", 10),
    ("t3", 11),
    ("t4", 12),
    ("t5", 13),
    ("t6", 14),
    ("t7", 15),
    ("s0", 16),
    ("s1", 17),
    ("s2", 18),
    ("s3", 19),
    ("s4", 20),
    ("s5", 21),
    ("s6", 22),
    ("s7", 23),
    ("t8", 24),
    ("t9", 25),
    ("k0", 26),
    ("k1", 27),
    ("gp", 28),
    ("sp", 29),
    ("fp", 30),
    ("ra", 31),
];

/// Convert a GPR name (like "$s1" or "s1") to its register number
pub fn gpr_name_to_number(name: &str) -> Option<u32> {
    let name = name.trim_start_matches('$');

    for &(reg_name, num) in GPR_NAMES {
        if name == reg_name {
            return Some(num);
        }
    }

    // Try parsing as a number (for $0, $1, etc.)
    name.parse().ok()
}

/// Convert a Capstone RegId to a MIPS GPR number (0-31)
/// Capstone MIPS register IDs are sequential: MIPS_REG_0/MIPS_REG_ZERO = 2,
/// MIPS_REG_31/MIPS_REG_RA = 33, so GPR number = reg_id - 2.
pub fn capstone_reg_to_gpr_num(reg: capstone::RegId) -> Option<usize> {
    let reg_id = reg.0 as u32; // RegId.0 is u16, need to widen
    if (MIPS_REG_ZERO..=MIPS_REG_RA).contains(&reg_id) {
        Some((reg_id - MIPS_REG_ZERO) as usize)
    } else {
        None
    }
}
