// SPDX-License-Identifier: GPL-3.0-or-later
//! MIPS instruction identification and classification helpers.
//!
//! Note that Capstone's instruction classification for MIPS is often wrong or incomplete.
//! Tested with capstone 0.12.0 / capstone-sys 0.16.0.
//! (see `src/bin/check_groups.rs` for verification)
//!
//! Control-flow group assignments:
//!
//! | Instruction | Groups                     |
//! |-------------|----------------------------|
//! | `j`         | JUMP                       |
//! | `jal`       | (none)                     |
//! | `jr`        | JUMP                       |
//! | `jr $ra`    | JUMP (not RET)             |
//! | `jalr`      | CALL                       |
//! | `b`         | BRANCH_RELATIVE, JUMP      |
//! | `bal`       | BRANCH_RELATIVE (not CALL) |
//! | `beq`       | BRANCH_RELATIVE, JUMP      |
//! | `eret`      | (none)                     |
//!
//! Additionally, both `addu $rd, $rs, $zero` and `or $rd, $rs, $zero` are reported
//! as `MIPS_INS_MOVE`, so raw bits must be checked to distinguish them.

use capstone::arch::mips::{MipsInsn, MipsInsnGroup, MipsOperand};
use capstone::prelude::*;

/// "Branch likely" instructions (nullify delay slot if not taken)
pub const BRANCH_LIKELY_INSNS: &[MipsInsn] = &[
    MipsInsn::MIPS_INS_BEQL,
    MipsInsn::MIPS_INS_BNEL,
    MipsInsn::MIPS_INS_BLEZL,
    MipsInsn::MIPS_INS_BGTZL,
    MipsInsn::MIPS_INS_BLTZL,
    MipsInsn::MIPS_INS_BGEZL,
    MipsInsn::MIPS_INS_BLTZALL,
    MipsInsn::MIPS_INS_BGEZALL,
    MipsInsn::MIPS_INS_BC1TL,
    MipsInsn::MIPS_INS_BC1FL,
];

/// Branches/jumps with immediate targets (need label replacement)
pub const IMMEDIATE_TARGET_INSNS: &[MipsInsn] = &[
    // Branch instructions with PC-relative targets
    MipsInsn::MIPS_INS_B,
    MipsInsn::MIPS_INS_BAL,
    MipsInsn::MIPS_INS_BEQ,
    MipsInsn::MIPS_INS_BEQL,
    MipsInsn::MIPS_INS_BEQZ,
    MipsInsn::MIPS_INS_BGEZ,
    MipsInsn::MIPS_INS_BGEZAL,
    MipsInsn::MIPS_INS_BGEZALL,
    MipsInsn::MIPS_INS_BGEZL,
    MipsInsn::MIPS_INS_BGTZ,
    MipsInsn::MIPS_INS_BGTZL,
    MipsInsn::MIPS_INS_BLEZ,
    MipsInsn::MIPS_INS_BLEZL,
    MipsInsn::MIPS_INS_BLTZ,
    MipsInsn::MIPS_INS_BLTZAL,
    MipsInsn::MIPS_INS_BLTZALL,
    MipsInsn::MIPS_INS_BLTZL,
    MipsInsn::MIPS_INS_BNE,
    MipsInsn::MIPS_INS_BNEL,
    MipsInsn::MIPS_INS_BNEZ,
    MipsInsn::MIPS_INS_BC1F,
    MipsInsn::MIPS_INS_BC1FL,
    MipsInsn::MIPS_INS_BC1T,
    MipsInsn::MIPS_INS_BC1TL,
    // Jump instructions with absolute targets
    MipsInsn::MIPS_INS_J,
    MipsInsn::MIPS_INS_JAL,
];

/// Load instructions
pub const LOAD_INSNS: &[MipsInsn] = &[
    MipsInsn::MIPS_INS_LB,
    MipsInsn::MIPS_INS_LBU,
    MipsInsn::MIPS_INS_LH,
    MipsInsn::MIPS_INS_LHU,
    MipsInsn::MIPS_INS_LW,
    MipsInsn::MIPS_INS_LWU,
    MipsInsn::MIPS_INS_LD,
    MipsInsn::MIPS_INS_LWL,
    MipsInsn::MIPS_INS_LWR,
    MipsInsn::MIPS_INS_LDL,
    MipsInsn::MIPS_INS_LDR,
    MipsInsn::MIPS_INS_LL,
    MipsInsn::MIPS_INS_LLD,
    MipsInsn::MIPS_INS_LWC1,
    MipsInsn::MIPS_INS_LDC1,
];

/// Store instructions
pub const STORE_INSNS: &[MipsInsn] = &[
    MipsInsn::MIPS_INS_SB,
    MipsInsn::MIPS_INS_SH,
    MipsInsn::MIPS_INS_SW,
    MipsInsn::MIPS_INS_SD,
    MipsInsn::MIPS_INS_SWL,
    MipsInsn::MIPS_INS_SWR,
    MipsInsn::MIPS_INS_SDL,
    MipsInsn::MIPS_INS_SDR,
    MipsInsn::MIPS_INS_SC,
    MipsInsn::MIPS_INS_SCD,
    MipsInsn::MIPS_INS_SWC1,
    MipsInsn::MIPS_INS_SDC1,
];

/// Check if instruction belongs to any of the specified groups
pub fn has_any_group(cs: &Capstone, insn: &capstone::Insn, groups: &[u32]) -> bool {
    if let Ok(detail) = cs.insn_detail(insn) {
        for group in detail.groups() {
            if groups.contains(&(group.0 as u32)) {
                return true;
            }
        }
    }
    false
}

/// Check if instruction matches a specific MIPS instruction type
pub fn insn_is(insn: &capstone::Insn, expected: MipsInsn) -> bool {
    insn.id().0 == expected as u32
}

/// Check if instruction matches any in a list of MIPS instruction types
pub fn insn_in(insn: &capstone::Insn, expected: &[MipsInsn]) -> bool {
    let id = insn.id().0;
    expected.iter().any(|&e| id == e as u32)
}

/// Check if instruction is a branch or jump (has a delay slot)
pub fn is_branch(cs: &Capstone, insn: &capstone::Insn) -> bool {
    // JAL has no CALL group, ERET has no groups at all
    insn_in(insn, &[MipsInsn::MIPS_INS_JAL, MipsInsn::MIPS_INS_ERET])
        || has_any_group(
            cs,
            insn,
            &[
                MipsInsnGroup::MIPS_GRP_BRANCH_RELATIVE,
                MipsInsnGroup::MIPS_GRP_JUMP,
                MipsInsnGroup::MIPS_GRP_CALL, // jalr
            ],
        )
}

/// Check if instruction is an unconditional branch
///
/// Cannot rely solely on groups since conditional branches also have JUMP group.
/// RET group is never assigned by Capstone for MIPS.
pub fn is_unconditional_branch(insn: &capstone::Insn) -> bool {
    insn_in(
        insn,
        &[
            MipsInsn::MIPS_INS_B,
            MipsInsn::MIPS_INS_J,
            MipsInsn::MIPS_INS_JR,
            MipsInsn::MIPS_INS_ERET,
        ],
    )
}

/// Check if instruction is a "branch likely" instruction.
pub fn is_branch_likely(insn: &capstone::Insn) -> bool {
    insn_in(insn, BRANCH_LIKELY_INSNS)
}

/// Check if instruction is a function call (jal, bal, jalr)
pub fn is_call_instruction(cs: &Capstone, insn: &capstone::Insn) -> bool {
    // JAL and BAL have no CALL group; CALL group catches jalr
    insn_in(insn, &[MipsInsn::MIPS_INS_JAL, MipsInsn::MIPS_INS_BAL])
        || has_any_group(cs, insn, &[MipsInsnGroup::MIPS_GRP_CALL])
}

/// Check if instruction is a function return (jr) or exception return (eret)
///
/// Note: Capstone never assigns RET group for MIPS, even for `jr $ra`.
pub fn is_function_end(insn: &capstone::Insn) -> bool {
    insn_in(insn, &[MipsInsn::MIPS_INS_JR, MipsInsn::MIPS_INS_ERET])
}

/// Get the branch target address from an instruction
pub fn get_branch_target(cs: &Capstone, insn: &capstone::Insn) -> Option<u32> {
    let detail = cs.insn_detail(insn).ok()?;
    let arch_detail = detail.arch_detail();
    let mips_detail = arch_detail.mips()?;

    for op in mips_detail.operands() {
        if let MipsOperand::Imm(imm) = op {
            return Some(imm as u32);
        }
    }
    None
}

/// Check if instruction has an immediate target that should be replaced with a label
pub fn has_immediate_target(insn: &capstone::Insn) -> bool {
    insn_in(insn, IMMEDIATE_TARGET_INSNS)
}

/// Check if instruction is a jump (j/jal) with pseudo-absolute target
pub fn is_absolute_jump(insn: &capstone::Insn) -> bool {
    insn_is(insn, MipsInsn::MIPS_INS_J) || insn_is(insn, MipsInsn::MIPS_INS_JAL)
}

/// Check if instruction is a load or store
pub fn is_load_or_store(insn: &capstone::Insn) -> bool {
    insn_in(insn, LOAD_INSNS) || insn_in(insn, STORE_INSNS)
}

/// Return the memory access size in bytes for a load/store instruction.
pub fn load_store_access_size(insn: &capstone::Insn) -> u8 {
    let id = insn.id().0;
    if id == MipsInsn::MIPS_INS_LB as u32
        || id == MipsInsn::MIPS_INS_LBU as u32
        || id == MipsInsn::MIPS_INS_SB as u32
    {
        1
    } else if id == MipsInsn::MIPS_INS_LH as u32
        || id == MipsInsn::MIPS_INS_LHU as u32
        || id == MipsInsn::MIPS_INS_SH as u32
    {
        2
    } else if id == MipsInsn::MIPS_INS_LD as u32
        || id == MipsInsn::MIPS_INS_SD as u32
        || id == MipsInsn::MIPS_INS_LDL as u32
        || id == MipsInsn::MIPS_INS_LDR as u32
        || id == MipsInsn::MIPS_INS_SDL as u32
        || id == MipsInsn::MIPS_INS_SDR as u32
        || id == MipsInsn::MIPS_INS_LLD as u32
        || id == MipsInsn::MIPS_INS_SCD as u32
        || id == MipsInsn::MIPS_INS_LDC1 as u32
        || id == MipsInsn::MIPS_INS_SDC1 as u32
    {
        8
    } else {
        4
    }
}

/// Check if instruction is a load (writes to register)
pub fn is_load(insn: &capstone::Insn) -> bool {
    insn_in(insn, LOAD_INSNS)
}

/// Check if instruction is a move (or $rd, $rs, $zero with 2 operands displayed)
pub fn is_move_insn(insn: &capstone::Insn) -> bool {
    insn_is(insn, MipsInsn::MIPS_INS_MOVE)
}

/// Disassemble a single instruction and process it with the given closure.
/// Returns None if disassembly fails or no instruction is produced.
pub fn with_single_insn<F, R>(cs: &Capstone, code: &[u8], addr: u64, f: F) -> Option<R>
where
    F: FnOnce(&capstone::Insn) -> R,
{
    let insns = cs.disasm_count(code, addr, 1).ok()?;
    insns.first().map(f)
}
