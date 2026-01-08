// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests verifying assumptions about Capstone's MIPS instruction decoding.
//!
//! These tests document how Capstone assigns instruction IDs and groups to
//! various MIPS instructions. The decompiler relies on these behaviors for
//! control flow analysis and instruction formatting.
//!
//! Note: Capstone's group assignments don't always match intuition:
//! - `jal` doesn't have CALL group (only `jalr` does)
//! - `jr $ra` doesn't have RET group (just JUMP)
//! - `bal` has BRANCH_RELATIVE but not CALL
//! - `eret` doesn't have IRET group

use capstone::arch::mips::{MipsInsn, MipsInsnGroup};
use capstone::prelude::*;
use capstone::{Endian, Error, Syntax};

fn create_capstone() -> Capstone {
    Capstone::new()
        .mips()
        .mode(arch::mips::ArchMode::Mips64)
        .endian(Endian::Big)
        .detail(true)
        .build()
        .expect("Failed to create Capstone instance")
}

fn disasm_one(cs: &Capstone, bytes: &[u8]) -> capstone::OwnedInsn<'static> {
    cs.disasm_count(bytes, 0, 1)
        .expect("disassembly failed")
        .iter()
        .next()
        .expect("no instruction decoded")
        .into()
}

fn has_group(cs: &Capstone, insn: &capstone::OwnedInsn, group: u32) -> bool {
    cs.insn_detail(insn)
        .expect("no detail")
        .groups()
        .iter()
        .any(|g| g.0 as u32 == group)
}

// =============================================================================
// Jump instruction group tests
// =============================================================================

#[test]
fn j_has_jump_group() {
    let cs = create_capstone();
    // j 0x100 (opcode 0x02)
    let insn = disasm_one(&cs, &[0x08, 0x00, 0x00, 0x40]);
    assert!(has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_JUMP));
}

#[test]
fn jr_has_jump_group() {
    let cs = create_capstone();
    // jr $t0 (opcode 0x00, funct 0x08)
    let insn = disasm_one(&cs, &[0x01, 0x00, 0x00, 0x08]);
    assert!(has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_JUMP));
}

#[test]
fn jr_ra_has_jump_but_not_ret_group() {
    let cs = create_capstone();
    // jr $ra - Capstone marks as JUMP, not RET
    let insn = disasm_one(&cs, &[0x03, 0xe0, 0x00, 0x08]);
    assert!(has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_JUMP));
    assert!(!has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_RET));
}

// =============================================================================
// Call instruction group tests
// =============================================================================

#[test]
fn jal_has_no_call_group() {
    let cs = create_capstone();
    // jal 0x100 - Capstone doesn't mark as CALL (surprisingly)
    let insn = disasm_one(&cs, &[0x0c, 0x00, 0x00, 0x40]);
    assert!(!has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_CALL));
}

#[test]
fn jalr_has_call_group() {
    let cs = create_capstone();
    // jalr $t0 (opcode 0x00, funct 0x09)
    let insn = disasm_one(&cs, &[0x01, 0x00, 0xf8, 0x09]);
    assert!(has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_CALL));
}

#[test]
fn bal_has_branch_relative_but_not_call() {
    let cs = create_capstone();
    // bal 0x100 (BGEZAL $zero, offset) - has BRANCH_RELATIVE but not CALL
    let insn = disasm_one(&cs, &[0x04, 0x11, 0x00, 0x3e]);
    assert!(has_group(
        &cs,
        &insn,
        MipsInsnGroup::MIPS_GRP_BRANCH_RELATIVE
    ));
    assert!(!has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_CALL));
}

// =============================================================================
// Branch instruction group tests
// =============================================================================

#[test]
fn b_has_branch_relative_and_jump_groups() {
    let cs = create_capstone();
    // b 0x100 (BEQ $zero, $zero, offset)
    let insn = disasm_one(&cs, &[0x10, 0x00, 0x00, 0x3e]);
    assert!(has_group(
        &cs,
        &insn,
        MipsInsnGroup::MIPS_GRP_BRANCH_RELATIVE
    ));
    assert!(has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_JUMP));
}

#[test]
fn beq_has_branch_relative_and_jump_groups() {
    let cs = create_capstone();
    // beq $t0, $t1, 0x100
    let insn = disasm_one(&cs, &[0x11, 0x09, 0x00, 0x3e]);
    assert!(has_group(
        &cs,
        &insn,
        MipsInsnGroup::MIPS_GRP_BRANCH_RELATIVE
    ));
    assert!(has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_JUMP));
}

// =============================================================================
// Privileged instruction tests
// =============================================================================

#[test]
fn eret_has_no_iret_group() {
    let cs = create_capstone();
    // eret - Capstone doesn't mark as IRET
    let insn = disasm_one(&cs, &[0x42, 0x00, 0x00, 0x18]);
    assert!(!has_group(&cs, &insn, MipsInsnGroup::MIPS_GRP_IRET));
}

// =============================================================================
// Move instruction ID tests
// =============================================================================

#[test]
fn addu_with_zero_is_move() {
    let cs = create_capstone();
    // addu $t0, $t1, $zero -> move $t0, $t1
    let insn = disasm_one(&cs, &[0x01, 0x20, 0x40, 0x21]);
    assert_eq!(insn.id().0, MipsInsn::MIPS_INS_MOVE as u32);
}

#[test]
fn or_with_zero_is_move() {
    let cs = create_capstone();
    // or $t0, $t1, $zero -> move $t0, $t1
    let insn = disasm_one(&cs, &[0x01, 0x20, 0x40, 0x25]);
    assert_eq!(insn.id().0, MipsInsn::MIPS_INS_MOVE as u32);
}

// =============================================================================
// CP0 instruction tests
// =============================================================================

#[test]
fn mfc0_shows_cp0_reg_as_gpr_name() {
    let cs = create_capstone();
    // mfc0 $t0, $17, 0 (CP0 register 17 = LLAddr)
    // Capstone shows CP0 reg as GPR name ($s1 for reg 17)
    let insn = disasm_one(&cs, &[0x40, 0x08, 0x88, 0x00]);
    assert_eq!(insn.mnemonic(), Some("mfc0"));
    // Capstone outputs "$t0, $s1, 0" - the $s1 is actually CP0 reg 17
    let op_str = insn.op_str().unwrap();
    assert!(op_str.contains("$t0"));
    assert!(op_str.contains("$s1")); // CP0 reg 17 shown as GPR name
}

// =============================================================================
// Syntax option tests
// =============================================================================

#[test]
fn noregname_syntax_not_supported() {
    // CS_OPT_SYNTAX_NOREGNAME is not supported for MIPS in Capstone 5.x.
    // Support was added in the upstream `next` branch (Sep 2024) but hasn't
    // been released yet. This test will fail once a new Capstone version
    // with MIPS NOREGNAME support is released, signaling we can simplify
    // the CP0 register formatting code.
    let mut cs = create_capstone();
    let result = cs.set_syntax(Syntax::NoRegName);
    assert!(
        matches!(result, Err(Error::InvalidOption)),
        "MIPS NOREGNAME is now supported - consider simplifying gpr_name_to_number usage"
    );
}
