// SPDX-License-Identifier: GPL-3.0-or-later
//! Assembly file generation for firmware sections.
//!
//! This module generates assembly source files (.S) for firmware sections,
//! handling code disassembly, data emission, and the SHDR header structure.

use anyhow::{Context, Result, ensure};
use byteorder::{BigEndian, ByteOrder};
use capstone::prelude::*;
use std::fs::File;
use std::path::Path;

use crate::annotations::{Annotations, BssNames, Comments, Functions, Labels, Operands};
use crate::hardware::SystemConstants;
use crate::mips::format::{format_instruction_for_gas, replace_magic_constants};
use crate::mips::insn::is_branch;
use crate::output::util::{count_consecutive_words, create_output_file, read_word};
use crate::output::writer::{AssemblyWriter, build_comment};
use crate::section::{DataType, Section, escape_string};
use crate::shdr::{
    ELF_OFFSET_EHSIZE, ELF_OFFSET_PHNUM, ELF_OFFSET_PHOFF, ELF_OFFSET_SHNUM, ELF_OFFSET_SHOFF,
    SHDR_SIZE, SUBSECTION_HEADER_SIZE, SUBSECTION_RODATA, SUBSECTION_RWDATA,
};

/// Context for assembly emission, bundling commonly-passed parameters.
///
/// This struct groups together the disassembler, section data, and all annotation
/// sources needed during assembly generation, reducing parameter count in functions.
struct EmissionContext<'a> {
    cs: &'a Capstone,
    section: &'a Section,
    labels: &'a Labels,
    comments: &'a mut Comments,
    funcs: &'a mut Functions,
    operands: &'a mut Operands,
    sys_consts: &'a SystemConstants,
    bss_names: &'a BssNames,
}

/// Get the ELF section name for a data subsection index.
fn subsection_name(index: usize) -> &'static str {
    match index {
        SUBSECTION_RODATA => "rodata",
        SUBSECTION_RWDATA => "rwdata",
        _ => panic!("Unexpected subsection index: {}", index),
    }
}

/// Extract disassembly info (mnemonic, op_str) from a Capstone instruction.
fn get_disasm_info<'a>(insn: &'a capstone::Insn) -> (&'a str, &'a str) {
    (
        insn.mnemonic().unwrap_or("???"),
        insn.op_str().unwrap_or(""),
    )
}

/// Emit a label and optional function header for the given offset, if applicable.
fn emit_label_and_function_header(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    offset: usize,
    addr: u32,
) -> Result<()> {
    if let Some(label) = ctx.section.get_label_at_offset(offset, ctx.labels) {
        if ctx.section.control_flow.function_starts.contains(&offset) {
            let end_addr = ctx.section.get_function_end_addr(offset);
            let desc = ctx.funcs.remove(addr);
            w.function_header(&label, addr, end_addr, desc.as_deref())?;
        }
        w.label(&label, addr)?;
    }
    Ok(())
}

/// Emit a single instruction at the given offset.
/// Returns (new_offset, is_branch) where is_branch indicates if this instruction has a delay slot.
fn emit_instruction(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    offset: usize,
    prev_was_branch: bool,
) -> Result<(usize, bool)> {
    let addr = ctx.section.offset_to_addr(offset);

    if offset + 4 > ctx.section.data.len() {
        return Ok((offset + 1, false));
    }

    let code_slice = &ctx.section.data[offset..offset + 4];
    let word = read_word(&ctx.section.data, offset);

    emit_label_and_function_header(w, ctx, offset, addr)?;

    // Try to emit as actual instruction
    let mut emitted_instruction = false;
    let mut current_is_branch = false;

    if let Ok(insns) = ctx.cs.disasm_all(code_slice, addr.into())
        && let Some(insn) = insns.iter().next()
    {
        // Check if this instruction is a branch (has delay slot)
        current_is_branch = is_branch(ctx.cs, insn);

        // Build comment: combine user comment with unreachable marker if needed
        let is_unreachable = ctx.section.control_flow.unreachable_code.contains(&offset);
        let user_comment = ctx.comments.remove(addr);
        let comment = build_comment(user_comment.as_deref(), is_unreachable);

        // Try to format for gas
        if let Some(formatted) = format_instruction_for_gas(
            ctx.cs,
            insn,
            ctx.section,
            offset,
            ctx.labels,
            ctx.sys_consts,
            ctx.bss_names,
        ) {
            // Apply operand replacements and magic constant replacement
            let formatted = ctx.operands.apply_and_remove(addr, &formatted);
            let formatted = replace_magic_constants(&formatted, ctx.sys_consts);

            w.instruction(&formatted, prev_was_branch, comment.as_deref())?;
        } else {
            // Fallback to .word with disassembly comment for instructions we can't format
            w.word_fallback(
                word,
                prev_was_branch,
                Some(get_disasm_info(insn)),
                comment.as_deref(),
            )?;
        }
        emitted_instruction = true;
    }

    if !emitted_instruction {
        let user_comment = ctx.comments.remove(addr);
        w.word_fallback(word, prev_was_branch, None, user_comment.as_deref())?;
    }

    Ok((offset + 4, current_is_branch))
}

/// Get fill byte and word values for a padding data type.
/// Returns (fill_byte, fill_word) where fill_byte is 0x00 or 0xff
/// and fill_word is the corresponding 32-bit value.
fn get_fill_values(dtype: DataType) -> (u8, u32) {
    match dtype {
        DataType::PadZero => (0x00, 0x00000000),
        DataType::PadOnes => (0xff, 0xffffffff),
        _ => (0x00, 0x00000000), // Default to zeros for non-padding types
    }
}

/// Find the effective end offset for a fill run, stopping at string boundaries.
fn fill_end_before_string(section: &Section, start_offset: usize, end_offset: usize) -> usize {
    (start_offset + 4..end_offset)
        .step_by(4)
        .find(|o| section.strings.contains_key(o))
        .unwrap_or(end_offset)
}

/// Emit a data word as .int, using a label if the word is a pointer to a known target,
/// a symbolic device address if it matches a known device register, or an operand
/// replacement if one is defined for this address.
fn emit_data_word(
    w: &mut AssemblyWriter<File>,
    section: &Section,
    word: u32,
    addr: u32,
    labels: &Labels,
    operands: &mut Operands,
    sys_consts: &SystemConstants,
) -> Result<()> {
    // Check if the word is a pointer to a known target (branch target or labeled address)
    if let Some(label) = section.get_label_for_pointer(word, labels) {
        w.int_label(&label)?;
    } else if let Some(symbolic) = sys_consts.lookup_device_address(word) {
        // Use symbolic device register address
        w.int_label(&symbolic)?;
    } else {
        // Check for operand replacement (e.g., replacing 0x100 with ROM_ALIGN)
        let hex_str = format!("{:#010x}", word);
        let replaced = operands.apply_and_remove(addr, &hex_str);
        if replaced != hex_str {
            // Operand was replaced with a symbolic name
            w.int_label(&replaced)?;
        } else {
            w.int_hex(word)?;
        }
    }
    Ok(())
}

/// Emit 4 bytes with labels at unaligned positions.
/// If `fill_byte` is Some, emit that value for all bytes; otherwise read from section data.
fn emit_word_as_bytes_with_labels(
    w: &mut AssemblyWriter<File>,
    section: &Section,
    offset: usize,
    labels: &Labels,
    fill_byte: Option<u8>,
) -> Result<()> {
    for byte_offset in 0..4 {
        let byte_addr = section.offset_to_addr(offset + byte_offset);
        if let Some(label) = labels.get(byte_addr) {
            w.label(label, byte_addr)?;
        }
        let byte_value = fill_byte.unwrap_or(section.data[offset + byte_offset]);
        w.byte_hex(byte_value)?;
    }
    Ok(())
}

/// Emit a run of padding bytes, breaking at label points.
/// Uses .fill directives for efficiency, but breaks into byte emission at label boundaries.
fn emit_padding_run(
    w: &mut AssemblyWriter<File>,
    ctx: &EmissionContext,
    start_offset: usize,
    run_end: usize,
    fill_byte: u8,
    fill_value: u32,
) -> Result<()> {
    let mut pending_count = 0usize;

    for i in (start_offset..run_end).step_by(4) {
        let a = ctx.section.offset_to_addr(i);
        let has_unaligned_label = ctx.labels.has_any_in_range(a, a + 4);

        if has_unaligned_label {
            w.fill_words(pending_count, fill_value)?;
            pending_count = 0;
            emit_word_as_bytes_with_labels(w, ctx.section, i, ctx.labels, Some(fill_byte))?;
        } else if let Some(label) = ctx.labels.get(a) {
            w.fill_words(pending_count, fill_value)?;
            pending_count = 0;
            w.label(label, a)?;
            pending_count += 1;
        } else {
            pending_count += 1;
        }
    }

    w.fill_words(pending_count, fill_value)
}

/// Emit a run of data words, emitting labels and handling unaligned labels.
fn emit_data_word_run(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    start_offset: usize,
    run_end: usize,
) -> Result<()> {
    for i in (start_offset..run_end).step_by(4) {
        let word = read_word(&ctx.section.data, i);
        let a = ctx.section.offset_to_addr(i);

        if ctx.labels.has_any_in_range(a, a + 4) {
            emit_word_as_bytes_with_labels(w, ctx.section, i, ctx.labels, None)?;
        } else {
            if let Some(label) = ctx.labels.get(a) {
                w.label(label, a)?;
            }
            emit_data_word(
                w,
                ctx.section,
                word,
                a,
                ctx.labels,
                ctx.operands,
                ctx.sys_consts,
            )?;
        }
    }
    Ok(())
}

/// Find the end of a run of consecutive data types starting at start_offset.
fn find_run_end(
    ctx: &EmissionContext,
    start_offset: usize,
    end_offset: usize,
    dtype: DataType,
) -> usize {
    let mut run_end = start_offset;
    while run_end < end_offset {
        if ctx.section.data_type_at(run_end) != dtype {
            break;
        }
        run_end += 4;
    }
    run_end
}

/// Emit a run of data/padding bytes starting at the given offset.
/// Scans forward to find all consecutive bytes of the same type, then emits them.
/// Returns the new offset after the run.
fn emit_data_run(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    start_offset: usize,
    end_offset: usize,
    start_dtype: DataType,
) -> Result<usize> {
    let run_end = find_run_end(ctx, start_offset, end_offset, start_dtype);

    if start_dtype.is_padding() {
        let (fill_byte, fill_value) = get_fill_values(start_dtype);
        emit_padding_run(w, ctx, start_offset, run_end, fill_byte, fill_value)?;
    } else {
        emit_data_word_run(w, ctx, start_offset, run_end)?;
    }

    Ok(run_end)
}

/// Emit a string at the given offset, handling any inner labels.
/// Returns the new offset after the string (including padding).
fn emit_string(
    w: &mut AssemblyWriter<File>,
    ctx: &EmissionContext,
    offset: usize,
) -> Result<usize> {
    let addr = ctx.section.offset_to_addr(offset);
    let is_data = ctx.section.shdr.is_data();
    let pad_to = if is_data { 1 } else { 4 };

    let Some(detected_string) = ctx.section.strings.get(&offset) else {
        // String data marked but no string info found - skip
        return Ok(offset + if is_data { 1 } else { 4 });
    };

    let string_start = offset;
    let string_bytes = detected_string.length;

    // Calculate the full padded length of the string (content + NUL + padding)
    // The string macro pads to pad_to alignment
    let content_len = string_bytes - 1; // Length without NUL
    let padded_len = if is_data {
        string_bytes
    } else {
        // For code sections, align to pad_to bytes
        // The string macro formula: content + fill where fill = pad_to - (content % pad_to)
        let fill = pad_to - (content_len % pad_to);
        content_len + fill
    };

    // Find all labels that fall inside this string (after start, within padded region)
    let mut inner_labels = Vec::new();
    for label_offset in (string_start + 1)..(string_start + padded_len) {
        let label_addr = ctx.section.offset_to_addr(label_offset);
        if let Some(label) = ctx.labels.get(label_addr) {
            inner_labels.push((label_offset, label.to_string()));
        }
    }

    // Emit the string, breaking at label points if necessary
    let start_label = ctx
        .labels
        .get(addr)
        .map(|s| s.to_string())
        .unwrap_or_else(|| ctx.section.data_label_for_addr(addr));

    // Content ends before NUL terminator
    let content_end_offset = string_start + content_len;

    if inner_labels.is_empty() {
        // No labels inside, emit as before
        w.label(&start_label, addr)?;
        w.string_macro(pad_to, &detected_string.escaped)?;
    } else {
        // Break string at label points
        // Emit the start label
        w.label(&start_label, addr)?;

        let mut current_offset = string_start;
        let string_end_offset = string_start + padded_len;

        for (label_offset, label) in &inner_labels {
            if *label_offset > current_offset {
                if current_offset < content_end_offset {
                    // Emit content bytes as .ascii
                    let end = (*label_offset).min(content_end_offset);
                    let bytes = &ctx.section.data[current_offset..end];
                    let escaped = escape_string(bytes, false);
                    w.ascii(&escaped)?;
                    current_offset = end;
                }
                // Emit any NUL/padding bytes before this label
                if current_offset < *label_offset {
                    w.fill_bytes(*label_offset - current_offset, 0)?;
                    current_offset = *label_offset;
                }
            }
            // Emit the inner label
            let label_addr = ctx.section.offset_to_addr(*label_offset);
            w.label(label, label_addr)?;
        }

        // Emit remaining content if any
        if current_offset < content_end_offset {
            let bytes = &ctx.section.data[current_offset..content_end_offset];
            let escaped = escape_string(bytes, false);
            w.ascii(&escaped)?;
            current_offset = content_end_offset;
        }

        // Emit remaining NUL/padding bytes
        if current_offset < string_end_offset {
            w.fill_bytes(string_end_offset - current_offset, 0)?;
        }
    }

    Ok(offset + padded_len)
}

/// Check if the range from `offset` to the next exception vector can be skipped.
/// For Code: requires unreachable nops throughout.
/// For PadZero: requires all zero bytes throughout.
fn check_skip_to_exception_vector(
    ctx: &EmissionContext,
    offset: usize,
    dtype: DataType,
) -> Option<usize> {
    // For Code, only check unreachable code
    if dtype == DataType::Code && !ctx.section.control_flow.unreachable_code.contains(&offset) {
        return None;
    }

    let next_vec = ctx.section.next_exception_vector(offset + 1)?;

    let can_skip = match dtype {
        DataType::Code => ctx.section.is_unreachable_nop_range(offset, next_vec),
        DataType::PadZero => (offset..next_vec).step_by(4).all(|off| {
            ctx.section
                .data
                .get(off..off + 4)
                .is_some_and(|bytes| bytes == [0, 0, 0, 0])
        }),
        _ => false,
    };

    if can_skip { Some(next_vec) } else { None }
}

/// Emit code/data for a range of offsets
fn emit_code_range(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    start_offset: usize,
    end_offset: usize,
) -> Result<()> {
    let mut offset = start_offset;
    // Track if previous instruction was a branch to indent delay slot
    let mut prev_was_branch = false;

    while offset < end_offset {
        let dtype = ctx.section.data_type_at(offset);

        match dtype {
            DataType::Code => {
                // Check if we're at a run of unreachable nops leading to an exception vector
                if let Some(next_vec) = check_skip_to_exception_vector(ctx, offset, dtype) {
                    w.org(next_vec)?;
                    offset = next_vec;
                    prev_was_branch = false;
                    continue;
                }
                let (new_offset, is_branch) = emit_instruction(w, ctx, offset, prev_was_branch)?;
                offset = new_offset;
                prev_was_branch = is_branch;
            }
            DataType::Data | DataType::Unknown | DataType::PadZero | DataType::PadOnes => {
                // For PadZero, check if this leads to an exception vector
                if dtype == DataType::PadZero
                    && let Some(next_vec) = check_skip_to_exception_vector(ctx, offset, dtype)
                {
                    w.org(next_vec)?;
                    offset = next_vec;
                    prev_was_branch = false;
                    continue;
                }
                offset = emit_data_run(w, ctx, offset, end_offset, dtype)?;
                prev_was_branch = false;
            }
            DataType::Header => {
                offset += 4;
                prev_was_branch = false;
            }
            DataType::String => {
                offset = emit_string(w, ctx, offset)?;
                prev_was_branch = false;
            }
        }
    }

    Ok(())
}

/// Emit a data section (like env or version) with byte-level string handling
fn emit_data_section(
    w: &mut AssemblyWriter<File>,
    section: &Section,
    start_offset: usize,
    end_offset: usize,
) -> Result<()> {
    let is_env_section = section.shdr.name == "env";
    let string_align = if is_env_section { 1 } else { 4 };
    let mut offset = start_offset;

    while offset < end_offset {
        // Check if there's a string starting at this exact offset
        if let Some(detected_string) = section.strings.get(&offset) {
            // Emit the string with data label
            let addr = section.offset_to_addr(offset);
            w.label_simple(&section.data_label_for_addr(addr))?;
            w.string_macro(string_align, &detected_string.escaped)?;

            // Advance past the string (plus padding for version section)
            offset += if is_env_section {
                detected_string.length
            } else {
                detected_string.length.next_multiple_of(4)
            };
        } else if offset.is_multiple_of(4)
            && offset + 4 <= end_offset
            && offset + 4 <= section.data.len()
        {
            // Emit as 4-byte word(s) (only when 4-byte aligned)
            let word = read_word(&section.data, offset);
            // Check for runs of zeros or ones and emit as fill
            let count = if word == 0x00000000 || word == 0xffffffff {
                let fill_end = fill_end_before_string(section, offset, end_offset);
                count_consecutive_words(&section.data, offset, fill_end, word)
            } else {
                1
            };
            w.fill_words(count, word)?;
            offset += count * 4;
        } else {
            // Emit remaining bytes individually (less than 4 bytes left)
            let byte = *section.data.get(offset).unwrap_or(&0);
            w.byte_hex(byte)?;
            offset += 1;
        }
    }

    Ok(())
}

/// Emit the first two words of a section (at offsets 0 and 4).
/// For code sections, these are instructions (first is a branch, second is its delay slot).
/// For data sections, these are emitted as .word directives.
fn emit_initial_instructions(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
) -> Result<()> {
    for offset in [0usize, 4usize] {
        let addr = ctx.section.offset_to_addr(offset);
        let word = read_word(&ctx.section.data, offset);

        emit_label_and_function_header(w, ctx, offset, addr)?;

        if ctx.section.shdr.is_data() {
            // Data sections: emit as .word
            w.int_hex(word)?;
        } else {
            // Code sections: emit as instructions
            let code_slice = &ctx.section.data[offset..offset + 4];
            // Second instruction is the delay slot of the first (branch) instruction
            let delay_slot = offset == 4;

            let insns = ctx
                .cs
                .disasm_count(code_slice, addr.into(), 1)
                .context("Failed to disassemble initial instruction")?;
            let insn = insns.iter().next().context("No instruction decoded")?;

            // First instruction must be a branch
            if offset == 0 {
                ensure!(
                    is_branch(ctx.cs, insn),
                    "First instruction of section must be a branch"
                );
            }

            if let Some(formatted) = format_instruction_for_gas(
                ctx.cs,
                insn,
                ctx.section,
                offset,
                ctx.labels,
                ctx.sys_consts,
                ctx.bss_names,
            ) {
                let formatted = ctx.operands.apply_and_remove(addr, &formatted);
                let formatted = replace_magic_constants(&formatted, ctx.sys_consts);
                w.instruction(&formatted, delay_slot, None)?;
            } else {
                // Fall back to .word with disassembly comment
                w.word_fallback(word, delay_slot, Some(get_disasm_info(insn)), None)?;
            }
        }
    }

    Ok(())
}

/// Build the SHDR length expression for a loadable section.
/// The length is the sum of all ELF section sizes (text, data headers, data, sentinel).
fn build_shdr_length_expr(num_subsections: usize) -> String {
    let mut parts = vec!["ELFSECT_SIZE(text)".to_string()];
    for i in 1..num_subsections {
        let sect_name = subsection_name(i);
        parts.push(format!("ELFSECT_SIZE({}_header)", sect_name));
        parts.push(format!("ELFSECT_SIZE({})", sect_name));
    }
    parts.push("ELFSECT_SIZE(sentinel)".to_string());
    parts.join(" + ")
}

/// Emit a data subsection (rodata or rwdata) with its header.
fn emit_data_subsection(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    subsection: &crate::section::Subsection,
    sect_name: &str,
) -> Result<()> {
    let header_name = format!("{}_header", sect_name);

    // Emit header in its own section
    w.section(&header_name, "a")?;
    w.raw(&format!("\telfsect_start {}", header_name))?;
    w.raw(&format!("\tsubsect_header {:#010x}", subsection.load_addr))?;
    w.raw(&format!("\telfsect_end {}", header_name))?;
    w.blank_line()?;

    // Emit data in its own section
    w.section(sect_name, "a")?;
    w.raw(&format!("\telfsect_start {}", sect_name))?;
    w.raw(&format!("\tsubsect_start {:#010x}", subsection.load_addr))?;
    w.blank_line()?;

    // Emit code/data for this subsection
    let subsect_end = subsection.code_offset + subsection.length;
    emit_code_range(w, ctx, subsection.code_offset, subsect_end)?;

    // Emit subsect_end and ELF section end
    w.blank_line()?;
    w.raw(&format!("\tsubsect_end {:#010x}", subsection.load_addr))?;
    w.raw(&format!("\telfsect_end {}", sect_name))?;

    // Define BSS_BASE after rwdata ends
    if sect_name == "rwdata" {
        w.comment("BSS (uninitialized data) starts after rwdata")?;
        w.raw("BSS_BASE = .")?;
    }
    w.blank_line()?;

    Ok(())
}

/// Emit a loadable section with subsections (text, rodata, rwdata, sentinel).
fn emit_loadable_section(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    section_type_expr: &str,
) -> Result<()> {
    let first_subsection = ctx
        .section
        .subsections
        .first()
        .context("loadable sections must have subsections")?;

    // 1. Emit subsect_start for first subsection (at offset 0) and start of .text ELF section
    w.raw(&format!(
        "\tsubsect_start {:#010x}",
        first_subsection.load_addr
    ))?;
    w.raw("\telfsect_start text")?;
    w.blank_line()?;

    // 2. Emit the first two instructions with load addresses
    emit_initial_instructions(w, ctx)?;

    // 3. Build and emit SHDR with explicit length expression
    let length_expr = build_shdr_length_expr(ctx.section.subsections.len());
    w.blank_line()?;
    w.raw(&format!(
        "\tshdr_with_len {}, {}, {}, {}",
        ctx.section.shdr.name, ctx.section.shdr.version, section_type_expr, length_expr
    ))?;
    w.blank_line()?;

    // 4. Emit subsect_header for first subsection
    w.raw(&format!(
        "\tsubsect_header {:#010x}",
        first_subsection.load_addr
    ))?;
    w.blank_line()?;

    // 5. Emit code for first subsection (from code_offset onwards)
    let subsect_end = first_subsection.code_offset + first_subsection.length;
    emit_code_range(w, ctx, first_subsection.code_offset, subsect_end)?;

    // 6. Emit subsect_end for first subsection and end of .text ELF section
    w.blank_line()?;
    w.raw(&format!(
        "\tsubsect_end {:#010x}",
        first_subsection.load_addr
    ))?;
    w.raw("\telfsect_end text")?;
    w.blank_line()?;

    // 7. Handle subsequent subsections (rodata, rwdata)
    for (i, subsection) in ctx.section.subsections.iter().enumerate().skip(1) {
        emit_data_subsection(w, ctx, subsection, subsection_name(i))?;
    }

    // 8. Emit sentinel in its own section
    w.section("sentinel", "a")?;
    w.raw("\telfsect_start sentinel")?;
    let sentinel_addr = ctx.section.sentinel_addr();
    w.raw(&format!("\tsentinel {:#010x}", sentinel_addr))?;

    Ok(())
}

/// Emit a non-loadable section (no subsections).
fn emit_non_loadable_section(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    section_type_expr: &str,
) -> Result<()> {
    // Emit first two instructions then SHDR then code
    emit_initial_instructions(w, ctx)?;

    // Mark section start (used for automatic length calculation)
    w.blank_line()?;
    w.raw(&format!("\tsection_start {}", ctx.section.shdr.name))?;

    // Emit the SHDR header using the macro
    w.raw(&format!(
        "\tshdr {}, {}, {}",
        ctx.section.shdr.name, ctx.section.shdr.version, section_type_expr
    ))?;
    w.blank_line()?;

    // Non-loadable code sections have a sentinel (8 zero bytes) after the SHDR
    if ctx.section.shdr.is_code() {
        w.raw("\tsentinel 0x00000000")?;
        w.blank_line()?;

        // Code starts after SHDR + sentinel
        let code_start = SHDR_SIZE + SUBSECTION_HEADER_SIZE;
        let end_offset = ctx.section.shdr.checksum_offset();

        // If we have virtual subsections, emit code in segments
        if !ctx.section.virtual_subsections.is_empty() {
            emit_code_with_virtual_subsections(w, ctx, code_start, end_offset)?;
        } else {
            emit_code_range(w, ctx, code_start, end_offset)?;
        }
    } else {
        // Data sections: emit from SHDR onwards with byte-level string handling
        let end_offset = ctx.section.shdr.checksum_offset();
        emit_data_section(w, ctx.section, SHDR_SIZE, end_offset)?;
    }

    Ok(())
}

/// Emit code for a section with virtual subsections.
/// This handles the transitions between normal .text and virtual subsections.
fn emit_code_with_virtual_subsections(
    w: &mut AssemblyWriter<File>,
    ctx: &mut EmissionContext,
    code_start: usize,
    code_end: usize,
) -> Result<()> {
    // Collect virtual subsection boundaries, sorted by start offset
    let mut vsub_ranges: Vec<(usize, usize, &str)> = ctx
        .section
        .virtual_subsections
        .iter()
        .map(|vsub| {
            let elf_section = vsub.elf_section.as_deref().unwrap_or("text_ram");
            (
                vsub.code_offset,
                vsub.code_offset + vsub.length,
                elf_section,
            )
        })
        .collect();
    vsub_ranges.sort_by_key(|(start, _, _)| *start);

    let mut current_offset = code_start;
    let mut segment_index = 0; // Track which text segment we're in

    for (vsub_start, vsub_end, elf_section) in &vsub_ranges {
        // Emit any code before this virtual subsection
        if current_offset < *vsub_start {
            if segment_index > 0 {
                // After a virtual section, use .text_after_N to avoid concatenation
                w.blank_line()?;
                w.section(&format!("text_after_{}", segment_index), "ax")?;
                w.blank_line()?;
            }
            emit_code_range(w, ctx, current_offset, *vsub_start)?;
        }

        // Switch to the virtual subsection's ELF section
        w.blank_line()?;
        w.comment("Relocated code section: executes at VMA, stored at LMA")?;
        w.section(elf_section, "ax")?;
        w.blank_line()?;

        // Emit the virtual subsection's code
        emit_code_range(w, ctx, *vsub_start, (*vsub_end).min(code_end))?;

        current_offset = *vsub_end;
        segment_index += 1;
    }

    // Emit any remaining code after the last virtual subsection
    if current_offset < code_end {
        if segment_index > 0 {
            w.blank_line()?;
            w.section(&format!("text_after_{}", segment_index), "ax")?;
            w.blank_line()?;
        }
        emit_code_range(w, ctx, current_offset, code_end)?;
    }

    Ok(())
}

/// Emit ELF identification fields (bytes 0-7 of version header).
fn emit_elf_ident(w: &mut AssemblyWriter<File>) -> Result<()> {
    // e_ident bytes 0-3: magic
    w.directive_with_comment("int", "ELF_MAGIC", "e_ident[EI_MAG0-3]")?;
    // e_ident bytes 4-7: class, data, version, osabi
    w.directive_with_comment("byte", "ELFCLASS32", "e_ident[EI_CLASS]")?;
    w.directive_with_comment("byte", "ELFDATA2MSB", "e_ident[EI_DATA]")?;
    w.directive_with_comment("byte", "EV_CURRENT", "e_ident[EI_VERSION]")?;
    w.directive_with_comment("byte", "ELFOSABI_NONE", "e_ident[EI_OSABI]")?;
    Ok(())
}

/// Emit SHDR metadata fields (magic, section_len, name_len block).
fn emit_shdr_meta_fields(w: &mut AssemblyWriter<File>, section: &Section) -> Result<()> {
    w.directive_with_comment("int", "SHDR_MAGIC", "SHDR magic / e_ident[EI_PAD]")?;
    w.directive_with_comment("int", "version_end - version_start", "SHDR section_len")?;
    w.directive_with_comment("byte", "version_name_end - version_name_start", "name_len")?;
    w.directive_with_comment(
        "byte",
        "version_version_end - version_version_start",
        "version_len",
    )?;
    w.directive_with_comment(
        "byte",
        section.shdr.section_type_expr(),
        "type / e_machine high byte",
    )?;
    w.directive_with_comment("byte", "EM_MIPS", "pad / e_machine low byte")?;
    Ok(())
}

/// Emit a labeled string field with 4-byte alignment padding.
fn emit_labeled_string(
    w: &mut AssemblyWriter<File>,
    label_prefix: &str,
    content: &str,
) -> Result<()> {
    w.label_simple(&format!("{}_start", label_prefix))?;
    w.ascii(content)?;
    w.label_simple(&format!("{}_end", label_prefix))?;
    w.raw(&format!(
        "\t.fill\t4 - (({}_end - {}_start) & 3), 1, 0",
        label_prefix, label_prefix
    ))?;
    Ok(())
}

/// Emit ELF header fields that overlay with the SHDR name/version area.
fn emit_elf_overlay_fields(w: &mut AssemblyWriter<File>, data: &[u8]) -> Result<()> {
    let e_phoff = BigEndian::read_u32(&data[ELF_OFFSET_PHOFF..]);
    let e_shoff = BigEndian::read_u32(&data[ELF_OFFSET_SHOFF..]);
    let ehsize_word = BigEndian::read_u32(&data[ELF_OFFSET_EHSIZE..]);
    let phnum_word = BigEndian::read_u32(&data[ELF_OFFSET_PHNUM..]);
    let shnum_word = BigEndian::read_u32(&data[ELF_OFFSET_SHNUM..]);

    w.directive_with_comment("int", format_args!("{:#010x}", e_phoff), "e_phoff")?;
    w.directive_with_comment("int", format_args!("{:#010x}", e_shoff), "e_shoff")?;
    w.directive_with_comment(
        "int",
        "EF_MIPS_ARCH_2 | EF_MIPS_NOREORDER | EF_MIPS_PIC",
        "e_flags",
    )?;

    let e_ehsize = (ehsize_word >> 16) & 0xffff;
    let e_phentsize = ehsize_word & 0xffff;
    w.directive_with_comment("short", e_ehsize, "e_ehsize")?;
    w.directive_with_comment("short", e_phentsize, "e_phentsize")?;

    let e_phnum = (phnum_word >> 16) & 0xffff;
    let e_shentsize = phnum_word & 0xffff;
    w.directive_with_comment("short", e_phnum, "e_phnum")?;
    w.directive_with_comment("short", e_shentsize, "e_shentsize")?;

    let e_shnum = (shnum_word >> 16) & 0xffff;
    let e_shstrndx = shnum_word & 0xffff;
    w.directive_with_comment("short", e_shnum, "e_shnum")?;
    w.directive_with_comment("short", e_shstrndx, "e_shstrndx")?;

    Ok(())
}

/// Emit the version section (ELF binary with overlaid SHDR header).
/// The version section starts with an ELF identification header (bytes 0-7),
/// but bytes 8-63 follow the standard SHDR format. The SHDR magic appears
/// at offset 8, overlaid with the ELF e_ident padding area.
fn emit_version_section(w: &mut AssemblyWriter<File>, section: &Section) -> Result<()> {
    w.label_simple("version_start")?;
    w.comment("ELF/SHDR Header (64 bytes) - ELF e_ident overlaid on SHDR")?;

    // ELF identification (bytes 0-7)
    emit_elf_ident(w)?;

    // SHDR metadata fields (bytes 8-19)
    emit_shdr_meta_fields(w, section)?;

    // Name field with labels (bytes 20+)
    emit_labeled_string(w, "version_name", &section.shdr.name)?;

    // ELF header fields overlaid on SHDR name area (bytes 28-51)
    emit_elf_overlay_fields(w, &section.data)?;

    // Version field with labels (bytes 52+)
    emit_labeled_string(w, "version_version", &section.shdr.version)?;

    // SHDR checksum (bytes 60-63)
    w.raw("\tshdr_checksum")?;
    w.blank_line()?;

    // Emit the rest of the version section (data after the 64-byte header)
    let end_offset = section.shdr.checksum_offset();
    emit_data_section(w, section, SHDR_SIZE, end_offset)?;

    // Emit section checksum and end label
    w.blank_line()?;
    w.raw("\tsection_checksum")?;
    w.label_simple("version_end")?;

    Ok(())
}

/// Generate an assembly file for a section
pub fn generate_assembly(
    cs: &Capstone,
    section: &Section,
    output_path: &Path,
    annotations: &mut Annotations,
    sys_consts: &SystemConstants,
) -> Result<()> {
    let file = create_output_file(output_path, "assembly file")?;
    let mut w = AssemblyWriter::new(file);

    w.comment(&format!("Section: {}", section.shdr.name))?;
    w.comment(&format!("Version: {}", section.shdr.version))?;
    w.comment(&format!("Type: {}", section.shdr.section_type_expr()))?;
    w.comment(&format!(
        "Length: {:#x} ({} bytes)",
        section.shdr.section_len, section.shdr.section_len
    ))?;
    w.blank_line()?;
    w.raw("#include \"definitions.h\"")?;
    w.raw("#include \"macros.inc\"")?;
    w.blank_line()?;

    w.raw(".set noreorder")?;
    w.raw(".set noat")?;
    w.blank_line()?;

    // The "version" section has non-standard header data, so emit it as raw bytes
    if section.shdr.name == "version" {
        return emit_version_section(&mut w, section);
    }

    // Create emission context for the section
    let mut ctx = EmissionContext {
        cs,
        section,
        labels: &annotations.labels,
        comments: &mut annotations.comments,
        funcs: &mut annotations.funcs,
        operands: &mut annotations.operands,
        sys_consts,
        bss_names: &annotations.bss_names,
    };

    let section_type_expr = section.shdr.section_type_expr();

    // For loadable sections with subsections, use special structure
    if !section.subsections.is_empty() {
        emit_loadable_section(&mut w, &mut ctx, section_type_expr)?;
    } else {
        emit_non_loadable_section(&mut w, &mut ctx, section_type_expr)?;
    }

    // Emit section checksum and section end macros
    w.blank_line()?;
    w.raw("\tsection_checksum")?;

    // For loadable sections with multiple subsections, close the sentinel ELF section
    if !section.subsections.is_empty() && section.subsections.len() > 1 {
        w.raw("\telfsect_end sentinel")?;
    }

    w.raw(&format!("\tsection_end {}", section.shdr.name))?;

    Ok(())
}
