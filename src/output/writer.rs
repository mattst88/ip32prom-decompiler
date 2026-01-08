// SPDX-License-Identifier: GPL-3.0-or-later
//! Assembly writer abstraction for consistent output formatting.
//!
//! This module provides the `AssemblyWriter` struct, which encapsulates
//! common patterns for emitting assembly output. It handles:
//! - Labels with address comments
//! - Instructions with delay slot indentation
//! - Directives (`.int`, `.byte`, `.ascii`, etc.)
//! - Comments (line and block)
//! - Fill directives with automatic optimization

use anyhow::Result;
use std::fmt::Display;
use std::io::Write;

/// Assembly writer that provides a consistent API for emitting assembly output.
///
/// This struct wraps a `Write` implementation and provides methods for
/// emitting common assembly constructs with consistent formatting.
pub struct AssemblyWriter<W: Write> {
    writer: W,
}

impl<W: Write> AssemblyWriter<W> {
    /// Create a new `AssemblyWriter` wrapping the given writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Get a mutable reference to the underlying writer.
    ///
    /// Use this for cases where the `AssemblyWriter` API doesn't provide
    /// the needed functionality.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consume the writer and return the underlying `Write` implementation.
    pub fn into_inner(self) -> W {
        self.writer
    }

    // -------------------------------------------------------------------------
    // Labels
    // -------------------------------------------------------------------------

    /// Emit a label with an address comment.
    ///
    /// Output format: `label: /* 0xADDRESS */`
    pub fn label(&mut self, name: &str, addr: u32) -> Result<()> {
        writeln!(self.writer, "{}: /* {:#010x} */", name, addr)?;
        Ok(())
    }

    /// Emit a label without an address comment.
    ///
    /// Output format: `label:`
    pub fn label_simple(&mut self, name: &str) -> Result<()> {
        writeln!(self.writer, "{}:", name)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Instructions
    // -------------------------------------------------------------------------

    /// Emit an instruction with optional delay slot indentation and comment.
    ///
    /// - `instruction`: The formatted instruction (mnemonic + operands)
    /// - `delay_slot`: If true, adds extra indentation for delay slot
    /// - `comment`: Optional comment to append after the instruction
    pub fn instruction(
        &mut self,
        instruction: &str,
        delay_slot: bool,
        comment: Option<&str>,
    ) -> Result<()> {
        let indent = if delay_slot { " " } else { "" };
        if let Some(c) = comment {
            writeln!(self.writer, "\t{}{}\t\t# {}", indent, instruction, c)?;
        } else {
            writeln!(self.writer, "\t{}{}", indent, instruction)?;
        }
        Ok(())
    }

    /// Emit a `.word` fallback for an instruction that couldn't be formatted.
    ///
    /// - `word`: The 32-bit word value
    /// - `delay_slot`: If true, adds extra indentation for delay slot
    /// - `disasm`: Optional (mnemonic, operands) for a disassembly comment
    /// - `comment`: Optional user comment
    pub fn word_fallback(
        &mut self,
        word: u32,
        delay_slot: bool,
        disasm: Option<(&str, &str)>,
        comment: Option<&str>,
    ) -> Result<()> {
        let indent = if delay_slot { " " } else { "" };
        match (disasm, comment) {
            (Some((mnemonic, op_str)), Some(c)) => writeln!(
                self.writer,
                "\t{}.word\t{:#010x}\t/* {} {} */\t\t# {}",
                indent, word, mnemonic, op_str, c
            )?,
            (Some((mnemonic, op_str)), None) => writeln!(
                self.writer,
                "\t{}.word\t{:#010x}\t/* {} {} */",
                indent, word, mnemonic, op_str
            )?,
            (None, Some(c)) => {
                writeln!(self.writer, "\t{}.word\t{:#010x}\t\t# {}", indent, word, c)?
            }
            (None, None) => writeln!(self.writer, "\t{}.word\t{:#010x}", indent, word)?,
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Directives
    // -------------------------------------------------------------------------

    /// Emit a directive with a single operand.
    ///
    /// Output format: `\t.directive\toperand`
    pub fn directive(&mut self, directive: &str, operand: impl Display) -> Result<()> {
        writeln!(self.writer, "\t.{}\t{}", directive, operand)?;
        Ok(())
    }

    /// Emit a directive with an operand and inline comment.
    ///
    /// Output format: `\t.directive\toperand\t/* comment */`
    pub fn directive_with_comment(
        &mut self,
        directive: &str,
        operand: impl Display,
        comment: &str,
    ) -> Result<()> {
        writeln!(
            self.writer,
            "\t.{}\t{}\t/* {} */",
            directive, operand, comment
        )?;
        Ok(())
    }

    /// Emit a `.int` directive with a 32-bit hex value.
    pub fn int_hex(&mut self, value: u32) -> Result<()> {
        writeln!(self.writer, "\t.int\t{:#010x}", value)?;
        Ok(())
    }

    /// Emit a `.int` directive with a label reference.
    pub fn int_label(&mut self, label: &str) -> Result<()> {
        writeln!(self.writer, "\t.int\t{}", label)?;
        Ok(())
    }

    /// Emit a `.byte` directive with an 8-bit hex value.
    pub fn byte_hex(&mut self, value: u8) -> Result<()> {
        writeln!(self.writer, "\t.byte\t{:#04x}", value)?;
        Ok(())
    }

    /// Emit a `.ascii` directive with an escaped string.
    pub fn ascii(&mut self, escaped: &str) -> Result<()> {
        writeln!(self.writer, "\t.ascii\t\"{}\"", escaped)?;
        Ok(())
    }

    /// Emit a `string` macro invocation with alignment and escaped content.
    ///
    /// Output format: `\tstring pad_to, "escaped_content"`
    pub fn string_macro(&mut self, pad_to: usize, escaped: &str) -> Result<()> {
        writeln!(self.writer, "\tstring {}, \"{}\"", pad_to, escaped)?;
        Ok(())
    }

    /// Emit a `.org` directive.
    pub fn org(&mut self, addr: usize) -> Result<()> {
        writeln!(self.writer, "\n\t.org\t{:#x}", addr)?;
        Ok(())
    }

    /// Emit a `.section` directive.
    pub fn section(&mut self, name: &str, flags: &str) -> Result<()> {
        writeln!(self.writer, ".section .{}, \"{}\"", name, flags)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Fill Directives
    // -------------------------------------------------------------------------

    /// Emit fill words (.int or .fill directive based on count).
    ///
    /// - For count=0: emits nothing
    /// - For count=1: emits `.int value`
    /// - For count>1: emits `.fill count, 4, value`
    pub fn fill_words(&mut self, count: usize, value: u32) -> Result<()> {
        match count {
            0 => {}
            1 => writeln!(self.writer, "\t.int\t{:#010x}", value)?,
            _ => writeln!(self.writer, "\t.fill\t{}, 4, {:#010x}", count, value)?,
        }
        Ok(())
    }

    /// Emit fill bytes (.byte or .fill directive based on count).
    ///
    /// - For count=0: emits nothing
    /// - For count=1: emits `.byte value`
    /// - For count>1: emits `.fill count, 1, value`
    pub fn fill_bytes(&mut self, count: usize, value: u8) -> Result<()> {
        match count {
            0 => {}
            1 => writeln!(self.writer, "\t.byte\t{}", value)?,
            _ => writeln!(self.writer, "\t.fill\t{}, 1, {}", count, value)?,
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Comments
    // -------------------------------------------------------------------------

    /// Emit a line comment.
    ///
    /// Output format: `/* comment */`
    pub fn comment(&mut self, text: &str) -> Result<()> {
        writeln!(self.writer, "/* {} */", text)?;
        Ok(())
    }

    /// Emit a function header block comment.
    ///
    /// Output format:
    /// ```text
    /// /* Function name [start - end)
    ///  *
    ///  * description line 1
    ///  * description line 2
    ///  */
    /// ```
    pub fn function_header(
        &mut self,
        name: &str,
        addr: u32,
        end_addr: Option<u32>,
        description: Option<&str>,
    ) -> Result<()> {
        // Blank line before function comment
        writeln!(self.writer)?;

        // Function header line
        if let Some(end) = end_addr {
            writeln!(
                self.writer,
                "/* Function {} [{:#010x} - {:#010x})",
                name, addr, end
            )?;
        } else {
            writeln!(self.writer, "/* Function {} [{:#010x} - ???)", name, addr)?;
        }

        // Description lines
        if let Some(desc) = description
            && !desc.is_empty()
        {
            writeln!(self.writer, " *")?;
            for line in desc.lines() {
                if line.is_empty() {
                    writeln!(self.writer, " *")?;
                } else {
                    writeln!(self.writer, " * {}", line)?;
                }
            }
        }

        writeln!(self.writer, " */")?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Misc
    // -------------------------------------------------------------------------

    /// Emit a blank line.
    pub fn blank_line(&mut self) -> Result<()> {
        writeln!(self.writer)?;
        Ok(())
    }

    /// Emit raw text (no formatting applied).
    ///
    /// Use this for assembly macros, special directives, or other output
    /// that doesn't fit the standard patterns.
    pub fn raw(&mut self, text: &str) -> Result<()> {
        writeln!(self.writer, "{}", text)?;
        Ok(())
    }

    /// Emit a macro invocation with arguments.
    ///
    /// Output format: `\tmacro_name arg1, arg2, ...`
    pub fn macro_call(&mut self, name: &str, args: &[impl Display]) -> Result<()> {
        if args.is_empty() {
            writeln!(self.writer, "\t{}", name)?;
        } else {
            let args_str: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            writeln!(self.writer, "\t{} {}", name, args_str.join(", "))?;
        }
        Ok(())
    }
}

/// Build a comment string combining a user comment with an "unreachable" marker.
///
/// Returns:
/// - `Some("unreachable; user_comment")` if both unreachable and has comment
/// - `Some("user_comment")` if only has comment
/// - `Some("unreachable")` if only unreachable
/// - `None` if neither
pub fn build_comment(user_comment: Option<&str>, is_unreachable: bool) -> Option<String> {
    match (user_comment, is_unreachable) {
        (Some(c), true) => Some(format!("unreachable; {}", c)),
        (Some(c), false) => Some(c.to_string()),
        (None, true) => Some("unreachable".to_string()),
        (None, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label() {
        let mut buf = Vec::new();
        let mut writer = AssemblyWriter::new(&mut buf);
        writer.label("my_label", 0x1234_5678).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "my_label: /* 0x12345678 */\n"
        );
    }

    #[test]
    fn test_instruction_no_comment() {
        let mut buf = Vec::new();
        let mut writer = AssemblyWriter::new(&mut buf);
        writer.instruction("nop", false, None).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\tnop\n");
    }

    #[test]
    fn test_instruction_with_comment() {
        let mut buf = Vec::new();
        let mut writer = AssemblyWriter::new(&mut buf);
        writer
            .instruction("nop", false, Some("do nothing"))
            .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\tnop\t\t# do nothing\n");
    }

    #[test]
    fn test_instruction_delay_slot() {
        let mut buf = Vec::new();
        let mut writer = AssemblyWriter::new(&mut buf);
        writer.instruction("nop", true, None).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\t nop\n");
    }

    #[test]
    fn test_fill_words() {
        // Count 0 - no output
        {
            let mut buf = Vec::new();
            let mut writer = AssemblyWriter::new(&mut buf);
            writer.fill_words(0, 0).unwrap();
            assert_eq!(buf.len(), 0);
        }

        // Count 1 - single .int
        {
            let mut buf = Vec::new();
            let mut writer = AssemblyWriter::new(&mut buf);
            writer.fill_words(1, 0x1234_5678).unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), "\t.int\t0x12345678\n");
        }

        // Count > 1 - .fill
        {
            let mut buf = Vec::new();
            let mut writer = AssemblyWriter::new(&mut buf);
            writer.fill_words(5, 0).unwrap();
            assert_eq!(
                String::from_utf8(buf).unwrap(),
                "\t.fill\t5, 4, 0x00000000\n"
            );
        }
    }

    #[test]
    fn test_word_fallback() {
        let mut buf = Vec::new();
        let mut writer = AssemblyWriter::new(&mut buf);
        writer
            .word_fallback(0xDEAD_BEEF, false, Some(("add", "$t0, $t1, $t2")), None)
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "\t.word\t0xdeadbeef\t/* add $t0, $t1, $t2 */\n"
        );
    }

    #[test]
    fn test_build_comment() {
        assert_eq!(build_comment(None, false), None);
        assert_eq!(build_comment(None, true), Some("unreachable".to_string()));
        assert_eq!(build_comment(Some("test"), false), Some("test".to_string()));
        assert_eq!(
            build_comment(Some("test"), true),
            Some("unreachable; test".to_string())
        );
    }
}
