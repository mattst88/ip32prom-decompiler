// SPDX-License-Identifier: GPL-3.0-or-later
//! System constants and device register lookup tables for symbolic name replacement.

use super::memmap::*;
use std::collections::HashMap;

/// Time constants
pub const EPOC_1970: u32 = 1970;
pub const SECONDS_IN_1_DAY: u32 = 24 * 60 * 60;
pub const SECONDS_IN_365_DAYS: u32 = 365 * SECONDS_IN_1_DAY;
pub const SECONDS_IN_366_DAYS: u32 = 366 * SECONDS_IN_1_DAY;

/// Magic numbers (as big-endian u32)
pub const ARCS_MAGIC: u32 = 0x5343_5241; // "ARCS"
pub const ELF_MAGIC: u32 = 0x7f45_4c46; // "\x7fELF"
pub const GDA_MAGIC: u32 = 0x5846_4552; // "XFER"
pub const RTSB_MAGIC: u32 = 0x4254_5352; // "RTSB" (Restart Block)
pub const SGI_LABEL_MAGIC: u32 = 0x0be5_a941; // SGI disk partition label
pub const SHDR_MAGIC: u32 = 0x5348_4452; // "SHDR"
pub const WARM_START_COOKIE: u32 = 0x7d83;

/// Sentinel values
pub const HEXDIGIT_INVALID: u32 = 999999; // 0x000f423f - returned by hexdigit() for invalid input

/// Hardware constants
pub const UART_BASE_CLOCK: u32 = 1843200; // 1.8432 MHz

/// ctype table offsets
pub const CTYPE_TOLOWER: u32 = 0x102; // offset to lowercase mapping in ctype_table

/// Macro to create (value, "name") tuples where the string matches the token.
macro_rules! M {
    ($name:tt) => {
        ($name, stringify!($name))
    };
}

/// System constants and device register lookup tables.
/// Maps device base addresses to their register offset tables, and
/// provides lookup for well-known constants (magic numbers, addresses, etc.)
pub struct SystemConstants {
    /// Maps base addresses to (offset -> name) lookup tables
    devices: HashMap<u32, HashMap<i32, &'static str>>,
    /// Maps full 32-bit constants to symbolic names
    constants: HashMap<u32, &'static str>,
}

impl SystemConstants {
    pub fn new() -> Self {
        let constants = HashMap::from([
            // Numeric constants
            M!(1000),
            M!(10000),
            M!(100000),
            M!(500000),
            M!(1000000),
            M!(133333000), // 133.333 MHz clock
            // Time constants
            M!(EPOC_1970),
            M!(SECONDS_IN_1_DAY),
            M!(SECONDS_IN_365_DAYS),
            M!(SECONDS_IN_366_DAYS),
            // Magic numbers
            M!(ARCS_MAGIC),
            M!(ELF_MAGIC),
            M!(GDA_MAGIC),
            M!(RTSB_MAGIC),
            M!(SGI_LABEL_MAGIC),
            M!(SHDR_MAGIC),
            // Sentinel values
            M!(HEXDIGIT_INVALID),
            // ctype table offsets
            M!(CTYPE_TOLOWER),
            // Memory segments
            M!(KSEG0),
            M!(KSEG1),
            M!(KSEG2),
            // System ROM
            M!(ROM_SIZE),
            M!(ROM_START),
            M!(ROM_END),
            // Low memory areas
            M!(ARCS_SPB),
            // SPB offsets
            (ARCS_SPB + ARCS_SPB_OFFSET_LENGTH, "ARCS_SPB + ARCS_SPB_OFFSET_LENGTH"),
            (ARCS_SPB + ARCS_SPB_OFFSET_VERSION, "ARCS_SPB + ARCS_SPB_OFFSET_VERSION"),
            (ARCS_SPB + ARCS_SPB_OFFSET_REVISION, "ARCS_SPB + ARCS_SPB_OFFSET_REVISION"),
            (ARCS_SPB + ARCS_SPB_OFFSET_RESTART_BLOCK, "ARCS_SPB + ARCS_SPB_OFFSET_RESTART_BLOCK"),
            (ARCS_SPB + ARCS_SPB_OFFSET_DEBUG_BLOCK, "ARCS_SPB + ARCS_SPB_OFFSET_DEBUG_BLOCK"),
            (ARCS_SPB + ARCS_SPB_OFFSET_GE_VECTOR, "ARCS_SPB + ARCS_SPB_OFFSET_GE_VECTOR"),
            (ARCS_SPB + ARCS_SPB_OFFSET_UTLB_MISS_VECTOR, "ARCS_SPB + ARCS_SPB_OFFSET_UTLB_MISS_VECTOR"),
            (ARCS_SPB + ARCS_SPB_OFFSET_FIRMWARE_VECTOR_LENGTH, "ARCS_SPB + ARCS_SPB_OFFSET_FIRMWARE_VECTOR_LENGTH"),
            (ARCS_SPB + ARCS_SPB_OFFSET_FIRMWARE_VECTOR, "ARCS_SPB + ARCS_SPB_OFFSET_FIRMWARE_VECTOR"),
            (ARCS_SPB + ARCS_SPB_OFFSET_PRIVATE_VECTOR_LENGTH, "ARCS_SPB + ARCS_SPB_OFFSET_PRIVATE_VECTOR_LENGTH"),
            (ARCS_SPB + ARCS_SPB_OFFSET_PRIVATE_VECTOR, "ARCS_SPB + ARCS_SPB_OFFSET_PRIVATE_VECTOR"),
            (ARCS_SPB + ARCS_SPB_OFFSET_ADAPTER_COUNT, "ARCS_SPB + ARCS_SPB_OFFSET_ADAPTER_COUNT"),
            M!(FIRMWARE_VECTOR),
            M!(PRIVATE_VECTOR),
            // Device base addresses
            M!(BASE_CRIME),
            M!(BASE_RENDER),
            M!(BASE_MACE_PCI),
            M!(BASE_MEC),
            M!(BASE_AUDIO),
            M!(BASE_ISA),
            M!(BASE_KBD_MS),
            M!(BASE_I2C),
            M!(BASE_UST),
            M!(BASE_UART_1),
            M!(BASE_UART_2),
            M!(BASE_RTC),
        ]);

        let uart_regs = HashMap::from([
            (0x0007, "UART_DATA"),
            (0x0107, "UART_IER"),
            (0x0207, "UART_IIR"),
            (0x0307, "UART_LCR"),
            (0x0407, "UART_MCR"),
            (0x0507, "UART_LSR"),
            (0x0607, "UART_MSR"),
            (0x0707, "UART_SCR"),
        ]);

        let devices = HashMap::from([
            (
                BASE_CRIME,
                HashMap::from([
                    (0x0000, "CRIME_ID_OFFSET"),
                    (0x0004, "CRIME_ID_OFFSET + LO32_OFFSET"),
                    (0x0008, "CRIME_CONTROL_OFFSET"),
                    (0x0010, "CRIME_INTSTAT_OFFSET"),
                    (0x0018, "CRIME_INTMASK_OFFSET"),
                    (0x0020, "CRIME_SOFT_INT_OFFSET"),
                    (0x0028, "CRIME_HARD_INT_OFFSET"),
                    (0x0030, "CRIME_WATCHDOG_OFFSET"),
                    (0x0038, "CRIME_TIMER_OFFSET"),
                    (0x0040, "CRIME_CPU_ERROR_ADDR"),
                    (0x0048, "CRIME_CPU_ERROR_STAT"),
                    (0x0050, "CRIME_CPU_ERROR_ENA"),
                    (0x0200, "CRIME_MC_STATUS_CTRL"),
                    (0x0208, "CRIME_BANK_0_CTRL"),
                    (0x020c, "CRIME_BANK_0_CTRL + LO32_OFFSET"),
                    (0x0210, "CRIME_BANK_1_CTRL"),
                    (0x0218, "CRIME_BANK_2_CTRL"),
                    (0x0220, "CRIME_BANK_3_CTRL"),
                    (0x0228, "CRIME_BANK_4_CTRL"),
                    (0x0230, "CRIME_BANK_5_CTRL"),
                    (0x0238, "CRIME_BANK_6_CTRL"),
                    (0x0240, "CRIME_BANK_7_CTRL"),
                    (0x0248, "CRIME_REFRESH_COUNTER"),
                    (0x0250, "CRIME_ERROR_STATUS"),
                    (0x0258, "CRIME_ERROR_ADDR"),
                    (0x0260, "CRIME_SYNDROME_BITS"),
                    (0x0268, "CRIME_GENERATED_CHECK_BITS"),
                    (0x0270, "CRIME_REPLACEMENT_CHECK_BITS"),
                ]),
            ),
            (
                BASE_RENDER,
                HashMap::from([
                    (0x0400, "RENDER_INTERFACE_CTRL"),
                    // Rendering Engine TLBs
                    (0x1000, "CRIME_RE_TLB_A"),
                    (0x1200, "CRIME_RE_TLB_B"),
                    (0x1400, "CRIME_RE_TLB_C"),
                    // Drawing Engine registers
                    (0x2000, "CRIME_DE_MODE_SRC"),
                    (0x2008, "CRIME_DE_MODE_DST"),
                    (0x2018, "CRIME_DE_DRAWMODE"),
                    (0x2020, "CRIME_DE_SCRMASK0"),
                    (0x2028, "CRIME_DE_SCRMASK1"),
                    (0x2030, "CRIME_DE_SCRMASK2"),
                    (0x2038, "CRIME_DE_SCRMASK3"),
                    (0x2040, "CRIME_DE_SCRMASK4"),
                    (0x2048, "CRIME_DE_SCISSOR"),
                    (0x2050, "CRIME_DE_WINOFFSET_SRC"),
                    (0x2058, "CRIME_DE_WINOFFSET_DST"),
                    (0x2060, "CRIME_DE_PRIMITIVE"),
                    (0x2070, "CRIME_DE_X_VERTEX_0"),
                    (0x2074, "CRIME_DE_X_VERTEX_1"),
                    (0x20a8, "CRIME_DE_XFER_STEP_X"),
                    (0x20ac, "CRIME_DE_XFER_STEP_Y"),
                    (0x20c0, "CRIME_DE_STIPPLE_MODE"),
                    (0x20c4, "CRIME_DE_STIPPLE_PAT"),
                    (0x20d0, "CRIME_DE_FG"),
                    (0x21b0, "CRIME_DE_ROP"),
                    (0x21b8, "CRIME_DE_PLANEMASK"),
                    (0x21f0, "CRIME_DE_NULL"),
                    (0x21f8, "CRIME_DE_FLUSH"),
                    // Drawing Engine status
                    (0x4000, "CRIME_DE_STATUS"),
                    // MTE (Memory Transfer Engine) registers
                    (0x3000, "MTE_MODE"),
                    (0x3008, "MTE_BYTE_MASK"),
                    (0x3010, "MTE_STIPPLE_MASK"),
                    (0x3018, "MTE_FG_VALUE"),
                    (0x3020, "MTE_SRC0"),
                    (0x3028, "MTE_SRC1"),
                    (0x3030, "MTE_DST0"),
                    (0x3038, "MTE_DST1"),
                    (0x3040, "MTE_SRC_Y_STEP"),
                    (0x3048, "MTE_DST_Y_STEP"),
                    (0x3070, "MTE_NULL"),
                    (0x3078, "MTE_FLUSH"),
                ]),
            ),
            (
                BASE_MACE_PCI,
                HashMap::from([
                    (0x0000, "MACE_PCI_ERROR_ADDR"),
                    (0x0004, "MACE_PCI_ERROR_FLAGS"),
                    (0x0008, "MACE_PCI_CONTROL"),
                    (0x0cf8, "MACE_PCI_CONFIG_ADDR"),
                    (0x0cfc, "MACE_PCI_CONFIG_DATA"),
                ]),
            ),
            (
                BASE_ISA,
                HashMap::from([
                    (0x0000, "ISA_RING_BASE_AND_RESET"),
                    (0x0004, "ISA_RING_BASE_AND_RESET + LO32_OFFSET"),
                    (0x0008, "ISA_MISC_CONTROL"),
                    (0x000c, "ISA_MISC_CONTROL + LO32_OFFSET"),
                ]),
            ),
            (
                BASE_AUDIO,
                HashMap::from([
                    (0x00, "MACE_AUDIO_STATUS"),
                    (0x08, "MACE_AUDIO_CODEC_STATUS"),
                    (0x10, "MACE_AUDIO_CODEC_INPUT_MASK"),
                    (0x18, "MACE_AUDIO_CODEC_INPUT"),
                    // Channel 1: base = 0x20
                    (0x20, "MACE_AUDIO_RING_CTRL_CHAN(1)"),
                    (0x28, "MACE_AUDIO_RD_PTR_CHAN(1)"),
                    (0x30, "MACE_AUDIO_WR_PTR_CHAN(1)"),
                    (0x38, "MACE_AUDIO_RING_DEPTH_CHAN(1)"),
                    // Channel 2: base = 0x40
                    (0x40, "MACE_AUDIO_RING_CTRL_CHAN(2)"),
                    (0x48, "MACE_AUDIO_RD_PTR_CHAN(2)"),
                    (0x50, "MACE_AUDIO_WR_PTR_CHAN(2)"),
                    (0x58, "MACE_AUDIO_RING_DEPTH_CHAN(2)"),
                    // Channel 3: base = 0x60
                    (0x60, "MACE_AUDIO_RING_CTRL_CHAN(3)"),
                    (0x68, "MACE_AUDIO_RD_PTR_CHAN(3)"),
                    (0x70, "MACE_AUDIO_WR_PTR_CHAN(3)"),
                    (0x78, "MACE_AUDIO_RING_DEPTH_CHAN(3)"),
                ]),
            ),
            (
                BASE_I2C,
                HashMap::from([
                    (0x0000, "MACE_I2C_CONFIG"),
                    (0x0010, "MACE_I2C_STATUS"),
                    (0x0018, "MACE_I2C_DATA"),
                ]),
            ),
            (BASE_UART_1, uart_regs.clone()),
            (BASE_UART_2, uart_regs),
            (
                BASE_MEC,
                HashMap::from([
                    (0x0000, "MACE_ETH_MAC_CONTROL"),
                    (0x0004, "MACE_ETH_MAC_CONTROL + LO32_OFFSET"),
                    (0x0008, "MACE_ETH_INTR_STATUS"),
                    (0x0045, "MACE_ETH_RX_MCL_WR_PTR"),
                    (0x0046, "MACE_ETH_RX_MCL_RD_PTR"),
                    (0x0047, "MACE_ETH_RX_MCL_DEPTH"),
                    (0x0104, "MACE_ETH_MCL_RECEIVE_FIFO(0x04)"),
                ]),
            ),
            (
                BASE_KBD_MS,
                HashMap::from([
                    (0x0000, "MACE_KEYBOARD_TX_BUF"),
                    (0x0008, "MACE_KEYBOARD_RX_BUF"),
                    (0x0010, "MACE_KEYBOARD_CONTROL"),
                    (0x0018, "MACE_KEYBOARD_STATUS"),
                    (0x0020, "MACE_MOUSE_TX_BUF"),
                    (0x0028, "MACE_MOUSE_RX_BUF"),
                    (0x0030, "MACE_MOUSE_CONTROL"),
                    (0x0038, "MACE_MOUSE_STATUS"),
                ]),
            ),
            (
                BASE_RTC,
                HashMap::from([
                    (0x0007, "BYTE_OFFSET"),
                    (0x0000, "RTC_SECONDS"),
                    (0x0100, "RTC_SECONDS_ALARM"),
                    (0x0200, "RTC_MINUTES"),
                    (0x0300, "RTC_MINUTES_ALARM"),
                    (0x0400, "RTC_HOURS"),
                    (0x0500, "RTC_HOURS_ALARM"),
                    (0x0600, "RTC_DAY_OF_WEEK"),
                    (0x0700, "RTC_DAY_OF_MONTH"),
                    (0x0800, "RTC_MONTH"),
                    (0x0900, "RTC_YEAR"),
                    (0x0a00, "RTC_CTRL_A"),
                    (0x0b00, "RTC_CTRL_B"),
                    (0x0c00, "RTC_CTRL_C"),
                    (0x0d00, "RTC_CTRL_D"),
                    (0x4700, "RTC_CRC"),
                    (0x4800, "RTC_CENTURY"),
                    (0x4900, "RTC_DATE_ALARM"),
                    (0x4a00, "RTC_EXT_CTRL_4A"),
                    (0x4b00, "RTC_EXT_CTRL_4B"),
                ]),
            ),
        ]);

        SystemConstants { devices, constants }
    }

    /// Look up a symbolic name for a well-known constant value.
    /// This includes magic numbers, memory-mapped addresses, and other constants.
    pub fn lookup_constant(&self, value: u32) -> Option<&'static str> {
        self.constants.get(&value).copied()
    }

    /// Look up a symbolic name for a device register offset
    /// base_addr: The device base address (e.g., BASE_CRIME)
    /// offset: The register offset from the base
    pub fn lookup_register(&self, base_addr: u32, offset: i32) -> Option<&'static str> {
        self.devices.get(&base_addr)?.get(&offset).copied()
    }

    /// Iterate over all device base addresses
    pub fn device_base_addrs(&self) -> impl Iterator<Item = u32> + '_ {
        self.devices.keys().copied()
    }

    /// Iterate over all constants as (value, name) pairs, sorted by value
    pub fn constants_sorted(&self) -> Vec<(u32, &'static str)> {
        let mut items: Vec<_> = self.constants.iter().map(|(&v, &n)| (v, n)).collect();
        items.sort_by_key(|(v, _)| *v);
        items
    }

    /// Iterate over registers for a given base address as (offset, name) pairs, sorted by offset
    pub fn registers_for_base(&self, base: u32) -> Vec<(i32, &'static str)> {
        if let Some(regs) = self.devices.get(&base) {
            let mut items: Vec<_> = regs.iter().map(|(&o, &n)| (o, n)).collect();
            items.sort_by_key(|(o, _)| *o);
            items
        } else {
            Vec::new()
        }
    }

    /// Look up a full address and return its symbolic form as "BASE + OFFSET"
    /// Returns None if the address doesn't match any known device register
    pub fn lookup_device_address(&self, addr: u32) -> Option<String> {
        // First check if it's an exact constant match
        if let Some(name) = self.constants.get(&addr) {
            return Some((*name).to_string());
        }

        // Try to decompose as base + offset
        for (&base, regs) in &self.devices {
            if addr >= base {
                let offset = (addr - base) as i32;
                if let Some(reg_name) = regs.get(&offset) {
                    let base_name = self.constants.get(&base)?;
                    return Some(format!("{} + {}", base_name, reg_name));
                }
            }
        }
        None
    }
}

impl Default for SystemConstants {
    fn default() -> Self {
        Self::new()
    }
}
