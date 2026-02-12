// SPDX-License-Identifier: GPL-3.0-or-later
//! SGI O2 (IP32) memory map constants.

/// Global Data Area address
pub const GDA_ADDR: u32 = KSEG0 | 0x400;

/// Memory segment constants
pub const KSEG0: u32 = 0x8000_0000;
pub const KSEG1: u32 = 0xa000_0000;
pub const KSEG2: u32 = 0xc000_0000;

/// Physical base addresses
pub const PHYS_BASE_CRIME: u32 = 0x1400_0000;
pub const PHYS_BASE_RENDER: u32 = 0x1500_0000;
pub const PHYS_BASE_MACE: u32 = 0x1f00_0000;
pub const PHYS_SYSTEM_ROM: u32 = 0x1fc0_0000;

/// System ROM constants
pub const ROM_SIZE: u32 = 512 * 1024;
pub const ROM_START: u32 = KSEG1 | PHYS_SYSTEM_ROM;
pub const ROM_END: u32 = ROM_START + ROM_SIZE;
pub const ROM_ALIGN: usize = 0x100;

/// MACE offsets
pub const MACE_PCI: u32 = 0x08_0000;
pub const MACE_ETHERNET: u32 = 0x28_0000;
pub const MACE_PERIPHERAL: u32 = 0x30_0000;
pub const MACE_PERIPHERAL_AUDIO: u32 = 0x0_0000;
pub const MACE_PERIPHERAL_ISA: u32 = 0x1_0000;
pub const MACE_PERIPHERAL_KBD_MS: u32 = 0x2_0000;
pub const MACE_PERIPHERAL_I2C: u32 = 0x3_0000;
pub const MACE_PERIPHERAL_UST: u32 = 0x4_0000;
pub const MACE_ISA_EXTERNAL: u32 = 0x38_0000;
pub const MACE_ISA_UART_1: u32 = 0x1_0000;
pub const MACE_ISA_UART_2: u32 = 0x1_8000;
pub const MACE_ISA_RTC: u32 = 0x2_0000;

/// Device base addresses (virtual, uncached via KSEG1)
pub const BASE_CRIME: u32 = KSEG1 | PHYS_BASE_CRIME;
pub const BASE_RENDER: u32 = KSEG1 | PHYS_BASE_RENDER;
pub const BASE_MACE_PCI: u32 = KSEG1 | PHYS_BASE_MACE | MACE_PCI;
pub const BASE_MEC: u32 = KSEG1 | PHYS_BASE_MACE | MACE_ETHERNET;
pub const BASE_AUDIO: u32 = KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_AUDIO;
pub const BASE_ISA: u32 = KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_ISA;
pub const BASE_KBD_MS: u32 = KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_KBD_MS;
pub const BASE_I2C: u32 = KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_I2C;
pub const BASE_UST: u32 = KSEG1 | PHYS_BASE_MACE | MACE_PERIPHERAL | MACE_PERIPHERAL_UST;
pub const BASE_UART_1: u32 = KSEG1 | PHYS_BASE_MACE | MACE_ISA_EXTERNAL | MACE_ISA_UART_1;
pub const BASE_UART_2: u32 = KSEG1 | PHYS_BASE_MACE | MACE_ISA_EXTERNAL | MACE_ISA_UART_2;
pub const BASE_RTC: u32 = KSEG1 | PHYS_BASE_MACE | MACE_ISA_EXTERNAL | MACE_ISA_RTC;

/// BYTE_OFFSET for RTC/UART register access (because devices are little endian?)
pub const BYTE_OFFSET: i32 = 7;

/// Offset to low 32 bits of a 64-bit register (big-endian)
pub const LO32_OFFSET: u32 = 4;

/// TLB entry offset mask (each TLB entry covers two 4KB pages)
pub const PAGE_OFFSET_MASK: u32 = 0x1fff;

/// High 16 bits of base addresses (for lui state preservation checks)
pub const HI_BASE_RTC: u32 = BASE_RTC >> 16;
pub const HI_BASE_UART_1: u32 = BASE_UART_1 >> 16;
pub const HI_BASE_UART_2: u32 = BASE_UART_2 >> 16;
pub const LO_BASE_UART_2: i32 = (BASE_UART_2 & 0xffff) as i32;

/// High 16 bits of KSEG1 (for detecting KSEG1 OR patterns)
pub const HI_KSEG1: u32 = KSEG1 >> 16;
