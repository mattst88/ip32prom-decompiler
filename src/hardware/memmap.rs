// SPDX-License-Identifier: GPL-3.0-or-later
//! SGI O2 (IP32) memory map constants.

/// Global Data Area address
pub const GDA_ADDR: u32 = KSEG0 | 0x400;

/// ARCS System Parameter Block (SPB) - Low memory structure used by firmware
pub const ARCS_SPB: u32 = KSEG1 | 0x1000;

/// SPB field offsets from ARCS_SPB base ("Advanced RISC Computing Specification" section 4.2.2)
pub const ARCS_SPB_OFFSET_SIGNATURE: u32 = 0x00;
pub const ARCS_SPB_OFFSET_LENGTH: u32 = 0x04;
pub const ARCS_SPB_OFFSET_VERSION: u32 = 0x08;
pub const ARCS_SPB_OFFSET_REVISION: u32 = 0x0a;
pub const ARCS_SPB_OFFSET_RESTART_BLOCK: u32 = 0x0c;
pub const ARCS_SPB_OFFSET_DEBUG_BLOCK: u32 = 0x10;
pub const ARCS_SPB_OFFSET_GE_VECTOR: u32 = 0x14;
pub const ARCS_SPB_OFFSET_UTLB_MISS_VECTOR: u32 = 0x18;
pub const ARCS_SPB_OFFSET_FIRMWARE_VECTOR_LENGTH: u32 = 0x1c;
pub const ARCS_SPB_OFFSET_FIRMWARE_VECTOR: u32 = 0x20;
pub const ARCS_SPB_OFFSET_PRIVATE_VECTOR_LENGTH: u32 = 0x24;
pub const ARCS_SPB_OFFSET_PRIVATE_VECTOR: u32 = 0x28;
pub const ARCS_SPB_OFFSET_ADAPTER_COUNT: u32 = 0x2c;

/// Restart Block field offsets ("Advanced RISC Computing Specification" section 4.2.3)
pub const RTSB_OFFSET_SIGNATURE: u32 = 0x00;
pub const RTSB_OFFSET_LENGTH: u32 = 0x04;
pub const RTSB_OFFSET_VERSION: u32 = 0x08;
pub const RTSB_OFFSET_REVISION: u32 = 0x0a;
pub const RTSB_OFFSET_NEXT_RSTB: u32 = 0x0c;
pub const RTSB_OFFSET_RESTART_ADDRESS: u32 = 0x10;
pub const RTSB_OFFSET_BOOT_MASTER_ID: u32 = 0x14;
pub const RTSB_OFFSET_PROCESSOR_ID: u32 = 0x18;
pub const RTSB_OFFSET_BOOT_STATUS: u32 = 0x1c;
pub const RTSB_OFFSET_CHECKSUM: u32 = 0x20;
pub const RTSB_OFFSET_SAVE_AREA_LENGTH: u32 = 0x24;
pub const RTSB_OFFSET_SAVED_STATE_AREA: u32 = 0x28;

/// Exception handler code area (copied from firmware rwdata)
pub const EXCEPTION_HANDLERS: u32 = KSEG1 | 0x1800;

/// UTLB exception handler code area (copied from firmware rwdata)
pub const UTLB_HANDLERS: u32 = KSEG1 | 0x1c00;

/// Restart Block field offsets ("Advanced RISC Computing Specification" section 4.3.7)
pub const FV_OFFSET_LOAD: u32 = 0x00;
pub const FV_OFFSET_INVOKE: u32 = 0x04;
pub const FV_OFFSET_EXECUTE: u32 = 0x08;
pub const FV_OFFSET_HALT: u32 = 0x0c;
pub const FV_OFFSET_POWER_DOWN: u32 = 0x10;
pub const FV_OFFSET_RESTART: u32 = 0x14;
pub const FV_OFFSET_REBOOT: u32 = 0x18;
pub const FV_OFFSET_ENTER_INTERACTIVE_MODE: u32 = 0x1c;
/* Reserved: 0x20 */
pub const FV_OFFSET_GET_PEER: u32 = 0x24;
pub const FV_OFFSET_GET_CHILD: u32 = 0x28;
pub const FV_OFFSET_GET_PARENT: u32 = 0x2c;
pub const FV_OFFSET_GET_CONFIGURATION_DATA: u32 = 0x30;
pub const FV_OFFSET_ADD_CHILD: u32 = 0x34;
pub const FV_OFFSET_DELETE_COMPONENT: u32 = 0x38;
pub const FV_OFFSET_GET_COMPONENT: u32 = 0x3c;
pub const FV_OFFSET_SAVE_CONFIGURATION: u32 = 0x40;
pub const FV_OFFSET_GET_SYSTEM_ID: u32 = 0x44;
pub const FV_OFFSET_GET_MEMORY_DESCRIPTOR: u32 = 0x48;
/* Reserved: 0x4c */
pub const FV_OFFSET_GET_TIME: u32 = 0x50;
pub const FV_OFFSET_GET_RELATIVE_TIME: u32 = 0x54;
pub const FV_OFFSET_GET_DIRECTORY_ENTRY: u32 = 0x58;
pub const FV_OFFSET_OPEN: u32 = 0x5c;
pub const FV_OFFSET_CLOSE: u32 = 0x60;
pub const FV_OFFSET_READ: u32 = 0x64;
pub const FV_OFFSET_GET_READ_STATUS: u32 = 0x64;
pub const FV_OFFSET_WRITE: u32 = 0x6c;
pub const FV_OFFSET_SEEK: u32 = 0x70;
pub const FV_OFFSET_MOUNT: u32 = 0x74;
pub const FV_OFFSET_GET_ENVIRONMENT_VARIABLE: u32 = 0x78;
pub const FV_OFFSET_SET_ENVIRONMENT_VARIABLE: u32 = 0x7c;
pub const FV_OFFSET_GET_FILE_INFORMATION: u32 = 0x80;
pub const FV_OFFSET_SET_FILE_INFORMATION: u32 = 0x84;
pub const FV_OFFSET_FLUSH_ALL_CACHES: u32 = 0x88;
pub const FV_OFFSET_TEST_UNICODE_CHARACTER: u32 = 0x8c;
pub const FV_OFFSET_GET_DISPLAY_STATUS: u32 = 0x90;

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
