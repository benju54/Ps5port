//! RAD Game Tools Kraken hardware decompression DMA engine virtual stub for PS5.
//!
//! Provides ultra-high-speed streaming decompression interface (5-9 GB/s raw fast-path)
//! offloading Zen 2 CPU cores.

use crate::mmio::{MmioDevice, MmioError};

pub const KRAKEN_REG_CONTROL: u64 = 0x00;
pub const KRAKEN_REG_STATUS: u64 = 0x04;
pub const KRAKEN_REG_SRC_LO: u64 = 0x08;
pub const KRAKEN_REG_SRC_HI: u64 = 0x0C;
pub const KRAKEN_REG_DST_LO: u64 = 0x10;
pub const KRAKEN_REG_DST_HI: u64 = 0x14;
pub const KRAKEN_REG_COMPRESSED_SIZE: u64 = 0x18;
pub const KRAKEN_REG_DECOMPRESSED_SIZE: u64 = 0x1C;
pub const KRAKEN_REG_ALGORITHM: u64 = 0x20;

pub const KRAKEN_STATUS_IDLE: u32 = 0x0;
pub const KRAKEN_STATUS_BUSY: u32 = 0x1;
pub const KRAKEN_STATUS_COMPLETE: u32 = 0x2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OodleAlgorithm {
    Kraken = 0,
    Mermaid = 1,
    Selkie = 2,
    Leviathan = 3,
}

pub struct KrakenDmaEngine {
    base_address: u64,
    size: u64,
    control: u32,
    status: u32,
    src_addr: u64,
    dst_addr: u64,
    compressed_size: u32,
    decompressed_size: u32,
    algorithm: OodleAlgorithm,
}

impl KrakenDmaEngine {
    pub fn new(base_address: u64) -> Self {
        Self {
            base_address,
            size: 0x1000,
            control: 0,
            status: KRAKEN_STATUS_IDLE,
            src_addr: 0,
            dst_addr: 0,
            compressed_size: 0,
            decompressed_size: 0,
            algorithm: OodleAlgorithm::Kraken,
        }
    }

    pub fn trigger_decompression(&mut self) {
        self.status = KRAKEN_STATUS_BUSY;
        // In emulation host, this delegates to Oodle / libdeflate fast-path worker
        self.status = KRAKEN_STATUS_COMPLETE;
    }
}

impl MmioDevice for KrakenDmaEngine {
    fn name(&self) -> &str {
        "SceKrakenDmaAccelerator"
    }

    fn base_address(&self) -> u64 {
        self.base_address
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn read(&self, offset: u64, _size: usize) -> Result<u64, MmioError> {
        let val: u32 = match offset {
            KRAKEN_REG_CONTROL => self.control,
            KRAKEN_REG_STATUS => self.status,
            KRAKEN_REG_SRC_LO => (self.src_addr & 0xFFFF_FFFF) as u32,
            KRAKEN_REG_SRC_HI => (self.src_addr >> 32) as u32,
            KRAKEN_REG_DST_LO => (self.dst_addr & 0xFFFF_FFFF) as u32,
            KRAKEN_REG_DST_HI => (self.dst_addr >> 32) as u32,
            KRAKEN_REG_COMPRESSED_SIZE => self.compressed_size,
            KRAKEN_REG_DECOMPRESSED_SIZE => self.decompressed_size,
            KRAKEN_REG_ALGORITHM => self.algorithm as u32,
            _ => 0,
        };
        Ok(val as u64)
    }

    fn write(&mut self, offset: u64, value: u64, _size: usize) -> Result<(), MmioError> {
        let val32 = value as u32;
        match offset {
            KRAKEN_REG_CONTROL => {
                self.control = val32;
                if val32 & 0x1 != 0 {
                    self.trigger_decompression();
                }
            }
            KRAKEN_REG_STATUS => self.status = val32,
            KRAKEN_REG_SRC_LO => self.src_addr = (self.src_addr & !0xFFFF_FFFF) | (val32 as u64),
            KRAKEN_REG_SRC_HI => self.src_addr = (self.src_addr & 0xFFFF_FFFF) | ((val32 as u64) << 32),
            KRAKEN_REG_DST_LO => self.dst_addr = (self.dst_addr & !0xFFFF_FFFF) | (val32 as u64),
            KRAKEN_REG_DST_HI => self.dst_addr = (self.dst_addr & 0xFFFF_FFFF) | ((val32 as u64) << 32),
            KRAKEN_REG_COMPRESSED_SIZE => self.compressed_size = val32,
            KRAKEN_REG_DECOMPRESSED_SIZE => self.decompressed_size = val32,
            KRAKEN_REG_ALGORITHM => {
                self.algorithm = match val32 {
                    1 => OodleAlgorithm::Mermaid,
                    2 => OodleAlgorithm::Selkie,
                    3 => OodleAlgorithm::Leviathan,
                    _ => OodleAlgorithm::Kraken,
                };
            }
            _ => {}
        }
        Ok(())
    }
}
