//! Custom NVMe / flash controller MMIO interface stub for PS5 custom SSD controller.

use crate::mmio::{MmioDevice, MmioError};

pub const NVME_REG_CAP: u64 = 0x00;
pub const NVME_REG_VS: u64 = 0x08;
pub const NVME_REG_CC: u64 = 0x14;
pub const NVME_REG_CSTS: u64 = 0x1C;
pub const NVME_REG_AQA: u64 = 0x24;
pub const NVME_REG_ASQ: u64 = 0x28;
pub const NVME_REG_ACQ: u64 = 0x30;

pub struct Ps5StorageController {
    base_address: u64,
    size: u64,
    cc: u32,
    csts: u32,
    asq: u64,
    acq: u64,
}

impl Ps5StorageController {
    pub fn new(base_address: u64) -> Self {
        Self {
            base_address,
            size: 0x4000,
            cc: 0,
            csts: 0,
            asq: 0,
            acq: 0,
        }
    }
}

impl MmioDevice for Ps5StorageController {
    fn name(&self) -> &str {
        "Ps5CustomNvmeController"
    }

    fn base_address(&self) -> u64 {
        self.base_address
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn read(&self, offset: u64, _size: usize) -> Result<u64, MmioError> {
        let val: u64 = match offset {
            NVME_REG_CAP => 0x0000_0030_0000_003F, // 64K max queue, 4K page
            NVME_REG_VS => 0x0001_0400,            // NVMe 1.4
            NVME_REG_CC => self.cc as u64,
            NVME_REG_CSTS => self.csts as u64,
            NVME_REG_ASQ => self.asq,
            NVME_REG_ACQ => self.acq,
            _ => 0,
        };
        Ok(val)
    }

    fn write(&mut self, offset: u64, value: u64, _size: usize) -> Result<(), MmioError> {
        match offset {
            NVME_REG_CC => {
                self.cc = value as u32;
                if self.cc & 0x1 != 0 {
                    self.csts |= 0x1; // RDY flag set
                } else {
                    self.csts &= !0x1;
                }
            }
            NVME_REG_ASQ => self.asq = value,
            NVME_REG_ACQ => self.acq = value,
            _ => {}
        }
        Ok(())
    }
}
