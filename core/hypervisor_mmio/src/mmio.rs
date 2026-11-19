//! Memory-Mapped I/O (MMIO) trap routing bus and virtual device traits.

use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum MmioError {
    UnmappedAddress(u64),
    InvalidAccessSize(usize),
    DeviceFault(String),
}

pub trait MmioDevice: Send + Sync {
    fn name(&self) -> &str;
    fn base_address(&self) -> u64;
    fn size(&self) -> u64;
    fn read(&self, offset: u64, size: usize) -> Result<u64, MmioError>;
    fn write(&mut self, offset: u64, value: u64, size: usize) -> Result<(), MmioError>;
}

#[derive(Default)]
pub struct MmioBus {
    devices: Vec<Box<dyn MmioDevice>>,
}

impl MmioBus {
    pub fn new() -> Self {
        Self { devices: Vec::new() }
    }

    pub fn register_device(&mut self, device: Box<dyn MmioDevice>) {
        self.devices.push(device);
    }

    pub fn read(&self, gpa: u64, size: usize) -> Result<u64, MmioError> {
        for dev in &self.devices {
            let base = dev.base_address();
            let limit = base + dev.size();
            if gpa >= base && gpa < limit {
                return dev.read(gpa - base, size);
            }
        }
        Err(MmioError::UnmappedAddress(gpa))
    }

    pub fn write(&mut self, gpa: u64, value: u64, size: usize) -> Result<(), MmioError> {
        for dev in &mut self.devices {
            let base = dev.base_address();
            let limit = base + dev.size();
            if gpa >= base && gpa < limit {
                return dev.write(gpa - base, value, size);
            }
        }
        Err(MmioError::UnmappedAddress(gpa))
    }
}
