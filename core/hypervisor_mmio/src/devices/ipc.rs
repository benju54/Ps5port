//! Inter-Processor Communication (IPC) and Mailbox interface stub.
//!
//! Connects x86-64 CPU cores with Secure Processor / System Software daemon stubs.

use crate::mmio::{MmioDevice, MmioError};

pub const IPC_REG_INBOX: u64 = 0x00;
pub const IPC_REG_OUTBOX: u64 = 0x08;
pub const IPC_REG_STATUS: u64 = 0x10;
pub const IPC_REG_DOORBELL: u64 = 0x18;

pub struct IpcMailbox {
    base_address: u64,
    size: u64,
    inbox: u64,
    outbox: u64,
    status: u64,
}

impl IpcMailbox {
    pub fn new(base_address: u64) -> Self {
        Self {
            base_address,
            size: 0x1000,
            inbox: 0,
            outbox: 0,
            status: 0,
        }
    }
}

impl MmioDevice for IpcMailbox {
    fn name(&self) -> &str {
        "SceSecureIpcMailbox"
    }

    fn base_address(&self) -> u64 {
        self.base_address
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn read(&self, offset: u64, _size: usize) -> Result<u64, MmioError> {
        let val = match offset {
            IPC_REG_INBOX => self.inbox,
            IPC_REG_OUTBOX => self.outbox,
            IPC_REG_STATUS => self.status,
            _ => 0,
        };
        Ok(val)
    }

    fn write(&mut self, offset: u64, value: u64, _size: usize) -> Result<(), MmioError> {
        match offset {
            IPC_REG_INBOX => self.inbox = value,
            IPC_REG_OUTBOX => self.outbox = value,
            IPC_REG_DOORBELL => {
                // Signal mailbox event
                self.status |= 0x1;
            }
            _ => {}
        }
        Ok(())
    }
}
