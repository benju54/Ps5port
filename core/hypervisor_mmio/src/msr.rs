//! x86-64 Model-Specific Registers (MSRs) trap emulation.
//!
//! Tracks syscall registers, segment base addresses, and performance counters
//! expected by the FreeBSD/Prospero x86-64 kernel.

use std::collections::HashMap;

pub const IA32_TSC: u32 = 0x0000_0010;
pub const IA32_APIC_BASE: u32 = 0x0000_001B;
pub const IA32_EFER: u32 = 0xC000_0080;
pub const IA32_STAR: u32 = 0xC000_0081;
pub const IA32_LSTAR: u32 = 0xC000_0082;
pub const IA32_CSTAR: u32 = 0xC000_0083;
pub const IA32_SFMASK: u32 = 0xC000_0084;
pub const IA32_FS_BASE: u32 = 0xC000_0100;
pub const IA32_GS_BASE: u32 = 0xC000_0101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const IA32_TSC_AUX: u32 = 0xC000_0103;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsrError {
    GeneralProtectionFault(u32),
    InvalidValue { msr: u32, value: u64 },
}

#[derive(Debug, Default)]
pub struct MsrRegisterFile {
    registers: HashMap<u32, u64>,
}

impl MsrRegisterFile {
    pub fn new() -> Self {
        let mut file = Self {
            registers: HashMap::new(),
        };
        // Initialize default EFER (LME = Long Mode Enable, NXE = No-Execute Enable, SCE = Syscall Enable)
        file.registers.insert(IA32_EFER, 0xD01); // SCE | LME | LMA | NXE
        file
    }

    pub fn read(&self, msr: u32) -> Result<u64, MsrError> {
        match msr {
            IA32_TSC => Ok(100_000_000), // Virtual TSC ticks
            msr_id => self
                .registers
                .get(&msr_id)
                .copied()
                .ok_or(MsrError::GeneralProtectionFault(msr_id)),
        }
    }

    pub fn write(&mut self, msr: u32, value: u64) -> Result<(), MsrError> {
        match msr {
            IA32_FS_BASE | IA32_GS_BASE | IA32_KERNEL_GS_BASE => {
                // Canonical address check (48-bit sign-extended)
                let sign_ext = ((value as i64) << 16) >> 16;
                if sign_ext as u64 != value {
                    return Err(MsrError::InvalidValue { msr, value });
                }
                self.registers.insert(msr, value);
                Ok(())
            }
            IA32_STAR | IA32_LSTAR | IA32_CSTAR | IA32_SFMASK | IA32_EFER | IA32_APIC_BASE | IA32_TSC_AUX => {
                self.registers.insert(msr, value);
                Ok(())
            }
            _ => Err(MsrError::GeneralProtectionFault(msr)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msr_lstar_and_fs_base() {
        let mut msr = MsrRegisterFile::new();
        let kernel_syscall_entry = 0xFFFFFFFF80200000;
        msr.write(IA32_LSTAR, kernel_syscall_entry).expect("LSTAR write failed");
        assert_eq!(msr.read(IA32_LSTAR).unwrap(), kernel_syscall_entry);

        let user_tls = 0x00007FFFFFF00000;
        msr.write(IA32_FS_BASE, user_tls).expect("FS_BASE write failed");
        assert_eq!(msr.read(IA32_FS_BASE).unwrap(), user_tls);
    }
}
