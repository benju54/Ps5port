//! AMD Zen 2 "Oberon" APU CPUID leaf emulation for PS5 guest execution.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Debug, Clone)]
pub struct CpuidEmulator {
    brand_string: [u8; 48],
}

impl Default for CpuidEmulator {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuidEmulator {
    pub fn new() -> Self {
        let mut brand_string = [0u8; 48];
        let name = b"AMD Custom APU 0405 (Oberon / Zen 2)\0";
        brand_string[..name.len()].copy_from_slice(name);
        Self { brand_string }
    }

    /// Emulate CPUID execution for specified leaf (eax) and subleaf (ecx).
    pub fn query(&self, leaf: u32, subleaf: u32) -> CpuidResult {
        match leaf {
            // Leaf 0: Vendor String ("AuthenticAMD") & Maximum Basic Leaf
            0x0000_0000 => CpuidResult {
                eax: 0x0000_0010, // Max supported standard leaf
                ebx: 0x6874_7541, // "Auth"
                edx: 0x6974_6E65, // "enti"
                ecx: 0x444D_4163, // "cAMD"
            },

            // Leaf 1: Family/Model/Stepping & Basic Feature Identifiers
            // Zen 2 Ariel/Oberon APU: Family 17h, Model 60h, Stepping 1
            0x0000_0001 => {
                // EAX: Extended Family=0x8 (17h total), Base Family=0xF, Ext Model=0x6, Model=0x0, Stepping=0x1
                let family_model_stepping: u32 = (0x8 << 20) | (0x6 << 16) | (0xF << 8) | 0x1;
                // EBX: Logical processor count (16 threads), CLFLUSH size (8), Brand ID (0)
                let brand_info: u32 = (16 << 16) | (8 << 8);
                // ECX: SSE3, SSSE3, FMA, SSE4.1, SSE4.2, MOVBE, POPCNT, AES, XSAVE, AVX, F16C, RDRAND
                let features_ecx: u32 = (1 << 0)   // SSE3
                    | (1 << 9)   // SSSE3
                    | (1 << 12)  // FMA
                    | (1 << 19)  // SSE4.1
                    | (1 << 20)  // SSE4.2
                    | (1 << 22)  // MOVBE
                    | (1 << 23)  // POPCNT
                    | (1 << 25)  // AES-NI
                    | (1 << 26)  // XSAVE
                    | (1 << 27)  // OSXSAVE
                    | (1 << 28)  // AVX
                    | (1 << 29)  // F16C
                    | (1 << 30); // RDRAND
                // EDX: FPU, VME, DE, PSE, TSC, MSR, PAE, MCE, CX8, APIC, SEP, MTRR, PGE, MCA, CMOV, PAT, PSE-36, CLFLUSH, MMX, FXSR, SSE, SSE2, HTT
                let features_edx: u32 = (1 << 0)   // FPU
                    | (1 << 3)   // PSE
                    | (1 << 4)   // TSC
                    | (1 << 5)   // MSR
                    | (1 << 6)   // PAE
                    | (1 << 8)   // CX8
                    | (1 << 9)   // APIC
                    | (1 << 11)  // SEP
                    | (1 << 12)  // MTRR
                    | (1 << 13)  // PGE
                    | (1 << 15)  // CMOV
                    | (1 << 16)  // PAT
                    | (1 << 19)  // CLFLUSH
                    | (1 << 23)  // MMX
                    | (1 << 24)  // FXSR
                    | (1 << 25)  // SSE
                    | (1 << 26)  // SSE2
                    | (1 << 28); // HTT (Hyperthreading / SMT active)
                CpuidResult {
                    eax: family_model_stepping,
                    ebx: brand_info,
                    ecx: features_ecx,
                    edx: features_edx,
                }
            }

            // Leaf 7: Structured Extended Feature Flags (Subleaf 0)
            0x0000_0007 if subleaf == 0 => {
                // EBX: FSGSBASE, BMI1, AVX2, SMEP, BMI2, ERMS, INVPCID, RDSEED, ADX, SMAP, CLFLUSHOPT, SHA
                let features_ebx = (1 << 0)   // FSGSBASE
                    | (1 << 3)   // BMI1
                    | (1 << 5)   // AVX2
                    | (1 << 7)   // SMEP
                    | (1 << 8)   // BMI2
                    | (1 << 9)   // ERMS
                    | (1 << 10)  // INVPCID
                    | (1 << 18)  // RDSEED
                    | (1 << 19)  // ADX
                    | (1 << 20)  // SMAP
                    | (1 << 23)  // CLFLUSHOPT
                    | (1 << 29); // SHA extensions
                CpuidResult {
                    eax: 0,
                    ebx: features_ebx,
                    ecx: (1 << 9), // VAES
                    edx: 0,
                }
            }

            // Leaf 0x80000000: Max Extended Function
            0x8000_0000 => CpuidResult {
                eax: 0x8000_001F,
                ebx: 0x6874_7541,
                edx: 0x6974_6E65,
                ecx: 0x444D_4163,
            },

            // Leaf 0x80000002..0x80000004: Processor Brand String
            0x8000_0002..=0x8000_0004 => {
                let chunk_idx = (leaf - 0x8000_0002) as usize * 16;
                let chunk = &self.brand_string[chunk_idx..chunk_idx + 16];
                CpuidResult {
                    eax: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                    ebx: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
                    ecx: u32::from_le_bytes(chunk[8..12].try_into().unwrap()),
                    edx: u32::from_le_bytes(chunk[12..16].try_into().unwrap()),
                }
            }

            // Leaf 0x80000008: Long Mode Address Size & Physical Core Count
            0x8000_0008 => {
                // EAX: Physical address bits (48), Linear address bits (48)
                let addr_sizes = (48 << 8) | 48;
                // ECX: NC (Number of Cores - 1) = 7 (8 cores)
                let core_count = 7;
                CpuidResult {
                    eax: addr_sizes,
                    ebx: 0,
                    ecx: core_count,
                    edx: 0,
                }
            }

            _ => CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpuid_vendor() {
        let cpuid = CpuidEmulator::new();
        let res = cpuid.query(0, 0);
        assert_eq!(res.ebx, 0x6874_7541);
        assert_eq!(res.edx, 0x6974_6E65);
        assert_eq!(res.ecx, 0x444D_4163);
    }

    #[test]
    fn test_cpuid_zen2_oberon_family() {
        let cpuid = CpuidEmulator::new();
        let res = cpuid.query(1, 0);
        let ext_family = (res.eax >> 20) & 0xFF;
        let base_family = (res.eax >> 8) & 0xF;
        assert_eq!(ext_family + base_family, 0x17); // Family 17h (Zen 2)
    }
}
