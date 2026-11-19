//! RDNA 2 (Navi 2x / Oberon GPU) architectural specification for PS5.

#[derive(Debug, Clone)]
pub struct OberonGpuProfile {
    pub compute_units: u32,
    pub workgroup_processors: u32,
    pub simd_per_cu: u32,
    pub wave_size: u32,
    pub max_gpu_clock_mhz: u32,
    pub ray_tracing_units: u32,
    pub vram_total_bytes: u64,
}

impl Default for OberonGpuProfile {
    fn default() -> Self {
        Self {
            compute_units: 36,
            workgroup_processors: 18,
            simd_per_cu: 2,
            wave_size: 32, // Default Wave32 mode on RDNA 2
            max_gpu_clock_mhz: 2233,
            ray_tracing_units: 36, // 1 per CU / Ray Accelerator
            vram_total_bytes: 16 * 1024 * 1024 * 1024, // 16 GB GDDR6 Unified
        }
    }
}
