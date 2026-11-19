//! Virtual memory segment structures and security classification.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentSecurityState {
    Plaintext,
    Compressed,
    EncryptedHighEntropy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemoryProtection {
    pub const RX: Self = Self { read: true, write: false, execute: true };
    pub const RW: Self = Self { read: true, write: true, execute: false };
    pub const RO: Self = Self { read: true, write: false, execute: false };
}

#[derive(Debug, Clone)]
pub struct VirtualMemorySegment {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub protection: MemoryProtection,
    pub security_state: SegmentSecurityState,
    pub backing_data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SegmentMap {
    segments: Vec<VirtualMemorySegment>,
}

impl SegmentMap {
    pub fn new() -> Self {
        Self { segments: Vec::new() }
    }

    pub fn insert(&mut self, segment: VirtualMemorySegment) {
        self.segments.push(segment);
    }

    pub fn find_segment(&self, vaddr: u64) -> Option<&VirtualMemorySegment> {
        self.segments.iter().find(|seg| {
            vaddr >= seg.vaddr && vaddr < (seg.vaddr + seg.size)
        })
    }

    pub fn segments(&self) -> &[VirtualMemorySegment] {
        &self.segments
    }
}
