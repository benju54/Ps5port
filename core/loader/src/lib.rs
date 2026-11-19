//! Ps5port Loader: Firmware container (SLB2) and ELF64 header/segment parser.

pub mod elf64;
pub mod error;
pub mod segment;
pub mod slb2;

pub use elf64::{Elf64Header, Elf64ProgramHeader, SegmentType};
pub use error::LoaderError;
pub use segment::{MemoryProtection, SegmentMap, SegmentSecurityState, VirtualMemorySegment};
pub use slb2::{Slb2Entry, Slb2Header};
