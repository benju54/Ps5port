//! Error types for container and binary loading.

use std::fmt;

#[derive(Debug)]
pub enum LoaderError {
    InvalidMagic { expected: &'static str, found: [u8; 4] },
    TruncatedHeader { expected_bytes: usize, available_bytes: usize },
    UnsupportedArchitecture(u16),
    InvalidSegmentTable(String),
    HighEntropyEncryptedBlock { offset: u64, size: u64 },
    Io(std::io::Error),
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic { expected, found } => {
                write!(
                    f,
                    "Invalid container magic: expected '{}', found {:02X?}",
                    expected, found
                )
            }
            Self::TruncatedHeader { expected_bytes, available_bytes } => {
                write!(
                    f,
                    "Truncated header: expected at least {} bytes, available: {}",
                    expected_bytes, available_bytes
                )
            }
            Self::UnsupportedArchitecture(arch) => {
                write!(f, "Unsupported ELF architecture: 0x{:04X} (expected x86-64 0x003E)", arch)
            }
            Self::InvalidSegmentTable(msg) => write!(f, "Invalid segment table: {}", msg),
            Self::HighEntropyEncryptedBlock { offset, size } => {
                write!(
                    f,
                    "Encountered encrypted / high-entropy block at 0x{:08X} ({} bytes)",
                    offset, size
                )
            }
            Self::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for LoaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LoaderError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
