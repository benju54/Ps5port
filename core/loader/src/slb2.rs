//! SLB2 firmware container parser.
//!
//! Outer container used across PlayStation firmware updates and diagnostic images.

use crate::error::LoaderError;
use std::io::{Read, Seek, SeekFrom};

pub const SLB2_MAGIC: [u8; 4] = *b"SLB2";
pub const SLB2_ENTRY_SIZE: usize = 48; // 0x30 bytes
pub const SECTOR_SIZE: u64 = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slb2Entry {
    pub index: usize,
    pub name: String,
    pub offset_sectors: u32,
    pub size_sectors: u32,
    pub byte_offset: u64,
    pub byte_size: u64,
    pub reserved: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slb2Header {
    pub version: u32,
    pub entry_count: u32,
    pub total_sectors: u32,
    pub entries: Vec<Slb2Entry>,
}

impl Slb2Header {
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self, LoaderError> {
        reader.seek(SeekFrom::Start(0))?;

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != SLB2_MAGIC {
            return Err(LoaderError::InvalidMagic {
                expected: "SLB2",
                found: magic,
            });
        }

        let mut hdr_bytes = [0u8; 12];
        reader.read_exact(&mut hdr_bytes)?;
        let version = u32::from_le_bytes(hdr_bytes[0..4].try_into().unwrap());
        let entry_count = u32::from_le_bytes(hdr_bytes[4..8].try_into().unwrap());
        let total_sectors = u32::from_le_bytes(hdr_bytes[8..12].try_into().unwrap());

        let mut entries = Vec::with_capacity(entry_count as usize);

        for i in 0..entry_count {
            let entry_offset = 0x30 + (i as u64 * SLB2_ENTRY_SIZE as u64);
            reader.seek(SeekFrom::Start(entry_offset))?;

            let mut raw_entry = [0u8; SLB2_ENTRY_SIZE];
            reader.read_exact(&mut raw_entry)?;

            let off_sec = u32::from_le_bytes(raw_entry[0..4].try_into().unwrap());
            let sz_sec = u32::from_le_bytes(raw_entry[4..8].try_into().unwrap());
            let reserved = u64::from_le_bytes(raw_entry[8..16].try_into().unwrap());

            let name_raw = &raw_entry[16..48];
            let name_len = name_raw.iter().position(|&c| c == 0).unwrap_or(32);
            let name = String::from_utf8_lossy(&name_raw[..name_len]).to_string();

            entries.push(Slb2Entry {
                index: i as usize,
                name,
                offset_sectors: off_sec,
                size_sectors: sz_sec,
                byte_offset: off_sec as u64 * SECTOR_SIZE,
                byte_size: sz_sec as u64 * SECTOR_SIZE,
                reserved,
            });
        }

        Ok(Slb2Header {
            version,
            entry_count,
            total_sectors,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_slb2_header() {
        let mut buf = vec![0u8; 1024];
        buf[0..4].copy_from_slice(b"SLB2");
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // 1 entry
        buf[12..16].copy_from_slice(&10u32.to_le_bytes()); // 10 total sectors

        // Entry at 0x30
        let entry_off = 0x30;
        buf[entry_off..entry_off + 4].copy_from_slice(&1u32.to_le_bytes()); // sector 1
        buf[entry_off + 4..entry_off + 8].copy_from_slice(&2u32.to_le_bytes()); // 2 sectors
        let name = b"pup_entries\0";
        buf[entry_off + 16..entry_off + 16 + name.len()].copy_from_slice(name);

        let mut cursor = Cursor::new(buf);
        let slb2 = Slb2Header::parse(&mut cursor).expect("Failed to parse SLB2");
        assert_eq!(slb2.version, 1);
        assert_eq!(slb2.entry_count, 1);
        assert_eq!(slb2.entries.len(), 1);
        assert_eq!(slb2.entries[0].name, "pup_entries");
        assert_eq!(slb2.entries[0].byte_offset, 512);
        assert_eq!(slb2.entries[0].byte_size, 1024);
    }
}
