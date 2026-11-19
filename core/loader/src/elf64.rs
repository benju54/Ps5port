//! ELF64 binary header and segment structure parsing for AMD x86-64 Prospero payloads.

use crate::error::LoaderError;
use std::io::{Read, Seek, SeekFrom};

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const EM_X86_64: u16 = 0x3E;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_SCE_RELA: u32 = 0x6000_0000;
pub const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;
pub const PT_SCE_PROCPARAM: u32 = 0x6100_0001;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    Load,
    Dynamic,
    Interp,
    Note,
    Phdr,
    Tls,
    SceRela,
    SceDynlibData,
    SceProcParam,
    Unknown(u32),
}

impl From<u32> for SegmentType {
    fn from(val: u32) -> Self {
        match val {
            PT_LOAD => Self::Load,
            PT_DYNAMIC => Self::Dynamic,
            PT_INTERP => Self::Interp,
            PT_NOTE => Self::Note,
            PT_PHDR => Self::Phdr,
            PT_TLS => Self::Tls,
            PT_SCE_RELA => Self::SceRela,
            PT_SCE_DYNLIBDATA => Self::SceDynlibData,
            PT_SCE_PROCPARAM => Self::SceProcParam,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf64ProgramHeader {
    pub index: usize,
    pub p_type: SegmentType,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64ProgramHeader {
    pub fn is_readable(&self) -> bool {
        (self.p_flags & PF_R) != 0
    }
    pub fn is_writable(&self) -> bool {
        (self.p_flags & PF_W) != 0
    }
    pub fn is_executable(&self) -> bool {
        (self.p_flags & PF_X) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf64Header {
    pub machine: u16,
    pub entry_point: u64,
    pub ph_offset: u64,
    pub sh_offset: u64,
    pub flags: u32,
    pub ph_num: u16,
    pub sh_num: u16,
    pub program_headers: Vec<Elf64ProgramHeader>,
}

impl Elf64Header {
    pub fn parse<R: Read + Seek>(reader: &mut R, base_offset: u64) -> Result<Self, LoaderError> {
        reader.seek(SeekFrom::Start(base_offset))?;

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != ELF_MAGIC {
            return Err(LoaderError::InvalidMagic {
                expected: "ELF",
                found: magic,
            });
        }

        let mut ident_tail = [0u8; 12];
        reader.read_exact(&mut ident_tail)?;
        let ei_class = ident_tail[0]; // 2 = 64-bit
        let ei_data = ident_tail[1]; // 1 = Little endian
        if ei_class != 2 || ei_data != 1 {
            return Err(LoaderError::InvalidSegmentTable(
                "Not a 64-bit Little-Endian ELF".into(),
            ));
        }

        let mut body = [0u8; 48];
        reader.read_exact(&mut body)?;

        let _e_type = u16::from_le_bytes(body[0..2].try_into().unwrap());
        let e_machine = u16::from_le_bytes(body[2..4].try_into().unwrap());
        if e_machine != EM_X86_64 {
            return Err(LoaderError::UnsupportedArchitecture(e_machine));
        }

        let _e_version = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let e_entry = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let e_phoff = u64::from_le_bytes(body[16..24].try_into().unwrap());
        let e_shoff = u64::from_le_bytes(body[24..32].try_into().unwrap());
        let e_flags = u32::from_le_bytes(body[32..36].try_into().unwrap());
        let _e_ehsize = u16::from_le_bytes(body[36..38].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes(body[38..40].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(body[40..42].try_into().unwrap());
        let _e_shentsize = u16::from_le_bytes(body[42..44].try_into().unwrap());
        let e_shnum = u16::from_le_bytes(body[44..46].try_into().unwrap());

        let mut program_headers = Vec::with_capacity(e_phnum as usize);

        for i in 0..e_phnum as usize {
            let ph_pos = base_offset + e_phoff + (i * e_phentsize) as u64;
            reader.seek(SeekFrom::Start(ph_pos))?;

            let mut ph_raw = [0u8; 56];
            reader.read_exact(&mut ph_raw)?;

            let p_type = u32::from_le_bytes(ph_raw[0..4].try_into().unwrap());
            let p_flags = u32::from_le_bytes(ph_raw[4..8].try_into().unwrap());
            let p_offset = u64::from_le_bytes(ph_raw[8..16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(ph_raw[16..24].try_into().unwrap());
            let p_paddr = u64::from_le_bytes(ph_raw[24..32].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(ph_raw[32..40].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(ph_raw[40..48].try_into().unwrap());
            let p_align = u64::from_le_bytes(ph_raw[48..56].try_into().unwrap());

            program_headers.push(Elf64ProgramHeader {
                index: i,
                p_type: SegmentType::from(p_type),
                p_flags,
                p_offset,
                p_vaddr,
                p_paddr,
                p_filesz,
                p_memsz,
                p_align,
            });
        }

        Ok(Elf64Header {
            machine: e_machine,
            entry_point: e_entry,
            ph_offset: e_phoff,
            sh_offset: e_shoff,
            flags: e_flags,
            ph_num: e_phnum,
            sh_num: e_shnum,
            program_headers,
        })
    }
}
