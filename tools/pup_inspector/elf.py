"""
Parser for x86-64 ELF64 and SCE SELF headers and segment maps.
Identifies PT_LOAD, PT_DYNAMIC, SCE-specific segment types, and entropy classification.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, asdict
from typing import List, Optional, BinaryIO
from .entropy import calculate_entropy, classify_entropy

ELF_MAGIC = b"\x7fELF"
SELF_MAGIC_1 = b"\x4f\x15\x3d\x1d"  # 0x1D3D154F
SELF_MAGIC_SCE = b"SCE\x00"

# ELF Segment types
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_SCE_RELA = 0x60000000
PT_SCE_DYNLIBDATA = 0x61000000
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_MODULE_PARAM = 0x61000002
PT_SCE_COMMENT = 0x6FFFFF00
PT_SCE_VERSION = 0x6FFFFF01

SEGMENT_TYPE_MAP = {
    PT_NULL: "PT_NULL",
    PT_LOAD: "PT_LOAD",
    PT_DYNAMIC: "PT_DYNAMIC",
    PT_INTERP: "PT_INTERP",
    PT_NOTE: "PT_NOTE",
    PT_SHLIB: "PT_SHLIB",
    PT_PHDR: "PT_PHDR",
    PT_TLS: "PT_TLS",
    PT_SCE_RELA: "PT_SCE_RELA",
    PT_SCE_DYNLIBDATA: "PT_SCE_DYNLIBDATA",
    PT_SCE_PROCPARAM: "PT_SCE_PROCPARAM",
    PT_SCE_MODULE_PARAM: "PT_SCE_MODULE_PARAM",
    PT_SCE_COMMENT: "PT_SCE_COMMENT",
    PT_SCE_VERSION: "PT_SCE_VERSION",
}


@dataclass
class Elf64ProgramHeader:
    index: int
    p_type: int
    type_name: str
    p_flags: int
    flags_str: str
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int
    entropy: float
    entropy_status: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Elf64Header:
    format_type: str  # "ELF64" or "SELF_WRAPPED"
    machine: str
    entry_point: int
    ph_offset: int
    sh_offset: int
    flags: int
    ph_num: int
    sh_num: int
    program_headers: List[Elf64ProgramHeader]

    def to_dict(self):
        d = asdict(self)
        d["entry_point_hex"] = hex(self.entry_point)
        d["ph_offset_hex"] = hex(self.ph_offset)
        return d


def flags_to_string(flags: int) -> str:
    r = "R" if (flags & 4) else "-"
    w = "W" if (flags & 2) else "-"
    x = "X" if (flags & 1) else "-"
    return f"{r}{w}{x}"


def parse_elf64_stream(stream: BinaryIO, base_offset: int = 0) -> Optional[Elf64Header]:
    """Parse ELF64 / SELF header from binary stream at base_offset."""
    stream.seek(base_offset)
    magic = stream.read(4)
    if not magic:
        return None

    format_type = "ELF64"
    elf_start = base_offset

    if magic in (SELF_MAGIC_1, SELF_MAGIC_SCE):
        format_type = "SELF_WRAPPED"
        # In SELF, the raw ELF header is typically offset at 0x20 or after SELF metadata
        # Read SELF header fields (32 bytes)
        stream.seek(base_offset + 0x10)
        extended_info = stream.read(16)
        if len(extended_info) >= 8:
            elf_offset_candidate = struct.unpack("<I", extended_info[0:4])[0]
            if 0 < elf_offset_candidate < 0x10000:
                stream.seek(base_offset + elf_offset_candidate)
                candidate_magic = stream.read(4)
                if candidate_magic == ELF_MAGIC:
                    elf_start = base_offset + elf_offset_candidate
                else:
                    elf_start = base_offset + 0x20
            else:
                elf_start = base_offset + 0x20
        else:
            elf_start = base_offset + 0x20

        stream.seek(elf_start)
        magic = stream.read(4)
        if magic != ELF_MAGIC:
            # Encrypted or non-standard SELF payload where ELF header is protected
            return Elf64Header(
                format_type="SELF_ENCRYPTED_OR_OPAQUE",
                machine="x86-64 (Assumed Prospero/Orbis)",
                entry_point=0,
                ph_offset=0,
                sh_offset=0,
                flags=0,
                ph_num=0,
                sh_num=0,
                program_headers=[],
            )

    if magic != ELF_MAGIC:
        return None

    # Read e_ident rest (12 bytes)
    stream.seek(elf_start + 4)
    ident_tail = stream.read(12)
    if len(ident_tail) < 12:
        return None

    ei_class = ident_tail[0]  # 2 for 64-bit
    ei_data = ident_tail[1]   # 1 for little-endian
    if ei_class != 2 or ei_data != 1:
        return None

    # Read 64-bit ELF header body (from 0x10 to 0x40 = 48 bytes)
    stream.seek(elf_start + 16)
    elf_body = stream.read(48)
    if len(elf_body) < 48:
        return None

    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack("<HHIQQQIHHHHHH", elf_body)

    machine_str = "x86-64" if e_machine == 0x3E else f"Unknown (0x{e_machine:x})"

    program_headers: List[Elf64ProgramHeader] = []
    if e_phentsize >= 56 and 0 < e_phnum < 1024:
        for i in range(e_phnum):
            stream.seek(elf_start + e_phoff + (i * e_phentsize))
            ph_raw = stream.read(56)
            if len(ph_raw) < 56:
                break
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = (
                struct.unpack("<IIQQQQQQ", ph_raw)
            )

            # Sample segment data for entropy
            entropy = 0.0
            entropy_status = "EMPTY"
            if p_filesz > 0:
                try:
                    stream.seek(elf_start + p_offset)
                    sample_len = min(p_filesz, 65536)
                    sample_data = stream.read(sample_len)
                    entropy = calculate_entropy(sample_data)
                    entropy_status = classify_entropy(entropy)
                except Exception:
                    entropy_status = "READ_ERROR"

            type_name = SEGMENT_TYPE_MAP.get(p_type, f"0x{p_type:08X}")
            program_headers.append(
                Elf64ProgramHeader(
                    index=i,
                    p_type=p_type,
                    type_name=type_name,
                    p_flags=p_flags,
                    flags_str=flags_to_string(p_flags),
                    p_offset=p_offset,
                    p_vaddr=p_vaddr,
                    p_paddr=p_paddr,
                    p_filesz=p_filesz,
                    p_memsz=p_memsz,
                    p_align=p_align,
                    entropy=round(entropy, 4),
                    entropy_status=entropy_status,
                )
            )

    return Elf64Header(
        format_type=format_type,
        machine=machine_str,
        entry_point=e_entry,
        ph_offset=e_phoff,
        sh_offset=e_shoff,
        flags=e_flags,
        ph_num=e_phnum,
        sh_num=e_shnum,
        program_headers=program_headers,
    )
