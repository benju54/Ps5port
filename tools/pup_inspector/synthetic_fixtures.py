"""
Synthetic binary fixtures for testing SLB2, PUP inner containers, and ELF64 headers.
Allows 100% offline, legal, self-contained unit testing with zero external binaries.
"""

from __future__ import annotations
import os
import struct
from .container import SLB2_MAGIC, PUP_INNER_MAGIC_BYTES_LE
from .elf import ELF_MAGIC, PT_LOAD


def create_synthetic_elf64(entry_point: int = 0x400000) -> bytes:
    """
    Construct a minimalist, syntactically valid x86-64 ELF64 binary with 2 PT_LOAD segments.
    """
    # 1. ELF Header (64 bytes)
    # e_ident: magic (4), class=2 (64-bit), data=1 (little-endian), ver=1, osabi=0, abiver=0, pad (7)
    e_ident = ELF_MAGIC + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7

    e_type = 2          # ET_EXEC
    e_machine = 0x3E    # AMD x86-64
    e_version = 1
    e_entry = entry_point
    e_phoff = 64        # Immediately following ELF header
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 2
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
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
    )

    # 2. Program Headers (2 * 56 = 112 bytes)
    # Segment 0: Text (RX)
    # p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
    p_offset_0 = 512
    p_vaddr_0 = 0x400000
    p_paddr_0 = 0x400000
    p_filesz_0 = 256
    p_memsz_0 = 256
    p_flags_0 = 5  # R | X
    p_align_0 = 0x1000

    ph0 = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,
        p_flags_0,
        p_offset_0,
        p_vaddr_0,
        p_paddr_0,
        p_filesz_0,
        p_memsz_0,
        p_align_0,
    )

    # Segment 1: Data (RW)
    p_offset_1 = 512 + 256
    p_vaddr_1 = 0x600000
    p_paddr_1 = 0x600000
    p_filesz_1 = 128
    p_memsz_1 = 512  # .bss extension
    p_flags_1 = 6  # R | W
    p_align_1 = 0x1000

    ph1 = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,
        p_flags_1,
        p_offset_1,
        p_vaddr_1,
        p_paddr_1,
        p_filesz_1,
        p_memsz_1,
        p_align_1,
    )

    # Construct payload buffer
    buffer = bytearray(header + ph0 + ph1)
    # Pad to segment 0 offset
    if len(buffer) < p_offset_0:
        buffer.extend(b"\x00" * (p_offset_0 - len(buffer)))

    # Segment 0 code: synthetic NOP sled with RET
    code = b"\x90" * 255 + b"\xC3"
    buffer.extend(code)

    # Pad to segment 1 offset
    if len(buffer) < p_offset_1:
        buffer.extend(b"\x00" * (p_offset_1 - len(buffer)))

    # Segment 1 data: plaintext ASCII string
    data = b"Ps5port Synthetic Plaintext ELF64 Segment Data Payload\x00"
    data = data.ljust(p_filesz_1, b"\x00")
    buffer.extend(data)

    return bytes(buffer)


def create_high_entropy_block(size: int = 4096) -> bytes:
    """Generate cryptographically pseudo-random high-entropy bytes."""
    return os.urandom(size)


def create_synthetic_slb2(entries_data: list[tuple[str, bytes]]) -> bytes:
    """
    Construct a synthetic SLB2 container image.
    entries_data: list of (entry_name, content_bytes)
    """
    sector_size = 512
    entry_count = len(entries_data)
    # Header takes at least 1 sector (0x30 + N * 48 <= 512 for small N)
    header_sectors = max(1, (0x30 + (entry_count * 48) + sector_size - 1) // sector_size)

    # Calculate sector offsets for each entry
    current_sector = header_sectors
    packed_entries: list[tuple[int, int, str, bytes]] = []

    for name, content in entries_data:
        size_sectors = (len(content) + sector_size - 1) // sector_size
        packed_entries.append((current_sector, size_sectors, name, content))
        current_sector += size_sectors

    total_sectors = current_sector

    # Build Header
    header = bytearray(sector_size * header_sectors)
    # Magic (4), Version (4), Entry Count (4), Total Sectors (4)
    struct.pack_into("<4sIII", header, 0x00, SLB2_MAGIC, 1, entry_count, total_sectors)

    # Write entry descriptors at 0x30
    for i, (off_sec, sz_sec, name, _) in enumerate(packed_entries):
        entry_offset = 0x30 + (i * 48)
        name_bytes = name.encode("ascii")[:31].ljust(32, b"\x00")
        struct.pack_into("<IIQ", header, entry_offset, off_sec, sz_sec, 0)
        header[entry_offset + 16 : entry_offset + 48] = name_bytes

    # Build file body with aligned sectors
    body = bytearray(header)
    for off_sec, sz_sec, _, content in packed_entries:
        target_byte = off_sec * sector_size
        if len(body) < target_byte:
            body.extend(b"\x00" * (target_byte - len(body)))
        body.extend(content)
        # Pad up to sector boundary
        rem = len(body) % sector_size
        if rem != 0:
            body.extend(b"\x00" * (sector_size - rem))

    return bytes(body)


def create_synthetic_pup_inner(file_descriptors: list[tuple[int, int, bytes]]) -> bytes:
    """
    Construct a synthetic inner PUP container (0xEEF51454).
    file_descriptors: list of (file_id, flags, content_bytes)
    """
    header_size = 32 + (len(file_descriptors) * 32)
    package_type = 1
    file_count = len(file_descriptors)
    segment_count = file_count
    flags = 0

    header = bytearray(header_size)
    header[0:4] = PUP_INNER_MAGIC_BYTES_LE
    struct.pack_into(
        "<IIIIQ",
        header,
        4,
        package_type,
        header_size,
        file_count,
        segment_count,
        flags,
    )

    body = bytearray(header)
    current_off = header_size

    for i, (fid, fflags, content) in enumerate(file_descriptors):
        entry_pos = 32 + (i * 32)
        content_len = len(content)
        struct.pack_into("<IIQQ", body, entry_pos, fid, fflags, current_off, content_len)
        current_off += content_len

    for _, _, content in file_descriptors:
        body.extend(content)

    return bytes(body)
