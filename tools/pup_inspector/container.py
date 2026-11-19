"""
Parsers for outer SLB2 archives and inner PUP container headers (0xEEF51454).
Zero external dependencies.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, asdict
from typing import List, Optional, BinaryIO
from .entropy import calculate_entropy, classify_entropy

SLB2_MAGIC = b"SLB2"
SLB2_ENTRY_SIZE = 48  # 0x30 bytes
PUP_INNER_MAGIC_LE = 0xEEF51454
PUP_INNER_MAGIC_BYTES_LE = struct.pack("<I", PUP_INNER_MAGIC_LE)  # b"\x54\x14\xF5\xEE"
PUP_INNER_MAGIC_BYTES_BE = struct.pack(">I", PUP_INNER_MAGIC_LE)  # b"\xEE\xF5\x14\x54"


@dataclass
class Slb2Entry:
    index: int
    name: str
    offset_sectors: int
    size_sectors: int
    byte_offset: int
    byte_size: int
    reserved: int
    entropy: float
    entropy_status: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Slb2Header:
    magic: str
    version: int
    entry_count: int
    total_sectors: int
    reserved: bytes
    entries: List[Slb2Entry]

    def to_dict(self):
        d = asdict(self)
        d["reserved"] = self.reserved.hex()
        return d


@dataclass
class PupInnerEntry:
    index: int
    file_id: int
    flags: int
    byte_offset: int
    byte_size: int
    entropy: float
    entropy_status: str

    def to_dict(self):
        return asdict(self)


@dataclass
class PupInnerHeader:
    magic: str
    package_type: int
    header_size: int
    file_count: int
    segment_count: int
    flags: int
    entries: List[PupInnerEntry]

    def to_dict(self):
        return asdict(self)


def parse_slb2_stream(stream: BinaryIO, sector_size: int = 512) -> Optional[Slb2Header]:
    """Parse SLB2 archive header and entries table from a binary stream."""
    stream.seek(0)
    magic = stream.read(4)
    if magic != SLB2_MAGIC:
        return None

    raw_header = stream.read(44)  # up to 0x30
    if len(raw_header) < 44:
        raise ValueError("Truncated SLB2 header")

    version, entry_count, total_sectors = struct.unpack("<III", raw_header[0:12])
    reserved = raw_header[12:44]

    entries: List[Slb2Entry] = []
    for i in range(entry_count):
        stream.seek(0x30 + i * SLB2_ENTRY_SIZE)
        raw_entry = stream.read(SLB2_ENTRY_SIZE)
        if len(raw_entry) < SLB2_ENTRY_SIZE:
            break

        offset_sectors, size_sectors, reserved_val = struct.unpack("<IIQ", raw_entry[0:16])
        name_raw = raw_entry[16:48]
        name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")

        byte_offset = offset_sectors * sector_size
        byte_size = size_sectors * sector_size

        # Sample entropy from data (first 64KB max)
        entropy = 0.0
        entropy_status = "UNKNOWN"
        try:
            stream.seek(byte_offset)
            sample_len = min(byte_size, 65536)
            if sample_len > 0:
                sample = stream.read(sample_len)
                entropy = calculate_entropy(sample)
                entropy_status = classify_entropy(entropy)
        except Exception:
            entropy_status = "READ_ERROR"

        entries.append(
            Slb2Entry(
                index=i,
                name=name,
                offset_sectors=offset_sectors,
                size_sectors=size_sectors,
                byte_offset=byte_offset,
                byte_size=byte_size,
                reserved=reserved_val,
                entropy=round(entropy, 4),
                entropy_status=entropy_status,
            )
        )

    return Slb2Header(
        magic="SLB2",
        version=version,
        entry_count=entry_count,
        total_sectors=total_sectors,
        reserved=reserved,
        entries=entries,
    )


def parse_pup_inner_stream(stream: BinaryIO, base_offset: int = 0) -> Optional[PupInnerHeader]:
    """Parse inner SCE PUP container (0xEEF51454) starting at base_offset."""
    stream.seek(base_offset)
    magic_bytes = stream.read(4)
    if len(magic_bytes) < 4:
        return None

    if magic_bytes == PUP_INNER_MAGIC_BYTES_LE:
        endianness = "<"
    elif magic_bytes == PUP_INNER_MAGIC_BYTES_BE:
        endianness = ">"
    else:
        return None

    raw = stream.read(28)
    if len(raw) < 28:
        return None

    package_type, header_size, file_count, segment_count = struct.unpack(
        endianness + "IIII", raw[0:16]
    )
    flags = struct.unpack(endianness + "Q", raw[16:24])[0]

    entries: List[PupInnerEntry] = []
    # In PUP container layout, table entries follow header (each 32 bytes: file_id, flags, offset, size)
    current_pos = base_offset + 32
    for i in range(min(file_count, 1024)):
        stream.seek(current_pos + i * 32)
        entry_raw = stream.read(32)
        if len(entry_raw) < 32:
            break
        file_id, entry_flags, file_off, file_sz = struct.unpack(
            endianness + "IIQQ", entry_raw[0:24]
        )

        entropy = 0.0
        entropy_status = "UNKNOWN"
        try:
            stream.seek(base_offset + file_off)
            sample_len = min(file_sz, 65536)
            if sample_len > 0:
                sample = stream.read(sample_len)
                entropy = calculate_entropy(sample)
                entropy_status = classify_entropy(entropy)
        except Exception:
            entropy_status = "READ_ERROR"

        entries.append(
            PupInnerEntry(
                index=i,
                file_id=file_id,
                flags=entry_flags,
                byte_offset=base_offset + file_off,
                byte_size=file_sz,
                entropy=round(entropy, 4),
                entropy_status=entropy_status,
            )
        )

    return PupInnerHeader(
        magic="0xEEF51454",
        package_type=package_type,
        header_size=header_size,
        file_count=file_count,
        segment_count=segment_count,
        flags=flags,
        entries=entries,
    )
