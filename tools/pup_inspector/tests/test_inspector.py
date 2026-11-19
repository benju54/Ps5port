"""
Comprehensive unit tests for Ps5port PUP / SLB2 / ELF64 Inspector.
Tests with synthetic fixtures: zero external dependencies, 100% reproducible.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.pup_inspector.container import parse_slb2_stream, parse_pup_inner_stream
from tools.pup_inspector.elf import parse_elf64_stream, PT_LOAD
from tools.pup_inspector.entropy import (
    calculate_entropy,
    classify_entropy,
    scan_entropy_blocks,
    ENTROPY_HIGH_THRESHOLD,
)
from tools.pup_inspector.manifest import export_to_json, export_entries_to_csv
from tools.pup_inspector.synthetic_fixtures import (
    create_synthetic_elf64,
    create_high_entropy_block,
    create_synthetic_slb2,
    create_synthetic_pup_inner,
)
from tools.pup_inspector.cli import inspect_binary_buffer


class TestEntropyModule(unittest.TestCase):
    def test_null_bytes_entropy(self):
        zeros = b"\x00" * 1024
        ent = calculate_entropy(zeros)
        self.assertEqual(ent, 0.0)
        self.assertEqual(classify_entropy(ent), "LOW_ENTROPY_SPARSE")

    def test_ascii_entropy(self):
        text = b"Orbis OS Prospero Hypervisor Plaintext Test Data 1234567890" * 20
        ent = calculate_entropy(text)
        self.assertTrue(3.0 <= ent <= 6.5)
        self.assertEqual(classify_entropy(ent), "PLAINTEXT_CODE_OR_DATA")

    def test_high_entropy_random_block(self):
        rand_block = create_high_entropy_block(4096)
        ent = calculate_entropy(rand_block)
        self.assertGreaterEqual(ent, 7.7)
        self.assertEqual(classify_entropy(ent), "ENCRYPTED_OR_HIGH_ENTROPY")

    def test_scan_entropy_blocks(self):
        sparse = b"\x00" * 4096
        dense = create_high_entropy_block(4096)
        combined = sparse + dense
        blocks = scan_entropy_blocks(combined, block_size=4096)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0][0], 0)
        self.assertEqual(blocks[0][2], "LOW_ENTROPY_SPARSE")
        self.assertEqual(blocks[1][0], 4096)
        self.assertEqual(blocks[1][2], "ENCRYPTED_OR_HIGH_ENTROPY")


class TestElf64Parser(unittest.TestCase):
    def setUp(self):
        self.entry_point = 0x401000
        self.elf_bytes = create_synthetic_elf64(entry_point=self.entry_point)

    def test_parse_valid_elf64(self):
        stream = io.BytesIO(self.elf_bytes)
        elf = parse_elf64_stream(stream)
        self.assertIsNotNone(elf)
        self.assertEqual(elf.machine, "x86-64")
        self.assertEqual(elf.entry_point, self.entry_point)
        self.assertEqual(len(elf.program_headers), 2)

        ph0 = elf.program_headers[0]
        self.assertEqual(ph0.p_type, PT_LOAD)
        self.assertEqual(ph0.flags_str, "R-X")
        self.assertEqual(ph0.p_vaddr, 0x400000)

        ph1 = elf.program_headers[1]
        self.assertEqual(ph1.p_type, PT_LOAD)
        self.assertEqual(ph1.flags_str, "RW-")
        self.assertEqual(ph1.p_vaddr, 0x600000)

    def test_parse_corrupt_stream_does_not_crash(self):
        corrupt = b"\x7fELF" + b"\xff" * 20
        stream = io.BytesIO(corrupt)
        elf = parse_elf64_stream(stream)
        self.assertIsNone(elf)


class TestContainerParser(unittest.TestCase):
    def setUp(self):
        self.elf_bytes = create_synthetic_elf64()
        self.enc_bytes = create_high_entropy_block(4096)
        self.slb2_data = create_synthetic_slb2([
            ("bootloader.elf", self.elf_bytes),
            ("encrypted_segment.bin", self.enc_bytes),
        ])

    def test_parse_slb2_header_and_entries(self):
        stream = io.BytesIO(self.slb2_data)
        slb2 = parse_slb2_stream(stream)
        self.assertIsNotNone(slb2)
        self.assertEqual(slb2.magic, "SLB2")
        self.assertEqual(slb2.version, 1)
        self.assertEqual(slb2.entry_count, 2)
        self.assertEqual(len(slb2.entries), 2)

        entry0 = slb2.entries[0]
        self.assertEqual(entry0.name, "bootloader.elf")
        self.assertGreater(entry0.byte_size, 0)
        self.assertIn(entry0.entropy_status, ("PLAINTEXT_CODE_OR_DATA", "LOW_ENTROPY_SPARSE"))

        entry1 = slb2.entries[1]
        self.assertEqual(entry1.name, "encrypted_segment.bin")
        self.assertEqual(entry1.entropy_status, "ENCRYPTED_OR_HIGH_ENTROPY")

    def test_parse_inner_pup_container(self):
        inner_data = create_synthetic_pup_inner([
            (0x10, 0, b"Inner Plaintext Descriptor"),
            (0x20, 1, self.enc_bytes),
        ])
        stream = io.BytesIO(inner_data)
        inner = parse_pup_inner_stream(stream)
        self.assertIsNotNone(inner)
        self.assertEqual(inner.magic, "0xEEF51454")
        self.assertEqual(inner.file_count, 2)
        self.assertEqual(len(inner.entries), 2)
        self.assertEqual(inner.entries[0].file_id, 0x10)
        self.assertEqual(inner.entries[1].file_id, 0x20)
        self.assertEqual(inner.entries[1].entropy_status, "ENCRYPTED_OR_HIGH_ENTROPY")


class TestManifestAndCliPipeline(unittest.TestCase):
    def test_inspect_binary_buffer(self):
        elf_bytes = create_synthetic_elf64()
        slb2_bytes = create_synthetic_slb2([("app.elf", elf_bytes)])
        res = inspect_binary_buffer(slb2_bytes, "test_buffer")
        self.assertEqual(len(res["containers"]), 1)
        self.assertEqual(res["containers"][0]["type"], "SLB2")
        self.assertEqual(len(res["elf_files"]), 1)
        self.assertEqual(res["elf_files"][0]["parent_entry"], "app.elf")

    def test_manifest_export_json_and_csv(self):
        elf_bytes = create_synthetic_elf64()
        slb2_bytes = create_synthetic_slb2([("app.elf", elf_bytes)])
        res = inspect_binary_buffer(slb2_bytes, "test_buffer")

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "manifest.json"
            csv_path = Path(tmpdir) / "entries.csv"

            export_to_json(res, json_path)
            self.assertTrue(json_path.exists())
            with open(json_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["source"], "test_buffer")

            entries = res["containers"][0]["header"]["entries"]
            export_entries_to_csv(entries, csv_path)
            self.assertTrue(csv_path.exists())
            with open(csv_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertGreaterEqual(len(lines), 2)  # Header + 1 entry
            self.assertIn("app.elf", lines[1])


if __name__ == "__main__":
    unittest.main()
