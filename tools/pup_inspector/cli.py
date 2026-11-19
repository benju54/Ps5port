#!/usr/bin/env python3
"""
Ps5port PUP Inspector CLI
Usage:
    py tools/pup_inspector/cli.py --file firmware/PS5UPDATE.PUP --out-json out/manifest.json --out-csv out/entries.csv
"""

from __future__ import annotations
import argparse
import io
import os
import sys
from pathlib import Path
from typing import Dict, Any, List

if __package__ is None or __package__ == "":
    import sys
    from pathlib import Path
    # Add repo root to sys.path so tools.pup_inspector can be imported
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from tools.pup_inspector.container import parse_slb2_stream, parse_pup_inner_stream
    from tools.pup_inspector.elf import parse_elf64_stream
    from tools.pup_inspector.entropy import calculate_entropy, classify_entropy
    from tools.pup_inspector.manifest import export_to_json, export_entries_to_csv
    from tools.pup_inspector.synthetic_fixtures import (
        create_synthetic_elf64,
        create_high_entropy_block,
        create_synthetic_slb2,
        create_synthetic_pup_inner,
    )
else:
    from .container import parse_slb2_stream, parse_pup_inner_stream
    from .elf import parse_elf64_stream
    from .entropy import calculate_entropy, classify_entropy
    from .manifest import export_to_json, export_entries_to_csv
    from .synthetic_fixtures import (
        create_synthetic_elf64,
        create_high_entropy_block,
        create_synthetic_slb2,
        create_synthetic_pup_inner,
    )


def inspect_binary_buffer(data: bytes, source_name: str) -> Dict[str, Any]:
    """Inspect binary buffer, attempting SLB2, inner PUP, or ELF64 identification."""
    stream = io.BytesIO(data)
    result: Dict[str, Any] = {
        "source": source_name,
        "total_bytes": len(data),
        "overall_entropy": round(calculate_entropy(data[:131072]), 4),
        "containers": [],
        "elf_files": [],
    }

    # 1. Try SLB2
    slb2 = parse_slb2_stream(stream)
    if slb2:
        result["containers"].append({"type": "SLB2", "header": slb2.to_dict()})
        # Check sub-entries inside SLB2
        for entry in slb2.entries:
            sub_stream = io.BytesIO(data[entry.byte_offset : entry.byte_offset + entry.byte_size])
            # Check inner pup
            inner = parse_pup_inner_stream(sub_stream)
            if inner:
                result["containers"].append(
                    {"type": "INNER_PUP", "parent_entry": entry.name, "header": inner.to_dict()}
                )
            # Check inner ELF
            elf = parse_elf64_stream(sub_stream)
            if elf:
                result["elf_files"].append(
                    {"parent_entry": entry.name, "elf": elf.to_dict()}
                )
        return result

    # 2. Try Inner PUP directly
    inner = parse_pup_inner_stream(stream)
    if inner:
        result["containers"].append({"type": "INNER_PUP", "header": inner.to_dict()})
        return result

    # 3. Try ELF64 / SELF directly
    elf = parse_elf64_stream(stream)
    if elf:
        result["elf_files"].append({"parent_entry": "root", "elf": elf.to_dict()})
        return result

    # 4. Unknown format
    result["classification"] = classify_entropy(result["overall_entropy"])
    return result


def inspect_file(file_path: Path) -> Dict[str, Any]:
    """Open and inspect binary file."""
    with open(file_path, "rb") as f:
        data = f.read()
    return inspect_binary_buffer(data, str(file_path))


def run_fixtures_demo() -> Dict[str, Any]:
    """Generate and inspect synthetic fixture for validation."""
    elf_bytes = create_synthetic_elf64()
    encrypted_bytes = create_high_entropy_block(8192)
    inner_pup = create_synthetic_pup_inner([
        (0x1001, 0, elf_bytes),
        (0x1002, 1, encrypted_bytes),
    ])

    slb2_bytes = create_synthetic_slb2([
        ("kernel.elf", elf_bytes),
        ("secure_payload.enc", encrypted_bytes),
        ("inner.pup", inner_pup),
    ])

    return inspect_binary_buffer(slb2_bytes, "<synthetic_slb2_fixture>")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ps5port PS5 PUP/SLB2/ELF64 Container & Security Inspector"
    )
    parser.add_argument("--file", "-f", type=str, help="Path to .PUP, .bin, SLB2, or ELF64 file")
    parser.add_argument("--out-json", type=str, help="Path for output JSON manifest")
    parser.add_argument("--out-csv", type=str, help="Path for output entries.csv")
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Run inspection against built-in synthetic fixtures",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Print verbose output")

    args = parser.parse_args()

    if args.fixtures:
        print("[+] Running synthetic fixture inspection demo...")
        report = run_fixtures_demo()
    elif args.file:
        path = Path(args.file)
        if not path.is_file():
            print(f"[!] Error: File not found: {path}", file=sys.stderr)
            return 1
        print(f"[+] Inspecting: {path}")
        report = inspect_file(path)
    else:
        # Check firmware/ directory for default PUPs
        firmware_dir = Path("firmware")
        pups = list(firmware_dir.glob("*.PUP")) if firmware_dir.exists() else []
        if pups:
            print(f"[+] Found {len(pups)} PUP file(s) in firmware/ directory. Inspecting {pups[0]}...")
            report = inspect_file(pups[0])
        else:
            print("[*] No target file specified and no .PUP files found in firmware/.")
            print("[*] Falling back to synthetic fixtures demo to verify pipeline integrity.")
            report = run_fixtures_demo()

    # Console Summary
    print("=" * 60)
    print(f"Target: {report.get('source')} ({report.get('total_bytes', 0)} bytes)")
    print(f"Overall Entropy: {report.get('overall_entropy')} bits/byte")

    entries_for_csv: List[Dict[str, Any]] = []

    for container in report.get("containers", []):
        ctype = container.get("type")
        hdr = container.get("header", {})
        print(f"\n[Container: {ctype}]")
        if ctype == "SLB2":
            print(f"  Entries Count: {hdr.get('entry_count')}, Total Sectors: {hdr.get('total_sectors')}")
            print("  --- SLB2 Entry Table ---")
            for e in hdr.get("entries", []):
                print(
                    f"  [{e['index']:02d}] {e['name']:<24} "
                    f"Offset: 0x{e['byte_offset']:08X} ({e['byte_size']} B) "
                    f"Entropy: {e['entropy']} [{e['entropy_status']}]"
                )
                entries_for_csv.append(e)
        elif ctype == "INNER_PUP":
            print(f"  Package Type: {hdr.get('package_type')}, Files: {hdr.get('file_count')}")
            for e in hdr.get("entries", []):
                print(
                    f"  File ID: 0x{e['file_id']:X} Offset: 0x{e['byte_offset']:08X} "
                    f"Size: {e['byte_size']} B Entropy: {e['entropy']} [{e['entropy_status']}]"
                )
                entries_for_csv.append(e)

    for elf_info in report.get("elf_files", []):
        parent = elf_info.get("parent_entry", "root")
        elf = elf_info.get("elf", {})
        print(f"\n[ELF64 Binary inside '{parent}']")
        print(f"  Machine: {elf.get('machine')}, Entry Point: 0x{elf.get('entry_point', 0):016X}")
        print(f"  Program Headers: {elf.get('ph_num')}")
        for ph in elf.get("program_headers", []):
            print(
                f"    [{ph['index']:02d}] {ph['type_name']:<16} Flags: {ph['flags_str']} "
                f"VAddr: 0x{ph['p_vaddr']:016X} Filesz: {ph['p_filesz']} B "
                f"Entropy: {ph['entropy']} [{ph['entropy_status']}]"
            )
            entries_for_csv.append(ph)

    print("=" * 60)

    # Export outputs if requested
    if args.out_json:
        out_json_p = Path(args.out_json)
        export_to_json(report, out_json_p)
        print(f"[+] Exported JSON manifest to: {out_json_p}")

    if args.out_csv:
        out_csv_p = Path(args.out_csv)
        export_entries_to_csv(entries_for_csv, out_csv_p)
        print(f"[+] Exported CSV manifest to: {out_csv_p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
