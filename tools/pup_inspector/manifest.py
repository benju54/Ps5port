"""
Manifest exporter for SLB2/PUP/ELF inspection.
Supports CSV (entries.csv) and JSON structured export.
"""

from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Dict, Any, List


def export_to_json(data: Dict[str, Any], output_path: Path) -> None:
    """Export inspection results to formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_entries_to_csv(entries: List[Dict[str, Any]], output_path: Path) -> None:
    """Export container entries table to entries.csv."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not entries:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write("index,name,offset_bytes,size_bytes,entropy,entropy_status\n")
        return

    fieldnames = [
        "index",
        "name",
        "offset_bytes",
        "size_bytes",
        "entropy",
        "entropy_status",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            row = {
                "index": e.get("index"),
                "name": e.get("name") or e.get("file_id") or e.get("type_name"),
                "offset_bytes": e.get("byte_offset") if "byte_offset" in e else e.get("p_offset"),
                "size_bytes": e.get("byte_size") if "byte_size" in e else e.get("p_filesz"),
                "entropy": e.get("entropy"),
                "entropy_status": e.get("entropy_status"),
            }
            writer.writerow(row)
