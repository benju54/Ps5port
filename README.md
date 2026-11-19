# Ps5port

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-brightgreen.svg)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/)

**Ps5port** is an open-source, modular x86-64 research and system/hypervisor scaffolding toolkit designed for:
- Inspecting PlayStation 5 firmware container structures (`SLB2`, `PUP`, `SELF`, `ELF64`).
- Segment layout mapping and Shannon entropy security classification.
- Structuring an x86-64 Orbis/Prospero OS hardware-abstraction and hypervisor virtualization layer.

---

## Legal, Ethical, and Clean-Room Policy

> [!IMPORTANT]
> - **Zero Cryptographic Key Distribution:** `Ps5port` does not distribute, host, or fabricate proprietary Sony Interactive Entertainment (SIE) decryption keys or retail DRM circumvention tools.
> - **No Proprietary Binaries:** Proprietary firmware images (`.PUP`, `.bin`), decrypted game assets, and retail software dumps are strictly excluded from version control via `.gitignore`.
> - **Clean-Room Analysis:** This project inspects publicly readable container headers, partition tables, and plaintext ELF64 segment maps. High-entropy encrypted blocks are safely detected and flagged without attempting unlawful decryption.

---

## Repository Structure

```text
.
├── Cargo.toml                  # Rust workspace root configuration
├── docs/
│   └── architecture.md         # Comprehensive system & container architecture documentation
├── firmware/
│   └── README.md               # Local PUP staging instructions and policy guidelines
├── tools/
│   └── pup_inspector/          # Zero-dependency Python CLI container & ELF64 inspector
│       ├── cli.py              # CLI entry point
│       ├── container.py        # SLB2 and inner 0xEEF51454 PUP container parsers
│       ├── elf.py              # ELF64 and SELF header/segment parsers
│       ├── entropy.py          # Shannon entropy calculator and block scanner
│       ├── manifest.py         # CSV (entries.csv) and JSON manifest exporters
│       ├── synthetic_fixtures.py # Self-contained synthetic binary fixture generators
│       └── tests/
│           └── test_inspector.py # Unit tests using synthetic fixtures
└── core/                       # Modular Rust workspace skeleton
    ├── loader/                 # SLB2/ELF64 header parsers and virtual memory segment mapper
    ├── hypervisor_mmio/        # Zen 2 Oberon APU CPUID, MSRs, MMIO bus, and virtual device stubs
    └── graphics_agc/           # AGC / PM4 command packet decoder and Vulkan/NIR translation stubs
```

---

## Quickstart Guide

### 1. Inspecting Containers with `pup_inspector`

The `tools/pup_inspector` CLI runs on Python 3 with **zero external dependencies**:

```bash
# Run unit tests using synthetic fixtures
py -m unittest discover -s tools/pup_inspector/tests

# Run fixture validation demo and emit manifests
py tools/pup_inspector/cli.py --fixtures --out-json out/manifest.json --out-csv out/entries.csv

# Inspect a staged firmware PUP file
py tools/pup_inspector/cli.py --file firmware/PS5UPDATE.PUP --out-json out/manifest.json --out-csv out/entries.csv
```

### 2. Rust Core Workspace

The `core/` workspace provides modular crates for system loading and virtualization:

```bash
# Build the entire workspace
cargo build --workspace

# Run core unit tests
cargo test --workspace
```

---

## Core Architecture Highlights

- **Native x86-64 Execution:** Unlike ARM64 translation projects (e.g. Stela), the PS5 APU ("Oberon") utilizes AMD Zen 2 x86-64 cores. Consequently, guest execution targets direct hardware virtualization (KVM/WHPX) rather than instruction-level dynamic binary translation (DBT).
- **Kraken DMA Offload:** Models the dedicated hardware accelerator for streaming Oodle Kraken decompression (5-9 GB/s).
- **RDNA 2 Command Processor:** Decodes PM4 Type-3 command buffers (`IT_SET_CONTEXT_REG`, `IT_DRAW_INDEX_AUTO`, `IT_DISPATCH_DIRECT`) and maps pipeline state to host Vulkan 1.3 / NIR.

For detailed container layouts and hardware specifications, refer to [docs/architecture.md](docs/architecture.md).
