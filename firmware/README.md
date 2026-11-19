# PS5 Firmware Staging Directory

This directory is designated for staging PlayStation 5 firmware packages (`.PUP`) and related diagnostic binaries locally for research, header analysis, and container extraction.

## Legal and Policy Safeguards

> [!IMPORTANT]
> **Strict Non-Distribution Policy:**
> - Firmware packages (`.PUP`, `.bin`), extracted segment blobs, decrypted retail payloads, and proprietary cryptographic keys **must never** be checked into this Git repository.
> - The root `.gitignore` enforces exclusion of `*.PUP`, `*.bin`, and `firmware/extracted/`.
> - `Ps5port` operates as a clean-room research and emulation scaffolding framework. We analyze publicly readable container structures (SLB2, outer PUP headers, plaintext ELF segment headers) and do not distribute or fabricate copyrighted Sony Interactive Entertainment (SIE) retail firmware or decryption keys.

## Local Staging Workflow

1. **Obtain Official Firmware Packages:**
   Place legitimate, officially downloaded recovery or update PUP files directly into this directory:
   ```text
   firmware/PS5UPDATE.PUP
   ```

2. **Inspect Container Structure:**
   Run the zero-dependency Python inspector to view the outer SLB2 partition table and inner container descriptors:
   ```powershell
   py tools/pup_inspector/cli.py --file firmware/PS5UPDATE.PUP --out-json firmware/extracted/manifest.json --out-csv firmware/extracted/entries.csv
   ```

3. **Output Artifacts:**
   Extracted metadata and logs will be written to `firmware/extracted/` or the paths specified via CLI flags. These paths are ignored by Git.
