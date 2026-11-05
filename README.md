# Maltrace

    Maltrace is a cross-platform file scanning tool written in Rust, designed as a foundation for malware analysis.

    The project aims to identify files that may require further security analysis by examining file signatures (magic bytes) and calculating SHA-256 hashes.

    Maltrace is currently in early development, with plans to introduce local malware detection, improve scanning performance, and reduce reliance on external services.

## Features

- **Recursive directory scanning** — Traverses directories and subdirectories to discover files.
- **File type identification** — Compares file headers with known magic-byte signatures, rather than relying only on extensions.
- **SHA-256 hashing** — Computes hashes of selected files by reading them in chunks.
- **Directory exclusions** — Skips predefined development directories and operating-system-specific paths.
- **Symbolic link handling** — Skips detected symbolic links during recursive scanning.
- **Error handling** — Records file access, metadata, and read errors and continues when possible.
- **Logging** — Writes scanned paths, file hashes, and encountered errors to a log file.

## Supported File Signatures

| File type | Detection method |
| --- | --- |
| ELF | `7F 45 4C 46` |
| PE candidate | `MZ` prefix (does not validate the complete PE structure) |
| Mach-O | Selected 32-bit and 64-bit magic-byte signatures |
| Script | `#!` shebang prefix |
| ZIP | `PK 03 04` prefix |
| Java class | `CA FE BA BE` |
| RAR | `Rar!` signature prefix |
| 7z | 7-Zip magic bytes |

A matching signature identifies a possible format, **not whether a file is malicious**. Some formats need deeper inspection, and scripts without a shebang may not be detected.

## How It Works

1. The user provides a directory to scan.
2. The scanner walks through its subdirectories recursively.
3. Configured exclusions and detected symbolic links are skipped.
4. Metadata is used to select regular files.
5. The first bytes of each file are compared against supported signatures.
6. Matching files are read in chunks to calculate their SHA-256 hashes.
7. Results and errors are written to a log file.

### SHA-256 Hashing

The scanner reads files in chunks rather than loading each entire file into memory. A SHA-256 hash identifies file content for comparison.

## Project Structure

```text
src/
|-- main.rs
|-- scanner.rs
|-- exclusions.rs
|-- vt_scanner.rs
```

- **`main.rs`** — Application entry point.
- **`scanner.rs`** — Directory traversal and SHA-256 hashing.
- **`exclusions.rs`** — Directory exclusions and magic-byte filtering.
- **`vt_scanner.rs`** — Separate VirusTotal hash lookup functionality, not currently part of the automatic directory scan.

## Known Limitations

- Detection uses a limited set of file signatures and does not fully validate each file format.
- Scripts without a shebang may be missed.
- Excluded directories are not inspected, even if they could contain malicious files.
- Large scans may be slow.
- The automatic directory scan does not currently produce malware verdicts.
- Cross-platform behavior is a design goal; support across Windows, Linux, and macOS still needs testing.

## Development Status

Maltrace is an early-stage personal learning project. The focus is currently on reliable filesystem traversal, filtering, hashing, and error handling.
