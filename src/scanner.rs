use crate::exclusions::{should_skip_dir, should_skip_file};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

fn compute_sha256(file_path: &Path) -> io::Result<String> {
    let file = File::open(file_path)?;
    let mut reader = io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count])
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn scan_directory(dir: &Path, log: &mut std::fs::File) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            writeln!(log, "Cannot access directory {}: {}", dir.display(), e)?;
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                writeln!(log, "Cannot read directory entry: {}", e)?;
                continue;
            }
        };

        let path = entry.path();

        // Get metadata without following symlinks
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) => {
                writeln!(
                    log,
                    "Cannot read metadata {}: {}",
                    path.display(),
                    e
                )?;
                continue;
            }
        };

        // Do not follow symlinks
        if metadata.file_type().is_symlink() {
            writeln!(log, "Skipping symlink: {}", path.display())?;
            continue;
        }

        if metadata.is_dir() {
            if should_skip_dir(&path) {
                continue;
            }

            writeln!(log, "{}", path.display())?;

            scan_directory(&path, log)?;
        } else {
            let should_skip = match should_skip_file(&path, log) {
                Ok(value) => value,
                Err(e) => {
                    writeln!(
                        log,
                        "Cannot inspect file {}: {}",
                        path.display(),
                        e
                    )?;
                    continue;
                }
            };

            if !should_skip {
                match compute_sha256(&path) {
                    Ok(hash) => {
                        writeln!(
                            log,
                            "File: {} | SHA-256: {}",
                            path.display(),
                            hash
                        )?;
                    }

                    Err(e) => {
                        writeln!(
                            log,
                            "Could not hash file {}: {}",
                            path.display(),
                            e
                        )?;
                    }
                }
            }
        }
    }

    Ok(())
}