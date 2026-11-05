use crate::exclusions::{should_skip_dir, should_skip_file};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};
/// Computes the sha256 hash of a file
/// 
/// It returns a the hash as a String
/// 
/// # Arguments
/// * `file_path` - path of a file
/// 
/// # Errors
///     * The requested file cannot be opened
///     * An I/O error occurs while reading the file
/// 

fn compute_sha256(file_path: &Path) -> io::Result<String> {
    let file = match File::open(file_path){
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error oppening file {} : {}",file_path.display(),e);
            return Err(e);
        },
    };
    let mut reader = io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count =  match reader.read(&mut buffer){
            Ok(size) => size,
            Err(e) => {
                eprintln!("Error reading from file {} : {e}",file_path.display());
                return Err(e);
            }
        };
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count])
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Recursively scans a directory for potential mallicious files
/// 
/// It traverses the given directory and its subdirectories
/// skipping excluded directories and simbolic links
/// 
/// Files are filterTed based on their type, and sha-256 hashes are computed
/// for the files that pass the filtering process
/// 
/// Scan results and errors are written to a log file
/// 
/// # Arguments
/// 
/// * `dir` - the path of the directory
/// * `log` - mutable reference to the file used for logs
/// 
/// # Errors
/// 
/// * "io::Error" if writing to log file fails
/// 
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

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) => {
                writeln!(log,"Cannot read metadata {}: {}",path.display(), e)?;
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
        } else if metadata.is_file(){
            let should_skip = match should_skip_file(&path, log) {
                Ok(value) => value,
                Err(e) => {
                    writeln!(log,"Cannot inspect file {}: {}",path.display(), e)?;
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