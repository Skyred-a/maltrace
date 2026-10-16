use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::io::Read;
use std::path;

fn compute_sha256(file_path: &path::Path) -> io::Result<String> {
    let file = fs::File::open(file_path)?;
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

pub fn scan_directory(dir: &path::Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            println!("{}", path.display());
            scan_directory(&path)?;
        } else {
            match compute_sha256(&path) {
                Ok(hash) => println!("File: {} | SHA-256: {}", path.display(), hash),
                Err(e) => eprintln!("Could not hash file {}: {}", path.display(), e),
            }
        }
    }

    Ok(())
}
