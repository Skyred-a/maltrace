use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

const MAGIC_SIGNATURES: &[(&str, &[u8])] = &[
    ("ELF", b"\x7FELF"),
    ("PE", b"MZ"),
    ("Script", b"#!"),
    ("ZIP", b"PK\x03\x04"),
    //32-bit
    ("Mach-O", &[0xFE, 0xED, 0xFA, 0xCE]),
    ("Mach-O", &[0xCE, 0xFA, 0xED, 0xFE]),
    //64 bit
    ("Mach-O", &[0xFE, 0xED, 0xFA, 0xCF]),
    ("Mach-O", &[0xCF, 0xFA, 0xED, 0xFE]),
    ("Java Class", &[0xCA, 0xFE, 0xBA, 0xBE]),
    ("RAR", b"Rar!\x1A\x07"),
    ("7z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
];

const COMMON_SKIP_DIRS: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    "target",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".gradle",
    ".idea",
    ".vscode",
    ".cache",
    ".rustup",
    ".dartServer",
];

#[cfg(target_os = "linux")]
const SYSTEM_SKIP_PATHS: &[&str] = &["/proc", "/sys", "/dev", "/run"];
#[cfg(target_os = "macos")]
const SYSTEM_SKIP_PATHS: &[&str] = &["/dev", "/private/var/run"];

#[cfg(target_os = "windows")]
const SYSTEM_SKIP_PATHS: &[&str] = &[];

/// Checks if a directory is excluded by scanner rules
/// 
/// It returns `true` if the directory can be skipped, `false` otherwise
/// 
/// # Arguments 
/// * `dir_path` - path of a directory 
/// 
pub fn should_skip_dir(dir_path: &Path) -> bool {
    if let Some(name) = dir_path.file_name().and_then(|n| n.to_str())
        && COMMON_SKIP_DIRS.contains(&name)
    {
        return true;
    }
    for skip_path in SYSTEM_SKIP_PATHS {
        if dir_path.starts_with(skip_path) {
            return true;
        }
    }

    false
}

/// Checks if a file could be skip 
/// Reads the file header and compares it against known file signatures
/// 
/// It returns `true` if the file can be skipped, `false` otherwise
/// 
/// # Arguments 
/// * `file_path` - path of a file
/// * `log` - mutable reference to the file used for logs
/// 
/// # Errors
/// * "io::Error" if writing to log file fails
/// * The requested file cannot be oppened
/// * an I/O error occurs while reading from the file
/// 
pub fn should_skip_file(file_path: &Path, log : &mut std::fs::File) -> Result<bool, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; 16];
    let bytes_read = file.read(&mut buffer)?;
    let data = &buffer[..bytes_read];

    for (file_type, signature) in MAGIC_SIGNATURES {
        if data.starts_with(signature) {
            writeln!(log,":::     {file_type}    :::  True  ")?;
            return Ok(false);
        }
    }

    Ok(true)
}
