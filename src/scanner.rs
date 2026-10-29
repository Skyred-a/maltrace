use sha2::{Digest, Sha256};
use std::{
    fs::{self,File},
    io::{self,Read,Write},
    path::Path,
};

const MAGIC_SIGNATURES: &[(&str,&[u8])] = &[
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





pub fn should_scan_file(file_path : &Path) -> Result<bool,std::io::Error>{

    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; 16];
    let bytes_read = file.read(&mut buffer)?;
    let data = &buffer[..bytes_read];

    for (file_type,signature) in MAGIC_SIGNATURES {
        if data.starts_with(signature){
           println!(":::     {file_type}    :::  True  ");
            io::stdout().flush()?;
            return Ok(true);
        }
    }

    Ok(false)
}
pub fn scan_directory(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            println!("{}", path.display());
            scan_directory(&path)?;
        } else {
            if should_scan_file(&path)? {
                match compute_sha256(&path) {
                Ok(hash) => println!("File: {} | SHA-256: {}", path.display(), hash),
                Err(e) => eprintln!("Could not hash file {}: {}", path.display(), e),
            }
        }
       
        }
        
    }

    Ok(())
}