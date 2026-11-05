use std::fs::OpenOptions;
use std::{
    io::{self, Write},
    path,
};

use crate::vt_scanner::check_hash_vt;

mod exclusions;
mod scanner;
mod vt_scanner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open("scan.log")?;
    let mut dir = String::new();
    print!("Enter directory: ");
    io::stdout().flush()?; 
    io::stdin().read_line(&mut dir)?;
    let dir_path = path::Path::new(dir.trim());
    scanner::scan_directory(dir_path, &mut log)?;

    Ok(())
}
