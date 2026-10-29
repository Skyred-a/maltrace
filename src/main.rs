use std::{
    io::{self, Write}, path,
};


use crate::vt_scanner::{check_hash_vt, config};
mod scanner;
mod vt_scanner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut dir = String::new();
    print!("Enter directory: ");
    io::stdout().flush()?; // prints immediately
    io::stdin().read_line(&mut dir)?;
    let dir_path = path::Path::new(dir.trim());
    scanner::scan_directory(dir_path)?;

    // let mut input = String::new();

    // print!("Enter hash: ");
    // io::stdout().flush().unwrap();

    // io::stdin()
    //     .read_line(&mut input)
    //     .expect("Failed to read input");

    

    Ok(())
}
