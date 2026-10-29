use std::{
    arch::x86_64::_mm512_abs_epi32, io::{self, Write}, path,
};


use crate::vt_scanner::{check_hash_vt, config};
mod scanner;
mod vt_scanner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let mut dir = String::new();
    // print!("Enter directory: ");
    // io::stdout().flush()?; // prints immediately
    // io::stdin().read_line(&mut dir)?;
    // let dir_path = path::Path::new(dir.trim());
    // scanner::scan_directory(dir_path)?;

    // let mut input = String::new();

    // print!("Enter hash: ");
    // io::stdout().flush().unwrap();

    // io::stdin()
    //     .read_line(&mut input)
    //     .expect("Failed to read input");

    let input = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    let api_key=config()?;
    println!("{input}");
    let resp = check_hash_vt(&api_key, input.trim()).await?;
    println!("{resp}");

    Ok(())
}
