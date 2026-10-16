use std::{
    io::{self, Write},
    path,
};
mod scanner;

fn main() -> io::Result<()> {
    let mut dir = String::new();
    print!("Enter directory: ");
    io::stdout().flush()?; // prints immediately
    io::stdin().read_line(&mut dir)?;
    let dir_path = path::Path::new(dir.trim());
    scanner::scan_directory(dir_path)?;

    Ok(())
}
