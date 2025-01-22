use std::fs::{self, canonicalize};

use crate::{common::printkv, walker::WalkerDirectory, DVError};

pub fn sign_directory(directory: &str, private_key: &str) -> Result<(), DVError> {
    let directory = canonicalize(directory)?;
    let private_key = canonicalize(private_key)?;

    let out_file = directory.join("dverify.sig");

    if out_file.exists() {
        fs::remove_file(&out_file)?;
    }

    println!("Signing");
    printkv("Directory", directory.display());
    printkv("Private Key", private_key.display());

    let d = WalkerDirectory::new(&directory)?;

    printkv("Directory Hash", d.hash_str());
    printkv("Output File", out_file.display());

    let out_data = serde_json::to_string_pretty(&d)?;

    fs::write(out_file, out_data)?;

    Ok(())
}
