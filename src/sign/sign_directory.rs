use std::{
    fs::{self, canonicalize, File},
    io::Write,
    path::Path,
};

const CUR_SIG_FORMAT_VER: u32 = 1;

use base64::{prelude::BASE64_STANDARD, Engine};
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::{file_size_to_str, printkv, DEFAULT_SIGN_FILE_NAME},
    hash::{hash_string, DVHashType},
    walker::dir::WalkerDirectory,
};

use crate::error::Result;

use super::signer::DVSigner;

#[derive(Debug, Serialize, Deserialize)]
pub struct DVSignature {
    version: u32,
    directory_data: String,
    signature: String,
}

impl DVSignature {
    pub fn new<P: AsRef<Path>>(walker: &WalkerDirectory, private_key: P) -> Result<DVSignature> {
        let directory_data = walker.encode()?;

        let data_hash = hash_string(&directory_data, DVHashType::Sha512);

        let mut signer = DVSigner::new(private_key)?;
        let signature = signer.sign(&data_hash)?;
        let signature_b64 = BASE64_STANDARD.encode(signature);

        Ok(DVSignature {
            version: CUR_SIG_FORMAT_VER,
            directory_data,
            signature: signature_b64,
        })
    }

    pub fn from_file<P: AsRef<Path>>(signature_file: P) -> Result<DVSignature> {
        let b64_data = fs::read_to_string(&signature_file)?;

        let pem = pem::parse(b64_data)?;

        let s: DVSignature = serde_json::from_slice(pem.contents())?;

        Ok(s)
    }

    pub fn to_file<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        let json_string = serde_json::to_string(self)?;

        let base64_data = BASE64_STANDARD.encode(json_string);

        let mut fd = File::create(file_path)?;

        fd.write_all(b"-----BEGIN SIGNATURE -----\n")?;

        for line in textwrap::wrap(&base64_data, 64) {
            fd.write_all(line.as_bytes())?;
            fd.write_all(b"\n")?;
        }

        fd.write_all(b"-----END SIGNATURE -----\n")?;

        Ok(())
    }
}

pub fn sign_directory<P: AsRef<Path>>(
    directory: P,
    private_key: P,
    hash_type: DVHashType,
    output_sig_file: Option<P>,
) -> Result<()> {
    let directory = canonicalize(directory)?;
    let private_key = canonicalize(private_key)?;

    let out_file = match &output_sig_file {
        Some(v) => v.as_ref(),
        None => &directory.join(DEFAULT_SIGN_FILE_NAME),
    };

    let out_file = canonicalize(out_file)?;

    println!("Signing:");
    printkv("Directory", directory.display());
    printkv("Private Key", private_key.display());
    printkv("Hash Type", hash_type);
    printkv("Signature File", out_file.display());

    if out_file.exists() {
        fs::remove_file(&out_file)?;
    }

    let d = WalkerDirectory::new(&directory, hash_type)?;

    let s = DVSignature::new(&d, private_key)?;

    s.to_file(&out_file)?;

    let file_size = file_size_to_str(&out_file).unwrap_or("".into());
    printkv("Signature Size", file_size);

    Ok(())
}
