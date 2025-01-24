use std::{
    fs::{self, canonicalize},
    path::Path,
};

const CUR_SIG_FORMAT_VER: u32 = 1;
const DEFAULT_SIGN_FILE_NAME: &str = "dver.sig";

use base64::{prelude::BASE64_STANDARD, Engine};
use serde_derive::Serialize;
use sha2::{Digest, Sha512};

use crate::{
    common::{file_size_to_str, printkv},
    file_io::DVHashType,
    walker::dir::WalkerDirectory,
};

use crate::error::Result;

#[derive(Debug, Serialize)]
struct DVSignature {
    version: u32,
    encoded_data: String,
    signature: Vec<u8>,
}

impl DVSignature {
    pub fn new(walker: &WalkerDirectory) -> Result<DVSignature> {
        let encoded_data = walker.encode()?;

        let mut hash = Sha512::new();

        hash.update(&encoded_data);

        let signature = hash.finalize().to_vec();

        Ok(DVSignature {
            version: CUR_SIG_FORMAT_VER,
            encoded_data,
            signature,
        })
    }

    pub fn encode(&self) -> Result<String> {
        let json_data = serde_json::to_string(self)?;
        Ok(BASE64_STANDARD.encode(json_data))
    }
}

pub fn sign_directory<P: AsRef<Path>>(
    directory: P,
    private_key: P,
    hash_type: &str,
    output_sig_file: Option<P>,
) -> Result<()> {
    let directory = canonicalize(directory)?;
    let private_key = canonicalize(private_key)?;

    let out_file = match &output_sig_file {
        Some(v) => v.as_ref(),
        None => &directory.join(DEFAULT_SIGN_FILE_NAME),
    };

    println!("Signing");
    printkv("Directory", directory.display());
    printkv("Private Key", private_key.display());
    printkv("Hash Type", hash_type);
    printkv("Signature File", out_file.display());

    if out_file.exists() {
        fs::remove_file(out_file)?;
    }

    let hash_type: DVHashType = hash_type.parse()?;

    let d = WalkerDirectory::new(&directory, hash_type)?;

    let s = DVSignature::new(&d)?;

    let signature_data = s.encode()?;

    fs::write(out_file, signature_data)?;

    let file_size = file_size_to_str(out_file).unwrap_or("".into());
    printkv("Signature Size", file_size);

    Ok(())
}
