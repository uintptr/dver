use std::{
    fs::{self, canonicalize, File},
    io::Write,
    path::Path,
    vec,
};

use crate::{
    key::keys::{load_private_key, PrivateKeyTrait},
    serializer::{base64_deserializer, base64_serializer},
};

use base64::{prelude::BASE64_STANDARD, Engine};
use log::{info, warn};
use serde_derive::{Deserialize, Serialize};

use crate::{
    common::{file_size_to_str, printkv, DEFAULT_SIGN_FILE_NAME},
    common::{hash_string, DVHashType},
    walker::dir::WalkerDirectory,
};

use crate::error::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct DVSignature {
    data: String,
    #[serde(
        serialize_with = "base64_serializer",
        deserialize_with = "base64_deserializer"
    )]
    pub signature: Vec<u8>,
}

impl Default for DVSignature {
    fn default() -> Self {
        Self::new()
    }
}

impl DVSignature {
    pub fn new() -> DVSignature {
        DVSignature {
            data: String::new(),
            signature: vec![],
        }
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

    pub fn with_data(&mut self, data: &str) {
        self.data = data.to_string();
    }

    pub fn sign<P: AsRef<Path>>(&mut self, private_key: P) -> Result<()> {
        let mut key = load_private_key(private_key)?;

        let data_hash = hash_string(&self.data, DVHashType::Sha512);

        self.signature = key.sign(&data_hash)?;

        info!("data size: {}", self.data.len());
        info!("data hash: {}", hex::encode(&data_hash));
        info!("data sign: {}", hex::encode(&self.signature));

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

    println!("Signing:");
    printkv("Directory", directory.display());
    printkv("Private Key", private_key.display());
    printkv("Hash Type", hash_type);
    printkv("Signature File", out_file.display());

    if out_file.exists() {
        warn!("{:?} already exists", out_file);
    }

    let walker = WalkerDirectory::new(&directory, hash_type)?;

    let mut s = DVSignature::new();

    s.with_data(&walker.encode()?);
    s.sign(private_key)?;
    s.to_file(out_file)?;

    let file_size = file_size_to_str(out_file).unwrap_or("".into());
    printkv("File Size", file_size);

    Ok(())
}
