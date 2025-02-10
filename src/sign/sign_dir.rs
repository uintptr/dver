use core::fmt;
use std::{
    fs::{self, canonicalize, File},
    io::Write,
    path::Path,
    vec,
};

use crate::{
    common::{
        fmt::{file_size_to_str, printkv},
        hash::{hash_string, DVHashType},
        r#const::DEFAULT_SIGN_FILE_NAME,
    },
    directory::walker::Walker,
    error::Error,
    key::keys::load_private_key,
};

use crate::common::serializer::{base64_deserializer, base64_serializer};

use base64::{prelude::BASE64_STANDARD, Engine};
use log::{info, warn};
use serde_derive::{Deserialize, Serialize};

#[derive(Debug)]
pub enum DVSignType {
    Short = 0,
    Complete = 1,
}

impl std::str::FromStr for DVSignType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "short" => Ok(DVSignType::Short),
            "complete" => Ok(DVSignType::Complete),
            _ => Err(Error::UnknownSignatureType),
        }
    }
}

impl fmt::Display for DVSignType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DVSignType::Short => write!(f, "short"),
            DVSignType::Complete => write!(f, "complete"),
        }
    }
}

use crate::error::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct DVSignature {
    content: String,
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
            content: String::new(),
            signature: vec![],
        }
    }

    pub fn from_file<P: AsRef<Path>>(signature_file: P) -> Result<DVSignature> {
        let b64_data = fs::read_to_string(&signature_file)?;

        let pem = pem::parse(b64_data)?;

        // this doesn't feel right, but would it be better to let
        // serde_json::from_slice() fail since we're not loading json data
        //
        // we'll revisit
        //
        let s = match pem.contents()[0] {
            b'{' => {
                let s: DVSignature = serde_json::from_slice(pem.contents())?;
                s
            }
            _ => {
                let signature = pem.contents().to_vec();
                DVSignature {
                    content: String::new(),
                    signature,
                }
            }
        };

        Ok(s)
    }

    pub fn to_file<P: AsRef<Path>>(&self, file_path: P, signature_type: DVSignType) -> Result<()> {
        let signature_data = match signature_type {
            DVSignType::Complete => &serde_json::to_vec(self)?,
            DVSignType::Short => &self.signature,
        };

        let base64_data = BASE64_STANDARD.encode(signature_data);

        let mut fd = File::create(file_path)?;

        fd.write_all(b"-----BEGIN SIGNATURE -----\n")?;

        for line in textwrap::wrap(&base64_data, 64) {
            fd.write_all(line.as_bytes())?;
            fd.write_all(b"\n")?;
        }

        fd.write_all(b"-----END SIGNATURE -----\n")?;

        Ok(())
    }

    pub fn with_content(&mut self, data: &str) {
        self.content = data.to_string();
    }

    pub fn sign<P: AsRef<Path>>(&mut self, private_key: P) -> Result<()> {
        let mut key = load_private_key(private_key)?;

        let data_hash = hash_string(&self.content, DVHashType::Sha512);

        self.signature = key.sign(&data_hash)?;

        info!("data size: {}", self.content.len());
        info!("data hash: {}", hex::encode(&data_hash));
        info!("data sign: {}", hex::encode(&self.signature));

        Ok(())
    }
}

pub fn sign_directory<P: AsRef<Path>>(
    directory: P,
    private_key: String,
    hash_type: DVHashType,
    output_sig_file: Option<P>,
    signature_type: DVSignType,
    exclude_list: Vec<String>,
) -> Result<()> {
    let directory = canonicalize(directory)?;

    let out_file = match &output_sig_file {
        Some(v) => v.as_ref(),
        None => &directory.join(DEFAULT_SIGN_FILE_NAME),
    };

    println!("Signing:");
    printkv("Directory", directory.display());
    printkv("Private Key", &private_key);
    printkv("Hash Type", hash_type);
    printkv("Signature File", out_file.display());
    printkv("Signature Type", &signature_type);
    printkv("Exclude", format!("{:?}", exclude_list));

    if out_file.exists() {
        warn!("{:?} already exists", out_file);
    }

    let walker = Walker::new(&directory, hash_type)?;

    let mut s = DVSignature::new();

    s.with_content(&walker.encode()?);
    s.sign(private_key)?;
    s.to_file(out_file, signature_type)?;

    let file_size = file_size_to_str(out_file)?;
    printkv("File Size", file_size);

    Ok(())
}
