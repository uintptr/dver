use std::path::Path;

use base64::{prelude::BASE64_STANDARD, Engine};
use serde_derive::Serialize;

use crate::{common::hash::DVHashType, error::Result};

use super::dir::WalkerDirectory;
const CUR_SIG_FORMAT_VER: u8 = 1;

#[derive(Debug, Serialize)]
pub struct Walker {
    version: u8,
    root: WalkerDirectory,
}

impl Walker {
    pub fn new<P: AsRef<Path>>(directory: P, hash: DVHashType) -> Result<Walker> {
        let version = CUR_SIG_FORMAT_VER;
        let root = WalkerDirectory::new(directory, hash)?;

        Ok(Walker { version, root })
    }

    pub fn encode(&self) -> Result<String> {
        let json_string = serde_json::to_string(self)?;
        Ok(BASE64_STANDARD.encode(json_string))
    }
}
