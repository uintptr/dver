use core::fmt;
use std::path::{Path, PathBuf};

use serde_derive::Serialize;

use crate::{
    common::vec_hex_serializer,
    file_io::{hash_file, DVHashType},
};

use crate::error::Error;

#[derive(Debug, Serialize)]
pub struct WalkerFile {
    pub path: PathBuf,
    #[serde(serialize_with = "vec_hex_serializer")]
    pub hash: Vec<u8>,
}

impl fmt::Display for WalkerFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_str = hex::encode(&self.hash);
        write!(f, "{:?} @ {hash_str}", self.path)
    }
}

impl WalkerFile {
    pub fn new<P: AsRef<Path>, T: AsRef<Path>>(
        root: P,
        file: T,
        hash_type: DVHashType,
    ) -> Result<WalkerFile, Error> {
        let rel_name = file.as_ref().strip_prefix(&root)?;

        let hash = hash_file(&file, hash_type)?;

        Ok(WalkerFile {
            path: rel_name.into(),
            hash,
        })
    }
}
