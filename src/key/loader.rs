use std::{fs, path::Path};

use crate::Error;

pub struct DVPrivateKey {}

impl DVPrivateKey {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<DVPrivateKey, Error> {
        let key_data = fs::read_to_string(path)?;

        println!("key len: {}", key_data.len());

        Ok(DVPrivateKey {})
    }
}
