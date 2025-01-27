#![allow(unused)]

use std::path::Path;

use crate::{error::Result, key::keys::DVPublicKey};

pub struct DVVerifier {
    key: DVPublicKey,
}

impl DVVerifier {
    pub fn new<P: AsRef<Path>>(public_key: P) -> Result<DVVerifier> {
        //
        // try to get the file type
        //

        let key = DVPublicKey::new(public_key)?;

        Ok(DVVerifier { key })
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        self.key.verify(msg, signature)
    }
}
