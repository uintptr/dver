#![allow(unused)]

use std::path::Path;

use crate::error::Result;

struct DVVerifier;

impl DVVerifier {
    pub fn new<P: AsRef<Path>>(public_key: P) -> Result<DVVerifier> {
        //
        // try to get the file type
        //
        todo!()
    }

    pub fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<()> {
        todo!()
    }
}
