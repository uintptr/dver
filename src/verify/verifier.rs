use std::path::Path;

use crate::{
    common::{guess_key_type, DVKeyType},
    error::Result,
};

use super::verifier_ssh::SshVerifier;

#[derive(Debug)]
pub enum DVVerifier {
    Ssh(SshVerifier),
}

impl DVVerifier {
    pub fn new<P: AsRef<Path>>(public_key: P) -> Result<DVVerifier> {
        //
        // try to get the file type
        //

        let signer = match guess_key_type(&public_key)? {
            DVKeyType::Ssh => SshVerifier::new(public_key)?,
        };

        Ok(DVVerifier::Ssh(signer))
    }

    pub fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            DVVerifier::Ssh(s) => s.verify(msg, signature),
        }
    }
}
