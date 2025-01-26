use std::path::Path;

use crate::{
    common::{guess_key_type, DVKeyType},
    error::Result,
};

use super::ssh_key::SshSigner;

pub enum DVSigner {
    Ssh(SshSigner),
}

impl DVSigner {
    pub fn new<P: AsRef<Path>>(private_key: P) -> Result<DVSigner> {
        //
        // try to get the file type
        //

        let signer = match guess_key_type(&private_key)? {
            DVKeyType::Ssh => SshSigner::new(private_key)?,
        };

        Ok(DVSigner::Ssh(signer))
    }

    pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            DVSigner::Ssh(s) => s.sign(data),
        }
    }
}
