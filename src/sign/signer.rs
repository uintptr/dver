use std::{fs, path::Path};

use crate::error::{Error, Result};

use super::ssh_key::SshSigner;

enum DVKeyType {
    Ssh,
}

fn guess_key_type<P: AsRef<Path>>(private_key: P) -> Result<DVKeyType> {
    let _key_data = fs::read_to_string(&private_key);

    if private_key.as_ref().ends_with("id_ed25519"){
        return Ok(DVKeyType::Ssh)
    }
    if private_key.as_ref().ends_with("id_rsa"){
        return Ok(DVKeyType::Ssh)
    }

    Err(Error::InputKeyFormatNotSupported)
}

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
