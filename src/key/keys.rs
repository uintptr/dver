use std::path::Path;

use log::info;

use crate::error::{Error, Result};

use super::ssh::{ssh_sign::SshSigner, ssh_verify::SshVerifier};

#[derive(Debug)]
pub enum DVKey {
    PrivateOpenSsh(SshSigner),
    PublicOpenSsh(SshVerifier),
}

fn guess_key_by_file_name<P: AsRef<Path>>(path: P) -> Result<DVKey> {
    if path.as_ref().ends_with("id_ed25519") {
        info!("loading a ed25519 ssh private key");
        let key = SshSigner::new(path)?;
        return Ok(DVKey::PrivateOpenSsh(key));
    }

    if path.as_ref().ends_with("id_rsa") {
        info!("loading a rsa ssh private key");
        let key = SshSigner::new(path)?;
        return Ok(DVKey::PrivateOpenSsh(key));
    }

    if path.as_ref().ends_with("id_ed25519.pub") {
        info!("loading a ed25519 ssh public key");
        let key = SshVerifier::new(path)?;
        return Ok(DVKey::PublicOpenSsh(key));
    }

    if path.as_ref().ends_with("id_rsa.pub") {
        info!("loading a rsa ssh public key");
        let key = SshVerifier::new(path)?;
        return Ok(DVKey::PublicOpenSsh(key));
    }

    Err(Error::InputKeyFormatNotSupported)
}

impl DVKey {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<DVKey> {
        // try a few way to guess the user input
        if let Ok(k) = guess_key_by_file_name(path) {
            return Ok(k);
        }

        Err(Error::InputKeyFormatNotSupported)
    }

    pub fn sign(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            DVKey::PrivateOpenSsh(mut k) => k.sign(data),
            _ => Err(Error::KeyInvalidType),
        }
    }

    pub fn verify(self, msg: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            DVKey::PublicOpenSsh(k) => k.verify(msg, signature),
            _ => Err(Error::KeyInvalidType),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::logging::init_logging;

    use super::*;

    use log::info;

    #[test]
    fn test_example() {
        init_logging().unwrap();

        let home = home::home_dir().unwrap();

        let ssh_key = home.join(".ssh").join("id_ed25519");

        let k = DVKey::new(ssh_key).unwrap();

        info!("key: {:?}", k);
    }
}
