use std::path::Path;

use crate::error::{Error, Result};

use super::ssh::{ssh_sign::SshSigner, ssh_verify::SshVerifier};

#[derive(Debug)]
pub enum DVKey {
    PrivateOpenSsh(SshSigner),
    PublicOpenSsh(SshVerifier),
}

#[derive(Debug)]
pub struct DVPrivateKey {
    pub key: DVKey,
}

#[derive(Debug)]
pub struct DVPublicKey {
    pub key: DVKey,
}

fn get_key<P: AsRef<Path>>(path: P) -> Result<DVKey> {
    if path.as_ref().ends_with("id_ed25519") {
        let key = SshSigner::new(path)?;
        return Ok(DVKey::PrivateOpenSsh(key));
    }

    if path.as_ref().ends_with("id_rsa") {
        let key = SshSigner::new(path)?;
        return Ok(DVKey::PrivateOpenSsh(key));
    }

    if path.as_ref().ends_with("id_ed25519.pub") {
        let key = SshVerifier::new(path)?;
        return Ok(DVKey::PublicOpenSsh(key));
    }

    if path.as_ref().ends_with("id_rsa.pub") {
        let key = SshVerifier::new(path)?;
        return Ok(DVKey::PublicOpenSsh(key));
    }

    Err(Error::InputKeyFormatNotSupported)
}

impl DVPrivateKey {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<DVPrivateKey> {
        let key = get_key(path)?;
        Ok(DVPrivateKey { key })
    }

    pub fn sign(self, data: &[u8]) -> Result<Vec<u8>> {
        match self.key {
            DVKey::PrivateOpenSsh(mut k) => k.sign(data),
            _ => Err(Error::KeyInvalidType),
        }
    }
}

impl DVPublicKey {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<DVPublicKey> {
        let key = get_key(path)?;
        Ok(DVPublicKey { key })
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        match &self.key {
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

        let k = DVPrivateKey::new(ssh_key).unwrap();

        info!("key: {:?}", k);
    }
}
