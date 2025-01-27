use std::path::Path;

use log::info;

use crate::error::{Error, Result};

use super::ssh::{ssh_private::SshSigner, ssh_public::SshVerifier};

pub trait PrivateKeyTrait {
    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait PublicKeyTrait {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()>;
}

pub fn load_private_key<P: AsRef<Path>>(path: P) -> Result<impl PrivateKeyTrait> {
    if path.as_ref().ends_with("id_ed25519") {
        info!("loading a ed25519 ssh private key");
        let key = SshSigner::new(path)?;
        return Ok(key);
    }

    if path.as_ref().ends_with("id_rsa") {
        info!("loading a rsa ssh private key");
        let key = SshSigner::new(path)?;
        return Ok(key);
    }

    Err(Error::InputKeyFormatNotSupported)
}

pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<impl PublicKeyTrait> {
    if path.as_ref().ends_with("id_ed25519.pub") {
        info!("loading a ed25519 ssh public key");
        let key = SshVerifier::new(path)?;
        return Ok(key);
    }

    if path.as_ref().ends_with("id_rsa.pub") {
        info!("loading a rsa ssh public key");
        let key = SshVerifier::new(path)?;
        return Ok(key);
    }

    Err(Error::InputKeyFormatNotSupported)
}

#[cfg(test)]
mod tests {

    use crate::logging::init_logging;

    use super::*;

    #[test]
    fn test_example() {
        init_logging().unwrap();

        let home = home::home_dir().unwrap();

        let ssh_key = home.join(".ssh").join("id_ed25519");

        load_private_key(ssh_key).unwrap();
    }
}
