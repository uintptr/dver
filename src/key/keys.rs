use std::path::Path;

use log::info;

use crate::error::{Error, Result};

use super::{
    pgp::{gpg_private::GpgPrivate, gpg_public::GpgPublic},
    ssh::{ssh_private::SshPrivate, ssh_public::SshPublic},
};

pub trait Signer {
    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>>;
}

pub trait Verifier {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()>;
}

pub fn load_private_key<P: AsRef<Path>>(path: P) -> Result<Box<dyn Signer>> {
    let path = path.as_ref();
    let path_str = path.to_str();

    if path.ends_with("id_ed25519") {
        info!("loading a ed25519 ssh private key");
        let key = SshPrivate::new(path)?;
        return Ok(Box::new(key));
    }

    if path.ends_with("id_rsa") {
        info!("loading a rsa ssh private key");
        let key = SshPrivate::new(path)?;
        return Ok(Box::new(key));
    }

    if let Some(p) = path_str {
        if let Some(gpg_key_id) = p.strip_prefix("gpg://") {
            let key = GpgPrivate::new_with_key(gpg_key_id);
            return Ok(Box::new(key));
        } else if p == "gpg" {
            let key = GpgPrivate::new();
            return Ok(Box::new(key));
        }
    }

    Err(Error::InputKeyFormatNotSupported)
}

pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<Box<dyn Verifier>> {
    let path = path.as_ref();
    let path_str = path.to_str();

    if path.ends_with("id_ed25519.pub") {
        info!("loading a ed25519 ssh public key");
        let key = SshPublic::new(path)?;
        return Ok(Box::new(key));
    }

    if path.ends_with("id_rsa.pub") {
        info!("loading a rsa ssh public key");
        let key = SshPublic::new(path)?;
        return Ok(Box::new(key));
    }

    if let Some(p) = path_str {
        if let Some(gpg_key_id) = p.strip_prefix("gpg://") {
            let key = GpgPublic::new_with_key(gpg_key_id);
            return Ok(Box::new(key));
        } else if p == "gpg" {
            let key = GpgPublic::new();
            return Ok(Box::new(key));
        }
    }

    Err(Error::InputKeyFormatNotSupported)
}

#[cfg(test)]
mod tests {

    use log::warn;

    use super::*;

    #[test]
    fn keys() {
        let home = home::home_dir().unwrap();

        let ssh_key = home.join(".ssh").join("id_ed25519");

        if ssh_key.exists() {
            let res = load_private_key(ssh_key);
            assert!(res.is_ok());
        } else {
            warn!("{} doesn't exist", ssh_key.display())
        }
    }
}
