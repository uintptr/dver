use std::{fs, path::Path};

use ssh_key::PrivateKey;

use crate::error::{Error, Result};

#[derive(Debug)]
pub enum DVKeyType {
    Unknown = 0,
    OpenSSHEd25519 = 1,
    OpenSSHRsa = 2,
}

#[derive(Debug)]
pub struct DVPrivateKey {
    pub key_type: DVKeyType,
    pub key_data: Vec<u8>,
}

fn get_key_type<P: AsRef<Path>>(path: P) -> DVKeyType {
    let file_name = match path.as_ref().file_name() {
        Some(v) => match v.to_str() {
            Some(v) => v,
            None => return DVKeyType::Unknown,
        },
        None => return DVKeyType::Unknown,
    };

    if file_name.ends_with("id_ed25519") {
        return DVKeyType::OpenSSHEd25519;
    } else if file_name.ends_with("id_rsa") {
        return DVKeyType::OpenSSHRsa;
    }

    DVKeyType::Unknown
}

fn load_key_openssh<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let encoded_key = fs::read_to_string(path)?;

    let key_data = PrivateKey::from_openssh(encoded_key)?;

    match key_data.key_data().ed25519() {
        Some(v) => Ok(v.private.as_ref().to_vec()),
        _ => Err(Error::InputKeyFormatNotSupported),
    }
}

fn load_key<P: AsRef<Path>>(path: P) -> Result<DVPrivateKey> {
    let key_type = get_key_type(&path);

    let key_data = match key_type {
        DVKeyType::OpenSSHEd25519 => load_key_openssh(&path)?,
        DVKeyType::OpenSSHRsa => load_key_openssh(&path)?,
        DVKeyType::Unknown => return Err(Error::InputKeyFormatNotSupported),
    };

    Ok(DVPrivateKey { key_type, key_data })
}

impl DVPrivateKey {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<DVPrivateKey> {
        load_key(path)
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
