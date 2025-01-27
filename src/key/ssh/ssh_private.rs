use std::{
    fs,
    path::{Path, PathBuf},
};

use log::warn;
use ssh_key::{Cipher, HashAlg, PrivateKey};

use crate::{
    error::{Error, Result},
    key::keys::PrivateKeyTrait,
};

use super::ssh_agent::SshAgentClient;

#[derive(Debug)]
pub struct SshSigner {
    key_file: PathBuf,
    key: PrivateKey,
    agent: Option<SshAgentClient>,
}

impl PrivateKeyTrait for SshSigner {
    fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self.key.cipher().is_none() {
            true => self.sign_with_key(data),
            false => self.sign_with_agent(data),
        }
    }
}

impl SshSigner {
    pub fn new<P: AsRef<Path>>(private_key: P) -> Result<SshSigner> {
        let encoded_key = fs::read_to_string(&private_key)?;

        let key = PrivateKey::from_openssh(encoded_key)?;

        let agent = match key.cipher() {
            Cipher::None => None,
            _ => match SshAgentClient::new() {
                Ok(v) => Some(v),
                Err(_) => {
                    warn!("Unable to connect to ssh-agent");
                    None
                }
            },
        };

        Ok(SshSigner {
            key_file: private_key.as_ref().to_path_buf(),
            key,
            agent,
        })
    }

    fn sign_with_agent(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(a) = &mut self.agent {
            match a.find_identity(&self.key_file) {
                Ok(i) => a.sign(&i, data),
                Err(_) => Err(Error::SshIdentityNotFound),
            }
        } else {
            Err(Error::SshAgentNotRunning)
        }
    }

    fn sign_with_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self.key.sign("dverify", HashAlg::Sha512, data)?;
        Ok(sig.signature().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {

    use crate::logging::init_logging;

    use super::*;

    const SSH_KEY_NO_PASS: &str = r#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBQ3/LrI5TpcojmI82Fi98Q2pk/UIoIzhnLXRmdkKP1cgAAAJCaw3MNmsNz
DQAAAAtzc2gtZWQyNTUxOQAAACBQ3/LrI5TpcojmI82Fi98Q2pk/UIoIzhnLXRmdkKP1cg
AAAEBG00OGDC5akof3hIpltQXCEWDNg5NXd4OW0MkpHU463lDf8usjlOlyiOYjzYWL3xDa
mT9QigjOGctdGZ2Qo/VyAAAACmpvZUBsYXB0b3ABAgM=
-----END OPENSSH PRIVATE KEY-----
"#;

    const SSH_KEY: &str = r#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAHy6utqW
xfGIzM7qUQKPJAAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIF1iu/3inePfxFL9
tiaUSPbETidvVeeJbt2l3JK+TBnYAAAAkF7jFayjWJ4Fq1/XvyqtikSOcF0qcAReIobdyK
NLy5dNrNgQ7rdqCKcubqDg4vnTMLk0JtKEpyrrWBWCg/E2aUyKqgVISCKkR+B50xiG2m/x
844p6tAzykCm5mCeHPhMFMfvEmXwQXCbRIzs25iF0/EUSd4FJ0trosi6LMtw9BxYudZZN/
iEDuKa45ETd2d7aQ==
-----END OPENSSH PRIVATE KEY-----
"#;

    #[test]
    fn test_ssh_sign() {
        init_logging().unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let key_file = Path::new(&temp_dir.into_path()).join("key");
        fs::write(&key_file, SSH_KEY).unwrap();
        let mut s = SshSigner::new(key_file).unwrap();
        let ret = s.sign("hello".as_bytes());

        assert!(ret.is_err());

        let temp_dir = tempfile::tempdir().unwrap();
        let key_file = Path::new(&temp_dir.into_path()).join("key");
        fs::write(&key_file, SSH_KEY_NO_PASS).unwrap();
        let mut s = SshSigner::new(&key_file).unwrap();
        let ret = s.sign("hello".as_bytes());

        assert!(ret.is_ok());
    }
}
