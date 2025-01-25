#![allow(unused)]
use std::{fmt::format, fs, path::Path};

use log::{info, warn};
use ssh_key::{HashAlg, PrivateKey};

use crate::error::{Error, Result};

use super::ssh_agent::SshAgentClient;

pub struct SshSigner {
    key: PrivateKey,
    agent: Option<SshAgentClient>,
}

fn connect_ssh_agent(_key: &PrivateKey) -> Result<SshAgentClient> {
    todo!()
}

impl SshSigner {
    pub fn new<P: AsRef<Path>>(private_key: P) -> Result<SshSigner> {
        let encoded_key = fs::read_to_string(private_key)?;

        SshSigner::from_buffer(&encoded_key)
    }

    pub fn from_buffer(private_key: &str) -> Result<SshSigner> {
        let key = PrivateKey::from_openssh(private_key)?;
        info!("{:?}", key);

        key.sign("ns", HashAlg::default(), b"message")?;

        let mut agent: Option<SshAgentClient> = None;

        if key.cipher().is_some() {
            //
            // key is passwords protected
            //
            // 1) try talking to the ssh-agent if it exists
            // 2) fallback on asking for the password
            //
            agent = match connect_ssh_agent(&key) {
                Ok(v) => Some(v),
                Err(_) => {
                    warn!("Unable to connect to ssh-agent");
                    None
                }
            };

            if agent.is_none() {
                let msg = "encrypted ssh key is not supported".to_string();
                return Err(Error::NotImplementedError(msg));
            }

            if agent.is_none() {
                //
                // we'll need a password!
                //
                todo!()
            }
        } else {
            // that's not ideal
            warn!("ssh private key is not protected");
        }

        Ok(SshSigner { key, agent })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sig = self.key.sign("dverify", HashAlg::Sha512, data)?;
        Ok(sig.signature().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use rand::RngCore;

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

        let cwd = env::current_dir().unwrap();

        let ssh_test_dir = Path::new(&cwd).join("tests").join("ssh");

        let key_pass = ssh_test_dir.join("pass");
        let key_no_pass = ssh_test_dir.join("no_pass");

        let s = SshSigner::from_buffer(SSH_KEY).unwrap();
        s.sign("hello".as_bytes()).unwrap();

        let s = SshSigner::from_buffer(SSH_KEY_NO_PASS).unwrap();
        s.sign("hello".as_bytes()).unwrap();
    }
}
