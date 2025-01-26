use std::{fs, path::Path};

use ssh_key::PublicKey;

use crate::error::Result;

#[derive(Debug)]
pub struct SshVerifier {
    pub pub_key: PublicKey,
}

impl SshVerifier {
    pub fn new<P: AsRef<Path>>(public_key: P) -> Result<SshVerifier> {
        let pub_data = fs::read_to_string(public_key)?;

        let pub_key = PublicKey::from_openssh(&pub_data)?;

        Ok(SshVerifier { pub_key })
    }

    pub fn verify(&self, _msg: &[u8], _signature: &[u8]) -> Result<()> {
        //let s = self.pub_key.key_data()

        //Ok(self.pub_key.verify(DV_NS, msg, signature)?)
        Ok(())
    }
}
