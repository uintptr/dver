use std::{fs, path::Path};

use ssh_key::{HashAlg, PublicKey, Signature, SshSig};

use crate::{
    error::{Error, Result},
    key::keys::Verifier,
};

use super::ssh_agent::DV_NS_STR;

#[derive(Debug)]
pub struct SshPublic {
    pub pub_key: PublicKey,
}

impl Verifier for SshPublic {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::new(self.pub_key.algorithm(), signature)?;

        let ssh_sig = SshSig::new(
            self.pub_key.key_data().clone(),
            DV_NS_STR,
            HashAlg::Sha512,
            sig,
        )?;

        match self.pub_key.verify(DV_NS_STR, msg, &ssh_sig) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::VerificationFailure),
        }
    }
}

impl SshPublic {
    pub fn new<P: AsRef<Path>>(public_key: P) -> Result<SshPublic> {
        let pub_data = fs::read_to_string(public_key)?;

        let pub_key = PublicKey::from_openssh(&pub_data)?;

        Ok(SshPublic { pub_key })
    }
}
