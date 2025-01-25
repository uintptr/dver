#![allow(unused)]
use std::{
    env, fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    vec,
};

use log::info;
use serde_derive::Serialize;
use ssh_key::PrivateKey;

use crate::error::{Error, Result};

#[derive(Debug, Serialize)]
enum AgentMessageNumber {
    AgentIdentities = 11,
}

#[derive(Debug, Serialize)]
struct AgentMessage {
    pub length: u32,
    pub msg_num: u8,
    pub data: Vec<u8>,
}

impl AgentMessage {
    pub fn new(msg_num: AgentMessageNumber) -> AgentMessage {
        AgentMessage {
            length: 1,
            msg_num: msg_num as u8,
            data: vec![],
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();

        data.extend(self.length.to_be_bytes());
        data.extend(self.msg_num.to_be_bytes());
        data.extend(&self.data);

        data
    }
}

pub struct SshAgentClient {
    stream: UnixStream,
}

#[derive(Debug)]
pub struct SshIdentity {
    algorithm: String,
    pub_key: Vec<u8>,
    comment: String,
}

impl<'a> SshAgentClient {
    pub fn new() -> Result<SshAgentClient> {
        let auth_sock = match env::var("SSH_AUTH_SOCK") {
            Ok(v) => v,
            Err(_) => {
                // can't do much without this
                let msg = "env var SSH_AUTH_SOCK was not found";
                return Err(Error::NotFound(msg.into()));
            }
        };

        let stream = UnixStream::connect(auth_sock)?;

        Ok(SshAgentClient { stream })
    }

    fn read_u32(&mut self) -> Result<(u32)> {
        let mut buffer = [0; 4];
        self.stream.read_exact(&mut buffer)?;
        Ok(u32::from_be_bytes(buffer))
    }

    fn read_u8(&mut self) -> Result<u8> {
        let mut buffer = [0; 1];
        self.stream.read_exact(&mut buffer)?;
        Ok(u8::from_be_bytes(buffer))
    }

    fn read_string(&mut self) -> Result<String> {
        let len = self.read_u32()?;

        let mut str_data = vec![0u8; len as usize];

        self.stream.read(&mut str_data)?;

        let str = std::str::from_utf8(&str_data)?;

        Ok(str.into())
    }

    fn read_buffer(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()?;

        let mut str_data = vec![0u8; len as usize];

        self.stream.read(&mut str_data)?;

        Ok(str_data)
    }

    fn read_identity(&mut self) -> Result<SshIdentity> {
        self.read_u32()?;

        let algorithm = self.read_string()?;
        let pub_key = self.read_buffer()?;
        let comment = self.read_string()?;

        Ok(SshIdentity {
            algorithm,
            pub_key,
            comment,
        })
    }

    fn read_list_keys_answer(&mut self) -> Result<Vec<SshIdentity>> {
        let mut identities: Vec<SshIdentity> = Vec::new();

        self.read_u32()?;
        self.read_u8()?;

        let count = self.read_u32()?;

        for _ in 0..count {
            let identity = self.read_identity()?;
            identities.push(identity);
        }

        Ok(identities)
    }

    ////////////////////////////////////////////////////////////////////////////
    /// PUBLIC
    ////////////////////////////////////////////////////////////////////////////

    pub fn find_identity<P: AsRef<Path>>(&mut self, key_file: P) -> Result<SshIdentity> {
        let key_data = fs::read_to_string(key_file)?;
        let key = PrivateKey::from_openssh(key_data)?;

        //key.public_key().fingerprint(
        let public = key.public_key().key_data().ed25519();

        for k in self.list_keys()? {
            if "ssh-ed25519" == k.algorithm {
                if let Some(key) = key.public_key().key_data().ed25519() {
                    if k.pub_key == key.as_ref() {
                        return Ok(k);
                    }
                }
            }
        }

        return Err(Error::NotFound("key not in ssh-agent".into()));
    }

    pub fn list_keys(&mut self) -> Result<Vec<SshIdentity>> {
        let msg = AgentMessage::new(AgentMessageNumber::AgentIdentities);
        self.stream.write(&msg.serialize())?;
        self.read_list_keys_answer()
    }

    // https://www.agwa.name/blog/post/ssh_signatures
    pub fn sign(&mut self, identity: &SshIdentity, _data: &[u8]) -> Result<Vec<u8>> {
        info!("{:?}", identity);

        let encoded_key = hex::encode(&identity.pub_key);

        info!(
            "key: ({}) -> {} {}",
            encoded_key.len(),
            &encoded_key,
            &encoded_key[..0x20]
        );
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use home::home_dir;
    use rand::RngCore;

    use crate::logging::init_logging;

    use super::*;

    #[test]
    fn test_ssh_sign() {
        init_logging().unwrap();

        let home = home_dir().unwrap();

        let pkey_file = Path::new(&home).join(".ssh").join("id_ed25519");

        let mut client = SshAgentClient::new().unwrap();

        let ident = client.find_identity(&pkey_file).unwrap();

        let signature = client.sign(&ident, b"Hello, World").unwrap();

        info!("{:?}", signature);
    }
}
