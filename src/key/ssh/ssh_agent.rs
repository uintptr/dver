use std::{
    env, fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    vec,
};

pub const DV_NS: &[u8] = b"hello";
pub const DV_NS_STR: &str = "hello";
const SIG_ALG: &[u8] = b"sha512";

use log::info;
use serde_derive::Serialize;
use ssh_key::PrivateKey;

use crate::{
    common::hash::{hash_data, DVHashType},
    error::{Error, Result},
};

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

#[derive(Debug)]
pub struct SshAgentClient {
    stream: UnixStream,
}

#[derive(Debug)]
pub struct SshIdentity {
    algorithm: String,
    pub_key: Vec<u8>,
}

impl SshAgentClient {
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

    fn read_u32(&mut self) -> Result<u32> {
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

        self.stream.read_exact(&mut str_data)?;

        let str = std::str::from_utf8(&str_data)?;

        Ok(str.into())
    }

    fn read_buffer(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()?;

        let mut str_data = vec![0u8; len as usize];

        self.stream.read_exact(&mut str_data)?;

        Ok(str_data)
    }

    fn read_identity(&mut self) -> Result<SshIdentity> {
        self.read_u32()?;

        let algorithm = self.read_string()?;
        let pub_key = self.read_buffer()?;
        self.read_string()?; // comment

        Ok(SshIdentity { algorithm, pub_key })
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

    fn send_signing_request(&mut self, identity: &SshIdentity, data: &[u8]) -> Result<()> {
        // public key
        let mut pub_key_vec: Vec<u8> = Vec::new();
        let alg_len = identity.algorithm.len() as u32;
        pub_key_vec.extend(alg_len.to_be_bytes());
        pub_key_vec.extend(identity.algorithm.as_bytes());
        let key_len = identity.pub_key.len() as u32;
        pub_key_vec.extend(key_len.to_be_bytes());
        pub_key_vec.extend(&identity.pub_key);

        // sshsig
        let mut ssh_sig_vec: Vec<u8> = Vec::new();
        ssh_sig_vec.extend(b"SSHSIG");
        let ns_len = DV_NS.len() as u32;
        ssh_sig_vec.extend(ns_len.to_be_bytes());
        ssh_sig_vec.extend(DV_NS);
        let ns_res_string: u32 = 0;
        ssh_sig_vec.extend(ns_res_string.to_be_bytes());
        let sig_alg_len = SIG_ALG.len() as u32;
        ssh_sig_vec.extend(sig_alg_len.to_be_bytes());
        ssh_sig_vec.extend(SIG_ALG);
        let data_hash = hash_data(data, DVHashType::Sha512);
        let data_hash_len = data_hash.len() as u32;
        ssh_sig_vec.extend(data_hash_len.to_be_bytes());
        ssh_sig_vec.extend(data_hash);

        let msg_len = 4 + 1 + pub_key_vec.len() + ssh_sig_vec.len() + 8;
        let msg_len = msg_len as u32;
        let sign_msg_id: u8 = 0xd;
        let zero: u32 = 0;

        let mut sign_msg: Vec<u8> = Vec::new();

        sign_msg.extend(msg_len.to_be_bytes());
        sign_msg.extend(sign_msg_id.to_be_bytes());
        let key_len = pub_key_vec.len() as u32;
        sign_msg.extend(key_len.to_be_bytes());
        sign_msg.extend(pub_key_vec);
        let ssh_sig_len = ssh_sig_vec.len() as u32;
        sign_msg.extend(ssh_sig_len.to_be_bytes());
        sign_msg.extend(ssh_sig_vec);
        sign_msg.extend(zero.to_be_bytes());

        self.stream.write_all(&sign_msg)?;

        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    /// PUBLIC
    ////////////////////////////////////////////////////////////////////////////
    pub fn find_identity<P: AsRef<Path>>(&mut self, key_file: P) -> Result<SshIdentity> {
        let key_data = fs::read_to_string(key_file)?;
        let key = PrivateKey::from_openssh(key_data)?;

        for k in self.list_keys()? {
            if "ssh-ed25519" == k.algorithm {
                if let Some(key) = key.public_key().key_data().ed25519() {
                    if k.pub_key == key.as_ref() {
                        return Ok(k);
                    }
                }
            }
        }

        Err(Error::NotFound("key not in ssh-agent".into()))
    }

    pub fn list_keys(&mut self) -> Result<Vec<SshIdentity>> {
        let msg = AgentMessage::new(AgentMessageNumber::AgentIdentities);
        self.stream.write_all(&msg.serialize())?;
        self.read_list_keys_answer()
    }

    /*
    > 2025/01/25 09:45:18.000903414  length=5 from=0 to=4
     00 00 00 01 0b                                   .....
    --
    < 2025/01/25 09:45:18.000903676  length=78 from=0 to=77
     00 00 00 4a 0c 00 00 00 01 00 00 00 33 00 00 00  ...J........3...
     0b 73 73 68 2d 65 64 32 35 35 31 39 00 00 00 20  .ssh-ed25519...
     63 e9 15 1a 6e 8a 9e fe 9f 59 26 fa ac e9 71 d7  c...n....Y&...q.
     9c db b3 36 bb c4 2f 00 f7 29 bd 1b d0 c5 df 69  ...6../..).....i
     00 00 00 0a                                      ....
     6a 6f 65 40 6c 61 70 74 6f 70                    joe@laptop
    --
    > 2025/01/25 09:45:18.000904421  length=165 from=5 to=169
     00 00 00 a1 0d 00 00 00 33 00 00 00 0b 73 73 68  ........3....ssh
     2d 65 64 32 35 35 31 39 00 00 00 20 63 e9 15 1a  -ed25519... c...
     6e 8a 9e fe 9f 59 26 fa ac e9 71 d7 9c db b3 36  n....Y&...q....6
     bb c4 2f 00 f7 29 bd 1b d0 c5 df 69 00 00 00 61  ../..).....i...a
     53 53 48 53 49 47 00 00 00 05 68 65 6c 6c 6f 00  SSHSIG....hello.
     00 00 00 00 00 00 06 73 68 61 35 31 32 00 00 00  .......sha512...
     40 e7 c2 2b 99 4c 59 d9 cf 2b 48 e5 49 b1 e2 46  @..+.LY..+H.I..F
     66 63 60 45 93 0d 3d a7 c1 ac b2 99 d1 c3 b7 f9  fc`E..=.........
     31 f9 4a ae 41 ed da 2c 2b 20 7a 36 e1 0f 8b cb  1.J.A..,+ z6....
     8d 45 22 3e 54 87 8f 5b 31 6e 7c e3 b6 bc 01 96  .E">T..[1n|.....
     29 00 00 00 00                                   )....
    --
    < 2025/01/25 09:45:18.000906875  length=92 from=78 to=169
     00 00 00 58 0e 00 00 00 53 00 00 00 0b 73 73 68  ...X....S....ssh
     2d 65 64 32 35 35 31 39 00 00 00 40 ef ca e4 2a  -ed25519...@...*
     70 2e ed 79 0e 1b 18 97 76 37 76 61 a5 5f 3a 7c  p..y....v7va._:|
     0e 7f bb 08 6a 59 11 ee 5d d4 85 c7 18 0e e9 cf  ....jY..].......
     37 fb 11 71 2a 14 d8 32 a1 3f 10 dc 4b 00 1d 5d  7..q*..2.?..K..]
     99 79 c4 38 cd 25 26 7a cd 4f 2e 02              .y.8.%&z.O..
    --
    */

    // https://www.agwa.name/blog/post/ssh_signatures
    // https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.sshsig?annotate=HEAD
    pub fn sign(&mut self, identity: &SshIdentity, data: &[u8]) -> Result<Vec<u8>> {
        self.send_signing_request(identity, data)?;

        self.read_u32()?; // answer len
        let ans_msg_id = self.read_u8()?;

        if 0xe != ans_msg_id {
            return Err(Error::SShInvalidMessageId(ans_msg_id));
        }

        self.read_u32()?; // msg len
        self.read_string()?; // alg
        let sign = self.read_buffer()?;

        info!("{}", pretty_hex::pretty_hex(&sign));

        Ok(sign.to_vec())
    }
}

#[cfg(test)]
mod tests {

    use home::home_dir;
    use log::warn;

    use super::*;

    #[test]
    fn test_ssh_sign() {
        let home = home_dir().unwrap();

        let pkey_file = Path::new(&home).join(".ssh").join("id_ed25519");

        // it's possible the agent isn't running
        match SshAgentClient::new() {
            Ok(mut client) => {
                let ident = client.find_identity(&pkey_file).unwrap();

                let message = b"Hello, World!";
                let signature = client.sign(&ident, message).unwrap();

                info!("{:?}", hex::encode(signature));
            }
            Err(e) => warn!("Error: {e}"),
        }
    }
}
