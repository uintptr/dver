use core::fmt;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use sha2::{Digest, Sha256, Sha512};

const HASH_BUFFER_SIZE: usize = 1024 * 8;

use crate::error::{Error, Result};

#[derive(Debug, Copy, Clone)]
pub enum DVHashType {
    Sha256,
    Sha512,
}

impl fmt::Display for DVHashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DVHashType::Sha256 => write!(f, "sha256"),
            DVHashType::Sha512 => write!(f, "sha512"),
        }
    }
}

impl std::str::FromStr for DVHashType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "sha256" => Ok(DVHashType::Sha256),
            "sha512" => Ok(DVHashType::Sha512),
            _ => Err(Error::UnknownHashType),
        }
    }
}

fn sha_file<T: Digest, P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>> {
    let fd = File::open(file_path)?;

    let mut buffer: [u8; HASH_BUFFER_SIZE] = [0; HASH_BUFFER_SIZE];
    let mut rdr = BufReader::new(fd);

    let mut hash = T::new();

    loop {
        let len = rdr.read(&mut buffer)?;

        if 0 == len {
            break; // EOF
        }

        hash.update(&buffer[..len]);
    }

    let digest = hash.finalize();

    Ok(digest.to_vec())
}

fn sha_data<T: Digest>(data: &[u8]) -> Vec<u8> {
    let mut hash = T::new();

    hash.update(data);

    hash.finalize().to_vec()
}

////////////////////////////////////////////////////////////////////////////////
/// PUBLIC
////////////////////////////////////////////////////////////////////////////////
pub fn hash_file<P: AsRef<Path>>(file_path: P, hash_type: DVHashType) -> Result<Vec<u8>> {
    match hash_type {
        DVHashType::Sha256 => sha_file::<Sha256, _>(file_path),
        DVHashType::Sha512 => sha_file::<Sha512, _>(file_path),
    }
}

pub fn hash_data(data: &[u8], hash_type: DVHashType) -> Vec<u8> {
    match hash_type {
        DVHashType::Sha256 => sha_data::<Sha256>(data),
        DVHashType::Sha512 => sha_data::<Sha512>(data),
    }
}

pub fn hash_string(data: &str, hash_type: DVHashType) -> Vec<u8> {
    hash_data(data.as_bytes(), hash_type)
}

#[cfg(test)]
mod tests {

    use super::hash_file;
    use crate::common::hash::{hash_data, hash_string};

    #[test]
    fn test_hash() {
        let res = hash_file("/path/to/bleh", super::DVHashType::Sha256);
        assert!(res.is_err());

        let res_str = hash_string(&String::new(), super::DVHashType::Sha256);
        let res_data = hash_data(&vec![], super::DVHashType::Sha256);
        assert_eq!(res_str, res_data);
    }
}
