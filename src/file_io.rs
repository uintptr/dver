use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use sha2::{Digest, Sha256, Sha384, Sha512};

const HASH_BUFFER_SIZE: usize = 1024 * 8;

use crate::Error;

#[derive(Debug, Copy, Clone)]
pub enum DVHashType {
    Sha256,
    Sha384,
    Sha512,
}

impl std::str::FromStr for DVHashType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha256" => Ok(DVHashType::Sha256),
            "sha384" => Ok(DVHashType::Sha384),
            "sha512" => Ok(DVHashType::Sha512),
            _ => Err(Error::UnknownHashType),
        }
    }
}

fn sha_file<T: Digest, P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, Error> {
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

////////////////////////////////////////////////////////////////////////////////
/// PUBLIC
////////////////////////////////////////////////////////////////////////////////
pub fn hash_file<P: AsRef<Path>>(file_path: P, hash_type: DVHashType) -> Result<Vec<u8>, Error> {
    match hash_type {
        DVHashType::Sha256 => sha_file::<Sha256, _>(file_path),
        DVHashType::Sha384 => sha_file::<Sha384, _>(file_path),
        DVHashType::Sha512 => sha_file::<Sha512, _>(file_path),
    }
}
