use std::{
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use sha2::{Digest, Sha384};

use crate::DVError;

const HASH_BUFFER_SIZE: usize = 1024 * 8;

pub fn sha384_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<u8>, DVError> {
    let fd = File::open(file_path)?;

    let mut buffer = [0; HASH_BUFFER_SIZE];
    let mut rdr = BufReader::new(fd);

    let mut hash = Sha384::new();

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

pub fn sha384_file_as_hex<P: AsRef<Path>>(file_path: P) -> Result<String, DVError> {
    let digest = sha384_file(file_path)?;
    Ok(hex::encode(digest))
}
