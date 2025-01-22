#![allow(unused)]

use std::{
    fmt::{self, Display},
    fs,
    net::SocketAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use log::{error, info, logger};
use sha2::{Digest, Sha384};

use crate::{file_io::sha384_file, DVError};

enum WalkerHashType {
    Unknown = 0,
    Sha384 = 1,
}

pub struct WalkerFile {
    path: PathBuf,
    hash: Vec<u8>,
    hash_type: WalkerHashType,
    size: u64,
}

impl fmt::Display for WalkerFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_str = hex::encode(&self.hash);
        write!(f, "{:?} @ {hash_str}", self.path)
    }
}

pub struct WalkerDirectory {
    directory: PathBuf,
    files: Vec<WalkerFile>,
    directories: Vec<WalkerDirectory>,
    hash: Vec<u8>,
}

impl fmt::Display for WalkerDirectory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_string = match self.hash.len() {
            0 => "".to_string(),
            _ => format!("hash={}", hex::encode(&self.hash)),
        };

        write!(
            f,
            "directory: {:?} files={} dirs={} {}",
            self.directory,
            self.files.len(),
            self.directories.len(),
            hash_string,
        )
    }
}

impl WalkerFile {
    pub fn new<P: AsRef<Path>>(file: P) -> Result<WalkerFile, DVError> {
        let hash_type = WalkerHashType::Sha384;

        let stat = fs::metadata(&file)?;

        Ok(WalkerFile {
            path: file.as_ref().into(),
            hash: sha384_file(&file)?,
            hash_type: WalkerHashType::Sha384,
            size: stat.size(),
        })
    }
}

impl WalkerDirectory {
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<WalkerDirectory, DVError> {
        let mut d = WalkerDirectory {
            directory: dir.as_ref().into(),
            files: Vec::new(),
            directories: Vec::new(),
            hash: vec![],
        };

        d.parse(dir)?;

        info!("--> {d}");

        let mut hash = Sha384::new();

        for file in &d.files {
            hash.update(&file.hash);
        }

        for dir in &d.directories {
            if dir.hash.is_empty() {
                return Err(DVError::EmptyHash);
            }
        }

        let digest = hash.finalize();

        d.hash = digest.to_vec();

        Ok(d)
    }

    pub fn hash(&self) -> &[u8] {
        return &self.hash;
    }

    fn parse<P: AsRef<Path>>(&mut self, dir: P) -> Result<(), DVError> {
        if dir.as_ref().is_dir() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?.path();
                if entry.is_dir() {
                    let d = WalkerDirectory::new(entry)?;
                    self.directories.push(d);
                } else if entry.is_file() {
                    // we'll do it later
                } else {
                    let err = format!("{:?} is not a file or directory", entry);
                    return Err(DVError::InvalidPath(err));
                }
            }
            for entry in fs::read_dir(dir)? {
                let entry = entry?.path();
                if entry.is_file() {
                    let f = WalkerFile::new(entry)?;
                    self.files.push(f);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use crate::logging::init_logging;

    use super::*;

    #[test]
    fn walk_tmp() {
        init_logging().unwrap();

        let res = WalkerDirectory::new("/usr");
        assert!(res.is_ok());

        if let Ok(d) = res {
            info!("{d}");
        }
    }
}
