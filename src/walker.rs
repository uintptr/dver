use std::{
    env,
    fmt::{self},
    fs,
    path::{Path, PathBuf},
};

use serde::Serializer;
use serde_derive::Serialize;
use sha2::{Digest, Sha384};

use crate::{file_io::sha384_file, DVError};

fn to_hex_string<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

#[derive(Debug, Serialize)]
struct WalkerFile {
    path: PathBuf,
    #[serde(serialize_with = "to_hex_string")]
    hash: Vec<u8>,
}

impl fmt::Display for WalkerFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hash_str = hex::encode(&self.hash);
        write!(f, "{:?} @ {hash_str}", self.path)
    }
}

impl WalkerFile {
    fn new<P: AsRef<Path>, T: AsRef<Path>>(root: P, file: T) -> Result<WalkerFile, DVError> {
        let rel_name = file.as_ref().strip_prefix(&root)?;

        Ok(WalkerFile {
            path: rel_name.into(),
            hash: sha384_file(&file)?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct WalkerDirectory {
    directory: PathBuf,
    #[serde(serialize_with = "to_hex_string")]
    hash: Vec<u8>,
    files: Vec<WalkerFile>,
    directories: Vec<WalkerDirectory>,
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

impl WalkerDirectory {
    pub fn new<P: AsRef<Path>>(dir: P) -> Result<WalkerDirectory, DVError> {
        let dir: PathBuf = match dir.as_ref().is_absolute() {
            true => dir.as_ref().into(),
            false => {
                let cwd = env::current_dir()?;
                Path::new(&cwd).join(dir)
            }
        };

        match dir.parent() {
            Some(root) => WalkerDirectory::new_with_root(root, &dir),
            None => Err(DVError::InvalidRootDirectory),
        }
    }

    fn new_with_root<P: AsRef<Path>, T: AsRef<Path>>(
        root: P,
        dir: T,
    ) -> Result<WalkerDirectory, DVError> {
        let rel_name = dir.as_ref().strip_prefix(&root)?;

        let mut d = WalkerDirectory {
            directory: rel_name.into(),
            files: Vec::new(),
            directories: Vec::new(),
            hash: vec![],
        };

        d.parse(root, dir)?;

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

    pub fn hash_str(&self) -> String {
        hex::encode(&self.hash)
    }

    fn parse<P: AsRef<Path>, T: AsRef<Path>>(&mut self, root: P, dir: T) -> Result<(), DVError> {
        if dir.as_ref().is_dir() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?.path();
                if entry.is_dir() {
                    let d = WalkerDirectory::new_with_root(root.as_ref(), entry)?;
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
                    let f = WalkerFile::new(root.as_ref(), entry)?;
                    self.files.push(f);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::logging::init_logging;

    use super::*;

    #[test]
    fn walk_tmp() {
        init_logging().unwrap();

        let res = WalkerDirectory::new("/home/joe/tmp/rtl-sdr");
        assert!(res.is_ok());

        if let Ok(d) = res {
            let json_data = serde_json::to_string_pretty(&d).unwrap();

            fs::write("/tmp/bleh", json_data).unwrap();
        }
    }
}
