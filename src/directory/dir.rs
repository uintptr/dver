#![allow(unused)]
use std::{
    env,
    fmt::{self},
    fs,
    path::{Path, PathBuf},
    vec,
};

use crate::common::{
    hash::DVHashType, r#const::DEFAULT_SIGN_FILE_NAME, serializer::hex_serializer,
};

use log::info;
use serde_derive::Serialize;
use sha2::{Digest, Sha256, Sha512};
use walkdir::WalkDir;

use crate::error::{Error, Result};

use super::file::WalkerFile;

#[derive(Debug, Serialize)]
pub struct WalkerDirectory {
    directory: PathBuf,
    #[serde(serialize_with = "hex_serializer")]
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
    pub fn new<P: AsRef<Path>>(root: P, hash_type: DVHashType) -> Result<WalkerDirectory> {
        let absolute_root = match root.as_ref().is_absolute() {
            true => root.as_ref().into(),
            false => {
                let cwd = env::current_dir()?;
                Path::new(&cwd).join(root)
            }
        };

        WalkerDirectory::new_with_root(absolute_root, ".", hash_type)
    }

    fn new_with_root<P: AsRef<Path>, T: AsRef<Path>>(
        absolute: P,
        relative: T,
        hash_type: DVHashType,
    ) -> Result<WalkerDirectory> {
        let mut d = WalkerDirectory {
            directory: relative.as_ref().into(),
            files: Vec::new(),
            directories: Vec::new(),
            hash: vec![],
        };

        d.parse(absolute, relative, hash_type)?;

        d.hash = match hash_type {
            DVHashType::Sha256 => d.hash::<Sha256>(),
            DVHashType::Sha512 => d.hash::<Sha512>(),
        }?;

        Ok(d)
    }

    fn parse<P: AsRef<Path>, T: AsRef<Path>>(
        &mut self,
        absolute: P,
        relative: T,
        hash_type: DVHashType,
    ) -> Result<()> {
        let absolute_path = absolute.as_ref().join(relative.as_ref()).canonicalize()?;

        for entry in WalkDir::new(absolute_path).contents_first(false) {
            let abs_path = match entry {
                Ok(v) => v,
                Err(_) => return Err(Error::InvalidRootDirectory),
            };

            let rel_file = match abs_path.file_name().to_str() {
                Some(v) => v.to_string(),
                None => return Err(Error::InvalidRootDirectory),
            };

            let d = WalkerDirectory::new_with_root(abs_path.into_path(), rel_file, hash_type)?;
        }

        todo!()
    }

    fn hash<T: Digest>(&self) -> Result<Vec<u8>> {
        let mut hash = T::new();

        for file in &self.files {
            hash.update(&file.hash);
        }

        for dir in &self.directories {
            if dir.hash.is_empty() {
                return Err(Error::EmptyHash);
            }
        }

        let digest = hash.finalize();

        Ok(digest.to_vec())
    }
}
/*
impl WalkerDirectory {
    pub fn new<P: AsRef<Path>>(dir: P, hash_type: DVHashType) -> Result<WalkerDirectory, Error> {
        let dir: PathBuf = match dir.as_ref().is_absolute() {
            true => dir.as_ref().into(),
            false => {
                let cwd = env::current_dir()?;
                Path::new(&cwd).join(dir)
            }
        };

        match dir.parent() {
            Some(root) => WalkerDirectory::new_with_root(root, &dir, hash_type),
            None => Err(Error::InvalidRootDirectory),
        }
    }

    fn ignore_file(&self, file_path: &PathBuf) -> bool {
        if !file_path.is_file() {
            return false;
        }

        match file_path.file_name() {
            Some(basename) => {
                if basename == DEFAULT_SIGN_FILE_NAME {
                    info!("ignoring file={:?}", file_path);
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    fn new_with_root<P: AsRef<Path>, T: AsRef<Path>>(
        root: P,
        dir: T,
        hash_type: DVHashType,
    ) -> Result<WalkerDirectory, Error> {
        let rel_name = dir.as_ref().strip_prefix(&root)?;

        let mut d = WalkerDirectory {
            directory: rel_name.into(),
            files: Vec::new(),
            directories: Vec::new(),
            hash: vec![],
        };

        d.parse(root, dir, hash_type)?;

        d.hash = match hash_type {
            DVHashType::Sha256 => d.hash::<Sha256>(),
            DVHashType::Sha512 => d.hash::<Sha512>(),
        }?;

        Ok(d)
    }

    fn parse<P: AsRef<Path>, T: AsRef<Path>>(
        &mut self,
        root: P,
        dir: T,
        hash_type: DVHashType,
    ) -> Result<(), Error> {
        if dir.as_ref().is_dir() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?.path();
                if entry.is_dir() {
                    let d = WalkerDirectory::new_with_root(root.as_ref(), entry, hash_type)?;
                    self.directories.push(d);
                } else if entry.is_file() {
                    // we'll do it later
                } else {
                    let err = format!("{:?} is not a file or directory", entry);
                    return Err(Error::InvalidPath(err));
                }
            }
            for entry in fs::read_dir(dir)? {
                let entry = entry?.path();

                if self.ignore_file(&entry) {
                    continue;
                }

                if entry.is_file() {
                    let f = WalkerFile::new(root.as_ref(), entry, hash_type)?;
                    self.files.push(f);
                }
            }
        }

        Ok(())
    }

    fn hash<T: Digest>(&self) -> Result<Vec<u8>, Error> {
        let mut hash = T::new();

        for file in &self.files {
            hash.update(&file.hash);
        }

        for dir in &self.directories {
            if dir.hash.is_empty() {
                return Err(Error::EmptyHash);
            }
        }

        let digest = hash.finalize();

        Ok(digest.to_vec())
    }
}
*/

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn walk_tmp() {
        let tmp_dir = tempfile::tempdir().unwrap().into_path();

        let tmp_dir_1_2 = tmp_dir.join("1").join("2");
        let tmp_dir_3_4 = tmp_dir.join("3").join("4");

        fs::create_dir_all(tmp_dir_1_2).unwrap();
        fs::create_dir_all(tmp_dir_3_4).unwrap();

        WalkerDirectory::new(tmp_dir, DVHashType::Sha256).unwrap();
    }
}
