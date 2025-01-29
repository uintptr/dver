use core::fmt;
use std::{
    env,
    fmt::Display,
    fs::{self, File},
    io::{BufReader, Read},
    path::Path,
    process::Command,
};

use sha2::{Digest, Sha256, Sha512};

const HASH_BUFFER_SIZE: usize = 1024 * 8;

pub const DEFAULT_SIGN_FILE_NAME: &str = "dver.sig";

pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    if bytes as f64 >= TB {
        format!("{:.2} TB", bytes as f64 / TB)
    } else if bytes as f64 >= GB {
        format!("{:.2} GB", bytes as f64 / GB)
    } else if bytes as f64 >= MB {
        format!("{:.2} MB", bytes as f64 / MB)
    } else if bytes as f64 >= KB {
        format!("{:.2} KB", bytes as f64 / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

pub fn fmt_len(size: usize) -> String {
    format_size(size as u64)
}

pub fn file_size_to_str<P: AsRef<Path>>(file_path: P) -> crate::error::Result<String> {
    let stat = fs::metadata(file_path)?;

    //Ok(format_size(stat.size()))
    Ok(format_size(stat.len()))
}

pub fn printkv<D: Display>(k: &str, v: D) {
    let k = format!("{k}:");
    println!("    {k:<20}{v}");
}

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

pub struct DvCommand {
    pub ret: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl DvCommand {
    pub fn run(program: &str, args: &str) -> Result<DvCommand> {
        let cwd = env::current_dir()?;
        DvCommand::run_command(program, args, &cwd)
    }

    fn run_command<P: AsRef<Path>>(program: &str, args: &str, cwd: P) -> Result<DvCommand> {
        let ret = Command::new(program).arg(args).current_dir(cwd).output()?;

        Ok(DvCommand {
            ret: ret.status.code().unwrap_or(-1),
            stdout: ret.stdout,
            stderr: ret.stderr,
        })
    }

    pub fn stdout_text(&self) -> Result<String> {
        let out_str = String::from_utf8_lossy(&self.stdout);
        Ok(out_str.into())
    }

    pub fn stderr_text(&self) -> Result<String> {
        let out_str = String::from_utf8_lossy(&self.stderr);
        Ok(out_str.into())
    }
}

#[cfg(test)]
mod tests {
    use log::info;

    use crate::{common::DvCommand, logging::init_logging};

    #[test]
    fn test_cmd() {
        init_logging().unwrap();

        let res = DvCommand::run("/bleh", "");
        assert!(res.is_err());

        let res = DvCommand::run("/usr/bin/ping", "");
        assert!(res.is_ok());

        if let Ok(cmd) = res {
            assert_ne!(cmd.ret, 0);

            info!("stdout: {:?}", cmd.stdout);
            info!("stdout: {}", cmd.stdout_text().unwrap());
            info!("stderr: {:?}", cmd.stderr);
            info!("stderr: {:?}", cmd.stderr_text().unwrap());
        }
    }
}
