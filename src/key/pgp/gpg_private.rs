#![allow(unused)]
use std::{
    fmt::format,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use log::{error, info};
use tempfile::Builder;
use which::which;

use crate::{
    error::{Error, Result},
    key,
};

#[derive(Debug)]
pub struct GgpSigner {
    key_id: Option<String>,
}

fn log_command_failure(output: &Output) {
    if !output.stdout.is_empty() {
        error!("{}", String::from_utf8_lossy(&output.stdout))
    }

    if !output.stderr.is_empty() {
        error!("{}", String::from_utf8_lossy(&output.stderr))
    }
}

fn run_pgp_with_pass(
    gpg_exe: &PathBuf,
    key_id: &Option<String>,
    in_file: &PathBuf,
    out_file: &PathBuf,
) -> Result<()> {
    let mut args = vec!["--sign"];

    if let Some(key) = &key_id {
        args.push("--default-key");
        args.push(&key);
    }

    if out_file.exists() {
        fs::remove_file(out_file)?;
    }

    args.push("--batch");
    args.push("--pinentry-mode");
    args.push("loopback");
    args.push("--no-tty");
    args.push("--passphrase-fd");
    args.push("0");
    args.push("--output");
    args.push(out_file.to_str().unwrap_or(""));
    args.push(in_file.to_str().unwrap_or(""));

    info!("-----------------------------------");
    info!("{} {:?}", gpg_exe.display(), args);

    let mut child = Command::new(gpg_exe)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        let password = rpassword::prompt_password("gpg passphrase: ")?;
        stdin.write(password.as_bytes())?;
    }

    info!("password sent");

    let output = child.wait_with_output()?;

    let exit_code = match output.status.code() {
        Some(s) => s,
        None => 1,
    };

    match exit_code {
        0 => Ok(()),
        _ => {
            log_command_failure(&output);
            let msg = format!("{:?} returned {exit_code}", gpg_exe.display());
            Err(Error::ExecFailure(msg))
        }
    }
}

fn run_pgp(
    gpg_exe: &PathBuf,
    key_id: &Option<String>,
    in_file: &PathBuf,
    out_file: &PathBuf,
) -> Result<()> {
    let mut args = vec!["--sign"];

    if let Some(key) = &key_id {
        args.push("--default-key");
        args.push(&key);
    }

    args.push("--batch");
    args.push("--pinentry-mode");
    args.push("loopback");
    args.push("--no-tty");
    args.push("--output");
    args.push(out_file.to_str().unwrap_or(""));
    args.push(in_file.to_str().unwrap_or(""));

    let output = Command::new(&gpg_exe).args(args).output()?;

    let exit_code = match output.status.code() {
        Some(s) => s,
        None => 1,
    };

    info!("{:?} returned {exit_code}", gpg_exe.display());

    match exit_code {
        0 => Ok(()),
        _ => {
            log_command_failure(&output);
            let msg = format!("{:?} returned {exit_code}", gpg_exe.display());
            Err(Error::ExecFailure(msg))
        }
    }
}

impl GgpSigner {
    pub fn new_with_key(private_key_id: &str) -> GgpSigner {
        GgpSigner {
            key_id: Some(private_key_id.to_string()),
        }
    }

    pub fn new() -> GgpSigner {
        GgpSigner { key_id: None }
    }

    pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let tmp_dir = Builder::new().prefix("dver_gpg_").tempdir()?;

        let in_file = Path::new(tmp_dir.path()).join("input.bin");
        let out_file = Path::new(tmp_dir.path()).join("output.bin");

        fs::write(&in_file, data)?;

        let gpg_exe = which("gpg")?;

        //
        // trying without a password first in case the agent is running
        //
        if run_pgp(&gpg_exe, &self.key_id, &in_file, &out_file).is_err() {
            run_pgp_with_pass(&gpg_exe, &self.key_id, &in_file, &out_file)?;
        }

        let sig_data = fs::read(&out_file)?;

        info!("signature size: {}", sig_data.len());

        Ok(sig_data)
    }
}
