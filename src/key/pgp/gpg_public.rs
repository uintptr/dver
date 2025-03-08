use std::{fs, path::Path, process::Command};

use tempfile::Builder;
use which::which;

use log::info;

use crate::{
    error::{Error, Result},
    key::{keys::Verifier, pgp::pgp_common::log_command_failure},
};

pub struct GpgPublic {
    key_id: Option<String>,
}

fn gpg_verify(gpg_exe: &Path, key_id: &Option<String>, msg: &Path, sig: &Path) -> Result<()> {
    let mut command = Command::new(gpg_exe);

    if let Some(key) = &key_id {
        command.arg("--default-key").arg(key);
    }

    command
        .arg("--batch")
        .arg("--pinentry-mode")
        .arg("loopback")
        .arg("--no-tty")
        .arg("--verify")
        .arg(sig.to_str().unwrap_or(""))
        .arg(msg.to_str().unwrap_or(""));

    info!("-----------------------------------");
    info!("command: {:?}", command);

    let output = command.output()?;

    let exit_code = output.status.code().unwrap_or(1);

    match exit_code {
        0 => Ok(()),
        _ => {
            log_command_failure(&output);
            Err(Error::ExecFailure { command, output })
        }
    }
}

impl Verifier for GpgPublic {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        let tmp_dir = Builder::new().prefix("dver_gpg_").tempdir()?;

        let msg_file = Path::new(tmp_dir.path()).join("msg.bin");
        let sig_file = Path::new(tmp_dir.path()).join("sig.bin");

        fs::write(&msg_file, msg)?;
        fs::write(&sig_file, signature)?;

        let gpg_exe = which("gpg")?;

        gpg_verify(&gpg_exe, &self.key_id, &msg_file, &sig_file)
    }
}

impl GpgPublic {
    pub fn new_with_key(private_key_id: &str) -> GpgPublic {
        GpgPublic {
            key_id: Some(private_key_id.to_string()),
        }
    }

    pub fn new() -> GpgPublic {
        GpgPublic { key_id: None }
    }
}
