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
    let mut args = vec![];

    if let Some(key) = &key_id {
        args.push("--default-key");
        args.push(key);
    }

    args.push("--batch");
    args.push("--pinentry-mode");
    args.push("loopback");
    args.push("--no-tty");
    args.push("--verify");
    args.push(sig.to_str().unwrap_or(""));
    args.push(msg.to_str().unwrap_or(""));

    info!("-----------------------------------");
    info!("{} {:?}", gpg_exe.display(), args);

    let output = Command::new(gpg_exe).args(args).output()?;

    let exit_code = output.status.code().unwrap_or(1);

    match exit_code {
        0 => Ok(()),
        _ => {
            log_command_failure(&output);
            let msg = format!("{:?} returned {exit_code}", gpg_exe.display());
            Err(Error::ExecFailure(msg))
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
