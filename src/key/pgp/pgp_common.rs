use std::process::Output;

use log::error;

pub fn log_command_failure(output: &Output) {
    if !output.stdout.is_empty() {
        error!("{}", String::from_utf8_lossy(&output.stdout))
    }

    if !output.stderr.is_empty() {
        error!("{}", String::from_utf8_lossy(&output.stderr))
    }
}
