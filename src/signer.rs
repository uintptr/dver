#![allow(unused)]

use crate::DVError;

const CURRENT_SIGN_FORMAT_VER: i32 = 1;

struct DVSignature {
    version: i32,
    signature: String,
}

pub fn sign_directory(directory: &str, private_key: &str) -> Result<(), DVError> {
    Ok(())
}
