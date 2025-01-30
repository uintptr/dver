use std::{fs::canonicalize, path::Path};

use log::info;

use crate::{
    common::{
        fmt::printkv,
        hash::{hash_string, DVHashType},
        r#const::DEFAULT_SIGN_FILE_NAME,
    },
    directory::walker::Walker,
    error::Result,
    key::keys::load_public_key,
    sign::sign_dir::DVSignature,
};

pub fn verify_directory<P: AsRef<Path>>(
    directory: P,
    public_key: String,
    hash_type: DVHashType,
    signature_file: Option<P>,
) -> Result<()> {
    let directory = canonicalize(directory)?;

    let in_file = match &signature_file {
        Some(v) => v.as_ref(),
        None => &directory.join(DEFAULT_SIGN_FILE_NAME),
    };

    let in_file = canonicalize(in_file)?;

    println!("Verifying:");
    printkv("Directory", directory.display());
    printkv("Public Key", &public_key);
    printkv("Signature File", in_file.display());
    printkv("Hash Type", hash_type);

    let s = DVSignature::from_file(&in_file)?;

    let walker = Walker::new(&directory, hash_type)?;

    let dir_data = walker.encode()?;
    let dir_data_hash = hash_string(&dir_data, DVHashType::Sha512);

    info!("data len: {}", dir_data.len());
    info!("data hash: {}", hex::encode(&dir_data_hash));
    info!("data sign: {}", hex::encode(&s.signature));

    let verifier = load_public_key(public_key)?;

    let ret = verifier.verify(&dir_data_hash, &s.signature);

    let status = match ret {
        Ok(_) => "Success",
        Err(_) => "Failure",
    };

    printkv("Verification", status);

    ret
}
