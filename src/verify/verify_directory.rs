#![allow(unused)]
use std::{fs::canonicalize, path::Path};

use log::info;

use crate::{
    common::{printkv, DEFAULT_SIGN_FILE_NAME},
    error::Result,
    hash::{hash_string, DVHashType},
    sign::sign_directory::DVSignature,
    verify::verifier::DVVerifier,
    walker::dir::WalkerDirectory,
};

pub fn verify_directory<P: AsRef<Path>>(
    directory: P,
    public_key: P,
    hash_type: DVHashType,
    signature_file: Option<P>,
) -> Result<()> {
    let directory = canonicalize(directory)?;
    let public_key = canonicalize(public_key)?;

    let in_file = match &signature_file {
        Some(v) => v.as_ref(),
        None => &directory.join(DEFAULT_SIGN_FILE_NAME),
    };

    let in_file = canonicalize(in_file)?;

    println!("Verifying:");
    printkv("Directory", directory.display());
    printkv("Public Key", public_key.display());
    printkv("Signature File", in_file.display());

    let s = DVSignature::from_file(&in_file)?;

    let d = WalkerDirectory::new(&directory, hash_type)?;

    let dir_data = d.encode()?;
    let dir_data_hash = hash_string(&dir_data, DVHashType::Sha512);

    printkv("Data Hash", hex::encode(dir_data_hash));

    let v = DVVerifier::new(public_key)?;

    //v.verify(data

    info!("{:?}", v);

    // rebuild t
    todo!()
}
