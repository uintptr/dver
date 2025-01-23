use std::{path::StripPrefixError, time::SystemTimeError};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid Argument ({})", .0)]
    InvalidArgument(String),
    #[error("Input Key Format Not Supported")]
    InputKeyFormatNotSupported,
    #[error("Not Implemented")]
    NotImplementedError,
    #[error("Invalid Root Directory")]
    InvalidRootDirectory,
    #[error("Unknown Hash Type")]
    UnknownHashType,
    #[error("Logging Init Failure")]
    LoggingInitFailure,
    #[error("Unexpected input {:?}", .0)]
    InvalidPath(String),
    #[error("Empty Hash")]
    EmptyHash,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Time(#[from] SystemTimeError),
    #[error(transparent)]
    Rel(#[from] StripPrefixError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    LoadKey(#[from] ssh_key::Error),
}

pub mod common;
pub mod file_io;
pub mod key;
pub mod logging;
pub mod signer;
pub mod verifier;
pub mod walker;
