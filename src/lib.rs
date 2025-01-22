use std::time::SystemTimeError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DVError {
    #[error("Invalid Argument ({})", .0)]
    InvalidArgument(String),
    #[error("Not Implemented")]
    NotImplementedError,
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
}

pub mod file_io;
pub mod logging;
pub mod signer;
pub mod verifier;
pub mod walker;
