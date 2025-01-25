use std::{path::StripPrefixError, time::SystemTimeError};

use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{}", .0)]
    NotFound(String),
    #[error("Invalid Argument ({})", .0)]
    InvalidArgument(String),
    #[error("Serialization Error")]
    SerializeError,
    #[error("Input Key Format Not Supported")]
    InputKeyFormatNotSupported,
    #[error("{}", .0)]
    NotImplementedError(String),
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
    #[error("{}", .0)]
    SshAgentUnknownMessage(String),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    // ssh
    #[error("invalid message id {}", .0)]
    SShInvalidMessageId(u8),
    #[error("unable to connect to ssh-agent")]
    SshAgentNotRunning,
    #[error("ssh-agent identity not found for")]
    SshIdentityNotFound,
}
