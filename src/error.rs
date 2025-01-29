use std::{path::StripPrefixError, str::Utf8Error, string::FromUtf8Error, time::SystemTimeError};

use pem::PemError;
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
    Pem(#[from] PemError),

    //
    // String
    //
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),

    //
    // Exe
    //
    #[error(transparent)]
    NotInPath(#[from] which::Error),
    #[error("{}", .0)]
    ExecFailure(String),

    //
    // Key
    //
    #[error("Invalid Key Type")]
    KeyInvalidType,

    //
    //
    //
    #[error("Verification Failure")]
    VerificationFailure,

    //
    // Base64
    //
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
    //
    // ssh
    //
    #[error("invalid message id {}", .0)]
    SShInvalidMessageId(u8),
    #[error("unable to connect to ssh-agent")]
    SshAgentNotRunning,
    #[error("ssh-agent identity not found for")]
    SshIdentityNotFound,
}
