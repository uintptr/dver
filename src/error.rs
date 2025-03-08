use std::{
    path::StripPrefixError,
    process::{Command, Output},
    str::Utf8Error,
    string::FromUtf8Error,
    time::SystemTimeError,
};

use derive_more::From;
use pem::PemError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    NotFound(String),
    InvalidArgument(String),
    SerializeError,
    InputKeyFormatNotSupported,
    NotImplementedError(String),
    InvalidRootDirectory,
    UnknownHashType,
    UnknownSignatureType,
    LoggingInitFailure,
    InvalidPath(String),
    EmptyHash,
    #[from]
    Io(std::io::Error),
    #[from]
    Time(SystemTimeError),
    #[from]
    Rel(StripPrefixError),
    #[from]
    Serde(serde_json::Error),
    #[from]
    LoadKey(ssh_key::Error),
    #[from]
    SshAgentUnknownMessage(String),
    #[from]
    Pem(PemError),

    //
    // String
    //
    #[from]
    Utf8(Utf8Error),
    #[from]
    Utf8Error(FromUtf8Error),

    //
    // Exe
    //
    #[from]
    NotInPath(which::Error),
    ExecFailure {
        command: Command,
        output: Output,
    },

    //
    // Key
    //
    KeyInvalidType,

    //
    //
    //
    VerificationFailure,

    //
    // Base64
    //
    #[from]
    Base64Decode(base64::DecodeError),
    //
    // ssh
    //
    SShInvalidMessageId(u8),
    SshAgentNotRunning,
    SshIdentityNotFound,
}
impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}
