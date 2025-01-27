use base64::{prelude::BASE64_STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serializer};

pub fn hex_serializer<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

pub fn base64_serializer<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
}

pub fn base64_deserializer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    match BASE64_STANDARD.decode(s) {
        Ok(v) => Ok(v),
        Err(e) => Err(serde::de::Error::custom(e)),
    }
}
