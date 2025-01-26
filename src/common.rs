use std::{fmt::Display, fs, path::Path};

use serde::Serializer;

pub const DEFAULT_SIGN_FILE_NAME: &str = "dver.sig";

pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    if bytes as f64 >= TB {
        format!("{:.2} TB", bytes as f64 / TB)
    } else if bytes as f64 >= GB {
        format!("{:.2} GB", bytes as f64 / GB)
    } else if bytes as f64 >= MB {
        format!("{:.2} MB", bytes as f64 / MB)
    } else if bytes as f64 >= KB {
        format!("{:.2} KB", bytes as f64 / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

pub fn fmt_len(size: usize) -> String {
    format_size(size as u64)
}

pub fn file_size_to_str<P: AsRef<Path>>(file_path: P) -> crate::error::Result<String> {
    let stat = fs::metadata(file_path)?;

    //Ok(format_size(stat.size()))
    Ok(format_size(stat.len()))
}

pub fn printkv<D: Display>(k: &str, v: D) {
    let k = format!("{k}:");
    println!("    {k:<20}{v}");
}

pub fn vec_hex_serializer<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}
