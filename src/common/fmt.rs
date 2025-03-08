use std::{fmt::Display, fs, os::linux::fs::MetadataExt, path::Path};

pub fn fmt_size(bytes: u64) -> String {
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
    fmt_size(size as u64)
}

pub fn fmt_file_size<P: AsRef<Path>>(file_path: P) -> String {
    let file_size = match fs::metadata(file_path) {
        Ok(stat) => stat.st_size(),
        Err(_) => 0,
    };

    fmt_size(file_size)
}

pub fn printkv<D: Display>(k: &str, v: D) {
    let k = format!("{k}:");
    println!("    {k:<20}{v}");
}
