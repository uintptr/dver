use std::{
    env,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{info, LevelFilter, Metadata, Record};

use crate::Error;

//const CUR_CRATE_NAME: &str = env!("CARGO_PKG_NAME");

fn now_f64() -> Result<f64, Error> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(since.as_secs_f64())
}

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Info // && metadata.target().starts_with(CUR_CRATE_NAME)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let ts = match now_f64() {
                Ok(v) => v,
                Err(_) => return,
            };

            let file_path = record.file().unwrap_or("");

            let file_name = match Path::new(file_path).file_name() {
                Some(v) => v.to_str().unwrap_or(""),
                None => "",
            };

            let line = record.line().unwrap_or_default();

            let file_meta = format!("{file_name}:{line}");

            println!(
                "{ts:<18} :: {:<5} :: {:32} :: {file_meta:<25} :: {}",
                record.level(),
                record.metadata().target(),
                record.args(),
            );
        }
    }

    fn flush(&self) {}
}

fn get_log_level_from_env() -> Result<LevelFilter, Error> {
    let level = match env::var("LC_LOG_LEVEL") {
        Ok(v) => match v.as_str() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "debug" => LevelFilter::Debug,
            "error" => LevelFilter::Error,
            _ => return Err(Error::InvalidArgument("invalid LC_LOG_LEVEL value".into())),
        },
        Err(_) => LevelFilter::Debug,
    };

    Ok(level)
}

static LOGGER: SimpleLogger = SimpleLogger;

pub fn init_logging() -> Result<(), Error> {
    if log::set_logger(&LOGGER).is_err() {
        return Err(Error::LoggingInitFailure);
    }

    let debug_build = cfg!(debug_assertions);

    let log_level = match debug_build {
        true => get_log_level_from_env()?,
        false => LevelFilter::Warn,
    };

    log::set_max_level(log_level);
    info!("log level: {:?}", log_level);
    Ok(())
}
