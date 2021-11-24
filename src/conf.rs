use anyhow::{Error, Result};
use directories::BaseDirs;
use std::path::PathBuf;

#[derive(Clone)]
pub struct WateorConfig {
    pub data_dir: PathBuf,
    pub config_file: PathBuf,
}

impl WateorConfig {
    pub fn from_config() -> Self {
        Self {
            data_dir: storage_location().unwrap(),
            config_file: PathBuf::new(),
        }
    }
}

fn storage_location() -> Result<PathBuf> {
    let bd = BaseDirs::new().ok_or_else(|| Error::msg("Couldn't init base dirs"))?;
    let mut data_dir = PathBuf::from(bd.data_local_dir());
    data_dir.push("wateor");
    Ok(data_dir)
}
