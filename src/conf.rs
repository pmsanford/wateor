use anyhow::{Error, Result};
use config::{Config, Environment, File};
use directories::BaseDirs;
use std::path::PathBuf;

#[derive(Clone)]
pub struct WateorConfig {
    pub data_dir: PathBuf,
    pub config_file: PathBuf,
    pub max_file_size_bytes: u64,
    pub remove_on_restore: bool,
}

fn get_default_config_path() -> Result<PathBuf> {
    let bd = BaseDirs::new().ok_or_else(|| Error::msg("Couldn't init base dirs"))?;
    let mut config_dir = PathBuf::from(bd.config_dir());
    config_dir.push("wateor");
    config_dir.push("config.yaml");
    Ok(config_dir)
}

fn get_default_data_dir() -> Result<PathBuf> {
    let bd = BaseDirs::new().ok_or_else(|| Error::msg("Couldn't init base dirs"))?;
    let mut data_dir = PathBuf::from(bd.data_local_dir());
    data_dir.push("wateor");

    Ok(data_dir)
}

impl WateorConfig {
    pub fn read_config() -> Result<Self> {
        let config_path = get_default_config_path()?;
        WateorConfig::read_config_from(config_path)
    }

    pub fn read_config_from(config_path: PathBuf) -> Result<Self> {
        let mut settings = Config::default();
        settings
            .merge(File::from(config_path.clone()).required(false))?
            .merge(Environment::with_prefix("WATEOR"))?;

        let data_dir: PathBuf = if let Ok(data_dir) = settings.get("data_dir") {
            data_dir
        } else {
            get_default_data_dir()?
        };

        let max_file_size_bytes = settings.get("max_file_size_bytes").unwrap_or(1_048_576_u64);

        let remove_on_restore = settings.get("remove_on_restore").unwrap_or(false);

        Ok(Self {
            data_dir,
            config_file: config_path,
            max_file_size_bytes,
            remove_on_restore,
        })
    }
}
