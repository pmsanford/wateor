use std::path::{Path, PathBuf};

use anyhow::{Context, Error, Result};
use bincode::{config::Configuration, decode_from_slice, Decode, Encode};
use git2::Repository;
use sled::Db;

use crate::conf::WateorConfig;

pub static DB_FOLDER_NAME: &str = "wateor.db";

pub struct WateorDb {
    pub db: Db,
}

impl WateorDb {
    pub fn new(config: &WateorConfig) -> Result<Self> {
        let db =
            sled::open(config.data_dir.join(DB_FOLDER_NAME)).context("Couldn't open wateor db")?;

        Ok(Self { db })
    }

    pub fn iter_crates(&self) -> impl Iterator<Item = Crate> {
        self.db
            .iter()
            .rev()
            .map(|def| Ok(decode_from_slice(&def?.1, Configuration::standard())?))
            .filter_map(|crr: Result<Crate>| crr.ok())
    }

    pub fn delete(&self, cr: Crate) -> Result<()> {
        std::fs::remove_file(cr.archive_path)?;
        self.db.remove(cr.timestamp.to_be_bytes())?;

        Ok(())
    }
}

#[derive(Encode, Decode)]
pub struct Crate {
    pub timestamp: i64,
    pub archive_path: PathBuf,
    pub repo_path: PathBuf,
    pub branch: String,
    pub commit_id: String,
    pub file_list: Vec<String>,
    pub decryption_key: Vec<u8>,
    pub iv: [u8; 16],
}

impl Crate {
    pub fn new(
        timestamp: i64,
        archive_path: PathBuf,
        repo: &Repository,
        repo_path: &Path,
        file_list: Vec<String>,
        decryption_key: Vec<u8>,
        iv: [u8; 16],
    ) -> Result<Self> {
        let head = repo.head()?;
        let commit = head.peel_to_commit()?;

        Ok(Crate {
            timestamp,
            archive_path,
            repo_path: PathBuf::from(repo_path),
            branch: head
                .shorthand()
                .ok_or_else(|| Error::msg("Branch has non-utf8 shorthand"))?
                .to_string(),
            commit_id: commit.id().to_string(),
            file_list,
            decryption_key,
            iv,
        })
    }
}
