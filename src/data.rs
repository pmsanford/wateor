use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Error, Result};
use bincode::{config::Configuration, decode_from_slice, Decode, Encode};
use chrono::{Duration, Utc};
use git2::Repository;
use openssl::{rsa::Rsa, symm::Cipher};
use sled::Db;

use crate::{
    conf::WateorConfig,
    encryption::{PRIV_KEY_NAME, PUB_KEY_NAME},
    prompt,
};

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
            .map::<Result<Crate>, _>(|def| {
                Ok(decode_from_slice(&def?.1, Configuration::standard())?)
            })
            .filter_map(std::result::Result::ok)
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

pub fn cleanup(config: &WateorConfig, days: Option<i64>) -> Result<()> {
    let db = WateorDb::new(config)?;
    let days = days.unwrap_or(config.cleanup_older_than_days);
    let ts = (Utc::now() - Duration::days(days as i64)).timestamp();
    let crates_to_delete = db.iter_crates().filter(|cr| cr.timestamp < ts);

    for cr in crates_to_delete {
        db.delete(cr)?;
    }

    Ok(())
}

pub fn check_init(config: &WateorConfig) -> bool {
    config.data_dir.join(DB_FOLDER_NAME).exists()
}

pub fn init(config: &WateorConfig) -> Result<()> {
    std::fs::create_dir_all(&config.data_dir).with_context(|| {
        format!(
            "Failed to create data directory at {}",
            config.data_dir.to_string_lossy()
        )
    })?;
    let _db = WateorDb::new(config)?;
    println!("Initialized db");
    let rsa = Rsa::generate(2048)?;
    let pass = prompt("Passcode for key: ")?;
    let confirm = prompt("Confirm password: ")?;
    if pass != confirm {
        bail!("Passwords don't match");
    }
    let private_key: Vec<u8> =
        rsa.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), pass.as_bytes())?;
    let key_path = config.data_dir.join(PRIV_KEY_NAME);
    let mut pkey = File::create(&key_path)?;
    let public_key = rsa.public_key_to_pem()?;
    pkey.write_all(&private_key)
        .context("Couldn't write private key file")?;
    println!("Created private key at {:#?}", key_path);
    let pub_path = config.data_dir.join(PUB_KEY_NAME);
    let mut public = File::create(&pub_path)?;
    public
        .write_all(&public_key)
        .context("Couldn't write public key file")?;
    println!("Created public key at {:#?}", pub_path);

    Ok(())
}

pub fn destroy(config: &WateorConfig) -> Result<()> {
    let db = WateorDb::new(config)?;
    for archive in db.iter_crates() {
        std::fs::remove_file(&archive.archive_path).with_context(|| {
            format!(
                "Couldn't remove file at {}",
                archive.archive_path.to_string_lossy()
            )
        })?;
    }
    println!(
        "Removing contents of data directory at {}",
        config.data_dir.to_string_lossy()
    );
    std::fs::remove_dir_all(config.data_dir.join(DB_FOLDER_NAME))
        .context("Couldn't remove wateor db folder")?;
    std::fs::remove_file(config.data_dir.join(PRIV_KEY_NAME))
        .context("Couldn't remove private key file")?;
    std::fs::remove_file(config.data_dir.join(PUB_KEY_NAME))
        .context("Couldn't remove public key file")?;
    Ok(())
}
