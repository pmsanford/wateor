use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error, Result};
use bincode::{config::Configuration, decode_from_slice, encode_to_vec, Decode, Encode};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression};
use chrono::{DateTime, Local, TimeZone};
use git2::{Repository, Status};
use sled::Db;
use tar::{Archive, Builder};

use crate::encryption::Crypto;
use crate::{conf::WateorConfig, prompt};

pub static DB_FOLDER_NAME: &str = "wateor.db";

pub struct Archiver {
    crypto: Crypto,
    db: Db,
    repo: Repository,
    repo_path: PathBuf,
    config: WateorConfig,
}

impl Archiver {
    pub fn from_config(config: &WateorConfig) -> Result<Self> {
        let repo = Repository::discover(".")
            .context("Couldn't find a git repo from the current directory")?;
        let basepath = repo
            .workdir()
            .ok_or_else(|| Error::msg("Missing a work dir path. Is this a bare repo?"))?;

        let repo_path = PathBuf::from(basepath);

        let db =
            sled::open(config.data_dir.join(DB_FOLDER_NAME)).context("Couldn't open wateor db")?;

        let crypto = Crypto::from_config(config)?;

        Ok(Self {
            crypto,
            db,
            repo,
            repo_path,
            config: config.clone(),
        })
    }

    fn dirty_files(&self) -> Result<Vec<PathBuf>> {
        Ok(self
            .repo
            .statuses(None)?
            .iter()
            .filter_map(|s| match (s.status(), s.path()) {
                (Status::CURRENT, _) | (_, None) => None,
                (_, Some(p)) => Some(PathBuf::from(p)),
            })
            .collect())
    }
    fn new_files(&self) -> Result<Vec<String>> {
        Ok(self
            .repo
            .statuses(None)?
            .iter()
            .filter_map(|s| match (s.status(), s.path()) {
                (Status::WT_NEW, Some(p)) => Some(p.to_string()),
                _ => None,
            })
            .collect())
    }

    pub fn store(&self) -> Result<()> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let new_paths = self.new_files()?;

        let archive = archive_files(&self.repo_path, new_paths, self.config.max_file_size_bytes)?;
        let encrypted = self.crypto.encrypt_archive(&archive.archive_data)?;

        let dt: DateTime<Local> = Local::now();
        let file_name = dt.format("%Y-%m-%dT%H%M%S.tar.bz2").to_string();
        let save_path = self.config.data_dir.join(file_name);
        let mut file = File::create(&save_path).with_context(|| {
            format!(
                "Failed to create archive file at {}",
                save_path.to_string_lossy()
            )
        })?;

        file.write_all(&encrypted.encrypted_archive_data)?;

        let cr = Crate::new(
            time,
            save_path,
            &self.repo,
            archive.file_list.clone(),
            encrypted.encrypted_key,
            encrypted.iv,
        )?;

        self.db.insert(
            time.to_be_bytes(),
            encode_to_vec(cr, Configuration::standard())?,
        )?;

        for file in &archive.file_list {
            std::fs::remove_file(file)
                .with_context(|| format!("Failed to remove file at {}", file))?;
        }

        Ok(())
    }

    pub fn list(&self) -> Result<()> {
        for (idx, bccr) in self.db.iter().rev().enumerate() {
            let cr: Crate = decode_from_slice(&bccr?.1, Configuration::standard())
                .context("Failed to decode crate definition")?;
            let dt = Local.timestamp(cr.timestamp as i64, 0);
            println!("{}. Date: {}", idx + 1, dt);
            println!("   Branch: {} (commit id {})", cr.branch, cr.commit_id);
            println!("   Files:");
            for file in cr.file_list {
                println!("     {}", file);
            }
        }

        Ok(())
    }

    pub fn restore(&self, index: Option<usize>) -> Result<()> {
        let index = index.unwrap_or(1) - 1;
        let latest = self
            .db
            .iter()
            .rev()
            .nth(index)
            .ok_or_else(|| Error::msg(format!("Archive {} not found", index)))??;
        let pass = prompt("Passcode for key: ")?;

        let cr: Crate = decode_from_slice(&latest.1, Configuration::standard())
            .context("Failed to decode crate")?;

        let unencrypted =
            self.crypto
                .decrypt_archive(&pass, &cr.decryption_key, &cr.iv, &cr.archive_path)?;

        let decoder = BzDecoder::new(&*unencrypted);
        let mut tar = Archive::new(decoder);

        let non_current = self.dirty_files()?;

        println!("Restoring to {:#?}", self.repo_path);
        for entry in tar
            .entries()
            .context("Failed to read entries from archive")?
        {
            let mut entry = entry?;
            let path = entry.path()?;
            if non_current.iter().any(|p| p == &*path) {
                println!("{:#?} already in repo and dirty, skipping restore", path);
                continue;
            }
            println!("Unpacking {:#?}", path);
            entry
                .unpack_in(&self.repo_path)
                .context("Couldn't unpack entry from archive")?;
        }

        Ok(())
    }
}

#[derive(Encode, Decode)]
pub struct Crate {
    pub timestamp: u64,
    pub archive_path: PathBuf,
    pub repo_path: PathBuf,
    pub branch: String,
    pub commit_id: String,
    pub file_list: Vec<String>,
    pub decryption_key: Vec<u8>,
    pub iv: [u8; 16],
}

impl Crate {
    fn new(
        timestamp: u64,
        archive_path: PathBuf,
        repo: &Repository,
        file_list: Vec<String>,
        decryption_key: Vec<u8>,
        iv: [u8; 16],
    ) -> Result<Self> {
        let head = repo.head()?;
        let commit = head.peel_to_commit()?;

        Ok(Crate {
            timestamp,
            archive_path,
            repo_path: PathBuf::from(repo.path()),
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

struct ArchiveResult {
    archive_data: Vec<u8>,
    file_list: Vec<String>,
}

fn archive_files(
    base_path: &Path,
    paths: Vec<String>,
    max_file_size_bytes: u64,
) -> Result<ArchiveResult> {
    let mut back: Vec<u8> = Vec::new();
    let mut encoder = BzEncoder::new(&mut back, Compression::default());

    let mut stored_files = Vec::new();

    {
        let mut tar = Builder::new(&mut encoder);

        for path in paths {
            let file_path = base_path.join(&path);
            {
                let f = File::open(&file_path).with_context(|| {
                    format!("Couldn't open file at {}", file_path.to_string_lossy())
                })?;
                let size = f.metadata()?.len();
                if size > max_file_size_bytes {
                    println!(
                        "File {} is greater than {}, skipping",
                        path,
                        size_display::Size(max_file_size_bytes)
                    );
                    continue;
                }
            }
            tar.append_path_with_name(file_path, &path)?;
            stored_files.push(path);
        }

        tar.finish()?;
    }

    encoder.finish()?;

    Ok(ArchiveResult {
        archive_data: back,
        file_list: stored_files,
    })
}
