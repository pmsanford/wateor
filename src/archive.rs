use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error, Result};
use bincode::{config, encode_to_vec};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression};
use chrono::{DateTime, Local, Utc};
use git2::{Repository, Status};
use tar::{Archive, Builder};

use crate::{
    conf::WateorConfig,
    data::{input_to_index, print_crate_description},
    prompt,
};
use crate::{
    data::{Crate, WateorDb},
    encryption::Crypto,
};

pub struct Archiver {
    crypto: Crypto,
    db: WateorDb,
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

        let db = WateorDb::from_config(config)?;

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
        let time = Utc::now().timestamp();

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
            &self.repo_path,
            archive.file_list.clone(),
            encrypted.encrypted_key,
            encrypted.iv,
        )?;

        self.db
            .db
            .insert(time.to_be_bytes(), encode_to_vec(cr, config::standard())?)?;

        for file in archive.file_list.iter().map(|p| self.repo_path.join(p)) {
            std::fs::remove_file(&file)
                .with_context(|| format!("Failed to remove file at {}", file.to_string_lossy()))?;
        }

        Ok(())
    }

    fn iter_repo_crates(&self) -> impl Iterator<Item = Crate> + '_ {
        self.db
            .iter_crates()
            .filter(|cr| cr.repo_path == self.repo_path)
    }

    pub fn list(&self) {
        for (idx, cr) in self.iter_repo_crates().enumerate() {
            print_crate_description(cr, idx + 1);
        }
    }

    fn get_crate_description(&self, index: Option<usize>) -> Result<Crate> {
        let index = input_to_index(index);
        self.iter_repo_crates()
            .nth(index)
            .ok_or_else(|| Error::msg(format!("Archive {} not found", index)))
    }

    pub fn remove(&self, index: Option<usize>) -> Result<()> {
        let cr = self.get_crate_description(index)?;
        self.db.delete(cr)?;
        Ok(())
    }

    pub fn restore(&self, index: Option<usize>) -> Result<RestoreResult> {
        let cr = self.get_crate_description(index)?;
        let mut result = RestoreResult::Full;

        let pass = prompt("Passcode for key: ")?;
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
                result = RestoreResult::Partial;
                continue;
            }
            println!("Unpacking {:#?}", path);
            entry
                .unpack_in(&self.repo_path)
                .context("Couldn't unpack entry from archive")?;
        }

        Ok(result)
    }
}

#[derive(PartialEq)]
pub enum RestoreResult {
    Full,
    Partial,
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
