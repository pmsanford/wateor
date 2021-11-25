use std::{fs::File, io::Write, path::PathBuf};

mod archive;
mod conf;
mod encryption;

use anyhow::{bail, Context, Result};
use archive::{Archiver, Crate, DB_FOLDER_NAME};
use bincode::{config::Configuration, decode_from_slice};
use clap::Parser;
use conf::WateorConfig;
use encryption::{PRIV_KEY_NAME, PUB_KEY_NAME};
use openssl::{rsa::Rsa, symm::Cipher};
use sled::{Db, IVec};

/// Clean up files strewn about your git repo quickly and securely, with
/// the option to restore them later or consign them to an (encrypted)
/// black hole.
#[derive(Parser)]
#[clap(version = "0.1", author = "Paul Sanford <me@paulsanford.net>")]
struct Opts {
    /// Path to the config file for the application. If not specified, looks
    /// in an OS-dependent default config directory.
    #[clap(short, long)]
    config_file: Option<PathBuf>,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, PartialEq)]
enum Command {
    /// Create the database and encryption keys used by wateor.
    Init,
    /// Gather, compress, and encrypt all untracked files in the repo.
    Store,
    /// Decrypt an archive and restore its contents to their original locations
    /// in the repo.
    Restore(Restore),
    /// List archives managed by wateor.
    List,
    /// Delete all data managed by wateor.
    Destroy,
}

#[derive(Parser, PartialEq)]
struct Restore {
    /// The index of the archive to restore. If not specified, the most recent
    /// archive is restored. Find the index with the list command.
    index: Option<usize>,
}

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();
    let config = WateorConfig::read_config().context("Couldn't read config file")?;
    if opts.command != Command::Init && !check_init(&config) {
        bail!("You must run init first");
    }
    match opts.command {
        Command::Init => init(&config)?,
        Command::Store => Archiver::from_config(&config)?.store()?,
        Command::Restore(restore) => Archiver::from_config(&config)?.restore(restore.index)?,
        Command::List => Archiver::from_config(&config)?.list()?,
        Command::Destroy => destroy(&config)?,
    }

    Ok(())
}

fn open_db(config: &WateorConfig) -> Result<Db> {
    Ok(sled::open(config.data_dir.join(DB_FOLDER_NAME))?)
}

fn decode_crate(db_item: &(IVec, IVec)) -> Result<Crate> {
    Ok(decode_from_slice(&db_item.1, Configuration::standard())?)
}

fn check_init(config: &WateorConfig) -> bool {
    config.data_dir.join(DB_FOLDER_NAME).exists()
}

fn prompt(prompt: &str) -> Result<String> {
    Ok(rpassword::read_password_from_tty(Some(prompt))?)
}

fn init(config: &WateorConfig) -> Result<()> {
    std::fs::create_dir_all(&config.data_dir).with_context(|| {
        format!(
            "Failed to create data directory at {}",
            config.data_dir.to_string_lossy()
        )
    })?;
    let _db = open_db(config)?;
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

fn destroy(config: &WateorConfig) -> Result<()> {
    let db = open_db(config).context("Couldn't open database")?;
    for archive in db.iter().map(|r| r.map(|i| decode_crate(&i))) {
        let archive = archive??;
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
