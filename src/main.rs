use std::{env, fs::File, io::Write};

mod archive;
mod conf;
mod encryption;

use anyhow::{bail, Context, Result};
use archive::{Archiver, Crate, DB_FOLDER_NAME};
use bincode::{config::Configuration, decode_from_slice};
use conf::WateorConfig;
use encryption::{PRIV_KEY_NAME, PUB_KEY_NAME};
use openssl::{rsa::Rsa, symm::Cipher};
use sled::{Db, IVec};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let config = WateorConfig::read_config().context("Couldn't read config file")?;
    if args.len() < 2 {
        bail!("Need a command");
    }
    if args[1] == "init" {
        init(&config)?;
    } else {
        if !check_init(&config) {
            bail!("Need to run init first");
        }
        let archiver = Archiver::from_config(&config)?;
        match args[1].as_str() {
            "store" => archiver.store(),
            "restore" => {
                let index = args.get(2).and_then(|idx| idx.parse::<usize>().ok());
                archiver.restore(index)
            }
            "list" => archiver.list(),
            "clean" => {
                std::mem::drop(archiver);
                let db = open_db(&config).context("Couldn't open database")?;
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
            _ => {
                println!("Try init, store, restore, list, clean");
                Ok(())
            }
        }?;
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
