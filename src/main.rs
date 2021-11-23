use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{bail, Error, Result};
use bincode::{config::Configuration, decode_from_slice, encode_to_vec, Decode, Encode};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression};
use chrono::{DateTime, Local, NaiveDateTime};
use directories::BaseDirs;
use git2::{Repository, Status};
use openssl::{
    pkey::{Private, Public},
    rsa::{Padding, Rsa},
    symm::{decrypt, encrypt, Cipher},
};
use rand::Rng;
use sled::Db;
use tar::{Archive, Builder};

static PRIV_KEY_NAME: &str = "key.pem";
static PUB_KEY_NAME: &str = "pub.pem";
static DB_FOLDER_NAME: &str = "wateor.db";

struct Repo {
    repo: Repository,
    path: PathBuf,
}

fn storage_location() -> Result<PathBuf> {
    let bd = BaseDirs::new().ok_or_else(|| Error::msg("Couldn't init base dirs"))?;
    let mut data_dir = PathBuf::from(bd.data_local_dir());
    data_dir.push("wateor");
    std::fs::create_dir_all(&data_dir)?;
    Ok(data_dir)
}

fn open_db() -> Result<Db> {
    let data_dir = storage_location()?;
    Ok(sled::open(data_dir.join(DB_FOLDER_NAME))?)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!("Need a command");
    }
    if args[1] == "store" {
        store()?;
    }
    if args[1] == "restore" {
        restore()?;
    }
    if args[1] == "list" {
        list()?;
    }
    if args[1] == "init" {
        init()?;
    }
    if args[1] == "reinit" {
        let data_dir = storage_location()?;
        let _ = std::fs::remove_dir_all(data_dir.join(DB_FOLDER_NAME));
        let _ = std::fs::remove_file(data_dir.join("key.pem"));
        let _ = std::fs::remove_file(data_dir.join("pub.pem"));
        for entry in walkdir::WalkDir::new(&data_dir).max_depth(1) {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|ext| ext == "bz2") == Some(true) {
                std::fs::remove_file(path)?;
            }
        }
        init()?;
    }

    Ok(())
}

fn prompt(prompt: &str) -> Result<String> {
    Ok(rpassword::read_password_from_tty(Some(prompt))?)
}

fn init() -> Result<()> {
    let _db = open_db()?;
    println!("Initialized db");
    let rsa = Rsa::generate(2048)?;
    let pass = prompt("Passcode for key: ")?;
    let confirm = prompt("Confirm password: ")?;
    if pass != confirm {
        bail!("Passwords don't match");
    }
    let private_key: Vec<u8> =
        rsa.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), pass.as_bytes())?;
    let data_dir = storage_location()?;
    let key_path = data_dir.join(PRIV_KEY_NAME);
    let mut pkey = File::create(&key_path)?;
    let public_key = rsa.public_key_to_pem()?;
    pkey.write_all(&private_key)?;
    println!("Created private key at {:#?}", key_path);
    let pub_path = data_dir.join(PUB_KEY_NAME);
    let mut public = File::create(&pub_path)?;
    public.write_all(&public_key)?;
    println!("Created public key at {:#?}", pub_path);

    Ok(())
}

fn list() -> Result<()> {
    let db = open_db()?;

    for bccr in db.iter() {
        let cr: Crate = decode_from_slice(&bccr?.1, Configuration::standard())?;
        let ndt = NaiveDateTime::from_timestamp(cr.date as i64, 0);
        println!("{}:", ndt);
        for file in cr.file_list {
            println!("\t{}", file);
        }
    }

    Ok(())
}

fn restore() -> Result<()> {
    let repo = find_repo()?;
    let db = open_db()?;
    let latest = db.last()?.ok_or_else(|| Error::msg("No archives found"))?;
    let pass = prompt("Passcode for key: ")?;
    let priv_key = get_priv_key(&pass)?;

    let cr: Crate = decode_from_slice(&latest.1, Configuration::standard())?;

    let mut decryption_key = vec![0_u8; priv_key.size() as usize];
    println!("Decryption key size: {}", decryption_key.len());
    priv_key.private_decrypt(&cr.decryption_key, &mut decryption_key, Padding::PKCS1)?;

    let mut file = File::open(cr.archive_path)?;
    let mut encrypted = Vec::new();
    file.read_to_end(&mut encrypted)?;
    let unencrypted = decrypt(
        Cipher::aes_128_cbc(),
        &decryption_key[..16],
        Some(&cr.iv),
        &encrypted,
    )?;
    let decoder = BzDecoder::new(&*unencrypted);
    let mut tar = Archive::new(decoder);

    let statuses = repo.repo.statuses(None)?;
    let mut non_current = statuses
        .iter()
        .filter(|s| s.status() != Status::CURRENT && s.path().is_some())
        .map(|s| PathBuf::from(s.path().expect("We just filtered for this!")));

    println!("Restoring to {:#?}", repo.path);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if non_current.any(|p| p == path) {
            println!("{:#?} already in repo and dirty", path);
            continue;
        }
        println!("Unpacking {:#?}", path);
        entry.unpack_in(&repo.path)?;
    }

    Ok(())
}

fn find_repo() -> Result<Repo> {
    let repo = Repository::discover(".")?;
    let basepath = repo
        .workdir()
        .ok_or_else(|| Error::msg("Missing a work dir path. Is this a bare repo?"))?;

    let path = PathBuf::from(basepath);

    Ok(Repo { repo, path })
}

#[derive(Encode, Decode)]
struct Crate {
    date: u64,
    archive_path: PathBuf,
    file_list: Vec<String>,
    decryption_key: Vec<u8>,
    iv: [u8; 16],
}

fn get_priv_key(pass: &str) -> Result<Rsa<Private>> {
    let key_path = storage_location()?.join(PRIV_KEY_NAME);
    let mut key_cont = Vec::new();
    File::open(key_path)?.read_to_end(&mut key_cont)?;
    Ok(Rsa::private_key_from_pem_passphrase(
        &key_cont,
        pass.as_bytes(),
    )?)
}

fn get_pub_key() -> Result<Rsa<Public>> {
    let key_path = storage_location()?.join(PUB_KEY_NAME);
    let mut key_cont = Vec::new();
    File::open(key_path)?.read_to_end(&mut key_cont)?;
    Ok(Rsa::public_key_from_pem(&key_cont)?)
}

fn store() -> Result<()> {
    let data_dir = storage_location()?;
    let repo = find_repo()?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let db = open_db()?;
    let pub_key = get_pub_key()?;

    let statuses = repo.repo.statuses(None)?;

    let new = statuses
        .iter()
        .filter(|s| s.status() == Status::WT_NEW && s.path().is_some());

    let mut back: Vec<u8> = Vec::new();
    let mut encoder = BzEncoder::new(&mut back, Compression::fast());

    let mut stored_files = Vec::new();

    {
        let mut tar = Builder::new(&mut encoder);

        for file in new {
            let mut fullpath = repo.path.clone();
            let file_path = file.path().expect("We filtered for this");
            fullpath.push(file_path);
            {
                let f = File::open(&fullpath)?;
                let size = f.metadata()?.len();
                if size > 1024 * 1024 {
                    println!("File {} is greater than 1mb, skipping", file_path);
                    continue;
                }
            }
            tar.append_path_with_name(fullpath, file_path)?;
            stored_files.push(file);
        }

        tar.finish()?;
    }

    encoder.finish()?;

    let dt: DateTime<Local> = Local::now();
    let fname = dt.format("%Y-%m-%dT%H%M%S.tar.bz2").to_string();
    let mut savepath = data_dir;
    savepath.push(fname);

    let key = rand::thread_rng().gen::<[u8; 16]>();
    let iv = rand::thread_rng().gen::<[u8; 16]>();

    let mut file = File::create(savepath.clone())?;
    println!("Encrypting archive");
    let encrypted = encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), &back)?;

    file.write_all(&encrypted)?;

    for file in &stored_files {
        std::fs::remove_file(file.path().expect("We filtered for this"))?;
    }

    println!("Encrypting key");
    let mut encrypted_key = vec![0; pub_key.size() as usize];
    pub_key.public_encrypt(&key, &mut encrypted_key, Padding::PKCS1)?;
    println!("Encrypted size: {}", encrypted_key.len());

    let cr = Crate {
        date: time,
        archive_path: savepath,
        file_list: stored_files
            .into_iter()
            .map(|f| f.path().expect("We filtered for this").to_string())
            .collect(),
        decryption_key: encrypted_key,
        iv,
    };

    db.insert(
        time.to_be_bytes(),
        encode_to_vec(cr, Configuration::standard())?,
    )?;

    Ok(())
}
