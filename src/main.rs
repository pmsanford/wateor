use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Error, Result};
use bincode::{config::Configuration, decode_from_slice, encode_to_vec, Decode, Encode};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression};
use chrono::{DateTime, Local, TimeZone};
use directories::BaseDirs;
use git2::{Repository, Status};
use openssl::{
    pkey::{Private, Public},
    rsa::{Padding, Rsa},
    symm::{decrypt, encrypt, Cipher},
};
use rand::Rng;
use sled::{Db, IVec};
use tar::{Archive, Builder};

static PRIV_KEY_NAME: &str = "key.pem";
static PUB_KEY_NAME: &str = "pub.pem";
static DB_FOLDER_NAME: &str = "wateor.db";

struct Repo {
    repo: Repository,
    path: PathBuf,
}

impl Repo {
    fn dirty_files(&self) -> Result<Vec<PathBuf>> {
        Ok(self
            .repo
            .statuses(None)?
            .iter()
            .filter_map(|s| match (s.status(), s.path()) {
                (Status::CURRENT, _) => None,
                (_, Some(p)) => Some(PathBuf::from(p)),
                _ => None,
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

fn decode_crate(db_item: &(IVec, IVec)) -> Result<Crate> {
    Ok(decode_from_slice(&db_item.1, Configuration::standard())?)
}

fn check_init() -> Result<bool> {
    let data_dir = storage_location()?;
    Ok(data_dir.join(DB_FOLDER_NAME).exists())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!("Need a command");
    }
    if args[1] == "init" {
        init()?;
    } else {
        if !check_init()? {
            bail!("Need to run init first");
        }
        match args[1].as_str() {
            "store" => store(),
            "restore" => restore(),
            "list" => list(),
            "clean" => {
                let db = open_db()?;
                for archive in db.iter().map(|r| r.map(|i| decode_crate(&i))) {
                    let archive = archive??;
                    std::fs::remove_file(&archive.archive_path)?;
                }
                let data_dir = storage_location()?;
                std::fs::remove_dir_all(data_dir.join(DB_FOLDER_NAME))?;
                std::fs::remove_file(data_dir.join("key.pem"))?;
                std::fs::remove_file(data_dir.join("pub.pem"))?;
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
        let dt = Local.timestamp(cr.timestamp as i64, 0);
        println!("{}:", dt);
        println!("\t{} ({})", cr.branch, cr.commit_id);
        for file in cr.file_list {
            println!("\t{}", file);
        }
    }

    Ok(())
}

fn decrypt_archive(priv_key: &Rsa<Private>, cr: &Crate) -> Result<Vec<u8>> {
    let mut decryption_key = vec![0_u8; priv_key.size() as usize];
    priv_key.private_decrypt(&cr.decryption_key, &mut decryption_key, Padding::PKCS1)?;

    let mut file = File::open(&cr.archive_path)?;
    let mut encrypted = Vec::new();
    file.read_to_end(&mut encrypted)?;
    Ok(decrypt(
        Cipher::aes_128_cbc(),
        &decryption_key[..16],
        Some(&cr.iv),
        &encrypted,
    )?)
}

fn restore() -> Result<()> {
    let repo = find_repo()?;
    let db = open_db()?;
    let latest = db.last()?.ok_or_else(|| Error::msg("No archives found"))?;
    let pass = prompt("Passcode for key: ")?;
    let priv_key = get_priv_key(&pass)?;

    let cr: Crate = decode_from_slice(&latest.1, Configuration::standard())?;

    let unencrypted = decrypt_archive(&priv_key, &cr)?;

    let decoder = BzDecoder::new(&*unencrypted);
    let mut tar = Archive::new(decoder);

    let non_current = repo.dirty_files()?;

    println!("Restoring to {:#?}", repo.path);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if non_current.iter().any(|p| p == &*path) {
            println!("{:#?} already in repo and dirty, skipping restore", path);
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
    timestamp: u64,
    archive_path: PathBuf,
    repo_path: PathBuf,
    branch: String,
    commit_id: String,
    file_list: Vec<String>,
    decryption_key: Vec<u8>,
    iv: [u8; 16],
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

struct ArchiveResult {
    archive_data: Vec<u8>,
    file_list: Vec<String>,
}

fn archive_files(base_path: &Path, paths: Vec<String>) -> Result<ArchiveResult> {
    let mut back: Vec<u8> = Vec::new();
    let mut encoder = BzEncoder::new(&mut back, Compression::default());

    let mut stored_files = Vec::new();

    {
        let mut tar = Builder::new(&mut encoder);

        for path in paths {
            let file_path = base_path.join(&path);
            {
                let f = File::open(&file_path)?;
                let size = f.metadata()?.len();
                if size > 1024 * 1024 {
                    println!("File {} is greater than 1mb, skipping", path);
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

struct EncryptResult {
    encrypted_archive_data: Vec<u8>,
    encrypted_key: Vec<u8>,
    iv: [u8; 16],
}

fn encrypt_archive(pub_key: &Rsa<Public>, unencrypted_data: &[u8]) -> Result<EncryptResult> {
    let key = rand::thread_rng().gen::<[u8; 16]>();
    let iv = rand::thread_rng().gen::<[u8; 16]>();

    let encrypted = encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), unencrypted_data)?;

    let mut encrypted_key = vec![0; pub_key.size() as usize];
    pub_key.public_encrypt(&key, &mut encrypted_key, Padding::PKCS1)?;

    Ok(EncryptResult {
        encrypted_archive_data: encrypted,
        encrypted_key,
        iv,
    })
}

fn store() -> Result<()> {
    let data_dir = storage_location()?;
    let repo = find_repo()?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let db = open_db()?;
    let pub_key = get_pub_key()?;

    let new_paths = repo.new_files()?;

    let archive = archive_files(&repo.path, new_paths)?;
    let encrypted = encrypt_archive(&pub_key, &archive.archive_data)?;

    let dt: DateTime<Local> = Local::now();
    let file_name = dt.format("%Y-%m-%dT%H%M%S.tar.bz2").to_string();
    let save_path = data_dir.join(file_name);
    let mut file = File::create(&save_path)?;

    file.write_all(&encrypted.encrypted_archive_data)?;

    let cr = Crate::new(
        time,
        save_path,
        &repo.repo,
        archive.file_list.clone(),
        encrypted.encrypted_key,
        encrypted.iv,
    )?;

    db.insert(
        time.to_be_bytes(),
        encode_to_vec(cr, Configuration::standard())?,
    )?;

    for file in &archive.file_list {
        std::fs::remove_file(file)?;
    }

    Ok(())
}
