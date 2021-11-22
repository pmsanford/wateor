use std::{env, fs::File, io::Write, path::PathBuf};

use anyhow::{bail, Result};
use bincode::{config::Configuration, decode_from_slice, encode_to_vec, Decode, Encode};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression};
use chrono::{DateTime, Local, NaiveDateTime};
use directories::BaseDirs;
use git2::{Repository, Status};
use sled::Db;
use tar::{Archive, Builder};

struct Repo {
    repo: Repository,
    path: PathBuf,
}

fn storage_location() -> Result<PathBuf> {
    let bd = BaseDirs::new().unwrap();
    let mut data_dir = PathBuf::from(bd.data_local_dir());
    data_dir.push("wateor");
    std::fs::create_dir_all(&data_dir)?;
    Ok(data_dir)
}

fn open_db() -> Result<Db> {
    let data_dir = storage_location()?;
    Ok(sled::open(data_dir.join("wateor.db"))?)
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
    let latest = db.last()?;

    if latest.is_none() {
        bail!("No archives found");
    }
    let latest = latest.unwrap();
    let cr: Crate = decode_from_slice(&latest.1, Configuration::standard())?;

    let file = File::open(cr.archive_path)?;
    let decoder = BzDecoder::new(file);
    let mut tar = Archive::new(decoder);

    let non_current: Vec<_> = repo
        .repo
        .statuses(None)?
        .iter()
        .filter(|s| s.status() != Status::CURRENT && s.path().is_some())
        .map(|s| PathBuf::from(s.path().unwrap()))
        .collect();

    println!("Restoring to {:#?}", repo.path);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if non_current.contains(&PathBuf::from(&*path)) {
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
    let basepath = repo.workdir();

    if basepath.is_none() {
        bail!("Missing a work dir path. Is this a bare repo?");
    }

    let path = PathBuf::from(basepath.unwrap());

    Ok(Repo { repo, path })
}

#[derive(Encode, Decode)]
struct Crate {
    date: u64,
    archive_path: PathBuf,
    file_list: Vec<String>,
}

fn store() -> Result<()> {
    let data_dir = storage_location()?;
    let repo = find_repo()?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let db = open_db()?;

    let statuses = repo.repo.statuses(None)?;

    let new: Vec<_> = statuses
        .iter()
        .filter(|s| s.status() == Status::WT_NEW && s.path().is_some())
        .collect();

    let mut back: Vec<u8> = Vec::new();
    let mut encoder = BzEncoder::new(&mut back, Compression::fast());

    let mut stored_files = Vec::new();

    {
        let mut tar = Builder::new(&mut encoder);

        for file in new.into_iter() {
            let mut fullpath = repo.path.clone();
            fullpath.push(file.path().unwrap());
            {
                let f = File::open(&fullpath)?;
                let size = f.metadata()?.len();
                if size > 1024 * 1024 {
                    println!(
                        "File {} is greater than 1mb, skipping",
                        file.path().unwrap()
                    );
                    continue;
                }
            }
            tar.append_path_with_name(fullpath, file.path().unwrap())?;
            stored_files.push(file);
        }

        tar.finish()?;
    }

    encoder.finish()?;

    let dt: DateTime<Local> = Local::now();
    let fname = dt.format("%Y-%m-%dT%H%M%S.tar.bz2").to_string();
    let mut savepath = data_dir.clone();
    savepath.push(fname);

    let mut file = File::create(savepath.clone())?;

    file.write_all(&back)?;

    for file in stored_files.iter() {
        std::fs::remove_file(file.path().unwrap())?;
    }

    let cr = Crate {
        date: time,
        archive_path: PathBuf::from(savepath),
        file_list: stored_files
            .into_iter()
            .map(|f| f.path().unwrap().to_string())
            .collect(),
    };

    db.insert(
        time.to_be_bytes(),
        encode_to_vec(cr, Configuration::standard())?,
    )?;

    Ok(())
}
