use std::{env, fs::File, io::Write, path::PathBuf};

use anyhow::{bail, Result};
use bzip2::{read::BzDecoder, write::BzEncoder, Compression};
use chrono::{DateTime, Local};
use directories::BaseDirs;
use git2::{Repository, Status};
use tar::{Archive, Builder};

struct Repo {
    repo: Repository,
    path: PathBuf,
}

fn storage_location() -> Result<PathBuf> {
    let bd = BaseDirs::new().unwrap();
    let mut data_dir = PathBuf::from(bd.data_local_dir());
    data_dir.push("hateor");
    std::fs::create_dir_all(&data_dir)?;
    Ok(data_dir)
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
        if args.len() < 3 {
            bail!("Need a filename");
        }
        restore(args[2].clone())?;
    }

    Ok(())
}

fn restore(file_name: String) -> Result<()> {
    let data_dir = storage_location()?;
    let repo = find_repo()?;

    println!("Restoring from {}", file_name);
    let file = File::open(file_name)?;
    let decoder = BzDecoder::new(file);
    let mut tar = Archive::new(decoder);

    let non_current: Vec<_> = repo
        .repo
        .statuses(None)?
        .iter()
        .filter(|s| s.status() != Status::CURRENT && s.path().is_some())
        .map(|s| PathBuf::from(s.path().unwrap()))
        .collect();

    println!("Tar loaded");

    for entry in tar.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        if non_current.contains(&PathBuf::from(&*path)) {
            println!("{:#?} already in repo and dirty", path);
            continue;
        }
        let mut dest = File::create(path)?;
        dest.write_all(&entry.path_bytes())?;
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

fn store() -> Result<()> {
    let data_dir = storage_location()?;
    let repo = find_repo()?;

    let statuses = repo.repo.statuses(None)?;

    let new: Vec<_> = statuses
        .iter()
        .filter(|s| s.status() == Status::WT_NEW && s.path().is_some())
        .collect();

    let mut tar_back: Vec<u8> = Vec::new();

    let mut stored_files = Vec::new();

    {
        let mut tar = Builder::new(&mut tar_back);

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

    let mut bz2_back: Vec<u8> = Vec::new();

    let mut encoder = BzEncoder::new(&mut bz2_back, Compression::fast());
    encoder.write_all(&tar_back)?;

    encoder.finish()?;

    let dt: DateTime<Local> = Local::now();
    let fname = dt.format("%Y-%m-%dT%H%M%S.tar.bz2").to_string();
    let mut savepath = data_dir.clone();
    savepath.push(fname);

    let mut file = File::create(savepath)?;

    file.write_all(&bz2_back)?;

    for file in stored_files.into_iter() {
        std::fs::remove_file(file.path().unwrap())?;
    }

    Ok(())
}
