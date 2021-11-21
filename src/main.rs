use std::{fs::File, io::Write, path::PathBuf};

use anyhow::{Result, bail};
use bzip2::{Compression, write::BzEncoder};
use chrono::{DateTime, Local};
use directories::BaseDirs;
use git2::{Repository, Status};
use tar::Builder;

fn main() -> Result<()> {
    let bd = BaseDirs::new().unwrap();
    let mut data_dir = PathBuf::from(bd.data_local_dir());
    data_dir.push("hateor");
    std::fs::create_dir_all(&data_dir)?;
    let repo = Repository::discover(".")?;
    let basepath = repo.workdir();

    if basepath.is_none() {
        bail!("Missing a work dir path. Is this a bare repo?");
    }

    let basepath = basepath.unwrap();

    let statuses = repo.statuses(None)?;
    
    let new: Vec<_> = statuses.iter().filter(|s| s.status() == Status::WT_NEW && s.path().is_some()).collect();

    let mut tar_back: Vec<u8> = Vec::new();

    {
        let mut tar = Builder::new(&mut tar_back);

        for file in new.iter() {
            let mut fullpath = PathBuf::from(basepath);
            fullpath.push(file.path().unwrap());
            tar.append_path_with_name(fullpath, file.path().unwrap())?;
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

    for file in new.iter() {
        std::fs::remove_file(file.path().unwrap())?;
    }

    Ok(())
}
