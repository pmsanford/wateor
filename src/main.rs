use std::path::PathBuf;

mod archive;
mod conf;
mod data;
mod encryption;

use anyhow::{bail, Context, Result};
use archive::{Archiver, RestoreResult};
use clap::Parser;
use conf::WateorConfig;

use crate::data::{check_init, cleanup, decrypt, destroy, init, WateorDb};

/// Clean up files strewn about your git repo quickly and securely, with
/// the option to restore them later or consign them to an (encrypted)
/// black hole.
#[derive(Parser, Debug)]
#[clap(version = "0.1", author = "Paul Sanford <me@paulsanford.net>")]
struct Opts {
    /// Path to the config file for the application. If not specified, looks
    /// in an OS-dependent default config directory.
    #[clap(short, long)]
    config_file: Option<PathBuf>,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, PartialEq, Debug)]
enum Command {
    /// Create the database and encryption keys used by wateor.
    Init,
    /// Gather, compress, and encrypt all untracked files in the repo.
    #[clap(alias = "s")]
    Store,
    /// Decrypt an archive and restore its contents to their original locations
    /// in the repo.
    Restore(Restore),
    /// Decrypt a single archive without extracting it.
    Decrypt(Decrypt),
    /// List archives managed by wateor.
    #[clap(alias = "ls")]
    List(List),
    /// Remove a specific archive managed by wateor without restoring.
    #[clap(alias = "rm")]
    Remove(Remove),
    /// Remove archives older than a certain number of days.
    Cleanup(Cleanup),
    /// Serialize current config to yaml. This will be the combination of
    /// values specified in an existing config file, if any, and defaults for
    /// options not specified in the config file.
    Config,
    /// Delete all data managed by wateor.
    Destroy,
}

#[derive(Parser, PartialEq, Debug)]
struct List {
    #[clap(short, long)]
    all: bool,
}

#[derive(Parser, PartialEq, Debug)]
struct Decrypt {
    /// The index of the archive to decrypt. If not specified, the most recent
    /// archive is removed. Note that these indicies are not repo-specific, so
    /// you'll need to use list --all to find the index.
    index: Option<usize>,
    /// Directory to store the decrypted archive. If not specified, uses the
    /// current working directory.
    destination: Option<PathBuf>,
}

#[derive(Parser, PartialEq, Debug)]
struct Cleanup {
    /// Delete archives older than this number of days.
    older_than: Option<i64>,
}

#[derive(Parser, PartialEq, Debug)]
struct Remove {
    /// The index of the archive to remove. If not specified, the most recent
    /// archive is removed. Find the index with the list command.
    index: Option<usize>,
}

#[derive(Parser, PartialEq, Debug)]
struct Restore {
    /// The index of the archive to restore. If not specified, the most recent
    /// archive is restored. Find the index with the list command.
    index: Option<usize>,
    /// Remove the archive after restoration.
    #[clap(long, default_missing_value = "true")]
    rm: Option<bool>,
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
        Command::Restore(restore) => {
            let archiver = Archiver::from_config(&config)?;
            let result = archiver.restore(restore.index)?;
            if restore.rm.unwrap_or(config.remove_on_restore) {
                if result == RestoreResult::Full {
                    archiver.remove(restore.index)?;
                } else {
                    eprintln!("Some files could not be restored; archive not deleted");
                }
            }
        }
        Command::Decrypt(d) => decrypt(&config, d.index, d.destination)?,
        Command::Remove(remove) => Archiver::from_config(&config)?.remove(remove.index)?,
        Command::List(list) if list.all => WateorDb::from_config(&config)?.list_all(),
        Command::List(_) => Archiver::from_config(&config)?.list(),
        Command::Cleanup(c) => cleanup(&config, c.older_than)?,
        Command::Config => println!("{}", serde_yaml::to_string(&config)?),
        Command::Destroy => destroy(&config)?,
    }

    Ok(())
}

fn prompt(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}
