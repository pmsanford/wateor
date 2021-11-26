# wateor

## What is this?

This command line tool will collect all the untracked files in your repo, create a bzip2-compressed tar file from them, encrypt them with a password-proteceted key, and store them in a specific folder on your computer. You can then easily restore them to their original locations, remove them, or decrypt them with the same tool. You can also run a command to clean up archives older than a certain number of days (perfect for a cronjob). It uses asymmetric cryptography to protect the files, so storing everything is one quick command, but you still need a password to restore or decrypt them.

## Why is this?

I wrote this to solve a problem that may be one only I have: when I need to do some trouleshooting or ops-type stuff I'll open a new terminal (which, in my setup, defaults to the root of whatever repo I'm working in) and start working, spewing log files and temporary yaml configs all over the repo hierarchy. Then, I'll go to lunch, and come back ready to work on some code again, but my working tree is full of garbage.

Sure, there's `git clean -f`, but.. what if there's something in there I need later? OK, so just copy it all to a `maybe_later` directory. But.. what if there's a password or key in there somewhere I don't want to leave rotting in a folder somewhere? I really just want one command to sweep it all into a box I can put on a shelf and forget about - and now I have one.

## Note

This is a tool I developed in a few days to meet a need - I hope it's useful, but it's not a mature tool, so I wouldn't recommend using it to store or protect anything truly sensitive.

## Usage

```
wateor 0.1

Paul Sanford <me@paulsanford.net>

Clean up files strewn about your git repo quickly and securely, with the option to restore them
later or consign them to an (encrypted) black hole

USAGE:
    wateor [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -c, --config-file <CONFIG_FILE>    Path to the config file for the application. If not
                                       specified, looks in an OS-dependent default config directory
    -h, --help                         Print help information
    -V, --version                      Print version information

SUBCOMMANDS:
    cleanup    Remove archives older than a certain number of days
    config     Serialize current config to yaml. This will be the combination of values
               specified in an existing config file, if any, and defaults for options not
               specified in the config file
    destroy    Delete all data managed by wateor
    help       Print this message or the help of the given subcommand(s)
    init       Create the database and encryption keys used by wateor
    list       List archives managed by wateor
    remove     Remove a specific archive managed by wateor without restoring
    restore    Decrypt an archive and restore its contents to their original locations in the
               repo
    store      Gather, compress, and encrypt all untracked files in the repo
```
