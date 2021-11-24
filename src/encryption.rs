use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result};
use openssl::{
    pkey::{Private, Public},
    rsa::{Padding, Rsa},
    symm::{decrypt, encrypt, Cipher},
};
use rand::Rng;

use crate::conf::WateorConfig;

pub static PRIV_KEY_NAME: &str = "key.pem";
pub static PUB_KEY_NAME: &str = "pub.pem";

pub struct Crypto {
    private_key_encrypted: Vec<u8>,
    public_key: Rsa<Public>,
}

impl Crypto {
    pub fn from_config(config: &WateorConfig) -> Result<Self> {
        let public_key = get_pub_key(&config.data_dir.join(PUB_KEY_NAME))?;
        let private_key_encrypted = get_priv_key_data(&config.data_dir.join(PRIV_KEY_NAME))?;

        Ok(Self {
            private_key_encrypted,
            public_key,
        })
    }

    fn private_key(&self, pass: &str) -> Result<Rsa<Private>> {
        Rsa::private_key_from_pem_passphrase(&self.private_key_encrypted, pass.as_bytes())
            .context("Couldn't parse private key")
    }

    pub fn encrypt_archive(&self, unencrypted_data: &[u8]) -> Result<EncryptedArchive> {
        let key = rand::thread_rng().gen::<[u8; 16]>();
        let iv = rand::thread_rng().gen::<[u8; 16]>();

        let encrypted = encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), unencrypted_data)
            .context("Failed to encrypt archive")?;

        let mut encrypted_key = vec![0; self.public_key.size() as usize];
        self.public_key
            .public_encrypt(&key, &mut encrypted_key, Padding::PKCS1)
            .context("Failed to encrypt archive encryption key")?;

        Ok(EncryptedArchive {
            encrypted_archive_data: encrypted,
            encrypted_key,
            iv,
        })
    }

    pub fn decrypt_archive(
        &self,
        pass: &str,
        encrypted_key: &[u8],
        iv: &[u8; 16],
        archive_path: &Path,
    ) -> Result<Vec<u8>> {
        let private_key = self.private_key(pass)?;
        let mut decryption_key = vec![0_u8; private_key.size() as usize];
        private_key
            .private_decrypt(encrypted_key, &mut decryption_key, Padding::PKCS1)
            .context("Failed to decrypt archive encryption key")?;

        let mut file = File::open(archive_path).with_context(|| {
            format!(
                "Failed to open archive file at {}",
                archive_path.to_string_lossy()
            )
        })?;
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;
        decrypt(
            Cipher::aes_128_cbc(),
            &decryption_key[..16],
            Some(iv),
            &encrypted,
        )
        .with_context(|| {
            format!(
                "Failed to decrypt archive at {}",
                archive_path.to_string_lossy()
            )
        })
    }
}

fn get_pub_key(key_path: &Path) -> Result<Rsa<Public>> {
    let mut key_cont = Vec::new();
    File::open(key_path)
        .context("Couldn't open public key file")?
        .read_to_end(&mut key_cont)?;
    Rsa::public_key_from_pem(&key_cont).context("Couldn't parse public key")
}

fn get_priv_key_data(key_path: &Path) -> Result<Vec<u8>> {
    let mut key_cont = Vec::new();
    File::open(key_path)
        .context("Couldn't open private key file")?
        .read_to_end(&mut key_cont)?;

    Ok(key_cont)
}

pub struct EncryptedArchive {
    pub encrypted_archive_data: Vec<u8>,
    pub encrypted_key: Vec<u8>,
    pub iv: [u8; 16],
}
