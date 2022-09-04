pub mod aead;
mod cipher;
mod kind;
pub mod utils;
pub mod v2;

use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub use cipher::Cipher;

pub enum CipherCategory {
    Aead,
    Aead2022,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherKind {
    AES_128_GCM,
    AES_256_GCM,

    AEAD2022_BLAKE3_AES_128_GCM,
    AEAD2022_BLAKE3_AES_256_GCM,
    AEAD2022_BLAKE3_CHACHA20_POLY1305,
    AEAD2022_BLAKE3_CHACHA8_POLY1305,
}

impl CipherKind {
    pub fn is_aead(&self) -> bool {
        match *self {
            CipherKind::AES_128_GCM | CipherKind::AES_256_GCM => true,
            _ => false,
        }
    }

    pub fn is_aead2022(&self) -> bool {
        match *self {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM
            | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
            | CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
            | CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => true,
            _ => false,
        }
    }

    pub fn category(&self) -> CipherCategory {
        match *self {
            CipherKind::AES_128_GCM | CipherKind::AES_256_GCM => CipherCategory::Aead,
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM
            | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
            | CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
            | CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => CipherCategory::Aead2022,
        }
    }

    /// Key length of the cipher
    pub fn key_len(&self) -> usize {
        match *self {
            // AEAD
            CipherKind::AES_128_GCM => 128 / 8,
            CipherKind::AES_256_GCM => 256 / 8,

            // AEAD2022
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => todo!(),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => todo!(),
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => todo!(),
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => todo!(),
        }
    }

    /// AEAD Cipher's TAG length
    pub fn tag_len(&self) -> usize {
        match *self {
            // AEAD
            CipherKind::AES_128_GCM => 16,
            CipherKind::AES_256_GCM => 16,

            // AEAD 2022
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => todo!(),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => todo!(),
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => todo!(),
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => todo!(),
        }
    }

    /// AEAD Cipher's SALT length
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    /// AEAD Cipher's nonce length
    pub fn nonce_len(&self) -> usize {
        match *self {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                todo!()
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => todo!(),
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => todo!(),

            _ => panic!("only support AEAD 2022 ciphers"),
        }
    }
}

impl Display for CipherKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CipherKind::AES_128_GCM => "aes-128-gcm",
            CipherKind::AES_256_GCM => "aes-256-gcm",
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => "2022-blake3-aes-128-gcm",
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => "2022-blake3-aes-256-gcm",
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => "2022-blake3-chacha20-poly1305",
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => "2022-blake3-chacha8-poly1305",
        };

        f.write_str(s)
    }
}

#[derive(Debug, Clone)]
pub struct ParseCipherKindError;

impl FromStr for CipherKind {
    type Err = ParseCipherKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes-128-gcm" => Ok(CipherKind::AES_128_GCM),
            "aes-256-gcm" => Ok(CipherKind::AES_256_GCM),
            "2022-blake3-aes-128-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_128_GCM),
            "2022-blake3-aes-256-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_256_GCM),
            "2022-blake3-chacha20-poly1305" => Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305),
            "2022-blake3-chacha8-poly1305" => Ok(CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305),
            _ => Err(ParseCipherKindError),
        }
    }
}
