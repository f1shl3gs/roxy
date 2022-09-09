use hkdf::Hkdf;
use sha1::Sha1;

use super::aead::{Aes128Gcm, Aes256Gcm};
use crate::crypto::CipherKind;

#[allow(clippy::large_enum_variant)]
enum CipherVariant {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl CipherVariant {
    fn new(kind: CipherKind, key: &[u8]) -> Self {
        match kind {
            CipherKind::AES_128_GCM => CipherVariant::Aes128Gcm(Aes128Gcm::new(key)),
            CipherKind::AES_256_GCM => CipherVariant::Aes256Gcm(Aes256Gcm::new(key)),

            _ => unreachable!(),
        }
    }

    fn nonce_size(&self) -> usize {
        match *self {
            CipherVariant::Aes128Gcm(_) => Aes128Gcm::nonce_size(),
            CipherVariant::Aes256Gcm(_) => Aes256Gcm::nonce_size(),
        }
    }

    fn kind(&self) -> CipherKind {
        match *self {
            CipherVariant::Aes128Gcm(_) => CipherKind::AES_128_GCM,
            CipherVariant::Aes256Gcm(_) => CipherKind::AES_256_GCM,
        }
    }

    fn encrypt(&mut self, nonce: &[u8], out: &mut [u8]) {
        match *self {
            CipherVariant::Aes128Gcm(ref mut c) => c.encrypt(nonce, out),
            CipherVariant::Aes256Gcm(ref mut c) => c.encrypt(nonce, out),
        }
    }

    fn decrypt(&mut self, nonce: &[u8], out: &mut [u8]) -> bool {
        match *self {
            CipherVariant::Aes128Gcm(ref mut c) => c.decrypt(nonce, out),
            CipherVariant::Aes256Gcm(ref mut c) => c.decrypt(nonce, out),
        }
    }
}

pub struct Cipher {
    cipher: CipherVariant,
    nlen: usize,
    nonce: [u8; Self::N_MAX],
}

impl Cipher {
    const N_MAX: usize = 24;

    pub fn new(kind: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> Self {
        const SUBKEY_INFO: &[u8] = b"ss-subkey";
        const MAX_KEY_LEN: usize = 64;

        let ikm = key;
        let mut okm = [0u8; MAX_KEY_LEN];

        let hk = Hkdf::<Sha1>::new(Some(iv_or_salt), ikm);
        hk.expand(SUBKEY_INFO, &mut okm).expect("HKDF-SHA1");

        let subkey = &okm[..ikm.len()];
        let cipher = CipherVariant::new(kind, subkey);
        let nlen = cipher.nonce_size();
        debug_assert!(nlen <= Self::N_MAX);

        let nonce = [0u8; Self::N_MAX];

        Self {
            cipher,
            nlen,
            nonce,
        }
    }

    #[inline]
    pub fn tag_len(&self) -> usize {
        self.cipher.kind().tag_len()
    }

    #[inline]
    fn increase_nonce(&mut self) {
        let mut c = self.nonce[0] as u16 + 1;
        self.nonce[0] = c as u8;
        c >>= 8;
        let mut n = 1;
        while n < self.nlen {
            c += self.nonce[n] as u16;
            self.nonce[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }

    pub fn encrypt(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = &self.nonce[..self.nlen];
        self.cipher.encrypt(nonce, plaintext_in_ciphertext_out);
        self.increase_nonce();
    }

    pub fn decrypt(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = &self.nonce[..self.nlen];
        let ret = self.cipher.decrypt(nonce, ciphertext_in_plaintext_out);
        self.increase_nonce();
        ret
    }
}
