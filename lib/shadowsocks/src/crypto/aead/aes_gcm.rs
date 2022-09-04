use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, KeyInit, Nonce, Tag};

pub struct Aes128Gcm(aes_gcm::Aes128Gcm);

impl Aes128Gcm {
    pub fn new(key: &[u8]) -> Aes128Gcm {
        let key = GenericArray::from_slice(key);
        Aes128Gcm(aes_gcm::Aes128Gcm::new(key))
    }

    #[inline]
    pub fn key_size() -> usize {
        16
    }

    #[inline]
    pub fn nonce_size() -> usize {
        12
    }

    #[inline]
    pub fn tag_size() -> usize {
        16
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) = plaintext_in_ciphertext_out
            .split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_128_GCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);

        let (ciphertext, in_tag) = ciphertext_in_plaintext_out
            .split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0
            .decrypt_in_place_detached(nonce, &[], ciphertext, in_tag)
            .is_ok()
    }
}

pub struct Aes256Gcm(aes_gcm::Aes256Gcm);

impl Aes256Gcm {
    pub fn new(key: &[u8]) -> Aes256Gcm {
        let key = GenericArray::from_slice(key);
        Aes256Gcm(aes_gcm::Aes256Gcm::new(key))
    }

    pub fn key_size() -> usize {
        32
    }

    pub fn nonce_size() -> usize {
        12
    }

    pub fn tag_size() -> usize {
        16
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) = plaintext_in_ciphertext_out
            .split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_256_GCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);
        let (ciphertext, in_tag) = ciphertext_in_plaintext_out
            .split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0
            .decrypt_in_place_detached(nonce, &[], ciphertext, in_tag)
            .is_ok()
    }
}
