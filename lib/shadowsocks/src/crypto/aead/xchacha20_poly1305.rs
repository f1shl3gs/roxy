use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::KeyInit;
pub use chacha20poly1305::XChaCha20Poly1305 as CryptoXChaCha20Poly1305;
use chacha20poly1305::{aead::AeadInPlace, Tag, XNonce};

pub struct XChaCha20Poly1305(CryptoXChaCha20Poly1305);

impl XChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> XChaCha20Poly1305 {
        let key = GenericArray::from_slice(key);
        XChaCha20Poly1305(CryptoXChaCha20Poly1305::new(key))
    }

    #[inline]
    pub fn key_size() -> usize {
        32
    }

    #[inline]
    pub fn nonce_size() -> usize {
        24
    }

    #[inline]
    pub fn tag_size() -> usize {
        16
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = XNonce::from_slice(nonce);
        let (plaintext, out_tag) = plaintext_in_ciphertext_out
            .split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("XCHACHA20_POLY1305 encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = XNonce::from_slice(nonce);
        let (ciphertext, in_tag) = ciphertext_in_plaintext_out
            .split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0
            .decrypt_in_place_detached(nonce, &[], ciphertext, in_tag)
            .is_ok()
    }
}
