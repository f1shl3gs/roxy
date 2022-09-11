pub struct Aes128Gcm(crypto::Aes128Gcm);

impl Aes128Gcm {
    pub fn new(key: &[u8]) -> Self {
        Self(crypto::Aes128Gcm::new(key))
    }

    #[inline]
    pub fn key_size() -> usize {
        crypto::Aes128Gcm::KEY_LEN
    }

    #[inline]
    pub fn nonce_size() -> usize {
        crypto::Aes128Gcm::NONCE_LEN
    }

    #[inline]
    pub fn tag_size() -> usize {
        crypto::Aes128Gcm::TAG_LEN
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let aad = [0u8; 0];
        let (plaintext, tag_out) = plaintext_in_ciphertext_out
            .split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());

        self.0
            .encrypt_slice_detached(nonce, &aad, plaintext, tag_out)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let aad = [0u8; 0];
        let (plaintext, mut tag_in) = ciphertext_in_plaintext_out
            .split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());

        self.0
            .decrypt_slice_detached(nonce, &aad, plaintext, &mut tag_in)
    }
}

pub struct Aes256Gcm(crypto::Aes256Gcm);

impl Aes256Gcm {
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        Self(crypto::Aes256Gcm::new(key))
    }

    #[inline]
    pub fn key_size() -> usize {
        crypto::Aes256Gcm::KEY_LEN
    }

    #[inline]
    pub fn nonce_size() -> usize {
        crypto::Aes256Gcm::NONCE_LEN
    }

    #[inline]
    pub fn tag_size() -> usize {
        crypto::Aes256Gcm::TAG_LEN
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let aad = [0u8; 0];
        let (plaintext, tag_out) = plaintext_in_ciphertext_out
            .split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());

        self.0
            .encrypt_slice_detached(nonce, &aad, plaintext, tag_out);
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let aad = [0u8; 0];
        let (ciphertext, tag_in) = ciphertext_in_plaintext_out
            .split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());

        self.0
            .decrypt_slice_detached(nonce, &aad, ciphertext, tag_in)
    }
}
