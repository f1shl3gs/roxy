mod aes_gcm;

use self::aes_gcm::Cipher as AesGcmCipher;
use crate::crypto::aead::XChaCha20Poly1305 as ChaCha20Poly1305Cipher;
use crate::crypto::CipherKind;

#[allow(clippy::large_enum_variant)]
enum CipherVariant {
    AesGcm(AesGcmCipher),
    ChaCha20Poly1305(ChaCha20Poly1305Cipher),
    #[cfg(feature = "v2-extra")]
    ChaCha8Poly1305(ChaCha8Poly1305Cipher),
}

impl CipherVariant {
    fn new(kind: CipherKind, key: &[u8], session_id: u64) -> CipherVariant {
        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                CipherVariant::AesGcm(AesGcmCipher::new(kind, key, session_id))
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                CipherVariant::ChaCha20Poly1305(ChaCha20Poly1305Cipher::new(key))
            }
            #[cfg(feature = "v2-extra")]
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => {
                CipherVariant::ChaCha8Poly1305(ChaCha8Poly1305Cipher::new(key))
            }
            _ => unreachable!("Cipher {} is not an AEAD 2022 cipher", kind),
        }
    }

    fn encrypt_packet(&self, salt: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        match *self {
            CipherVariant::AesGcm(ref c) => c.encrypt_packet(salt, plaintext_in_ciphertext_out),
            CipherVariant::ChaCha20Poly1305(ref c) => c.encrypt(salt, plaintext_in_ciphertext_out),
            #[cfg(feature = "v2-extra")]
            CipherVariant::ChaCha8Poly1305(ref c) => {
                c.encrypt_packet(salt, plaintext_in_ciphertext_out)
            }
        }
    }

    fn decrypt_packet(&self, salt: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        match *self {
            CipherVariant::AesGcm(ref c) => c.decrypt_packet(salt, ciphertext_in_plaintext_out),
            CipherVariant::ChaCha20Poly1305(ref c) => c.decrypt(salt, ciphertext_in_plaintext_out),
            #[cfg(feature = "v2-extra")]
            CipherVariant::ChaCha8Poly1305(ref c) => {
                c.decrypt_packet(salt, ciphertext_in_plaintext_out)
            }
        }
    }
}

/// AEAD2022 UDP Cipher
pub struct UdpCipher {
    cipher: CipherVariant,
    kind: CipherKind,
}

impl UdpCipher {
    /// Create a new AEAD2022 UDP Cipher
    pub fn new(kind: CipherKind, key: &[u8], session_id: u64) -> UdpCipher {
        UdpCipher {
            cipher: CipherVariant::new(kind, key, session_id),
            kind,
        }
    }

    /// Encrypt a UDP packet, including packet header
    pub fn encrypt_packet(&self, salt: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher
            .encrypt_packet(salt, plaintext_in_ciphertext_out)
    }

    /// Decrypt a UDP packet, including packet header
    pub fn decrypt_packet(&self, salt: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        self.cipher
            .decrypt_packet(salt, ciphertext_in_plaintext_out)
    }
}
