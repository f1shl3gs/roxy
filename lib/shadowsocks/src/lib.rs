#![feature(test)]
extern crate test;

mod addr;
mod config;
mod crypto;
mod error;
mod option;
mod socks5;
mod sys;
mod tcp;
mod udp;

pub use addr::Address;
pub use config::{ServerConfig, UrlParseError};
pub use error::{Error, ProtocolError};
pub use option::{ConnectOpts, UdpSocketControlData};
pub use tcp::proxy::ProxyStream;
pub use udp::{ProxySocket, ProxySocketError};

/// The maximum UDP payload size (defined in the original shadowsocks)
pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65536;

/// AEAD 2022 maximum padding length
const AEAD2022_MAX_PADDING_SIZE: usize = 900;

/// Get a properly AEAD 2022 padding size according to payload's length
fn get_aead_2022_padding_size(payload: &[u8]) -> usize {
    use rand::{rngs::SmallRng, Rng, SeedableRng};
    use std::cell::RefCell;

    thread_local! {
        static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
    }

    if payload.is_empty() {
        PADDING_RNG.with(|rng| rng.borrow_mut().gen::<usize>() % AEAD2022_MAX_PADDING_SIZE)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit, Nonce};

    #[bench]
    fn aes_128_gcm(b: &mut test::Bencher) {
        let key = [
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let nonce = Nonce::from(nonce);
        let aad = [0u8; 0];

        let key = GenericArray::from(key);
        let cipher = Aes128Gcm::new(&key);

        b.bytes = 16;
        b.iter(|| {
            // let mut tag_out    = test::black_box([ 1u8; 16 ]);
            let mut ciphertext = test::black_box([
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
                0xb5,
                0xf0,
                // TAG
                // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);

            cipher
                .encrypt_in_place_detached(&nonce, &aad, &mut ciphertext)
                .unwrap();

            // cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
            // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);

            ciphertext
        })
    }

    #[bench]
    fn aes_256_gcm(b: &mut test::Bencher) {
        let key = [
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86,
            0x04, 0xf6, 0xb5, 0xf0,
        ];
        let nonce = Nonce::from([
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        let aad = [0u8; 0];

        let cipher = Aes256Gcm::new(&GenericArray::from(key));

        b.bytes = 16;
        b.iter(|| {
            // let mut tag_out    = test::black_box([ 1u8; 16 ]);
            let mut ciphertext = test::black_box([
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
                0xb5,
                0xf0,
                // TAG
                // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]);
            // cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
            // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);

            cipher
                .encrypt_in_place_detached(&nonce, &aad, &mut ciphertext)
                .unwrap();

            ciphertext
        })
    }
}
