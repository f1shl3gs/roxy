//! Crypto protocol for ShadowSocks UDP
//!
//! Payload with stream cipher
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | Fixed | Variable |
//! +-------+----------+
//! ```
//!
//! Payload with AEAD cipher
//!
//! ```plain
//! UDP (after encryption, *ciphertext*)
//! +--------+-----------+-----------+
//! | NONCE  |  *Data*   |  Data_TAG |
//! +--------+-----------+-----------+
//! | Fixed  | Variable  |   Fixed   |
//! +--------+-----------+-----------+
//! ```

use bytes::{Bytes, BytesMut};

use crate::crypto::{CipherCategory, CipherKind};
use crate::option::UdpSocketControlData;
use crate::udp::aead::{decrypt_payload_aead, encrypt_payload_aead};
use crate::Address;

/// UDP shadowsocks protocol errors
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("invalid address in packet, {0}")]
    InvalidAddress(crate::socks5::Error),
    #[error(transparent)]
    AeadError(#[from] super::aead::ProtocolError),
    // #[error(transparent)]
    // Aead2022Error(#[from] super::aead2022::ProtocolError),
}

/// Encrypt `Client -> Server` payload into ShadowSocks UDP encrypted packet
#[allow(clippy::too_many_arguments)]
pub fn encrypt_client_payload(
    kind: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    identity_keys: &[Bytes],
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match kind.category() {
        CipherCategory::Aead => {
            let _ = control;
            let _ = identity_keys;
            encrypt_payload_aead(kind, key, addr, payload, dst)
        }
        CipherCategory::Aead2022 => {
            todo!()
        }
    }
}

/// Decrypt `Server -> Client` payload from ShadowSocks UDP encrypted packet
pub async fn decrypt_server_payload(
    kind: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> Result<(usize, Address, Option<UdpSocketControlData>), ProtocolError> {
    match kind.category() {
        CipherCategory::Aead => decrypt_payload_aead(kind, key, payload)
            .await
            .map(|(n, a)| (n, a, None))
            .map_err(Into::into),
        CipherCategory::Aead2022 => todo!(),
    }
}
