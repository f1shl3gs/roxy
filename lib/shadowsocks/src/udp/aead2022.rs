//! Shadowsocks UDP AEAD 2022 protocol
//!
//! Payload with AEAD 2022 cipher
//!
//! Client -> Server
//!
//! ```plain
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Client Session ID                                             |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Packet ID                                                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | TYPE  |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | UNIX Epoch Timestamp                                          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | PADDING SIZE  | Padding (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Address (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Payload (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! Server -> Client
//!
//! ```plain
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Server Session ID                                             |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Packet ID                                                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | TYPE  |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | UNIX Epoch Timestamp                                          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Client Session ID                                             |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | PADDING SIZE  | Padding (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Address (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Payload (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Seek, SeekFrom};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use std::{io, slice};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use byte_string::ByteStr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use lru_time_cache::LruCache;
use tracing::{error, trace};

use crate::config::{method_support_eih, ServerUser};
use crate::crypto::aead::XChaCha20Poly1305 as ChaCha20Poly1305Cipher;
use crate::crypto::utils::generate_nonce;
use crate::crypto::v2::UdpCipher;
use crate::crypto::CipherKind;
use crate::option::UdpSocketControlData;
use crate::sys::get_now_timestamp;
use crate::{get_aead_2022_padding_size, Address};

const CLIENT_SOCKET_TYPE: u8 = 0;
const SERVER_SOCKET_TYPE: u8 = 1;
const SERVER_PACKET_TIMESTAMP_MAX_DIFF: u64 = 30;

/// AEAD 2022 protocol error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("packet too short, at least {0} bytes, but found {1} bytes")]
    PacketTooShort(usize, usize),
    #[error("invalid address in packet, {0}")]
    InvalidAddress(crate::socks5::Error),
    #[error("decrypt payload error")]
    DecryptPayloadError,
    #[error("invalid client user identity {:?}", ByteStr::new(.0))]
    InvalidClientUser(Bytes),
    #[error("invalid socket type, expecting {0:#x}, but found {1:#x}")]
    InvalidSocketType(u8, u8),
    #[error("invalid timestamp {0} - now {1} = {}", *.0 as i64 - *.1 as i64)]
    InvalidTimestamp(u64, u64),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct CipherKey {
    method: CipherKind,
    key: usize,
    session_id: u64,
}

impl PartialOrd for CipherKey {
    fn partial_cmp(&self, other: &CipherKey) -> Option<Ordering> {
        let hash1 = {
            let mut hasher = DefaultHasher::new();
            self.hash(&mut hasher);
            hasher.finish()
        };
        let hash2 = {
            let mut hasher = DefaultHasher::new();
            other.hash(&mut hasher);
            hasher.finish()
        };

        hash1.partial_cmp(&hash2)
    }
}

impl Ord for CipherKey {
    fn cmp(&self, other: &CipherKey) -> Ordering {
        let hash1 = {
            let mut hasher = DefaultHasher::new();
            self.hash(&mut hasher);
            hasher.finish()
        };
        let hash2 = {
            let mut hasher = DefaultHasher::new();
            other.hash(&mut hasher);
            hasher.finish()
        };

        hash1.cmp(&hash2)
    }
}

const CIPHER_CACHE_DURATION: Duration = Duration::from_secs(30);
const CIPHER_CACHE_LIMIT: usize = 102400;

thread_local! {
    static CIPHER_CACHE: RefCell<LruCache<CipherKey, Rc<UdpCipher>>> =
        RefCell::new(LruCache::with_expiry_duration_and_capacity(CIPHER_CACHE_DURATION, CIPHER_CACHE_LIMIT));
}

fn get_cipher(method: CipherKind, key: &[u8], session_id: u64) -> Rc<UdpCipher> {
    CIPHER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        let cache_key = CipherKey {
            method,
            // The key is stored in ServerConfig structure, so the address of it won't change.
            key: key.as_ptr() as usize,
            session_id,
        };

        cache
            .entry(cache_key)
            .or_insert_with(|| Rc::new(UdpCipher::new(method, key, session_id)))
            .clone()
    })
}

fn encrypt_message(
    kind: CipherKind,
    ipsk: &[u8],
    key: &[u8],
    packet: &mut BytesMut,
    session_id: u64,
    eih_len: usize,
) {
    unsafe {
        packet.advance_mut(kind.tag_len());
    }

    match kind {
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
            // ChaCha20-Poly1305 uses PSK as key, prepended nonce in packet
            let nonce_size = ChaCha20Poly1305Cipher::nonce_size();

            let cipher = get_cipher(kind, key, session_id);

            let (nonce, message) = packet.split_at_mut(nonce_size);
            cipher.encrypt_packet(nonce, message);
        }
        #[cfg(feature = "aead-cipher-2022-extra")]
        CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => {
            // ChaCha8-Poly1305 uses PSK as key, prepended nonce in packet
            let nonce_size = ChaCha8Poly1305Cipher::nonce_size();

            let cipher = get_cipher(kind, key, session_id);

            let (nonce, message) = packet.split_at_mut(nonce_size);
            cipher.encrypt_packet(nonce, message);
        }
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            // AES-*-GCM uses derived key, and part of the packet header as nonce

            let cipher = get_cipher(kind, key, session_id);

            // Encrypt the rest of the packet with AEAD cipher (AES-*-GCM)
            let (packet_header, mut message) = packet.split_at_mut(16);
            let nonce = &packet_header[4..16];

            if eih_len > 0 {
                message = &mut message[eih_len..];
            }

            cipher.encrypt_packet(nonce, message);

            // [SessionID + PacketID] is encrypted with AES-ECB with PSK
            // No padding is required because these 2 fields are 128-bits, which is exactly the same as AES's block size
            match kind {
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                    let cipher = Aes128::new_from_slice(ipsk).expect("AES-128 init");
                    let block = Block::from_mut_slice(packet_header);
                    cipher.encrypt_block(block);
                }
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                    let cipher = Aes256::new_from_slice(ipsk).expect("AES-256 init");
                    let block = Block::from_mut_slice(packet_header);
                    cipher.encrypt_block(block);
                }
                _ => unreachable!("{} is not an AES-*-GCM cipher", kind),
            }
        }
        _ => unreachable!("{} is not an AEAD 2022 cipher", kind),
    }
}

fn decrypt_message(
    method: CipherKind,
    key: &[u8],
    packet: &mut [u8],
) -> Result<Option<Arc<ServerUser>>, ProtocolError> {
    let client_user = None;

    match method {
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
            // ChaCha20-Poly1305 uses PSK as key, prepended nonce in packet
            let nonce_size = ChaCha20Poly1305Cipher::nonce_size();

            let (nonce, message) = packet.split_at_mut(nonce_size);

            // NOTE: ChaCha20-Poly1305's session_id is not required because it uses PSK directly
            //
            // But still, we get the session_id for cache
            let session_id = {
                let session_id_buf = &message[0..8];
                let session_id_slice: &[u64] =
                    unsafe { slice::from_raw_parts(session_id_buf.as_ptr() as *const _, 1) };
                u64::from_be(session_id_slice[0])
            };

            let cipher = get_cipher(method, key, session_id);

            if !cipher.decrypt_packet(nonce, message) {
                return Err(ProtocolError::DecryptPayloadError);
            }
        }
        #[cfg(feature = "aead-cipher-2022-extra")]
        CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => {
            // ChaCha8-Poly1305 uses PSK as key, prepended nonce in packet
            let nonce_size = ChaCha8Poly1305Cipher::nonce_size();

            let (nonce, message) = packet.split_at_mut(nonce_size);

            // NOTE: ChaCha20-Poly1305's session_id is not required because it uses PSK directly
            //
            // But still, we get the session_id for cache
            let session_id = {
                let session_id_buf = &message[0..8];
                let session_id_slice: &[u64] =
                    unsafe { slice::from_raw_parts(session_id_buf.as_ptr() as *const _, 1) };
                u64::from_be(session_id_slice[0])
            };

            let cipher = get_cipher(method, key, session_id);

            if !cipher.decrypt_packet(nonce, message) {
                return Err(ProtocolError::DecryptPayloadError);
            }
        }
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            // AES-*-GCM uses derived key, and part of the packet header as nonce
            //
            // Decrypt the header block first
            // [SessionID + PacketID] is encrypted with AES-ECB with PSK
            // No padding is required because these 2 fields are 128-bits, which is exactly the same as AES's block size

            let (packet_header, message) = packet.split_at_mut(16);

            match method {
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                    let cipher = Aes128::new_from_slice(key).expect("AES-128 init");
                    let block = Block::from_mut_slice(packet_header);
                    cipher.decrypt_block(block);
                }
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                    let cipher = Aes256::new_from_slice(key).expect("AES-256 init");
                    let block = Block::from_mut_slice(packet_header);
                    cipher.decrypt_block(block);
                }
                _ => unreachable!("{} is not an AES-*-GCM cipher", method),
            }

            // Session ID is the first 64-bits

            let session_id = {
                let session_id_buf = &packet_header[0..8];
                let session_id_slice: &[u64] =
                    unsafe { slice::from_raw_parts(session_id_buf.as_ptr() as *const _, 1) };
                u64::from_be(session_id_slice[0])
            };

            let cipher = get_cipher(method, key, session_id);

            let nonce = &packet_header[4..16];
            if !cipher.decrypt_packet(nonce, message) {
                return Err(ProtocolError::DecryptPayloadError);
            }
        }
        _ => unreachable!("{} is not an AEAD 2022 cipher", method),
    }

    Ok(client_user)
}

#[inline]
fn get_nonce_len(method: CipherKind) -> usize {
    match method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => 0,
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => method.nonce_len(),
        #[cfg(feature = "aead-cipher-2022-extra")]
        CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 => method.nonce_len(),
        _ => unreachable!("{} is not an AEAD 2022 cipher", method),
    }
}

/// Encrypt `Client -> Server` UDP AEAD protocol packet
#[allow(clippy::too_many_arguments)]
pub fn encrypt_client_payload_aead_2022(
    kind: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    identity_keys: &[Bytes],
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let padding_size = get_aead_2022_padding_size(payload);
    let nonce_size = get_nonce_len(kind);
    let require_eih = method_support_eih(kind) && !identity_keys.is_empty();
    let eih_size = if require_eih {
        identity_keys.len() * 16
    } else {
        0
    };

    dst.reserve(
        nonce_size
            + 8
            + 8
            + eih_size
            + 1
            + 8
            + 2
            + padding_size
            + addr.serialized_len()
            + payload.len()
            + kind.tag_len(),
    );

    // Generate IV
    if nonce_size > 0 {
        unsafe {
            dst.advance_mut(nonce_size);
        }
        let nonce = &mut dst[..nonce_size];

        generate_nonce(kind, nonce);
        trace!("UDP packet generated aead nonce {:?}", ByteStr::new(nonce));
    }

    // Add header fields
    dst.put_u64(control.client_session_id);
    dst.put_u64(control.packet_id);

    // Extensible Identity Header
    // https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
    if require_eih {
        #[inline]
        fn make_eih(
            method: CipherKind,
            ipsk: &[u8],
            ipskn: &[u8],
            session_id_packet_id: &[u8],
            identity_header: &mut [u8; 16],
        ) {
            let ipskn_hash = blake3::hash(ipskn);
            let plain_text = &ipskn_hash.as_bytes()[0..16];

            identity_header.copy_from_slice(plain_text);

            for i in 0..16 {
                identity_header[i] ^= session_id_packet_id[i];
            }

            match method {
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                    let cipher = Aes128::new_from_slice(ipsk).expect("AES-128 init");
                    cipher.encrypt_block(Block::from_mut_slice(identity_header));
                }
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                    let cipher = Aes256::new_from_slice(ipsk).expect("AES-256 init");
                    cipher.encrypt_block(Block::from_mut_slice(identity_header));
                }
                _ => unreachable!("{} doesn't support EIH", method),
            }

            trace!(
                "client EIH {:?}, hash: {:?}",
                ByteStr::new(identity_header),
                ByteStr::new(plain_text)
            );
        }

        for (ipsk, ipskn) in identity_keys.iter().map(AsRef::as_ref).zip(
            identity_keys
                .iter()
                .map(AsRef::as_ref)
                .skip(1)
                .chain(Some(key)),
        ) {
            let session_id_packet_id = &dst[nonce_size..nonce_size + 16];

            let mut identity_header = [0u8; 16];
            make_eih(
                kind,
                ipsk,
                ipskn,
                session_id_packet_id,
                &mut identity_header,
            );

            dst.put(identity_header.as_slice());
        }
    }

    dst.put_u8(CLIENT_SOCKET_TYPE);
    dst.put_u64(get_now_timestamp());
    dst.put_u16(padding_size as u16);
    if padding_size > 0 {
        unsafe {
            dst.advance_mut(padding_size);
        }
    }
    addr.write_to_buf(dst);
    dst.put_slice(payload);

    let ipsk = if identity_keys.is_empty() {
        key
    } else {
        &identity_keys[0]
    };
    encrypt_message(kind, ipsk, key, dst, control.client_session_id, eih_size);
}

/// Decrypt `Server -> Client` UDP AEAD protocol packet
pub async fn decrypt_server_payload_aead_2022(
    kind: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> Result<(usize, Address, UdpSocketControlData), ProtocolError> {
    let nonce_len = get_nonce_len(kind);
    let tag_len = kind.tag_len();
    let header_len = nonce_len + tag_len + 8 + 8 + 1 + 8 + 2;
    if payload.len() < header_len {
        return Err(ProtocolError::PacketTooShort(header_len, payload.len()));
    }

    let user = decrypt_message(kind, key, payload)?;
    debug_assert!(user.is_none(), "server respond packet shouldn't have EIH");

    let data = &payload[nonce_len..payload.len() - tag_len];
    let mut cursor = Cursor::new(data);

    let server_session_id = cursor.get_u64();
    let packet_id = cursor.get_u64();
    let socket_type = cursor.get_u8();
    if socket_type != SERVER_SOCKET_TYPE {
        return Err(ProtocolError::InvalidSocketType(
            SERVER_SOCKET_TYPE,
            socket_type,
        ));
    }
    let timestamp = cursor.get_u64();

    let now = get_now_timestamp();
    if now.abs_diff(timestamp) > SERVER_PACKET_TIMESTAMP_MAX_DIFF {
        return Err(ProtocolError::InvalidTimestamp(timestamp, now));
    }

    let client_session_id = cursor.get_u64();

    let padding_size = cursor.get_u16() as usize;
    if padding_size > 0 {
        cursor.seek(SeekFrom::Current(padding_size as i64))?;
    }

    let control = UdpSocketControlData {
        client_session_id,
        server_session_id,
        packet_id,
        user: None,
    };

    let addr = match Address::read_from(&mut cursor).await {
        Ok(a) => a,
        Err(err) => return Err(ProtocolError::InvalidAddress(err)),
    };

    let payload_start = cursor.position() as usize;
    let payload_len = data.len() - payload_start;

    payload.copy_within(
        nonce_len + payload_start..nonce_len + payload_start + payload_len,
        0,
    );

    Ok((payload_len, addr, control))
}
