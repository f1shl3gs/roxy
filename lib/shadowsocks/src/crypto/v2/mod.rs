mod udp;

pub use udp::UdpCipher;

/// AEAD2022 protocol Blake3 KDF context
pub const BLAKE3_KEY_DERIVE_CONTEXT: &str = "shadowsocks 2022 session subkey";
