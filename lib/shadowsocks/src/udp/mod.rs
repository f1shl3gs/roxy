//! Relay for UDP implementation
//!
//! ## ShadowSocks UDP protocol
//!
//! SOCKS5 UDP Request
//! ```ignore
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! SOCKS5 UDP Response
//! ```ignore
//! +----+------+------+----------+----------+----------+
//! |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +----+------+------+----------+----------+----------+
//! | 2  |  1   |  1   | Variable |    2     | Variable |
//! +----+------+------+----------+----------+----------+
//! ```
//!
//! shadowsocks UDP Request (before encrypted)
//! ```ignore
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//! ```
//!
//! shadowsocks UDP Response (before encrypted)
//! ```ignore
//! +------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+----------+----------+----------+
//! |  1   | Variable |    2     | Variable |
//! +------+----------+----------+----------+
//! ```
//!
//! shadowsocks UDP Request and Response (after encrypted)
//! ```ignore
//! +-------+--------------+
//! |   IV  |    PAYLOAD   |
//! +-------+--------------+
//! | Fixed |   Variable   |
//! +-------+--------------+
//! ```

mod aead;
mod aead2022;
mod crypto;
mod proxy_socket;

pub use proxy_socket::{ProxySocket, ProxySocketError};
