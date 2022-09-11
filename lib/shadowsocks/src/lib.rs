#![feature(test)]
extern crate test;

mod addr;
mod config;
mod crypto;
mod error;
mod flow;
mod option;
mod socks5;
mod sys;
mod tcp;
mod udp;

pub use addr::Address;
pub use config::{ServerConfig, UrlParseError};
pub use error::{Error, ProtocolError};
pub use flow::{FlowStat, MonProxyStream};
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
