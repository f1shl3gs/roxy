#[cfg(target_os = "linux")]
mod linux;

use std::net::SocketAddr;

#[cfg(target_os = "linux")]
pub use linux::*;

/// Address family `AF_INET`, `AF_INET6`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddrFamily {
    /// `AF_INET`
    Ipv4,
    /// `AF_INET6`
    Ipv6,
}

impl From<&SocketAddr> for AddrFamily {
    fn from(addr: &SocketAddr) -> AddrFamily {
        match *addr {
            SocketAddr::V4(..) => AddrFamily::Ipv4,
            SocketAddr::V6(..) => AddrFamily::Ipv6,
        }
    }
}

impl From<SocketAddr> for AddrFamily {
    fn from(addr: SocketAddr) -> AddrFamily {
        match addr {
            SocketAddr::V4(..) => AddrFamily::Ipv4,
            SocketAddr::V6(..) => AddrFamily::Ipv6,
        }
    }
}
