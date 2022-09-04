use std::fmt;
use std::fmt::Formatter;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::socks5::Error;

const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;

#[derive(Clone, Debug)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),

    /// Domain name address
    DomainNameAddress(String, u16),
}

impl From<SocketAddr> for Address {
    fn from(sa: SocketAddr) -> Self {
        Self::SocketAddress(sa)
    }
}

impl From<(&str, u16)> for Address {
    fn from((dn, port): (&str, u16)) -> Self {
        Self::DomainNameAddress(dn.to_owned(), port)
    }
}

impl Address {
    /// Get required buffer size for serializing
    #[inline]
    pub fn serialized_len(&self) -> usize {
        get_addr_len(self)
    }

    /// Write to buffer
    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            Address::SocketAddress(SocketAddr::V4(ref addr)) => {
                buf.put_u8(ADDR_TYPE_IPV4); // Address type
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::SocketAddress(SocketAddr::V6(ref addr)) => {
                buf.put_u8(ADDR_TYPE_IPV6); // Address type
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg); // IPv6 bytes
                }
                buf.put_u16(addr.port());
            }
            Address::DomainNameAddress(ref domain, ref port) => {
                assert!(
                    domain.len() <= u8::MAX as usize,
                    "domain name length must be smaller than 256"
                );

                buf.put_u8(ADDR_TYPE_DOMAIN_NAME);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain[..].as_bytes());
                buf.put_u16(*port);
            }
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            ADDR_TYPE_IPV4 => {
                let mut buf = [0u8; 6];
                let _ = stream.read_exact(&mut buf).await?;

                let v4addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = unsafe {
                    let raw_port = &buf[4..];
                    u16::from_be(*(raw_port.as_ptr() as *const _))
                };

                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    v4addr, port,
                ))))
            }

            ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                let _ = stream.read_exact(&mut buf).await?;

                let buf: &[u16] =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const _, 9) };
                let v6addr = Ipv6Addr::new(
                    u16::from_be(buf[0]),
                    u16::from_be(buf[1]),
                    u16::from_be(buf[2]),
                    u16::from_be(buf[3]),
                    u16::from_be(buf[4]),
                    u16::from_be(buf[5]),
                    u16::from_be(buf[6]),
                    u16::from_be(buf[7]),
                );
                let port = u16::from_be(buf[8]);

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }

            ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let _ = stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                let buf_len = length + 2;
                let mut raw_addr = vec![0u8; buf_len];
                let _ = stream.read_exact(&mut raw_addr).await?;

                let raw_port = &raw_addr[length..];
                let port = unsafe { u16::from_be(*(raw_port.as_ptr() as *const _)) };

                raw_addr.truncate(length);

                let addr = match String::from_utf8(raw_addr) {
                    Ok(addr) => addr,
                    Err(_) => return Err(Error::AddressDomainInvalidEncoding),
                };

                Ok(Address::DomainNameAddress(addr, port))
            }

            _ => {
                // Wrong Address type. Only IPv4, IPv6 and domain name supported
                Err(Error::AddressTypeNotSupported(addr_type))
            }
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

#[derive(Debug)]
pub enum AddressError {
    InvalidPort,
    MissingDomain,
    WithoutPort,
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(Address::SocketAddress(addr)),
            Err(_) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => {
                        if dn.is_empty() {
                            return Err(AddressError::MissingDomain);
                        }

                        match port.parse::<u16>() {
                            Ok(port) => Ok(Address::DomainNameAddress(dn.to_owned(), port)),
                            Err(_) => Err(AddressError::InvalidPort),
                        }
                    }
                    _ => Err(AddressError::WithoutPort),
                }
            }
        }
    }
}

#[inline]
fn get_addr_len(addr: &Address) -> usize {
    match addr {
        Address::SocketAddress(SocketAddr::V4(_)) => 1 + 4 + 2,
        Address::SocketAddress(SocketAddr::V6(_)) => 1 + 8 * 2 + 2,
        Address::DomainNameAddress(ref domain, _) => 1 + 1 + domain.len() + 2,
    }
}
