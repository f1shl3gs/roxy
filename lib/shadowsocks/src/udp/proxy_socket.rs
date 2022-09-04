use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use resolver::{ResolveError, Resolver};
use tokio::time;
use tracing::{error, trace, warn};

use crate::crypto::CipherKind;
use crate::option::{ConnectOpts, UdpSocketControlData};
use crate::sys::net::create_udp_socket;
use crate::udp::crypto::{decrypt_server_payload, encrypt_client_payload, ProtocolError};
use crate::{Address, ServerConfig};

/// `ProxySocket` error type
#[derive(thiserror::Error, Debug)]
pub enum ProxySocketError {
    /// std::io::Error
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ProtocolError(super::crypto::ProtocolError),
    #[error("peer: {0}, {1}")]
    ProtocolErrorWithPeer(SocketAddr, super::crypto::ProtocolError),
    #[error("invalid server user identity {:?}", ByteStr::new(.0))]
    InvalidServerUser(Bytes),
    #[error("resolve failed, {0}")]
    Resolve(#[from] ResolveError),
}

impl From<ProxySocketError> for io::Error {
    fn from(e: ProxySocketError) -> io::Error {
        match e {
            ProxySocketError::IoError(e) => e,
            _ => io::Error::new(ErrorKind::Other, e),
        }
    }
}

/// UDP client for communicating with ShadowSocks' server
pub struct ProxySocket {
    socket: tokio::net::UdpSocket,
    kind: CipherKind,
    key: Box<[u8]>,
    send_timeout: Option<Duration>,
    recv_timeout: Option<Duration>,
    identity_keys: Arc<Vec<Bytes>>,
}

impl ProxySocket {
    pub fn set_timeouts(&mut self, send: Option<Duration>, recv: Option<Duration>) {
        self.send_timeout = send;
        self.recv_timeout = recv;
    }

    /// Create a client to communicate with Shadowsocks' UDP server
    pub async fn connect(
        sc: &ServerConfig,
        resolver: &Resolver,
    ) -> Result<ProxySocket, ProxySocketError> {
        Self::connect_with_opts(sc, resolver, &ConnectOpts::default()).await
    }

    /// Create a client to communicate with Shadowsocks' UDP server
    pub async fn connect_with_opts(
        sc: &ServerConfig,
        resolver: &Resolver,
        opts: &ConnectOpts,
    ) -> Result<Self, ProxySocketError> {
        let socket = match sc.addr() {
            Address::SocketAddress(remote) => {
                let socket = create_udp_socket(remote.into(), opts).await?;
                socket.connect(remote).await?;
                socket
            }
            Address::DomainNameAddress(dn, port) => {
                let addr = resolver.resolve(&dn, *port).await?;
                let socket = create_udp_socket(addr.into(), opts).await?;
                socket.connect(addr).await?;
                socket
            }
        };

        Ok(Self {
            socket,
            kind: sc.kind(),
            key: sc.key().to_vec().into_boxed_slice(),
            send_timeout: None,
            recv_timeout: None,
            identity_keys: sc.clone_identity_keys(),
        })
    }

    fn encrypt_send_buffer(
        &self,
        addr: &Address,
        control: &UdpSocketControlData,
        identity_keys: &[Bytes],
        payload: &[u8],
        send_buf: &mut BytesMut,
    ) -> Result<(), ProxySocketError> {
        encrypt_client_payload(
            self.kind,
            &self.key,
            addr,
            control,
            identity_keys,
            payload,
            send_buf,
        );

        Ok(())
    }

    /// Send a UDP packet to addr through proxy
    pub async fn send(
        &self,
        addr: &Address,
        payload: &[u8],
        control: &UdpSocketControlData,
    ) -> Result<usize, ProxySocketError> {
        let mut send_buf = BytesMut::new();
        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        trace!(
            "UDP server client send to {}, control: {:?}, payload length {} bytes, packet length {} bytes",
            addr,
            control,
            payload.len(),
            send_buf.len()
        );

        let send_len = match self.send_timeout {
            None => self.socket.send(&send_buf).await?,
            Some(d) => match time::timeout(d, self.socket.send(&send_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        if send_buf.len() != send_len {
            warn!(
                "UDP server client send {} bytes, but actually sent {} bytes",
                send_buf.len(),
                send_len
            );
        }

        Ok(send_len)
    }

    async fn decrypt_recv_buffer(
        &self,
        recv_buf: &mut [u8],
    ) -> Result<(usize, Address, Option<UdpSocketControlData>), ProtocolError> {
        decrypt_server_payload(self.kind, &self.key, recv_buf).await
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    pub async fn recv(
        &self,
        recv_buf: &mut [u8],
    ) -> Result<(usize, Address, usize), ProxySocketError> {
        self.recv_with_ctrl(recv_buf)
            .await
            .map(|(n, a, rn, _)| (n, a, rn))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    pub async fn recv_with_ctrl(
        &self,
        recv_buf: &mut [u8],
    ) -> Result<(usize, Address, usize, Option<UdpSocketControlData>), ProxySocketError> {
        // Waiting for response from server SERVER -> CLIENT
        let recv_n = match self.recv_timeout {
            None => self.socket.recv(recv_buf).await?,
            Some(d) => match time::timeout(d, self.socket.recv(recv_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        let (n, addr, control) = match self.decrypt_recv_buffer(&mut recv_buf[..recv_n]).await {
            Ok(x) => x,
            Err(err) => return Err(ProxySocketError::ProtocolError(err)),
        };

        trace!(
            "UDP server client receive from {}, control: {:?}, packet length {} bytes, payload length {} bytes",
            addr,
            control,
            recv_n,
            n
        );

        Ok((n, addr, recv_n, control))
    }
}
