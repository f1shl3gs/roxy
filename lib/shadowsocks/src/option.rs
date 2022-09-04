use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::ServerUser;

#[derive(Clone, Debug, Default)]
pub struct ConnectOpts {
    /// Linux mark based routing, going to set by `setsockopt` with `SO_MARK` option
    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,

    /// Outbound socket binds to this IP address, mostly for choosing network interfaces
    ///
    /// It only affects sockets that trying to connect to addresses with the same family
    pub bind_local_addr: Option<IpAddr>,

    /// Outbound socket binds to interface
    pub bind_interface: Option<String>,

    /// TCP options
    pub tcp: TcpSocketOpts,
}

/// Options for connecting to TCP remote server
#[derive(Debug, Clone, Default)]
pub struct TcpSocketOpts {
    /// TCP socket's `SO_SNDBUF`
    pub send_buffer_size: Option<u32>,

    /// TCP socket's `SO_RCVBUF`
    pub recv_buffer_size: Option<u32>,

    /// `TCP_NODELAY`
    pub nodelay: bool,

    /// `TCP_FASTOPEN`, enables TFO
    pub fastopen: bool,

    /// `SO_KEEPALIVE` and sets `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `TCP_KEEPCNT` respectively,
    /// enables keep-alive messages on connection-oriented sockets
    pub keepalive: Option<Duration>,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct UdpSocketControlData {
    /// Session ID in client.
    ///
    /// For identifying an unique association in client
    pub client_session_id: u64,
    /// Session ID in server.
    ///
    /// For identifying an unique association in server
    pub server_session_id: u64,
    /// Packet counter
    pub packet_id: u64,
    /// Server user instance
    pub user: Option<Arc<ServerUser>>,
}
