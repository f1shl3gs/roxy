use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::{io, mem};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, error, warn};

use crate::option::ConnectOpts;
use crate::sys::net::AddrFamily;

/// Try to call `bind()` with dual-stack enabled.
///
/// Users have to ensure that `addr` is a dual-stack inbound address (`::`) when `ipv6_only` is `false`.
pub fn socket_bind_dual_stack<S>(socket: &S, addr: &SocketAddr, ipv6_only: bool) -> io::Result<()>
where
    S: AsRawFd,
{
    use std::os::unix::prelude::{FromRawFd, IntoRawFd};

    let fd = socket.as_raw_fd();

    let sock = unsafe { Socket::from_raw_fd(fd) };
    let result = socket_bind_dual_stack_inner(&sock, addr, ipv6_only);
    sock.into_raw_fd();

    result
}

fn socket_bind_dual_stack_inner(
    socket: &Socket,
    addr: &SocketAddr,
    ipv6_only: bool,
) -> io::Result<()> {
    let saddr = SockAddr::from(*addr);

    if ipv6_only {
        // Requested to set IPV6_V6ONLY
        socket.set_only_v6(true)?;
        socket.bind(&saddr)?;
    } else {
        if let Err(err) = socket.set_only_v6(false) {
            warn!(
                "failed to set IPV6_V6ONLY: false for socket, error: {}",
                err
            );

            // This is not a fatal error, just warn and skip
        }

        match socket.bind(&saddr) {
            Ok(..) => {}
            Err(ref err) if err.kind() == ErrorKind::AddrInUse => {
                // This is probably 0.0.0.0 with the same port has already been occupied
                debug!(
                    "0.0.0.0:{} may have already been occupied, retry with IPV6_V6ONLY",
                    addr.port()
                );

                if let Err(err) = socket.set_only_v6(true) {
                    warn!("failed to set IPV6_V6ONLY: true for socket, error: {}", err);

                    // This is not a fatal error, just warn and skip
                }
                socket.bind(&saddr)?;
            }
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawFd>(af: AddrFamily, socket: &S) -> io::Result<()> {
    // For Linux, IP_MTU_DISCOVER should be enabled for both IPv4 and IPv6 sockets
    // https://man7.org/linux/man-pages/man7/ip.7.html

    unsafe {
        let value: i32 = libc::IP_PMTUDISC_DO;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &value as *const _ as *const _,
            mem::size_of_val(&value) as libc::socklen_t,
        );

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if af == AddrFamily::Ipv6 {
            let value: i32 = libc::IP_PMTUDISC_DO;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &value as *const _ as *const _,
                mem::size_of_val(&value) as libc::socklen_t,
            );

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

pub fn set_bindtodevice<S: AsRawFd>(socket: &S, iface: &str) -> io::Result<()> {
    let iface_bytes = iface.as_bytes();

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const _ as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_BINDTODEVICE error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

/// Create a `UdpSocket` for connecting to `addr`
pub async fn create_udp_socket(af: AddrFamily, opts: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, opts.bind_local_addr) {
        (AddrFamily::Ipv4, Some(IpAddr::V4(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv6, Some(IpAddr::V6(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let socket = if af != AddrFamily::Ipv6 {
        UdpSocket::bind(bind_addr).await?
    } else {
        let socket = Socket::new(
            Domain::for_address(bind_addr),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        socket_bind_dual_stack(&socket, &bind_addr, false)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    if let Err(err) = set_disable_ip_fragmentation(af, &socket) {
        warn!(message = "failed to disable IP fragmentation", ?err);
    }

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    if let Some(mark) = opts.fwmark {
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const _,
                mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_MARK error: {}", err);
            return Err(err);
        }
    }

    // Set SO_BINDTODEVICE for binding to a specific interface
    if let Some(ref iface) = opts.bind_interface {
        set_bindtodevice(&socket, iface)?;
    }

    Ok(socket)
}
