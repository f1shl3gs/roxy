use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{io, mem};

use bytes::{BufMut, BytesMut};
use futures::future::Either;
use futures::ready;
use pin_project_lite::pin_project;
use resolver::Resolver;
use socket2::{Socket, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tracing::error;

use super::crypto::CryptoStream;
use crate::crypto::CipherKind;
use crate::flow::MonProxyStream;
use crate::option::ConnectOpts;
use crate::sys::net::set_bindtodevice;
use crate::tcp::utils::{copy_from_encrypted, copy_to_encrypted};
use crate::{get_aead_2022_padding_size, Address, FlowStat, ServerConfig};

enum WriteState {
    Connect(Address),
    Connecting(BytesMut),
    Connected,
}

enum ReadState {
    Established,
    // for aead2022
    CheckRequestNonce,
}

pin_project! {
    pub struct ProxyStream {
        #[pin]
        stream: CryptoStream<MonProxyStream<TcpStream>>,

        read_state: ReadState,
        write_state: WriteState,
    }
}

impl ProxyStream {
    /// Connects shadowsocks server
    pub async fn connect(
        conf: &ServerConfig,
        target_addr: Address,
        resolver: &Resolver,
        flow_stat: Arc<FlowStat>,
        opts: &ConnectOpts,
    ) -> io::Result<Self> {
        let stream = match conf.addr() {
            Address::SocketAddress(addr) => connect_server_with_opts(*addr, opts).await?,
            Address::DomainNameAddress(domain, port) => {
                let addr = resolver.resolve(domain, *port).await?;
                connect_server_with_opts(addr, opts).await?
            }
        };

        let stream = CryptoStream::from_stream(
            MonProxyStream::from_stream(stream, flow_stat),
            conf.kind(),
            conf.key(),
        );
        let read_state = if conf.kind().is_aead2022() {
            ReadState::CheckRequestNonce
        } else {
            ReadState::Established
        };

        Ok(ProxyStream {
            stream,
            read_state,
            write_state: WriteState::Connect(target_addr),
        })
    }

    pub async fn proxy(self, local: TcpStream) -> io::Result<()> {
        let kind = self.stream.kind();

        let (mut lr, mut lw) = tokio::io::split(local);
        let (mut pr, mut pw) = tokio::io::split(self);

        let l2p = copy_to_encrypted(kind, &mut lr, &mut pw);
        let p2l = copy_from_encrypted(kind, &mut pr, &mut lw);

        tokio::pin!(l2p);
        tokio::pin!(p2l);

        match futures::future::select(l2p, p2l).await {
            Either::Left((result, _)) => result,
            Either::Right((result, _)) => result,
        }
        .map(|_| ())
    }
}

async fn connect_server_with_opts(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

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
            error!(message = "set SO_MARK failed", ?err);
            return Err(err);
        }
    }

    // Set SO_BINDTODEVICE for binding to a specific interface
    if let Some(ref iface) = opts.bind_interface {
        set_bindtodevice(&socket, iface)?;
    }

    set_common_sockopt_for_connect(addr, &socket, opts)?;

    let stream = socket.connect(addr).await?;
    set_common_sockopt_after_connect(&stream, opts)?;

    Ok(stream)
}

fn set_common_sockopt_for_connect(
    addr: SocketAddr,
    socket: &TcpSocket,
    opts: &ConnectOpts,
) -> io::Result<()> {
    // Binds to IP Address
    if let Some(ip) = opts.bind_local_addr {
        match (ip, addr.ip()) {
            (IpAddr::V4(_), IpAddr::V6(_)) => {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            _ => {}
        }
    }

    // Set `SO_SNDBUF`
    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size)?;
    }

    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size)?;
    }

    Ok(())
}

fn set_common_sockopt_after_connect(stream: &TcpStream, opts: &ConnectOpts) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_fd(stream.as_raw_fd()) };

    macro_rules! try_sockopt {
        ($socket:ident . $func:ident ($($arg:expr),*)) => {
            match $socket . $func ($($arg),*) {
                Ok(e) => e,
                Err(err) => {
                    let _ = socket.into_raw_fd();
                    return Err(err);
                }
            }
        };
    }

    if opts.tcp.nodelay {
        try_sockopt!(socket.set_nodelay(true));
    }

    if let Some(keepalive_duration) = opts.tcp.keepalive {
        #[allow(unused_mut)]
        let mut keepalive = TcpKeepalive::new().with_time(keepalive_duration);
        keepalive = keepalive.with_interval(keepalive_duration);

        try_sockopt!(socket.set_tcp_keepalive(&keepalive));
    }

    let _ = socket.into_raw_fd();

    Ok(())
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        return match this.read_state {
            ReadState::Established => this.stream.poll_read_decrypted(cx, buf).map_err(Into::into),

            // AEAD2022
            ReadState::CheckRequestNonce => {
                ready!(this.stream.as_mut().poll_read_decrypted(cx, buf))?;

                // REQUEST_NONCE should be in the respond packet (header) of AEAD-2022.
                //
                // If received_request_nonce() is None, then:
                // 1. method.salt_len() == 0, no checking required.
                // 2. TCP stream read() returns EOF before receiving the header, no checking required.
                //
                // poll_read_decrypted will wait until the first non-zero size data chunk.
                let (data_chunk_count, _) = this.stream.current_data_chunk_remaining();
                if data_chunk_count > 0 {
                    // data_chunk_count > 0, so the reader received at least 1 data chunk
                    let sent_nonce = this.stream.sent_nonce();
                    let sent_nonce = if sent_nonce.is_empty() {
                        None
                    } else {
                        Some(sent_nonce)
                    };

                    if sent_nonce != this.stream.received_request_nonce() {
                        return Err(io::Error::new(
                            ErrorKind::Other,
                            "received TCP response header with unmatched salt",
                        ))
                        .into();
                    }

                    *(this.read_state) = ReadState::Established
                }

                Ok(()).into()
            }
        };
    }
}

fn make_first_packet_buffer(kind: CipherKind, addr: &Address, buf: &[u8]) -> BytesMut {
    // Target Address should be sent with the first packet together,
    // which would prevent from being detected.
    let addr_length = addr.serialized_len();
    let mut buffer = BytesMut::new();

    let padding_size = get_aead_2022_padding_size(buf);
    let header_length = if kind.is_aead2022() {
        addr_length + 2 + padding_size + buf.len()
    } else {
        addr_length + buf.len()
    };

    buffer.reserve(header_length);

    // STREAM / AEAD / AEAD2022 protocol, append the Address before payload
    addr.write_to_buf(&mut buffer);

    if kind.is_aead2022() {
        buffer.put_u16(padding_size as u16);

        if padding_size > 0 {
            unsafe {
                buffer.advance_mut(padding_size);
            }
        }
    }

    buffer.put_slice(buf);

    buffer
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();

        loop {
            match this.write_state {
                WriteState::Connect(ref addr) => {
                    let buffer = make_first_packet_buffer(this.stream.kind(), addr, buf);

                    // Save the concatenated buffer before it is written successfully.
                    // APIs require buffer to be kept alive before Poll::Ready
                    //
                    // Proactor APIs like IOCP on Windows, pointers of buffers have to be kept
                    // alive before IO completion.

                    *(this.write_state) = WriteState::Connecting(buffer);
                }

                WriteState::Connecting(ref buffer) => {
                    let n = ready!(this.stream.poll_write_encrypted(cx, buffer))?;

                    // In general, poll_write_encrypted should perform like write_all.
                    debug_assert!(n == buffer.len());

                    *(this.write_state) = WriteState::Connected;

                    // NOTE:
                    // poll_write will return Ok(0) if buf.len() == 0
                    // But for the first call, this function will eventually send the handshake
                    // packet (IV/Salt + ADDR) to the remote address.
                    //
                    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
                    //
                    // For protocols that requires *Server Hello* message, like FTP, clients won't
                    // send anything to the server until server sends handshake messages.
                    // This could be achieved by calling poll_write with an empty input buffer.
                    return Ok(buf.len()).into();
                }

                WriteState::Connected => {
                    return this
                        .stream
                        .poll_write_encrypted(cx, buf)
                        .map_err(Into::into)
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().stream.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().stream.poll_shutdown(cx).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, Bytes};
    use std::task::Poll::Pending;

    struct Mock {
        sent: Bytes,
        readed: bool,
    }

    impl Mock {
        fn new(s: &'static [u8]) -> Self {
            Self {
                sent: Bytes::from(s),
                readed: false,
            }
        }
    }

    impl AsyncRead for Mock {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.readed {
                Pending
            } else {
                buf.put_slice(self.sent.chunk());
                self.readed = true;

                Ok(()).into()
            }
        }
    }

    impl AsyncWrite for Mock {
        #[allow(clippy::print_stdout)]
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            println!("{}", std::str::from_utf8(buf).unwrap());
            Ok(buf.len()).into()
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Ok(()).into()
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Ok(()).into()
        }
    }
}
