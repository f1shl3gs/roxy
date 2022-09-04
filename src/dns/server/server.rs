use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use futures_util::StreamExt;
use resolver::Resolver;
use tokio::net;
use tokio::net::TcpListener;
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_proto::rr::{RData, Record};
use trust_dns_proto::tcp::TcpStream;
use trust_dns_proto::udp::UdpStream;
use trust_dns_proto::DnsStreamHandle;
use trust_dns_resolver::error::ResolveErrorKind;

use crate::dns::cache::Cache;
use crate::dns::error::Error;
use crate::dns::hijack::Hijack;
use crate::dns::reject::Reject;
use crate::dns::server::request::Request;
use crate::dns::server::response::Response;
use crate::dns::upstream::Upstream;
use crate::dns::Config;

pub struct Server {
    addr: String,
    handler: Arc<Handler>,
}

impl Server {
    pub async fn new(config: Config, resolver: Resolver) -> Result<Self, Error> {
        let cache = config.cache.map(|c| Cache::new(c.size, c.ttl));

        let reject = match config.reject {
            Some(rc) => {
                let reject = Reject::new(rc, resolver.clone())
                    .await
                    .map_err(Error::Reject)?;
                Some(reject)
            }
            None => None,
        };

        let hijacker = match config.hijack {
            Some(hc) => Some(Hijack::new(hc, resolver).await.map_err(Error::Hijack)?),
            None => None,
        };

        let upstream = Upstream::new(config.upstream.nameservers)?;

        Ok(Self {
            addr: config.listen,
            handler: Arc::new(Handler {
                cache,
                reject,
                hijacker,
                upstream,
            }),
        })
    }

    pub async fn serve(self) -> io::Result<()> {
        info!(message = "Starting DNS service", addr = self.addr);

        tokio::select! {
            tr = self.serve_tcp() => tr,
            ur = self.serve_udp() => ur,
        }
    }

    async fn serve_tcp(&self) -> io::Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;

        loop {
            let (stream, src) = listener.accept().await?;

            // verify that the src address is safe for responses
            if let Err(err) = sanitize_src_address(src) {
                warn!(message = "address can not be responded to", ?src, err);

                continue;
            }

            let handle = self.handler.clone();
            tokio::spawn(async move {
                let (mut buf_stream, mut stream_handle) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(stream), src);

                while let Some(msg) = buf_stream.next().await {
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(message = "error in TCP request stream", ?src, ?err);

                            return;
                        }
                    };

                    // build request from message
                    let req = match Request::from_message(msg, src) {
                        Ok(req) => req,
                        Err(err) => {
                            warn!(message = "decode dns request failed", ?err, ?src);
                            continue;
                        }
                    };

                    match handle.handle(&req).await {
                        Ok(resp) => {
                            let msg = match resp.message(src) {
                                Ok(msg) => msg,
                                Err(err) => {
                                    warn!(message = "encode response message failed", ?src, ?err);

                                    return;
                                }
                            };

                            if let Err(err) = stream_handle.send(msg) {
                                warn!(message = "send response message failed", ?src, ?err);

                                return;
                            }
                        }
                        Err(err) => {
                            warn!(message = "handle dns request failed", ?src, ?err);
                        }
                    }
                }
            });
        }
    }

    async fn serve_udp(&self) -> io::Result<()> {
        let socket = net::UdpSocket::bind(&self.addr).await?;
        // create the new UdpStream, the IP address isn't relevant, and ideally goes
        // essentially no where. the address used is acquired from the inbound queries.
        let (mut buf, stream_handle) =
            UdpStream::with_bound(socket, ([127, 255, 255, 254], 0).into());

        while let Some(next) = buf.next().await {
            let msg = match next {
                Err(err) => {
                    warn!(message = "error receiving message on udp_socket", ?err);
                    return Err(err);
                }
                Ok(msg) => msg,
            };

            let src = msg.addr();
            debug!("received udp request from: {}", src);

            // verify that the src address is safe for response
            if let Err(err) = sanitize_src_address(src) {
                warn!(message = "address can not be responded to", ?err, ?src);
                continue;
            }

            let req = match Request::from_message(msg, src) {
                Ok(req) => req,
                Err(err) => {
                    warn!(message = "decode dns request failed", ?err, ?src);
                    continue;
                }
            };

            let mut sender = stream_handle.with_remote_addr(src);
            let handler = Arc::clone(&self.handler);

            tokio::spawn(async move {
                let name = req.query().name();
                debug!(message = "serve dns request", ?name);

                let result = handler.handle(&req).await;

                match result {
                    Ok(resp) => {
                        let msg = match resp.message(src) {
                            Ok(msg) => msg,
                            Err(err) => {
                                error!(message = "encode response message failed", ?err, ?src);

                                return;
                            }
                        };

                        if let Err(err) = sender.send(msg) {
                            warn!(message = "send dns response failed", ?err, ?src);
                        }
                    }

                    Err(err) => {
                        if let Error::Resolve(ref re) = err {
                            if let ResolveErrorKind::NoRecordsFound { query, .. } = re.kind() {
                                debug!(message = "no record", ?query);

                                return;
                            }
                        }

                        warn!(message = "handle dns request failed", ?err, ?name);
                    }
                }
            });
        }

        Err(io::Error::new(
            ErrorKind::Other,
            "unexpected close of socket",
        ))
    }
}

struct Handler {
    cache: Option<Cache>,
    hijacker: Option<Hijack>,
    reject: Option<Reject>,
    upstream: Upstream,
}

impl Handler {
    pub async fn handle<'q>(&self, req: &'q Request) -> Result<Response<'q>, Error> {
        let name = req.query().name();

        // try cache
        if let Some(cache) = &self.cache {
            match cache.get(&req) {
                Some(resp) => {
                    return Ok(resp);
                }
                _ => {}
            }
        }

        // hijack
        if let Some(hijacker) = &self.hijacker {
            if let Some(to) = hijacker.hijacking(name) {
                debug!(message = "hijack dns request", ?name, ?to);

                let name = name.clone();
                let mut resp = Response::from_request(req);
                let rdata = match to {
                    IpAddr::V4(addr) => RData::A(addr),
                    IpAddr::V6(addr) => RData::AAAA(addr),
                };

                resp.answers
                    .push(Record::from_rdata(name.clone(), 60 * 60, rdata));

                return Ok(resp);
            }
        }

        // try reject
        if let Some(reject) = &self.reject {
            if reject.deny(name) {
                debug!(message = "request match reject rules", ?name,);

                return Ok(Response::no_records(req.header, &req.query));
            }
        }

        // try upstream
        match (self.upstream.resolve(req).await, &self.cache) {
            (Ok(resp), Some(cache)) => {
                cache.put(&resp);
                Ok(resp)
            }
            (result, _) => result,
        }
    }
}

/// Checks if the IP address is safe for returning messages
///
/// Examples of unsafe addresses are any with a port of `0`
///
/// # Returns
///
/// Error if the address should not be used for returned requests
fn sanitize_src_address(src: SocketAddr) -> Result<(), String> {
    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    if src.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {}", src));
    }

    fn verify_v4(src: Ipv4Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v4 addr: {}", src));
        }

        if src.is_broadcast() {
            return Err(format!("cannot respond to broadcast v4 addr: {}", src));
        }

        // TODO: add check for is_reserved when that stabilizes

        Ok(())
    }

    fn verify_v6(src: Ipv6Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v6 addr: {}", src));
        }

        Ok(())
    }

    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    match src.ip() {
        IpAddr::V4(v4) => verify_v4(v4),
        IpAddr::V6(v6) => verify_v6(v6),
    }
}
