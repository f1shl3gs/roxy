use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;

use futures_util::future::join_all;
use resolver::Resolver;
use serde::Deserialize;
use shadowsocks::{Address, ProxyStream};
use tokio::net::TcpListener;

use super::sniffing::destination_addr;
use crate::Upstream;

#[derive(Deserialize)]
pub struct Config {
    listen: Vec<SocketAddr>,
}

pub async fn serve(config: Config, upstream: Upstream, resolver: Resolver) -> io::Result<()> {
    let mut tasks = Vec::with_capacity(config.listen.len());
    info!(
        message = "start transparent http proxy server",
        listen = ?config.listen,
    );

    for addr in config.listen {
        let listener = TcpListener::bind(addr).await?;

        let balancer = upstream.clone();
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (mut local, src) = listener.accept().await.expect("listen success");
                let balancer = balancer.clone();
                let resolver = resolver.clone();

                // handle the connect
                tokio::spawn(async move {
                    let (host, port) = match destination_addr(&mut local).await {
                        Ok(dst) => dst,
                        Err(err) => {
                            warn!(message = "sniff hostname failed", ?err, ?src);
                            return Err(io::Error::new(ErrorKind::Other, err));
                        }
                    };

                    // Trying to connect 5 times
                    for _i in 0..5 {
                        let server = balancer.pick(&host).await;
                        let target = Address::DomainNameAddress(host.clone(), port);

                        debug!(message = "proxy connection",
                            ?src,
                            ?target,
                            relay = ?server.config().addr()
                        );

                        match ProxyStream::connect(
                            server.config(),
                            target,
                            &resolver,
                            server.flow(),
                            &Default::default(),
                        )
                        .await
                        {
                            Ok(proxy) => {
                                if let Err(err) = proxy.proxy(local).await {
                                    warn!(message = "proxy error",
                                        ?err,
                                        ?src,
                                        relay = ?server.config().addr()
                                    );

                                    server.report_failure();
                                }

                                return Ok(());
                            }
                            Err(err) => {
                                warn!(message = "connect proxy failed, try next",
                                    ?err,
                                    ?src,
                                    relay = ?server.config().addr()
                                );

                                server.report_failure()
                            }
                        }
                    }

                    Err(io::Error::new(
                        ErrorKind::NotConnected,
                        "no available proxy",
                    ))
                });
            }
        }));
    }

    join_all(tasks).await;

    Ok(())
}
