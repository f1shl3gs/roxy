use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;

use futures_util::future::join_all;
use resolver::Resolver;
use serde::{Deserialize, Serialize};
use shadowsocks::{Address, ProxyStream};
use tokio::net::TcpListener;

use super::sniffing::destination_addr;
use crate::upstream::Balancer;

#[derive(Deserialize, Serialize)]
pub struct Config {
    listen: Vec<SocketAddr>,
}

pub async fn serve(config: Config, balancer: Balancer, resolver: Resolver) -> io::Result<()> {
    let mut tasks = vec![];

    for addr in config.listen {
        let listener = TcpListener::bind(addr).await?;
        info!(
            message = "start transparent http proxy server",
            listen = ?addr,
        );

        let balancer = balancer.clone();
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (mut local, src) = listener.accept().await.expect("listen success");
                let balancer = balancer.clone();
                let resolver = resolver.clone();

                tokio::spawn(async move {
                    match destination_addr(&mut local).await {
                        Ok((host, port)) => {
                            let server = balancer.pick_tcp_server(&host);
                            let target = Address::DomainNameAddress(host, port);

                            debug!(message = "proxy connection", ?src, ?target, relay = ?server.config().remarks());

                            let proxy = ProxyStream::connect(
                                server.config(),
                                target,
                                &resolver,
                                &Default::default(),
                            )
                            .await?;

                            proxy.proxy(local).await?;

                            Ok(())
                        }
                        Err(err) => {
                            warn!(message = "sniff hostname failed", ?err, ?src);
                            Err(io::Error::new(ErrorKind::Other, err))
                        }
                    }
                });
            }
        }));
    }

    join_all(tasks).await;

    Ok(())
}
