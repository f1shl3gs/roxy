use std::net::SocketAddr;
use std::sync::Arc;

use resolver::Resolver;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use super::{Error, Request, Response};

pub struct Upstream {
    resolver: Arc<TokioAsyncResolver>,
}

async fn resolve_host(
    resolver: &Resolver,
    host: url::Host<&str>,
    port: u16,
    protocol: Protocol,
) -> Result<Vec<NameServerConfig>, Error> {
    use url::Host;

    let configs = match host {
        Host::Domain(s) => resolver
            .resolve(s, port)
            .await?
            .into_iter()
            .map(|addr| {
                let mut nsc = NameServerConfig::new(addr, protocol);
                nsc.tls_dns_name = Some(s.to_string());

                nsc
            })
            .collect::<Vec<_>>(),
        Host::Ipv4(ip) => {
            vec![NameServerConfig::new(
                SocketAddr::new(ip.into(), port),
                protocol,
            )]
        }
        Host::Ipv6(ip) => {
            vec![NameServerConfig::new(
                SocketAddr::new(ip.into(), port),
                protocol,
            )]
        }
    };

    Ok(configs)
}

async fn build_name_server_config(
    resolver: &Resolver,
    u: &str,
) -> Result<Vec<NameServerConfig>, Error> {
    let u = url::Url::parse(u)
        .map_err(|err| Error::InvalidNameServer(format!("{}, url: {}", err, u)))?;
    let scheme = u.scheme();
    let host = u
        .host()
        .ok_or(Error::InvalidNameServer("no host found".into()))?;

    let configs = match scheme {
        "udp" | "tcp" => {
            let protocol = match scheme {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => unreachable!(),
            };

            let port = u.port().unwrap_or(53);
            resolve_host(resolver, host, port, protocol).await?
        }
        "tls" => {
            let port = u.port().unwrap_or(853);
            resolve_host(resolver, host, port, Protocol::Tls).await?
        }
        _ => return Err(format!("invalid name server scheme of {}", u).into()),
    };

    Ok(configs)
}

impl Upstream {
    pub async fn new(servers: Vec<String>, resolver: &Resolver) -> Result<Self, Error> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.num_concurrent_reqs = 64; // default is 2, 64 should be large enough

        let mut conf = ResolverConfig::new();
        for svr in servers {
            build_name_server_config(resolver, &svr)
                .await?
                .into_iter()
                .for_each(|nsc| conf.add_name_server(nsc));
        }

        let resolver = TokioAsyncResolver::tokio(conf, opts)?;

        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }

    pub async fn resolve<'q>(&self, req: &'q Request) -> Result<Response<'q>, Error> {
        let query = req.query();
        let ips = self.resolver.lookup_ip(query.name().clone()).await?;
        let lookup = ips.as_lookup();

        Ok(Response::new(
            req.header,
            query,
            lookup.record_iter().cloned().collect::<Vec<_>>(),
            vec![],
            vec![],
            vec![],
            vec![],
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse() {
        let n = url::Url::parse("tls://dns.alidns.com").unwrap();
        println!("{:?}", n.to_string());
    }
}
