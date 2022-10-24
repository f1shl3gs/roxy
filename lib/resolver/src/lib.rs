use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
pub use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Clone)]
pub struct Resolver(Arc<TokioAsyncResolver>);

impl Resolver {
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>) -> Result<Self, ResolveError> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.num_concurrent_reqs = 128;

        let mut conf = ResolverConfig::new();
        addrs.into_iter().for_each(|addr| {
            conf.add_name_server(NameServerConfig::new(addr, Protocol::Udp))
        });

        let resolver = TokioAsyncResolver::tokio(conf, opts)?;

        Ok(Self(Arc::new(resolver)))
    }

    pub fn from(resolver: TokioAsyncResolver) -> Self {
        Self(Arc::new(resolver))
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
        let lu = self.0.lookup_ip(host).await?;
        let addrs = lu.into_iter().map(|ip| SocketAddr::new(ip, port)).collect::<Vec<_>>();
        Ok(addrs)
    }

    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
        let li = self.0.lookup_ip(host).await?;
        let addrs = li
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();

        Ok(addrs)
    }

    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let li = self.0.lookup_ip(host).await?;
        let addrs = li.iter().collect::<Vec<_>>();

        Ok(addrs)
    }

    pub fn inner(&self) -> Arc<TokioAsyncResolver> {
        self.0.clone()
    }
}
