use std::net::SocketAddr;
use std::sync::Arc;

use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::TokioAsyncResolver;

use crate::dns::error::Error;
use crate::dns::server::{Request, Response};

pub struct Upstream {
    resolver: Arc<TokioAsyncResolver>,
}

impl Upstream {
    pub fn new(addrs: Vec<SocketAddr>) -> Result<Self, ResolveError> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.num_concurrent_reqs = 64; // default is 2, 64 should be large enough

        let mut conf = ResolverConfig::new();
        addrs.into_iter().for_each(|addr| {
            conf.add_name_server(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: false,
                bind_addr: None,
            })
        });

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
            &query,
            lookup.record_iter().cloned().collect::<Vec<_>>(),
            vec![],
            vec![],
            vec![],
            vec![],
            None,
        ))
    }
}
