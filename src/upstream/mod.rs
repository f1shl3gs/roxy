// mod balancer;
mod checker;
mod config;
mod error;
mod hash;
mod provider;
mod server;

use std::net::AddrParseError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub use config::Config;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use hash::{fnv, jumphash};
use publicsuffix::effective_tld_plus_one;
use resolver::Resolver;
use server::{Server, Stat};
use tokio::sync::RwLock;
use tokio::time;

use crate::upstream::config::LoadBalanceType;
use crate::upstream::provider::Provider;

struct Peers {
    servers: Vec<Arc<Server>>,
    best: AtomicUsize,
}

impl Peers {
    fn new(servers: Vec<Arc<Server>>) -> Self {
        Self {
            servers,
            best: AtomicUsize::new(0),
        }
    }

    fn servers(&self) -> Vec<Arc<Server>> {
        self.servers.clone()
    }

    fn best(&self) -> Arc<Server> {
        let best = &self.servers[self.best.load(Ordering::Relaxed)];
        if best.alive() {
            return best.clone();
        }

        self.fallback()
    }

    fn by_etld(&self, host: &str) -> Arc<Server> {
        let servers = &self.servers;

        let etld = effective_tld_plus_one(host).unwrap_or(host);
        let mut key = fnv(etld.as_bytes());
        let buckets = servers.len();

        for _i in 0..5 {
            let index = jumphash(key, buckets as i64);
            let svr = &servers[index as usize];
            if svr.alive() {
                return svr.clone();
            }

            key += 1;
        }

        warn!(
            message = "pick tcp server by etld+1 failed, use first alive peer",
            host
        );

        self.fallback()
    }

    fn fallback(&self) -> Arc<Server> {
        for svr in &self.servers {
            if svr.alive() {
                return svr.clone();
            }
        }

        warn!("no alive proxy, return the first one");

        self.servers[0].clone()
    }

    async fn check_all(self: Arc<Self>, interval: Duration, timeout: Duration, resolver: Resolver) {
        loop {
            time::sleep(interval).await;

            self.check_once(timeout, false, resolver.clone()).await;
            trace!(message = "finished initializing server scores");
        }
    }

    async fn check_once(&self, timeout: Duration, first_run: bool, resolver: Resolver) {
        let servers = &self.servers;
        if servers.is_empty() {
            return;
        }

        let tasks = FuturesUnordered::new();
        for server in servers {
            tasks.push(
                checker::Checker::new(server.clone(), resolver.clone(), timeout)
                    .check_update_score(),
            );
        }

        let _n = tasks.collect::<Vec<_>>().await;

        let mut best_index = 0;
        let mut best_latency = u32::MAX;
        for (index, server) in servers.iter().enumerate() {
            let latency = server.latency();
            if latency == 0 {
                // not alive
                continue;
            }

            if latency < best_latency {
                best_index = index;
                best_latency = latency;
            }
        }

        self.best.store(best_index, Ordering::Relaxed);

        let best = &self.servers[best_index];
        let addr = best.config().addr().to_string();
        if first_run {
            info!(message = "choose best server", addr,);
        } else {
            info!(message = "switch best server", addr,);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("resolver must be IP address, {0}")]
    InvalidResolverAddr(#[from] AddrParseError),

    #[error(transparent)]
    Provider(#[from] provider::Error),
}

#[derive(Clone)]
pub struct Upstream {
    peers: Arc<RwLock<Arc<Peers>>>,
    lb_type: LoadBalanceType,
}

impl Upstream {
    pub async fn new(config: Config, resolver: Resolver) -> Result<Self, Error> {
        let check = config.check;
        let provider = Provider::new(config.provider.endpoint, resolver.clone());
        let servers = provider.load().await?;

        info!(
            message = "load proxy servers success",
            total = servers.len()
        );

        let peers = Arc::new(RwLock::new(Arc::new(Peers::new(servers))));
        {
            let cp = peers.read().await;

            // first check
            cp.check_once(check.timeout, true, resolver.clone()).await;
        }

        let cp = peers.clone();
        let cr = resolver.clone();
        tokio::spawn(async move {
            loop {
                time::sleep(check.interval).await;

                cp.read()
                    .await
                    .check_once(check.timeout, false, cr.clone())
                    .await;
            }
        });

        // update servers periodically
        {
            let peers = peers.clone();
            let interval = config.provider.interval;
            let timeout = check.timeout;

            tokio::spawn(async move {
                loop {
                    time::sleep(interval).await;

                    match provider.load().await {
                        Ok(servers) => {
                            let new = Peers::new(servers);
                            new.check_once(timeout, true, resolver.clone()).await;

                            let mut p = peers.write().await;
                            *p = Arc::new(new);

                            info!(message = "update servers success", total = p.servers.len());
                        }
                        Err(err) => {
                            warn!(message = "reload servers failed", ?err);
                        }
                    }
                }
            });
        }

        Ok(Self {
            peers,
            lb_type: config.load_balance,
        })
    }

    pub async fn pick(&self, host: &str) -> Arc<Server> {
        let peers = self.peers.read().await;

        match self.lb_type {
            LoadBalanceType::Best => peers.best(),
            LoadBalanceType::Etld => peers.by_etld(host),
        }
    }

    pub async fn stats(&self) -> Vec<Stat> {
        let mut stats = vec![];
        let peers = self.peers.read().await;

        for svr in &peers.servers {
            stats.push(svr.stat());
        }

        stats
    }
}
