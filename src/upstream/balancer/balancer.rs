use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::StreamExt;
use futures_util::stream::FuturesUnordered;
use publicsuffix::effective_tld_plus_one;
use resolver::Resolver;
use serde::Serialize;
use shadowsocks::ServerConfig;
use tokio::time;

use super::checker::{CheckType, Checker};
use super::hash::{fnv, jumphash};
use super::score::Score;
use crate::upstream::config::{CheckConfig, LoadBalanceType, ProviderConfig};
use crate::upstream::provider;
use crate::upstream::provider::Provider;

pub struct Server {
    config: ServerConfig,

    tcp_score: Score,
    udp_score: Score,
}

impl Server {
    #[inline]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    #[inline]
    pub fn tcp_score(&self) -> &Score {
        &self.tcp_score
    }

    #[inline]
    pub fn udp_score(&self) -> &Score {
        &self.udp_score
    }

    #[inline]
    pub fn report_failure(&self) {
        self.tcp_score.push_score(0);
        self.udp_score.push_score(0);
    }

    #[inline]
    pub fn remarks(&self) -> Option<&String> {
        self.config.remarks()
    }
}

struct BalancerInner {
    servers: Vec<Arc<Server>>,
    best_udp: AtomicUsize,
    best_tcp: AtomicUsize,

    resolver: Resolver,
    interval: Duration,
    timeout: Duration,
}

impl BalancerInner {
    /// Check each servers' score and update the best server's index
    async fn check_once(&self, first_run: bool) {
        let servers = &self.servers;
        if servers.is_empty() {
            return;
        }

        let mut vfut_tcp = Vec::with_capacity(servers.len());
        let mut vfut_udp = Vec::with_capacity(servers.len());

        for server in servers {
            let conf = server.config();

            if conf.tcp_enabled() {
                let checker = Checker::new(
                    server.clone(),
                    CheckType::Tcp,
                    self.resolver.clone(),
                    self.timeout,
                );

                vfut_tcp.push(checker.check_update_score());
            }

            // if conf.udp_enabled() {
            //     let checker = Checker::new(
            //         server.clone(),
            //         CheckType::Udp,
            //         self.resolver.clone(),
            //         self.timeout,
            //     );
            //
            //     vfut_udp.push(checker.check_update_score());
            // }
        }

        let check_tcp = vfut_tcp.len() > 1;
        let check_udp = vfut_udp.len() > 1;

        if !check_tcp && !check_udp {
            return;
        }

        let vfut = if !check_tcp {
            vfut_udp
        } else if !check_udp {
            vfut_tcp
        } else {
            vfut_tcp.append(&mut vfut_udp);
            vfut_tcp
        };

        // spawn all futures and wait
        vfut.into_iter()
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await;

        if check_tcp {
            let old_best_idx = self.best_tcp.load(Ordering::Acquire);
            let old_best = servers[old_best_idx].config();
            let mut old_best_score = u32::MAX;
            let mut best_idx = 0;
            let mut best_score = u32::MAX;
            for (idx, server) in servers.iter().enumerate() {
                let score = server.tcp_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }

                if idx == old_best_idx {
                    old_best_score = score;
                }
            }

            let best = servers[best_idx].config();
            if first_run {
                self.best_tcp.store(best_idx, Ordering::Release);

                debug!(
                    message = "chose best TCP server",
                    addr = %best.addr()
                );
            } else if should_switch(old_best_score, best_score) {
                self.best_tcp.store(best_idx, Ordering::Release);

                info!(
                    message = "switched best TCP server",
                    from = %old_best.addr(),
                    to = %best.addr(),
                    scores = format!("{}->{}", old_best_score, best_score)
                );
            } else {
                debug!(
                    message = "kept best TCP server",
                    addr = %best.addr(),
                );
            }
        }

        if check_udp {
            let old_best_idx = self.best_udp.load(Ordering::Acquire);
            let old_best = servers[old_best_idx].config();
            let mut best_idx = 0;
            let mut best_score = u32::MAX;
            let mut old_best_score = u32::MAX;
            for (idx, server) in servers.iter().enumerate() {
                let score = server.udp_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }

                if idx == old_best_idx {
                    old_best_score = score
                }
            }

            let best = servers[best_idx].config();
            if first_run {
                self.best_udp.store(best_idx, Ordering::Release);

                debug!(
                    message = "chose best UDP server",
                    addr = %best.addr()
                );
            } else if should_switch(old_best_score, best_score) {
                self.best_udp.store(best_idx, Ordering::Release);

                info!(
                    message = "switched best UDP server",
                    from = %old_best.addr(),
                    to = %best.addr(),
                    scores = format!("{}->{}", old_best_score, best_score)
                );
            } else {
                // best no changed, or it is not that best
                debug!(
                    message = "kept best UDP server",
                    addr = %best.addr()
                );
            }
        }
    }

    async fn check_all(self: Arc<Self>) {
        debug!(
            message = "start check loop",
            interval = ?self.interval,
        );

        loop {
            time::sleep(self.interval).await;

            self.check_once(false).await;
            trace!(message = "finished initializing server scores");
        }
    }
}

fn should_switch(old: u32, new: u32) -> bool {
    // old best is still
    if old < 200 {
        return false;
    }

    // if the new score is 10% larger than old one
    (old - new) as f64 / old as f64 > 0.1
}

#[derive(Debug, thiserror::Error)]
pub enum BalanceError {
    #[error("init server provider failed, {0}")]
    Provider(#[from] provider::Error),
    #[error("no server provided")]
    NoServerProvided,
}

#[derive(Clone)]
pub struct Balancer {
    inner: Arc<BalancerInner>,
    lb_typ: LoadBalanceType,
}

impl Balancer {
    pub async fn new(
        resolver: Resolver,
        lb_typ: LoadBalanceType,
        cc: CheckConfig,
        pc: ProviderConfig,
    ) -> Result<Self, BalanceError> {
        let provider = Provider::new(pc.endpoint);

        let servers = provider
            .fetch(resolver.clone())
            .await?
            .into_iter()
            .map(|config| {
                let tcp_weight = config.weight().tcp_weight();
                let udp_weight = config.weight().udp_weight();
                let inner = Server {
                    config,
                    tcp_score: Score::new(tcp_weight, cc.timeout, cc.interval),
                    udp_score: Score::new(udp_weight, cc.timeout, cc.interval),
                };

                Arc::new(inner)
            })
            .collect::<Vec<Arc<Server>>>();

        if servers.is_empty() {
            return Err(BalanceError::NoServerProvided);
        }

        info!(message = "fetch servers success", total = servers.len());

        let inner = BalancerInner {
            servers,
            best_udp: Default::default(),
            best_tcp: Default::default(),
            resolver,
            interval: cc.interval,
            timeout: cc.timeout,
        };

        inner.check_once(true).await;

        let inner = Arc::new(inner);
        tokio::spawn(inner.clone().check_all());

        Ok(Self { inner, lb_typ })
    }

    /// Pick the best TCP server
    fn best_tcp_server(&self) -> Arc<Server> {
        let inner = &self.inner;

        inner.servers[inner.best_tcp.load(Ordering::Relaxed)].clone()
    }

    #[inline]
    pub fn pick_tcp_server(&self, host: &str) -> Arc<Server> {
        match self.lb_typ {
            LoadBalanceType::Best => self.best_tcp_server(),
            LoadBalanceType::Etld => self.pick_tcp_server_by_etld(host),
        }
    }

    fn pick_tcp_server_by_etld(&self, host: &str) -> Arc<Server> {
        let servers = &self.inner.servers;
        let etld = effective_tld_plus_one(host).unwrap_or(host);
        let mut key = fnv(etld.as_bytes());
        let buckets = servers.len();

        for _i in 0..5 {
            let idx = jumphash(key, buckets as i64);
            let svr = &servers[idx as usize];
            if svr.tcp_score.score() < 2000 {
                return svr.clone();
            }

            key += 1;
        }

        warn!(
            message = "pick tcp server by etld+1 failed, use first alive proxy",
            host
        );

        for svr in servers {
            if svr.tcp_score().score() < 8000 {
                return svr.clone();
            }
        }

        warn!(message = "no alive proxy, return the first one");
        servers[0].clone()
    }

    /// Pick the best UDP server
    pub fn best_udp_server(&self) -> Arc<Server> {
        let inner = &self.inner;

        inner.servers[inner.best_udp.load(Ordering::Relaxed)].clone()
    }

    /// Get the server list
    pub fn servers(&self) -> ServerIter<'_> {
        let inner = &self.inner;
        let servers: &Vec<Arc<Server>> = unsafe { &*(&inner.servers as *const _) };

        ServerIter {
            iter: servers.iter(),
        }
    }

    pub fn stats(&self) -> Vec<ServerStats> {
        self.servers()
            .map(|svr| {
                let config = svr.config.clone();
                let tcp_score = svr.tcp_score().score();
                let udp_score = svr.udp_score().score();

                ServerStats {
                    addr: config.addr().to_string(),
                    remarks: config.remarks().cloned(),
                    tcp_score,
                    udp_score,
                }
            })
            .collect()
    }
}

#[derive(Serialize)]
pub struct ServerStats {
    pub addr: String,
    pub remarks: Option<String>,
    pub tcp_score: u32,
    pub udp_score: u32,
}

pub struct ServerIter<'a> {
    iter: std::slice::Iter<'a, Arc<Server>>,
}

impl<'a> Iterator for ServerIter<'a> {
    type Item = &'a Server;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(AsRef::as_ref)
    }
}
