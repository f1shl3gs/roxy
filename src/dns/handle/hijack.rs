use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use resolver::Resolver;
use tokio::time;
use trust_dns_proto::rr::Name;

use crate::dns::config::HijackConfig;
use crate::dns::rule::{self, Error as RuleError, Trie};

pub struct Hijack {
    trie: Arc<RwLock<Trie>>,
    hijack: IpAddr,
}

impl Hijack {
    pub async fn new(config: HijackConfig, resolver: Resolver) -> Result<Self, RuleError> {
        let HijackConfig {
            endpoint,
            hijack,
            interval,
        } = config;

        let (trie, total) = time::timeout(
            Duration::from_secs(60),
            rule::load(&endpoint, resolver.clone()),
        )
        .await??;

        info!(message = "load hijack rules success", total, reload = ?interval);

        let hijacker = Self {
            trie: Arc::new(RwLock::new(trie)),
            hijack,
        };

        if let Some(interval) = interval {
            let endpoint = endpoint;
            let trie = hijacker.trie.clone();

            tokio::spawn(async move {
                loop {
                    time::sleep(interval).await;

                    match rule::load(&endpoint, resolver.clone()).await {
                        Ok((new_trie, total)) => {
                            info!(message = "reload hijack rules success", total);

                            trie.write().swap(new_trie)
                        }
                        Err(err) => {
                            warn!(message = "reload hijack rules failed", ?err);
                        }
                    }
                }
            });
        }

        Ok(hijacker)
    }

    #[inline]
    pub fn hijacking(&self, name: &Name) -> Option<IpAddr> {
        let trie = self.trie.read();

        if trie.contains(name) {
            Some(self.hijack)
        } else {
            None
        }
    }
}
