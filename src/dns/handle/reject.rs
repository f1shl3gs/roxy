use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use resolver::Resolver;
use tokio::time;
use trust_dns_proto::rr::Name;

use crate::dns::{
    config::RejectConfig,
    rule,
    rule::{Error, Trie},
};

pub struct Reject {
    trie: Arc<RwLock<Trie>>,
}

impl Reject {
    pub async fn new(config: RejectConfig, resolver: Resolver) -> Result<Self, Error> {
        let RejectConfig { endpoint, interval } = config;

        let (trie, total) = time::timeout(
            Duration::from_secs(60),
            rule::load(&endpoint, resolver.clone()),
        )
        .await??;

        info!(message = "load reject rules success", total, reload = ?interval);

        let rejector = Reject {
            trie: Arc::new(RwLock::new(trie)),
        };

        if let Some(interval) = interval {
            let endpoint = endpoint;
            let trie = rejector.trie.clone();

            tokio::spawn(async move {
                loop {
                    time::sleep(interval).await;

                    match rule::load(&endpoint, resolver.clone()).await {
                        Ok((new_trie, total)) => {
                            info!(message = "reload reject rules success", total);

                            trie.write().swap(new_trie)
                        }
                        Err(err) => {
                            warn!(message = "reload reject rules failed", ?err);
                        }
                    }
                }
            });
        }

        Ok(rejector)
    }

    #[inline]
    pub fn deny(&self, name: &Name) -> bool {
        let trie = self.trie.read();
        trie.contains(name)
    }
}
