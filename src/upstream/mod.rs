mod balancer;
mod config;
mod error;
mod provider;

use std::net::AddrParseError;

pub use balancer::{BalanceError, Balancer};
pub use config::Config;
use resolver::Resolver;

pub struct Upstream {
    balancer: Balancer,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("resolver must be IP address, {0}")]
    InvalidResolverAddr(#[from] AddrParseError),
    #[error(transparent)]
    Balancer(#[from] BalanceError),
}

impl Upstream {
    pub async fn new(config: Config, resolver: Resolver) -> Result<Self, Error> {
        let balancer =
            Balancer::new(resolver, config.load_balance, config.check, config.provider).await?;

        Ok(Self { balancer })
    }

    pub fn balancer(&self) -> Balancer {
        self.balancer.clone()
    }
}
