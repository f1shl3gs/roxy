use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct CacheConfig {
    pub size: usize,
    #[serde(with = "crate::serde::duration")]
    pub ttl: Duration,
}

#[derive(Deserialize)]
pub struct UpstreamConfig {
    pub(crate) nameservers: Vec<SocketAddr>,
}

#[derive(Deserialize)]
pub struct RejectConfig {
    pub endpoint: String,
    #[serde(default, with = "crate::serde::duration::option")]
    pub interval: Option<Duration>,
}

#[derive(Deserialize)]
pub struct HijackConfig {
    pub endpoint: String,
    pub hijack: IpAddr,

    #[serde(default, with = "crate::serde::duration::option")]
    pub interval: Option<Duration>,
}

#[derive(Deserialize)]
pub struct Config {
    pub listen: String,
    pub cache: Option<CacheConfig>,
    pub upstream: UpstreamConfig,
    pub hosts: Option<BTreeMap<String, String>>,
    pub reject: Option<RejectConfig>,
    pub hijack: Option<HijackConfig>,
}
