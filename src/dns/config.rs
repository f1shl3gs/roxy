use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct CacheConfig {
    pub size: usize,
    #[serde(with = "crate::serde::duration")]
    pub ttl: Duration,
}

#[derive(Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub(crate) nameservers: Vec<SocketAddr>,
}

#[derive(Deserialize, Serialize)]
pub struct RejectConfig {
    pub endpoint: String,
    #[serde(default, with = "crate::serde::duration::option")]
    pub interval: Option<Duration>,
}

#[derive(Deserialize, Serialize)]
pub struct HijackConfig {
    pub endpoint: String,
    pub hijack: IpAddr,

    #[serde(default, with = "crate::serde::duration::option")]
    pub interval: Option<Duration>,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub listen: String,
    pub cache: Option<CacheConfig>,
    pub upstream: UpstreamConfig,
    pub hosts: Option<BTreeMap<String, String>>,
    pub reject: Option<RejectConfig>,
    pub hijack: Option<HijackConfig>,
}