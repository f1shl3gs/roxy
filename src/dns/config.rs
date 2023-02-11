use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    pub size: usize,
}

#[derive(Deserialize)]
pub struct RejectConfig {
    pub endpoint: String,
    #[serde(default, with = "humanize::duration::serde_option")]
    pub interval: Option<Duration>,
}

#[derive(Deserialize)]
pub struct HijackConfig {
    pub endpoint: String,
    pub hijack: IpAddr,

    #[serde(default, with = "humanize::duration::serde_option")]
    pub interval: Option<Duration>,
}

#[derive(Deserialize)]
pub struct Config {
    pub listen: String,
    pub upstream: Vec<String>,

    pub cache: Option<CacheConfig>,
    pub hosts: Option<BTreeMap<String, String>>,
    pub reject: Option<RejectConfig>,
    pub hijack: Option<HijackConfig>,
}
