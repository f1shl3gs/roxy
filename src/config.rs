use std::fmt::Formatter;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serializer};
use tracing::Level;

use crate::relay::thp;
use crate::{controller, dns, upstream};

const fn default_timestamp() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(
        deserialize_with = "deserialize_log_level",
        serialize_with = "serialize_log_level"
    )]
    pub level: Level,

    #[serde(default = "default_timestamp")]
    pub timestamp: bool,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            timestamp: true,
        }
    }
}

#[derive(Deserialize)]
pub struct Config {
    /// Worker threads for tokio runtime, if it is not set,
    /// use num_cpu::get()
    pub worker: Option<usize>,

    #[serde(default)]
    pub resolvers: Vec<SocketAddr>,

    /// Configuration for tracing logs
    #[serde(default)]
    pub log: Log,

    #[cfg(feature = "dns")]
    pub dns: dns::Config,

    // TODO: make controller optional
    pub controller: Option<controller::Config>,

    pub upstream: upstream::Config,

    pub thp: Option<thp::Config>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("read config failed, {0}")]
    Io(#[from] std::io::Error),

    #[error("deserialize config failed, {0}")]
    Deserialize(#[from] serde_yaml::Error),
}

impl Config {
    pub fn load() -> Result<Self, Error> {
        let content = match std::env::var("ROXY_CONFIG") {
            Ok(path) => std::fs::read(path),
            _ => std::fs::read("config.yaml"),
        }?;

        let cfg = serde_yaml::from_slice::<Config>(content.as_slice())?;

        Ok(cfg)
    }

    pub fn worker(&self) -> usize {
        if let Some(worker) = self.worker {
            worker
        } else {
            num_cpus::get()
        }
    }
}

fn deserialize_log_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor {}

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Level;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("trace, debug, info, warn and error")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Level::from_str(v)
                .map_err(|err| serde::de::Error::custom(format!("invalid level {}", err)))
        }
    }

    deserializer.deserialize_any(Visitor {})
}

fn serialize_log_level<S>(l: &Level, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(l.as_str())
}
