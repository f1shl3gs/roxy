use std::time::Duration;

use serde::Deserialize;

/// Interval between each check
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// Timeout of each check
pub const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(5); // A common connection timeout of 5 seconds.

const fn default_check_timeout() -> Duration {
    DEFAULT_CHECK_TIMEOUT
}

const fn default_check_interval() -> Duration {
    DEFAULT_CHECK_INTERVAL
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceType {
    #[default]
    Best,
    Etld,
}

#[derive(Deserialize)]
pub struct CheckConfig {
    #[serde(with = "humanize::duration::serde", default = "default_check_timeout")]
    pub timeout: Duration,
    #[serde(with = "humanize::duration::serde", default = "default_check_interval")]
    pub interval: Duration,
}

#[derive(Deserialize)]
pub struct ProviderConfig {
    pub endpoint: String,

    #[serde(with = "humanize::duration::serde")]
    pub interval: Duration,
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    pub load_balance: LoadBalanceType,

    pub check: CheckConfig,

    pub provider: ProviderConfig,
}
