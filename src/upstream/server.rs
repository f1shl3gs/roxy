use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use parking_lot::Mutex;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use shadowsocks::{FlowStat, ServerConfig};

use crate::DateTime;

const MAX_HISTORY: usize = 10;

#[derive(Clone)]
struct Latency {
    timestamp: Instant,
    value: u32,
}

impl Serialize for Latency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Latency", 2)?;

        let system_now = SystemTime::now();
        let instant_now = Instant::now();
        let approx = system_now - (instant_now - self.timestamp);
        let datetime = DateTime::from(approx);

        s.serialize_field("timestamp", &datetime.to_string())?;
        s.serialize_field("value", &self.value)?;

        s.end()
    }
}

pub struct Server {
    config: ServerConfig,
    flow: Arc<FlowStat>,

    latencies: Mutex<VecDeque<Latency>>,
}

impl Server {
    #[inline]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn remarks(&self) -> Option<&String> {
        self.config.remarks()
    }

    pub fn flow(&self) -> Arc<FlowStat> {
        self.flow.clone()
    }

    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            flow: Arc::new(FlowStat::default()),
            latencies: Mutex::new(VecDeque::with_capacity(MAX_HISTORY)),
        }
    }

    #[inline]
    pub fn alive(&self) -> bool {
        let history = self.latencies.lock();
        let latency = history.back().expect("at least on latency saved");
        latency.value > 0
    }

    #[inline]
    pub fn report_failure(&self) {
        self.push_latency(0);
    }

    pub fn push_latency(&self, value: u32) {
        let mut history = self.latencies.lock();

        if history.len() == MAX_HISTORY {
            history.pop_front();
        }

        history.push_back(Latency {
            timestamp: Instant::now(),
            value,
        });
    }

    pub fn stat(&self) -> Stat {
        let config = &self.config;
        let latencies = { self.latencies.lock().clone() };
        let (recv, sent) = self.flow.load();

        Stat {
            remarks: config.remarks().cloned(),
            address: config.addr().to_string(),
            recv,
            sent,
            latencies,
        }
    }

    pub fn latency(&self) -> u32 {
        let history = self.latencies.lock();
        history.back().expect("not empty").value
    }
}

#[derive(Serialize)]
pub struct Stat {
    remarks: Option<String>,
    address: String,
    recv: usize,
    sent: usize,
    latencies: VecDeque<Latency>,
}
