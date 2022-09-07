use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::DateTime;
use parking_lot::Mutex;
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

/// Statistic of a remote server
#[derive(Clone)]
pub struct Stat {
    /// Median of latency time (in ms)
    ///
    /// Use median instead of average time, because
    /// probing result may have some really bad cases.
    rtt: u32,

    /// Max server's RTT, normally the check timeout milliseconds.
    max_server_rtt: u32,

    /// Total fail / probe
    fail_rate: f64,

    /// Recently probe data
    latency_queue: VecDeque<(u32, Instant)>,

    /// Score's standard deviation
    latency_stdev: f64,

    /// Score's standard deviation MAX
    max_latency_stdev: f64,

    /// Score's average
    latency_mean: f64,

    /// User's customized weight
    user_weight: f32,

    /// Checking window size
    check_window: Duration,
}

impl Serialize for Stat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Latency {
            score: u32,
            timestamp: String,
        }

        let mut s = serializer.serialize_struct("Stat", 9)?;
        s.serialize_field("rtt", &self.rtt)?;
        s.serialize_field("max_server_rtt", &self.max_server_rtt)?;
        s.serialize_field("fail_rate", &self.fail_rate)?;

        let mut queue = Vec::with_capacity(self.latency_queue.len());
        for (score, instant) in &self.latency_queue {
            let elapsed = instant.elapsed();
            let timestamp = SystemTime::now() - elapsed;
            let date = DateTime::from(timestamp);

            queue.push(Latency {
                score: *score,
                timestamp: date.to_string(),
            });
        }
        s.serialize_field("latency_queue", &queue)?;

        s.serialize_field("latency_stdev", &self.latency_stdev)?;
        s.serialize_field("max_latency_stdev", &self.max_latency_stdev)?;
        s.serialize_field("latency_mean", &self.latency_mean)?;
        s.serialize_field("user_weight", &self.user_weight)?;
        s.serialize_field(
            "check_window",
            &format!("{}s", self.check_window.as_secs_f64()),
        )?;

        s.end()
    }
}

fn max_latency_stdev(max: u32) -> f64 {
    let mrtt = max as f64;
    let avg = (0.0 + mrtt) / 2.0;
    let diff1 = (0.0 - avg) * (0.0 - avg);
    let diff2 = (mrtt - avg) * (mrtt - avg);

    (diff1 + diff2).sqrt()
}

impl Stat {
    pub fn new(user_weight: f32, max_server_rtt: u32, check_window: Duration) -> Self {
        assert!((0.0..=1.0).contains(&user_weight));

        Self {
            rtt: max_server_rtt,
            max_server_rtt,
            fail_rate: 1.0,
            latency_queue: Default::default(),
            latency_stdev: 0.0,
            max_latency_stdev: max_latency_stdev(max_server_rtt),
            latency_mean: 0.0,
            user_weight,
            check_window,
        }
    }

    fn score(&self) -> u32 {
        // Normalize rtt
        let nrtt = self.rtt as f64 / self.max_server_rtt as f64;
        // Normlize stdev
        let nstdev = self.latency_stdev / self.max_latency_stdev;

        const SCORE_RTT_WEIGHT: f64 = 1.0;
        const SCORE_FAIL_WEIGHT: f64 = 3.0;
        const SCORE_STDEV_WEIGHT: f64 = 1.0;

        // [EPSILON, 1]
        // Just for avoiding divede by 0
        let user_weight = self.user_weight.max(f32::EPSILON);

        // Score = (norm_lat * 1.0 + prop_err * 3.0 + stdev * 1.0) / 5.0 / user_weight
        //
        // 1. The lower latency, the better
        // 2. The lower errored count, the better
        // 3. The lower latency's stdev, the better
        // 4. The higher user's weight, the better
        let score = (nrtt * SCORE_RTT_WEIGHT
            + self.fail_rate * SCORE_FAIL_WEIGHT
            + nstdev * SCORE_STDEV_WEIGHT)
            / (SCORE_RTT_WEIGHT + SCORE_FAIL_WEIGHT + SCORE_STDEV_WEIGHT)
            / user_weight as f64;

        // Times 10000 converts to u32, for 0.0001 precision
        (score * 10000.0) as u32
    }

    pub fn push_score(&mut self, score: u32) -> u32 {
        let now = Instant::now();

        self.latency_queue.push_back((score, now));

        // Removes stats that are not in the check window
        while let Some((_, timestamp)) = self.latency_queue.front() {
            if now - *timestamp > self.check_window {
                self.latency_queue.pop_front();
            } else {
                break;
            }
        }

        self.recalculate_score()
    }

    fn recalculate_score(&mut self) -> u32 {
        if self.latency_queue.is_empty() {
            return self.score();
        }

        let mut vlat = Vec::with_capacity(self.latency_queue.len());
        let mut cerr = 0;
        for (s, _) in &self.latency_queue {
            if *s == 0 {
                cerr += 1;
            } else {
                vlat.push(*s);
            }
        }

        // Error rate
        self.fail_rate = cerr as f64 / self.latency_queue.len() as f64;

        if !vlat.is_empty() {
            vlat.sort_unstable();

            // Find median of latency
            let mid = vlat.len() / 2;

            self.rtt = if vlat.len() % 2 == 0 {
                (vlat[mid] + vlat[mid - 1]) / 2
            } else {
                vlat[mid]
            };

            if vlat.len() > 1 {
                // STDEV
                let n = vlat.len() as f64;
                let mut total_lat = 0;
                for s in &vlat {
                    total_lat += *s;
                }

                self.latency_mean = total_lat as f64 / n;
                let mut acc_diff = 0.0;
                for s in &vlat {
                    let diff = *s as f64 - self.latency_mean;
                    acc_diff += diff * diff;
                }

                // Corrected Sample Standard Deviation
                self.latency_stdev = ((1.0 / (n - 1.0)) * acc_diff).sqrt();
            }
        }

        self.score()
    }
}

/// Server's statistic score
pub struct Score {
    stat: Mutex<Stat>,
    score: AtomicU32,
}

impl Score {
    /// Create a `Score`
    pub fn new(weight: f32, max_server_rtt: Duration, check_window: Duration) -> Self {
        let max_server_rtt = max_server_rtt.as_millis() as u32;
        assert!(max_server_rtt > 0);

        Self {
            stat: Mutex::new(Stat::new(weight, max_server_rtt, check_window)),
            score: AtomicU32::new(u32::MAX),
        }
    }

    /// Get server's current statistic scores
    #[inline]
    pub fn score(&self) -> u32 {
        self.score.load(Ordering::Acquire)
    }

    /// Append a `Score` into statistic and recalculate score of the server
    pub fn push_score(&self, score: u32) -> u32 {
        let mut stat = self.stat.lock();
        let updated = stat.push_score(score);

        self.score.store(updated, Ordering::Release);
        updated
    }

    pub fn stat(&self) -> Stat {
        let stat = self.stat.lock();
        stat.clone()
    }
}

impl Debug for Score {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Score")
            .field("score", &self.score())
            .finish()
    }
}
