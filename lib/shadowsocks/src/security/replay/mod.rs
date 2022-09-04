mod ppbloom;

use std::time::Duration;

use crate::crypto::CipherKind;
use lru_time_cache::LruCache;
use ppbloom::PingPongBloom;

pub const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;

/// A bloom Filter based protector against replay attack
pub struct ReplayProtector {
    /// Check for duplicated IV/Nonce, for prevent replay attack
    /// https://github.com/shadowsocks/shadowsocks-org/issues/44
    nonce_ppbloom: spin::Mutex<PingPongBloom>,

    /// AEAD2022 specific filter, this protocol has a timestamp, which can already reject
    /// most of the replay requests, so we only need to remember nonce that are in the
    /// valid time range.
    nonce_set: spin::Mutex<LruCache<Vec<u8>, ()>>,
}

impl ReplayProtector {
    /// Create a new ReplayProtector
    pub fn new() -> Self {
        Self {
            nonce_ppbloom: spin::Mutex::new(PingPongBloom::new()),
            nonce_set: spin::Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                SERVER_STREAM_TIMESTAMP_MAX_DIFF * 2,
            ))),
        }
    }

    /// Check if nonce exist or not
    pub fn check_nonce_and_set(&self, kind: CipherKind, nonce: &[u8]) -> bool {
        if kind.is_aead_2022() {
            let mut set = self.nonce_set.lock();
            if set.get(nonce).is_some() {
                return true;
            }

            self.insert(nonce.to_vec(), ());
            return false;
        }

        let mut ppbloom = self.nonce_ppbloom.lock();
        ppbloom.check_and_set(nonce)
    }
}
