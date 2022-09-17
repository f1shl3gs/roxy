use std::cmp;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru_cache::LruCache;
use parking_lot::Mutex;
use trust_dns_proto::op::{Edns, Query, ResponseCode};
use trust_dns_proto::rr::Record;

use crate::dns::Request;
use crate::dns::Response;

const MAX_RECORD_TTL: u32 = 24 * 60 * 60;

pub struct Entry {
    expire_at: Instant,

    answers: Vec<Record>,
    name_servers: Vec<Record>,
    soa: Vec<Record>,
    additionals: Vec<Record>,
    sig0: Vec<Record>,
    edns: Option<Edns>,
}

pub struct Cache {
    lru: Arc<Mutex<LruCache<Query, Entry>>>,
}

impl Cache {
    pub fn new(size: usize) -> Self {
        Self {
            lru: Arc::new(Mutex::new(LruCache::new(size))),
        }
    }

    pub fn get<'q>(&self, req: &'q Request) -> Option<Response<'q>> {
        let query = req.query();
        let mut cached = self.lru.lock();

        match cached.get_mut(query) {
            Some(entry) => {
                if entry.expire_at > Instant::now() {
                    // cache expired
                    cached.remove(query);
                    return None;
                }

                let mut header = req.header;
                header.set_response_code(ResponseCode::NoError);

                Some(Response::new(
                    header,
                    req.query(),
                    entry.answers.clone(),
                    entry.name_servers.clone(),
                    entry.soa.clone(),
                    entry.additionals.clone(),
                    entry.sig0.clone(),
                    entry.edns.clone(),
                ))
            }
            None => None,
        }
    }

    pub fn put(&self, resp: &Response) {
        let query = resp.query;
        let mut cached = self.lru.lock();

        if cached.contains_key(query) {
            return;
        }

        let ttl = resp
            .answers
            .iter()
            .fold(MAX_RECORD_TTL, |m, record| cmp::min(m, record.ttl()));

        cached.insert(
            query.clone(),
            Entry {
                expire_at: Instant::now().add(Duration::from_secs(ttl as u64)),
                answers: resp.answers.clone(),
                name_servers: resp.name_servers.clone(),
                soa: resp.soa.clone(),
                additionals: resp.additionals.clone(),
                sig0: resp.sig0.clone(),
                edns: resp.edns.clone(),
            },
        );
    }
}
