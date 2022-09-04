use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;
use trust_dns_proto::op::{Edns, Query, ResponseCode};
use trust_dns_proto::rr::Record;

use super::server::{Request, Response};

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
    ttl: Duration,
    lru: Arc<Mutex<LruCache<Query, Entry>>>,
}

impl Cache {
    pub fn new(size: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            lru: Arc::new(Mutex::new(LruCache::new(size))),
        }
    }

    pub fn get<'q>(&self, req: &'q Request) -> Option<Response<'q>> {
        let query = req.query();
        let mut cached = self.lru.lock();

        match cached.get(query) {
            Some(entry) => {
                if entry.expire_at > Instant::now() {
                    // cache expired
                    cached.pop(query);
                    return None;
                }

                let mut header = req.header;
                header.set_response_code(ResponseCode::NoError);

                Some(Response::new(
                    header,
                    &req.query,
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

        if cached.contains(query) {
            return;
        }

        cached.put(
            query.clone(),
            Entry {
                expire_at: Instant::now().add(self.ttl),
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
