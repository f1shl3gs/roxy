mod cache;
mod hijack;
mod reject;
mod upstream;

use std::collections::BTreeMap;
use std::net::IpAddr;

use cache::Cache;
use hijack::Hijack;
use reject::Reject;
use resolver::Resolver;
use trust_dns_proto::rr::{RData, Record};
use upstream::Upstream;

use super::config::{CacheConfig, HijackConfig, RejectConfig};
use super::{Error, Request, Response};
use crate::dns::UpstreamConfig;

pub struct Handler {
    cache: Option<Cache>,
    hijacker: Option<Hijack>,
    reject: Option<Reject>,
    upstream: Upstream,
}

impl Handler {
    pub async fn new(
        cache: Option<CacheConfig>,
        _hosts: Option<BTreeMap<String, String>>,
        reject: Option<RejectConfig>,
        hijack: Option<HijackConfig>,
        upstream: UpstreamConfig,
        resolver: Resolver,
    ) -> Result<Self, Error> {
        let cache = cache.map(|c| Cache::new(c.size));

        let reject = match reject {
            Some(rc) => {
                let reject = Reject::new(rc, resolver.clone())
                    .await
                    .map_err(Error::Reject)?;
                Some(reject)
            }
            None => None,
        };

        let hijacker = match hijack {
            Some(hc) => Some(
                Hijack::new(hc, resolver.clone())
                    .await
                    .map_err(Error::Hijack)?,
            ),
            None => None,
        };

        let upstream = Upstream::new(upstream.nameservers, &resolver).await?;

        Ok(Self {
            cache,
            reject,
            hijacker,
            upstream,
        })
    }

    pub async fn handle<'q>(&self, req: &'q Request) -> Result<Response<'q>, Error> {
        let name = req.query().name();

        // try cache
        if let Some(cache) = &self.cache {
            if let Some(resp) = cache.get(req) {
                return Ok(resp);
            }
        }

        // hijack
        if let Some(hijacker) = &self.hijacker {
            if let Some(to) = hijacker.hijacking(name) {
                debug!(message = "hijack dns request", ?name, ?to);

                let name = name.clone();
                let mut resp = Response::from_request(req);
                let rdata = match to {
                    IpAddr::V4(addr) => RData::A(addr),
                    IpAddr::V6(addr) => RData::AAAA(addr),
                };

                resp.answers.push(Record::from_rdata(name, 60 * 60, rdata));

                return Ok(resp);
            }
        }

        // try reject
        if let Some(reject) = &self.reject {
            if reject.deny(name) {
                debug!(message = "request match reject rules", ?name,);

                return Ok(Response::no_records(req.header, req.query()));
            }
        }

        // try upstream
        match (self.upstream.resolve(req).await, &self.cache) {
            (Ok(resp), Some(cache)) => {
                cache.put(&resp);
                Ok(resp)
            }
            (result, _) => result,
        }
    }
}
