use std::fmt::{Display, Formatter};
use std::net::AddrParseError;

use trust_dns_resolver::error::ResolveError;

use crate::dns::rule;

#[derive(Debug)]
pub enum Error {
    Resolve(ResolveError),

    InvalidIpAddress(AddrParseError),

    Reject(rule::Error),

    Hijack(rule::Error),
}

impl Display for Error {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl std::error::Error for Error {}

impl From<ResolveError> for Error {
    fn from(err: ResolveError) -> Self {
        Self::Resolve(err)
    }
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Self::InvalidIpAddress(err)
    }
}
