use std::fmt::{Display, Formatter};
use std::net::AddrParseError;

use trust_dns_proto::error::ProtoError;
use trust_dns_resolver::error::ResolveError;

use crate::dns::rule;

#[derive(Debug)]
pub enum Error {
    UnexpectedClose,

    Resolve(ResolveError),

    InvalidIpAddress(AddrParseError),

    InvalidHostname(ProtoError),

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
