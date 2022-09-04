use std::io::BufRead;
use std::str::FromStr;

use base64::DecodeError;
use hyper::http::uri::InvalidUri;
use hyper::{StatusCode, Uri};
use resolver::Resolver;
use shadowsocks::{ServerConfig, UrlParseError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    InvalidUri(#[from] InvalidUri),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Http(#[from] hyper::Error),
    #[error("unexpected status code {0}")]
    Unexpected(StatusCode),
    #[error("parse server url failed, {0:?}")]
    ServerUrl(UrlParseError),
}

impl From<StatusCode> for Error {
    fn from(s: StatusCode) -> Self {
        Error::Unexpected(s)
    }
}

impl From<UrlParseError> for Error {
    fn from(err: UrlParseError) -> Self {
        Self::ServerUrl(err)
    }
}

pub struct Provider {
    endpoint: String,
}

impl Provider {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    pub async fn fetch(&self, resolver: Resolver) -> Result<Vec<ServerConfig>, Error> {
        let client = crate::http::HttpClient::new(resolver);
        let uri = Uri::from_str(&self.endpoint)?;
        let resp = client.get(uri).await?;

        let (parts, body) = resp.into_parts();
        if parts.status != StatusCode::OK {
            return Err(parts.status.into());
        }

        let data = hyper::body::to_bytes(body).await?;

        base64::decode(data.as_ref())?
            .lines()
            .flatten()
            .map(|url| ServerConfig::from_url(&url).map_err(Into::into))
            .collect::<Result<Vec<ServerConfig>, Error>>()
    }
}
