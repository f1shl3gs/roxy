use std::io::BufRead;
use std::str::FromStr;
use std::sync::Arc;

use crate::upstream::server::Server;
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
    resolver: Resolver,
}

impl Provider {
    pub fn new(endpoint: String, resolver: Resolver) -> Self {
        Self { endpoint, resolver }
    }

    pub async fn load(&self) -> Result<Vec<Arc<Server>>, Error> {
        let servers = self.fetch().await?;

        Ok(servers
            .into_iter()
            .map(|config| Arc::new(Server::new(config)))
            .collect())
    }

    async fn fetch(&self) -> Result<Vec<ServerConfig>, Error> {
        let client = crate::http::HttpClient::new(self.resolver.clone());
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
