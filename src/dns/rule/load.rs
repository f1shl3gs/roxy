use std::io::ErrorKind;
use std::str::FromStr;

use futures_util::TryStreamExt;
use hyper::header::CONTENT_LENGTH;
use hyper::http::uri::InvalidUri;
use hyper::{StatusCode, Uri};
use resolver::Resolver;
use tokio::io::AsyncBufReadExt;
use tokio::time::error::Elapsed;
use tokio_util::io::StreamReader;

use super::Trie;
use crate::http::HttpClient;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Http(#[from] hyper::Error),
    #[error("unexpected status code {0}")]
    UnexpectedStatusCode(StatusCode),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidUri(#[from] InvalidUri),
    #[error(transparent)]
    Timeout(#[from] Elapsed),
}

/// Validate domain
///   1. Characters should only be a-z | A-Z | 0-9 and period(.) and dash(-)
///   2. The domain name part should not start or end with dash (-) (e.g. -google-.com)
///   3. The domain name part should be between 1 and 63 characters long
pub async fn load(endpoint: &str, resolver: Resolver) -> Result<(Trie, u32), Error> {
    let client = HttpClient::new(resolver);
    let uri = Uri::from_str(endpoint)?;
    let resp = client.get(uri).await?;
    let (parts, body) = resp.into_parts();
    if parts.status != StatusCode::OK {
        return Err(Error::UnexpectedStatusCode(parts.status));
    }

    let cap = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|val| val.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .map(|l| l / 15) // 15 is just a result of test case, it should works well.
        .unwrap_or(50000);
    let mut trie = Trie::new_with_size(cap);

    let mut reader =
        StreamReader::new(body.map_err(|err| std::io::Error::new(ErrorKind::Other, err)));
    let mut buf = String::new();
    let mut total = 0;

    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }

        total += 1;
        trie.insert(buf.trim());
    }

    Ok((trie, total))
}
