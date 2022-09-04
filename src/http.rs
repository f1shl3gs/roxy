use hyper::client::HttpConnector;
use hyper::{Body, Client, Response, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};

pub struct HttpClient(Client<HttpsConnector<HttpConnector<sealed::Resolver>>>);

impl HttpClient {
    pub fn new(r: resolver::Resolver) -> Self {
        // hyper's HttpConnector will check scheme by default, it has to be disabled
        // to get https resources.
        let mut hc = HttpConnector::new_with_resolver(sealed::Resolver::new(r));
        hc.enforce_http(false);

        let hc = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(hc);

        Self(Client::builder().build(hc))
    }

    #[inline]
    pub async fn get(&self, uri: Uri) -> Result<Response<Body>, hyper::Error> {
        self.0.get(uri).await
    }
}

mod sealed {
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::vec::IntoIter;

    use hyper::client::connect::dns::Name;
    use hyper::service::Service;
    use resolver::ResolveError;

    #[derive(Clone)]
    pub struct Resolver {
        inner: resolver::Resolver,
    }

    impl Resolver {
        pub fn new(resolver: resolver::Resolver) -> Self {
            Self { inner: resolver }
        }
    }

    impl Service<Name> for Resolver {
        type Response = IntoIter<SocketAddr>;
        type Error = ResolveError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, name: Name) -> Self::Future {
            let r = self.inner.clone();

            Box::pin(async move { Ok(r.lookup(name.as_str(), 0).await?.into_iter()) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Uri;
    use resolver::Resolver;
    use std::time::Instant;

    #[tokio::test]
    async fn request() {
        let cli =
            HttpClient::new(Resolver::new(vec!["114.114.114.114:53".parse().unwrap()]).unwrap());

        let uris = [
            "http://detectportal.firefox.com/success.txt",
            "https://detectportal.firefox.com/success.txt",
        ];

        for uri in uris {
            let uri = Uri::from_static(uri);
            let start = Instant::now();
            let resp = cli.get(uri).await.unwrap();
            let elapsed = start.elapsed().as_secs_f64();

            let (parts, body) = resp.into_parts();
            println!("{} {}", parts.status, elapsed);
            assert!(parts.status.is_success());
        }
    }
}
