use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn serve() {
    let addr: SocketAddr = "0.0.0.0:9001".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    loop {
        let (stream, _) = listener.accept().await.unwrap();

        tokio::task::spawn(async move {
            if let Err(err) = Http::new()
                .serve_connection(stream, service_fn(rules))
                .await
            {
                println!("Failed to serve connection: {:?}", err)
            }
        });
    }
}

async fn rules(req: Request<Body>) -> hyper::http::Result<Response<Body>> {
    let path = req.uri().path().strip_prefix('/').unwrap();

    let data = std::fs::read(format!("rules/{}", path)).unwrap();

    Response::builder().body(Body::from(data))
}
