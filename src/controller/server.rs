use std::convert::Infallible;
use std::io;
use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
use serde::Deserialize;

use super::{
    response::{err_resp, IntoResponse},
    stats,
};
use crate::Upstream;

#[derive(Deserialize)]
pub struct Config {
    listen: String,
}

#[derive(Clone)]
struct State {
    upstream: Upstream,
}

pub struct Server {
    listen: SocketAddr,

    upstream: Upstream,
}

impl Server {
    pub fn new(config: Config, upstream: Upstream) -> Result<Self, AddrParseError> {
        let listen = config.listen.parse::<SocketAddr>()?;

        Ok(Self { listen, upstream })
    }

    pub async fn serve(self) -> io::Result<()> {
        let state = Arc::new(State {
            upstream: self.upstream,
        });

        let service = make_service_fn(move |_conn| {
            let cs = state.clone();

            async { Ok::<_, Infallible>(service_fn(move |req| Self::handle(req, cs.clone()))) }
        });

        let server = hyper::Server::bind(&self.listen).serve(service);

        info!(message = "controller start", listen = ?self.listen);
        if let Err(err) = server.await {
            error!(message = "controller server exit", ?err);
        }

        Ok(())
    }

    async fn handle(req: Request<Body>, state: Arc<State>) -> Result<Response<Body>, Infallible> {
        let path = req.uri().path();

        match (req.method(), path) {
            (&Method::GET, "/stats") => match stats::ProcStat::read() {
                Ok(stats) => Ok(stats.into_resp()),
                Err(err) => {
                    error!(message = "read proc stats failed", ?err);

                    Ok(err_resp(StatusCode::INTERNAL_SERVER_ERROR, err))
                }
            },
            (&Method::GET, "/upstream") => {
                let stats = state.upstream.stats().await;
                Ok(stats.into_resp())
            }
            _ => Ok(not_found()),
        }
    }
}

/// HTTP status code 404
fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("Not Found".into())
        .unwrap()
}
