use std::convert::Infallible;
use std::io;
use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;

use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::controller::stats;
use crate::upstream::Balancer;

#[derive(Deserialize, Serialize)]
pub struct Config {
    listen: String,
}

#[derive(Clone)]
struct State {
    balancer: Balancer,
}

pub struct Server {
    listen: SocketAddr,

    balancer: Balancer,
}

impl Server {
    pub fn new(config: Config, balancer: Balancer) -> Result<Self, AddrParseError> {
        let listen = config.listen.parse::<SocketAddr>()?;

        Ok(Self { listen, balancer })
    }

    pub async fn serve(self) -> io::Result<()> {
        let state = Arc::new(State {
            balancer: self.balancer,
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
                Ok(stats) => {
                    let resp = format!(
                        r##"{{"max_fds": {},"open_fds": {}, "threads": {}, "vss": {}, "rss": {}}}"##,
                        stats.max_fds, stats.open_fds, stats.threads, stats.vss, stats.rss
                    );

                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .body(resp.into())
                        .unwrap())
                }
                Err(err) => {
                    error!(message = "read proc stats failed", ?err);

                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap())
                }
            },
            (&Method::GET, "/upstream") => {
                let stats = state.balancer.stats();
                let total = stats.len();
                let mut buf = String::from("[");
                for (index, stat) in stats.into_iter().enumerate() {
                    let s = format!(
                        r##"{{"addr":"{}","remarks":"{}","tcp_score":{},"udp_score":{}}}"##,
                        stat.addr,
                        stat.remarks.unwrap_or_default(),
                        stat.tcp_score,
                        stat.udp_score
                    );
                    buf.push_str(&s);
                    if index != total - 1 {
                        buf.push(',');
                    }
                }
                buf.push(']');

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(buf))
                    .unwrap())
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
