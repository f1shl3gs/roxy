mod signals;

#[cfg(feature = "scudo")]
#[global_allocator]
static SCUDO_ALLOCATOR: scudo::GlobalScudoAllocator = scudo::GlobalScudoAllocator;

use std::process::exit;

use futures_util::stream::FuturesUnordered;
use futures_util::{StreamExt, TryFutureExt};
use resolver::Resolver;
use tracing::{error, info};

use roxy::{controller, dns, thp, trace_init, Config, Upstream};

fn main() {
    let conf = match Config::load() {
        Ok(conf) => conf,

        #[allow(clippy::print_stderr)]
        Err(err) => {
            eprintln!("load config failed, {:?}", err);
            exit(1);
        }
    };

    trace_init(conf.log.level, conf.log.timestamp);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(conf.worker())
        .thread_name("roxy-worker")
        .thread_stack_size(512 * 1024)
        .enable_io()
        .enable_time()
        .build()
        .expect("build tokio runtime failed");

    runtime.block_on(async move {
        info!(message = "starting", worker = conf.worker());

        let mut tasks = FuturesUnordered::new();

        // Build resolver for query provider's endpoint and server domain.
        info!(message = "use custom dns servers", resolvers = ?conf.resolvers);
        // Serde will make sure conf.resolvers is not empty, cause we don't use default for this field.
        let resolver = Resolver::new(conf.resolvers).expect("initial resolver failed");

        // init DNS server
        let dns = dns::Server::new(conf.dns, resolver.clone())
            .await
            .expect("build dns server");
        tasks.push(tokio::spawn(dns.serve().inspect_err(|err| {
            error!(message = "dns server serve failed", ?err);
        })));

        // init upstream
        let upstream = Upstream::new(conf.upstream, resolver.clone())
            .await
            .expect("init upstream failed");

        // init controller, our RESTful service
        if let Some(cc) = conf.controller {
            let svr =
                controller::Server::new(cc, upstream.clone()).expect("create controller server");
            tasks.push(tokio::spawn(svr.serve().inspect_err(|err| {
                error!(message = "controller failed", ?err);
            })));
        }

        if let Some(tc) = conf.thp {
            tasks.push(tokio::spawn(
                thp::serve(tc, upstream, resolver).inspect_err(|err| {
                    error!(message = "transparent http proxy serve failed", ?err);
                }),
            ));
        }

        // Mimic Golang's errgroup
        let tasks = async move {
            while let Some(result) = tasks.next().await {
                match result {
                    Ok(Ok(())) => continue,
                    Ok(Err(_err)) => {
                        // Some task is returned with error, shutdown root CancellationToken, and exit
                        exit(1);
                    }
                    Err(err) => {
                        // This should never happened
                        panic!("async task join failed, {}", err);
                    }
                }
            }
        };

        tokio::select! {
            _ = crate::signals::shutdown() => {
                // shutdown signal received
            },
            _ = tasks => {}
        }
    });

    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
}
