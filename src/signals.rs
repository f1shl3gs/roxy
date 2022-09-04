use tokio::signal::unix::SignalKind;

pub async fn shutdown() {
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
        .expect("Failed to register signal handler");
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())
        .expect("Failed to register signal handler");

    info!("start watching signals");

    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {}
    };
}
