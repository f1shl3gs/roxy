use tracing::{Dispatch, Level};

use crate::log::Logger;

pub fn init(level: Level, timestamp: bool) {
    let logger = Logger::new(level, timestamp);
    let dispatcher = Dispatch::new(logger);

    tracing::dispatcher::set_global_default(dispatcher).expect("set global logger failed");
}

#[cfg(test)]
pub fn test_init() {
    init(Level::INFO, true)
}

#[test]
fn log() {
    test_init();

    info!("abc");
    info!(message = "abc");
    info!(message = "abc", foo = "bar");
}
