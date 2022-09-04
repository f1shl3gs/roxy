use tracing::Level;
use tracing_subscriber::fmt::fmt;

pub fn init(level: Level, timestamp: bool) {
    let base = fmt().with_max_level(level).with_file(false);

    if timestamp {
        base.without_time().init()
    } else {
        base.init()
    }
}

#[cfg(test)]
pub fn test_init() {
    tracing_subscriber::fmt::init()
}
