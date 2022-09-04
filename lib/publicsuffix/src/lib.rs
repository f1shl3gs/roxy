mod list;
mod table;

pub use list::{effective_tld_plus_one, public_suffix};

#[inline]
pub fn version() -> &'static str {
    table::VERSION
}
