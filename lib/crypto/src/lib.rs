#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]

mod blockcipher;
mod blockmode;
mod mac;
mod mem;
mod util;

pub use blockmode::{Aes128Gcm, Aes256Gcm};
