#![cfg_attr(target_arch = "aarch64", feature(stdsimd))]
#![allow(unused_macros, unused_assignments)]

pub mod blockcipher;
mod blockmode;
pub mod encoding;
pub mod hash;
pub mod kdf;
mod mac;
mod mem;
mod util;

pub use blockmode::{Aes128Gcm, Aes256Gcm};
