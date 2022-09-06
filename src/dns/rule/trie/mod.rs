#[cfg(feature = "bloom-trie")]
mod bloom;
#[cfg(feature = "set-trie")]
mod set;

#[cfg(feature = "bloom-trie")]
pub use self::bloom::Trie;
#[cfg(feature = "set-trie")]
pub use set::Trie;
