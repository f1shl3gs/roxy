//! Available character for domain names
//!   1. a-z ascii 97-122
//!   2. 0-9 ascii 48-57
//!   3. - ascii 45
//!   4. . ascii 46
//! so, a 38-length bitmap can represent all available characters.
//!
//! data structures
//!   1. exist of not - 38 bits
//!   2. has child - 38 bits
//!   3. wildcard - 38 bits
//! therefor a u128(114 needed actually) will contain all information we need.
//!
//! Slots looks like
//! -.0123456789abcdefghijklmnopqrstuvwxyz
//!
//! map node:
//! 1  bit: node type 0 for dense, 1 for data, 3 for ?
//! 13 bit: padding
//! 38 bit: char bitmap
//! 38 bit: child flag
//! 38 bit: wildcard flag
//!
//! data node:
//! 1   bit: node type
//! 4   bit: data length it can represent max 16, fit for data length
//! 3   bit: padding
//! 120 bit: data, 15 char
//!
fn validate(c: u8) -> bool {
    if c.is_ascii_digit() {
        return true;
    }

    if c >= b'a' && c <= b'z' {
        return true;
    }

    c == b'.' || c == b'-'
}

// ascii_to_index return the slot index of this character,
// Note: c must be a validate char.
fn ascii_to_index(c: u8) -> usize {
    if c >= b'a' && c <= b'z' {
        return (c - 97 + 2 + 10) as usize; // 2 for "-" and ".", 10 for digits
    }

    if c.is_ascii_digit() {
        return (c - 48 + 2) as usize; // the first 2 bit is for "-" and "."
    }

    if c == b'.' {
        0
    } else {
        1
    }
}

trait Bitmap {
    fn get(&self, index: usize) -> bool;
    fn set(&mut self, index: usize, value: bool);
    // fn next_index(bits: &Self, index: usize) -> Option<usize>;
}

impl Bitmap for u128 {
    #[inline]
    fn get(&self, index: usize) -> bool {
        (*self) & (1 << index) != 0
    }

    #[inline]
    fn set(&mut self, index: usize, value: bool) {
        let mask = 1 << index;

        if value {
            *self |= mask;
        } else {
            *self &= !mask;
        }
    }
}

struct Node {
    bitmap: u128, // 128 bits can store 16byte string
    children: Vec<Node>,
}

enum Data {
    Bitmap(u128),
    String(String),
}

struct Node1 {}

struct Trie {
    data: String,
}

impl Trie {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap() {
        let mut map = 0u128;

        assert!(!map.get(1));
        map.set(1, true);
        assert!(map.get(1));
        map.set(1, false);
        assert!(!map.get(1));
    }

    #[test]
    fn to_index() {
        assert_eq!(ascii_to_index(b'.'), 0);
        assert_eq!(ascii_to_index(b'-'), 1);

        assert_eq!(ascii_to_index(b'0'), 2);
        assert_eq!(ascii_to_index(b'3'), 5);
        assert_eq!(ascii_to_index(b'9'), 11);

        assert_eq!(ascii_to_index(b'a'), 12);
        assert_eq!(ascii_to_index(b'c'), 14);
        assert_eq!(ascii_to_index(b'z'), 37);
    }

    #[test]
    fn size() {
        union Ct {
            small: i32,
            large: i128,
        }

        enum Container {
            Small(i32),
            Large(i128),
        }

        println!("{}", std::mem::size_of::<Ct>());
        println!("{}", std::mem::size_of::<Container>());
    }
}
