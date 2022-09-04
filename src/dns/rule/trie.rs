use std::collections::HashSet;

use trust_dns_proto::rr::Name;

/// As you can see, this trie is not an "Trie" but a Vec.
/// You might be think Radix tree or some other fancy trie, might
/// be more suitable, but they are not as `memory effective` as this
/// implement(at least i can't find one). There is some reason i decided
/// not use them.
///
/// 1. Their `Node` is too big, and their payload is only u8. e.g. radix_tree will increase memory
///    to 68M at start, but only 70k rules loaded.
/// 2. The implement is too complex, some of them even got 3K lines of code.
///
/// The performance is not as good as Trie-like structures, but our dns server
/// is not a public one, it's QPS should be relative low, so i think it's totally
/// fine.
pub struct Trie {
    entries: HashSet<String>,
}

impl Trie {
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
        }
    }

    pub fn swap(&mut self, other: Self) {
        self.entries = other.entries
    }

    pub fn insert(&mut self, host: &str) {
        let s = host.rsplit('.').collect::<Vec<_>>().join(".");
        self.entries.insert(s);
    }

    pub fn contain(&self, name: &Name) -> bool {
        let length = name.num_labels() as usize;
        let segments = name.iter().rev();

        let mut buf = String::with_capacity(name.len());
        for (index, label) in segments.enumerate() {
            buf.push_str(unsafe { std::str::from_utf8_unchecked(label) });

            // exact match
            if self.entries.contains(&buf) {
                if index == length - 1 {
                    return true;
                }

                buf.push('.');
                continue;
            }

            // wildcard match
            buf.push('.');
            if self.entries.contains(&buf) {
                return true;
            }

            if index == length - 1 {
                break;
            }
        }

        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn insert_and_lookup() {
        let mut trie = Trie::new();

        trie.insert(".foo.com");
        trie.insert("bar.com");

        let tests = [
            ("foo.org.", false),
            ("foo.com.", true),
            ("abc.foo.com.", true),
            ("bar.com.", true),
            ("bb.bar.com.", false),
            ("blah.com.", false),
        ];

        for (input, want) in tests {
            let name = Name::from_str(input).unwrap();

            assert!(name.is_fqdn());
            assert_eq!(
                trie.contain(&name),
                want,
                "input: {}, want: {}",
                input,
                want
            );
        }
    }
}
