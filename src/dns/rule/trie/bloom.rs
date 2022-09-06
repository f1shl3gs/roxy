use bloom::{BloomFilter, ASMS};
use trust_dns_proto::rr::Name;

pub struct Trie {
    bloom: BloomFilter,
}

impl Trie {
    pub fn new() -> Self {
        Self {
            bloom: BloomFilter::with_rate(0.0001, 40_000),
        }
    }

    pub fn swap(&mut self, other: Self) {
        self.bloom = other.bloom;
    }

    pub fn insert(&mut self, host: &str) {
        let s = host.rsplit('.').collect::<Vec<_>>().join(".");
        self.bloom.insert(&s);
    }

    pub fn contain(&self, name: &Name) -> bool {
        let length = name.num_labels() as usize;
        let segments = name.iter().rev();

        let mut buf = String::with_capacity(name.len());
        for (index, label) in segments.enumerate() {
            buf.push_str(unsafe { std::str::from_utf8_unchecked(label) });

            // exact match
            if self.bloom.contains(&buf) {
                if index == length - 1 {
                    return true;
                }

                buf.push('.');
                continue;
            }

            // wildcard match
            buf.push('.');
            if self.bloom.contains(&buf) {
                return true;
            }

            if index == length - 1 {
                break;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom::needed_bits;
    use std::str::FromStr;

    #[test]
    fn nb() {
        let tests = [0.01, 0.001, 0.0001, 0.00001];

        for rate in tests {
            let n = needed_bits(rate, 50000);
            println!("{}", n);
        }
    }

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

    #[test]
    fn medium() {
        let mut trie = Trie::new();
        trie.insert(".medium.com");

        let name = Name::from_str("glyph.medium.com.").unwrap();
        assert!(name.is_fqdn());
        assert!(trie.contain(&name))
    }
}
