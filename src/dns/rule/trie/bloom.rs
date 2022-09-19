use bloom::{BloomFilter, ASMS};
use trust_dns_proto::rr::Name;

#[derive(Default)]
pub struct FnvHasher(u64);

impl FnvHasher {
    #[inline]
    pub(crate) fn current(&self) -> u64 {
        self.0
    }

    #[inline]
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        let FnvHasher(mut hash) = *self;

        for byte in bytes.iter() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }

        *self = FnvHasher(hash);
    }
}

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
        let mut parts = host.rsplit('.').peekable();
        let mut hash = FnvHasher::default();
        while let Some(part) = parts.next() {
            hash.write(part.as_bytes());

            if parts.peek().is_some() {
                hash.write(&[b'.']);
            }
        }

        self.bloom.insert(&hash.current());
    }

    pub fn contains(&self, name: &Name) -> bool {
        let length = name.num_labels() as usize;
        let segments = name.iter().rev();
        let mut hash = FnvHasher::default();

        for (index, label) in segments.enumerate() {
            hash.write(label);

            // exact match
            if self.bloom.contains(&hash.current()) {
                if index == length - 1 {
                    return true;
                }

                hash.write(&[b'.']);
                continue;
            }

            // wildcard match
            hash.write(&[b'.']);
            if self.bloom.contains(&hash.current()) {
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
                trie.contains(&name),
                want,
                "input: {}, want: {}",
                input,
                want
            );
        }
    }

    fn test_trie() -> Trie {
        let mut trie = Trie::new();
        trie.insert(".000webhost.com");
        trie.insert(".030buy.com");
        trie.insert(".0rz.tw");
        trie.insert(".1-apple.com.tw");
        trie.insert(".10.tt");
        trie.insert(".1000giri.net");
        trie.insert(".100ke.org");
        trie.insert(".10beasts.net");
        trie.insert(".10conditionsoflove.com");
        trie.insert(".10musume.com");
        trie.insert(".123rf.com");
        trie.insert(".12bet.com");
        trie.insert(".12vpn.com");
        trie.insert(".12vpn.net");
        trie.insert(".1337x.to");
        trie.insert(".138.com");
        trie.insert(".141hongkong.com");
        trie.insert(".141jj.com");
        trie.insert(".141tube.com");
        trie.insert(".1688.com.au");
        trie.insert(".173ng.com");
        trie.insert(".177pic.info");
        trie.insert(".17t17p.com");
        trie.insert(".18board.com");
        trie.insert(".18board.info");
        trie.insert(".18onlygirls.com");
        trie.insert(".18p2p.com");
        trie.insert(".18virginsex.com");
        trie.insert(".1949er.org");
        trie.insert(".1984bbs.com");
        trie.insert(".1984bbs.org");
        trie.insert(".1989report.hkja.org.hk");
        trie.insert(".1991way.com");
        trie.insert(".1998cdp.org");
        trie.insert(".1bao.org");
        trie.insert(".1dumb.com");
        trie.insert(".1e100.net");
        trie.insert(".1eew.com");
        trie.insert(".1mobile.com");
        trie.insert(".1mobile.tw");
        trie.insert(".1pondo.tv");
        trie.insert(".2-hand.info");
        trie.insert(".2000fun.com");
        trie.insert(".2008xianzhang.info");
        trie.insert(".2017.hk");
        trie.insert(".2021hkcharter.com");
        trie.insert(".2047.name");
        trie.insert(".21andy.com");
        trie.insert(".21join.com");
        trie.insert(".21pron.com");
        trie.insert(".21sextury.com");
        trie.insert(".228.net.tw");
        trie.insert(".233abc.com");
        trie.insert(".24hrs.ca");
        trie.insert(".24smile.org");
        trie.insert(".25u.com");
        trie.insert(".2lipstube.com");
        trie.insert(".2shared.com");
        trie.insert(".2waky.com");
        trie.insert(".3-a.net");
        trie.insert(".30boxes.com");
        trie.insert(".315lz.com");
        trie.insert(".32red.com");
        trie.insert(".36rain.com");
        trie.insert(".3a5a.com");
        trie.insert(".3arabtv.com");
        trie.insert(".3boys2girls.com");
        trie.insert(".3d-game.com");
        trie.insert(".3proxy.ru");
        trie.insert(".3ren.ca");
        trie.insert(".3tui.net");
        trie.insert(".404museum.com");
        trie.insert(".43110.cf");
        trie.insert(".466453.com");
        trie.insert(".4bluestones.biz");
        trie.insert(".4chan.com");
        trie.insert(".4dq.com");
        trie.insert(".4everproxy.com");
        trie.insert(".4irc.com");
        trie.insert(".4mydomain.com");
        trie.insert(".4pu.com");
        trie.insert(".4rbtv.com");
        trie.insert(".4shared.com");
        trie.insert(".4sqi.net");
        trie.insert(".51.ca");
        trie.insert(".51jav.org");
        trie.insert(".51luoben.com");
        trie.insert(".5278.cc");
        trie.insert(".5299.tv");
        trie.insert(".56cun04.jigsy.com");
        trie.insert(".5aimiku.com");
        trie.insert(".5i01.com");
        trie.insert(".5isotoi5.org");
        trie.insert(".5maodang.com");
        trie.insert(".63i.com");
        trie.insert(".64museum.org");
        trie.insert(".64tianwang.com");
        trie.insert(".64wiki.com");
        trie.insert(".66.ca");
        trie.insert(".666kb.com");

        trie
    }

    // String.push
    // test dns::rule::trie::bloom::tests::contains ... bench:         217 ns/iter (+/- 6)
    // Fnv.write
    // test dns::rule::trie::bloom::tests::contains ... bench:         163 ns/iter (+/- 5)

    #[bench]
    fn contains(b: &mut test::Bencher) {
        let trie = test_trie();
        let name = Name::from_str("glyph.medium.com.").unwrap();

        b.iter(|| {
            trie.contains(&name);
        })
    }

    #[test]
    fn medium() {
        let mut trie = Trie::new();
        trie.insert(".medium.com");

        let name = Name::from_str("glyph.medium.com.").unwrap();
        assert!(name.is_fqdn());
        assert!(trie.contains(&name))
    }
}
