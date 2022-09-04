use super::table::{
    CHILDREN, CHILDREN_BITS_HI, CHILDREN_BITS_LO, CHILDREN_BITS_NODE_TYPE, CHILDREN_BITS_WILDCARD,
    NODES, NODES_BITS_CHILDREN, NODES_BITS_ICANN, NODES_BITS_TEXT_LENGTH, NODES_BITS_TEXT_OFFSET,
    NODE_TYPE_EXCEPTION, NODE_TYPE_NORMAL, NUM_TLD, TEXT,
};

const NOT_FOUND: u32 = 1 << 32 - 1;

pub fn effective_tld_plus_one(domain: &str) -> Option<&str> {
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        // empty label in domain
        return None;
    }

    let domain = domain.as_bytes();
    let (suffix, _) = public_suffix(domain);
    if domain.len() <= suffix.len() {
        // cannot derive eTLD+1 for domain
        return None;
    }

    let i = domain.len() - suffix.len() - 1;
    if domain[i] != b'.' {
        // invalid public suffix for domain
        return None;
    }

    let etldp = unsafe {
        std::str::from_utf8_unchecked(&domain[(1 + last_index(&domain[..i], b'.')) as usize..])
    };

    Some(etldp)
}

pub fn public_suffix(domain: &[u8]) -> (&[u8], bool) {
    let mut lo = 0;
    let mut hi = NUM_TLD;
    let mut s = domain;
    let mut suffix = domain.len() as i32;
    let mut icann_node = false;
    let mut wildcard = false;

    let mut icann = false;

    loop {
        let dot = last_index(s, b'.');
        if wildcard {
            icann = icann_node;
            suffix = 1 + dot;
        }

        if lo == hi {
            break;
        }
        let f = find(&s[(1 + dot) as usize..], lo, hi);
        if f == NOT_FOUND {
            break;
        }

        let mut u = NODES[f as usize] >> (NODES_BITS_TEXT_OFFSET + NODES_BITS_TEXT_LENGTH);
        icann_node = u & ((1 << NODES_BITS_ICANN) - 1) != 0;
        u >>= NODES_BITS_ICANN;
        u = CHILDREN[(u & ((1 << NODES_BITS_CHILDREN) - 1)) as usize];
        lo = u & ((1 << CHILDREN_BITS_LO) - 1);
        u >>= CHILDREN_BITS_LO;
        hi = u & ((1 << CHILDREN_BITS_HI) - 1);
        u >>= CHILDREN_BITS_HI;

        match u & ((1 << CHILDREN_BITS_NODE_TYPE) - 1) {
            NODE_TYPE_NORMAL => suffix = 1 + dot,
            NODE_TYPE_EXCEPTION => {
                suffix = (1 + s.len()) as i32;
                break;
            }
            _ => {}
        }

        u >>= CHILDREN_BITS_NODE_TYPE;
        wildcard = u & ((1 << CHILDREN_BITS_WILDCARD) - 1) != 0;
        if !wildcard {
            icann = icann_node
        }

        if dot == -1 {
            break;
        }

        s = &s[..dot as usize];
    }

    if suffix == domain.len() as i32 {
        // If no rules match, the prevailing rule is "*"
        let li = last_index(domain, b'.');
        return (&domain[(1 + li) as usize..], icann);
    }

    return (&domain[suffix as usize..], icann);
}

// find returns the index of the node in the range [lo, hi) whose label equals
// label, or notFound if there is no such node. The range is assumed to be in
// strictly increasing node label order.
fn find(label: &[u8], mut lo: u32, mut hi: u32) -> u32 {
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let s = node_label(mid);

        if s < label {
            lo = mid + 1;
        } else if s == label {
            return mid;
        } else {
            hi = mid;
        }
    }

    return NOT_FOUND;
}

// node_label returns the label for the i'th node.
fn node_label(i: u32) -> &'static [u8] {
    let mut x = NODES[i as usize];
    let len = x & ((1 << NODES_BITS_TEXT_LENGTH) - 1);
    x >>= NODES_BITS_TEXT_LENGTH;
    let offset = x & ((1 << NODES_BITS_TEXT_OFFSET) - 1);

    &TEXT.as_bytes()[offset as usize..(offset + len) as usize]
}

fn last_index(data: &[u8], p: u8) -> i32 {
    let len = data.len() as i32;

    for i in (0..len).rev() {
        if data[i as usize] == p {
            return i;
        }
    }

    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_index() {
        let inputs = [("abc", -1), (".", 0), ("abc.", 3), (".abc", 0)];

        for (input, want) in inputs {
            let got = last_index(input.as_bytes(), b'.');
            assert_eq!(got, want, "input: {}", input);
        }
    }

    #[test]
    fn icann() {
        // "www.pb.ao", "pb.ao", true
        let tests = [
            // Empty string.
            ("", "", false),
            // The .ao rules are:
            // ao
            // ed.ao
            // gv.ao
            // og.ao
            // co.ao
            // pb.ao
            // it.ao
            ("ao", "ao", true),
            ("www.ao", "ao", true),
            ("pb.ao", "pb.ao", true),
            ("www.pb.ao", "pb.ao", true),
            ("www.xxx.yyy.zzz.pb.ao", "pb.ao", true),
            // The .ar rules are:
            // ar
            // com.ar
            // edu.ar
            // gob.ar
            // gov.ar
            // int.ar
            // mil.ar
            // net.ar
            // org.ar
            // tur.ar
            // blogspot.com.ar (in the PRIVATE DOMAIN section).
            ("ar", "ar", true),
            ("www.ar", "ar", true),
            ("nic.ar", "ar", true),
            ("www.nic.ar", "ar", true),
            ("com.ar", "com.ar", true),
            ("www.com.ar", "com.ar", true),
            ("blogspot.com.ar", "blogspot.com.ar", false), // PRIVATE DOMAIN.
            ("www.blogspot.com.ar", "blogspot.com.ar", false), // PRIVATE DOMAIN.
            ("www.xxx.yyy.zzz.blogspot.com.ar", "blogspot.com.ar", false), // PRIVATE DOMAIN.
            ("logspot.com.ar", "com.ar", true),
            ("zlogspot.com.ar", "com.ar", true),
            ("zblogspot.com.ar", "com.ar", true),
            // The .arpa rules are:
            // arpa
            // e164.arpa
            // in-addr.arpa
            // ip6.arpa
            // iris.arpa
            // uri.arpa
            // urn.arpa
            ("arpa", "arpa", true),
            ("www.arpa", "arpa", true),
            ("urn.arpa", "urn.arpa", true),
            ("www.urn.arpa", "urn.arpa", true),
            ("www.xxx.yyy.zzz.urn.arpa", "urn.arpa", true),
            // The relevant {kobe,kyoto}.jp rules are:
            // jp
            // *.kobe.jp
            // !city.kobe.jp
            // kyoto.jp
            // ide.kyoto.jp
            ("jp", "jp", true),
            ("kobe.jp", "jp", true),
            ("c.kobe.jp", "c.kobe.jp", true),
            ("b.c.kobe.jp", "c.kobe.jp", true),
            ("a.b.c.kobe.jp", "c.kobe.jp", true),
            ("city.kobe.jp", "kobe.jp", true),
            ("www.city.kobe.jp", "kobe.jp", true),
            ("kyoto.jp", "kyoto.jp", true),
            ("test.kyoto.jp", "kyoto.jp", true),
            ("ide.kyoto.jp", "ide.kyoto.jp", true),
            ("b.ide.kyoto.jp", "ide.kyoto.jp", true),
            ("a.b.ide.kyoto.jp", "ide.kyoto.jp", true),
            // The .tw rules are:
            // tw
            // edu.tw
            // gov.tw
            // mil.tw
            // com.tw
            // net.tw
            // org.tw
            // idv.tw
            // game.tw
            // ebiz.tw
            // club.tw
            // 網路.tw (xn--zf0ao64a.tw)
            // 組織.tw (xn--uc0atv.tw)
            // 商業.tw (xn--czrw28b.tw)
            // blogspot.tw
            ("tw", "tw", true),
            ("aaa.tw", "tw", true),
            ("www.aaa.tw", "tw", true),
            ("xn--czrw28b.aaa.tw", "tw", true),
            ("edu.tw", "edu.tw", true),
            ("www.edu.tw", "edu.tw", true),
            ("xn--czrw28b.edu.tw", "edu.tw", true),
            ("xn--czrw28b.tw", "xn--czrw28b.tw", true),
            ("www.xn--czrw28b.tw", "xn--czrw28b.tw", true),
            ("xn--uc0atv.xn--czrw28b.tw", "xn--czrw28b.tw", true),
            ("xn--kpry57d.tw", "tw", true),
            // The .uk rules are:
            // uk
            // ac.uk
            // co.uk
            // gov.uk
            // ltd.uk
            // me.uk
            // net.uk
            // nhs.uk
            // org.uk
            // plc.uk
            // police.uk
            // *.sch.uk
            // blogspot.co.uk (in the PRIVATE DOMAIN section).
            ("uk", "uk", true),
            ("aaa.uk", "uk", true),
            ("www.aaa.uk", "uk", true),
            ("mod.uk", "uk", true),
            ("www.mod.uk", "uk", true),
            ("sch.uk", "uk", true),
            ("mod.sch.uk", "mod.sch.uk", true),
            ("www.sch.uk", "www.sch.uk", true),
            ("co.uk", "co.uk", true),
            ("www.co.uk", "co.uk", true),
            ("blogspot.co.uk", "blogspot.co.uk", false), // PRIVATE DOMAIN.
            ("blogspot.nic.uk", "uk", true),
            ("blogspot.sch.uk", "blogspot.sch.uk", true),
            // The .рф rules are
            // рф (xn--p1ai)
            ("xn--p1ai", "xn--p1ai", true),
            ("aaa.xn--p1ai", "xn--p1ai", true),
            ("www.xxx.yyy.xn--p1ai", "xn--p1ai", true),
            // The .bd rules are:
            // *.bd
            ("bd", "bd", false), // The catch-all "*" rule is not in the ICANN DOMAIN section. See footnote (†).
            ("www.bd", "www.bd", true),
            ("xxx.www.bd", "www.bd", true),
            ("zzz.bd", "zzz.bd", true),
            ("www.zzz.bd", "zzz.bd", true),
            ("www.xxx.yyy.zzz.bd", "zzz.bd", true),
            // The .ck rules are:
            // *.ck
            // !www.ck
            ("ck", "ck", false), // The catch-all "*" rule is not in the ICANN DOMAIN section. See footnote (†).
            ("www.ck", "ck", true),
            ("xxx.www.ck", "ck", true),
            ("zzz.ck", "zzz.ck", true),
            ("www.zzz.ck", "zzz.ck", true),
            ("www.xxx.yyy.zzz.ck", "zzz.ck", true),
            // The .myjino.ru rules (in the PRIVATE DOMAIN section) are:
            // myjino.ru
            // *.hosting.myjino.ru
            // *.landing.myjino.ru
            // *.spectrum.myjino.ru
            // *.vps.myjino.ru
            ("myjino.ru", "myjino.ru", false),
            ("aaa.myjino.ru", "myjino.ru", false),
            ("bbb.ccc.myjino.ru", "myjino.ru", false),
            ("hosting.ddd.myjino.ru", "myjino.ru", false),
            ("landing.myjino.ru", "myjino.ru", false),
            ("www.landing.myjino.ru", "www.landing.myjino.ru", false),
            ("spectrum.vps.myjino.ru", "spectrum.vps.myjino.ru", false),
            // The .uberspace.de rules (in the PRIVATE DOMAIN section) are:
            // *.uberspace.de
            ("uberspace.de", "de", true), // "de" is in the ICANN DOMAIN section. See footnote (†).
            ("aaa.uberspace.de", "aaa.uberspace.de", false),
            ("bbb.ccc.uberspace.de", "ccc.uberspace.de", false),
            // There are no .nosuchtld rules.
            ("nosuchtld", "nosuchtld", false),
            ("foo.nosuchtld", "nosuchtld", false),
            ("bar.foo.nosuchtld", "nosuchtld", false),
        ];

        for (input, want_ps, want_icann) in tests {
            let (got_ps, got_icann) = public_suffix(input.as_bytes());
            let got_ps = std::str::from_utf8(got_ps).unwrap();

            assert_eq!(
                got_ps, want_ps,
                "want: {}, got: {}, input: {}",
                want_ps, got_ps, input
            );
            assert_eq!(
                got_icann, want_icann,
                "want: {}, got: {}, input: {}",
                want_icann, got_icann, input
            );
        }
    }
}
