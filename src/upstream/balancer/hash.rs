pub fn fnv(data: &[u8]) -> u64 {
    let mut hash = 0u64;

    for b in data.iter() {
        hash = hash ^ (*b as u64);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    hash
}

pub fn jumphash(mut key: u64, buckets: i64) -> i32 {
    let (mut b, mut j) = (-1i64, 0i64);

    while j < buckets {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b.wrapping_add(1) as f64) * (((1u64 << 31) as f64) / (((key >> 33) + 1) as f64)))
            as i64;
    }

    b as i32
}
