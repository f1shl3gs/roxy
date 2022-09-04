use bloomfilter::Bloom;
use tracing::debug;

// A bloom filter borrowed
pub struct PingPongBloom {
    blooms: [Bloom<u8>; 2],
    bloom_count: [usize; 2],
    item_count: usize,
    current: usize,
}

impl PingPongBloom {
    pub fn new() -> Self {
        let mut item_count = 10_000;
        let fp_p = 1e-15;

        item_count /= 2;

        Self {
            blooms: [
                Bloom::new_for_fp_rate(item_count, fp_p),
                Bloom::new_for_fp_rate(item_count, fp_p),
            ],
            bloom_count: [0, 0],
            item_count,
            current: 0,
        }
    }

    // Check if data in `buf` exist.
    //
    // Set into the current bloom filter if not exist
    //
    // Return `true` if data exist in bloom filter.
    pub fn check_and_set(&mut self, buf: &[u8]) -> bool {
        for bloom in &self.blooms {
            if bloom.check(buf) {
                return true;
            }
        }

        if self.bloom_count[self.current] >= self.item_count {
            // Current bloom filter is full, Create a new
            // one and use that one as current.
            self.current = (self.current + 1) % 2;
            self.bloom_count[self.current] = 0;
            self.blooms[self.current].clear();

            debug!(
                message = "bloom filter based replay protector full",
                cpacity = self.item_count,
                filters = self.blooms.len()
            );
        }

        // Cannot be optimized by `check_and_set`
        // Because we have to check every filters in `blooms` before `set`
        self.blooms[self.current].set(buf);
        self.bloom_count[self.current] += 1;

        false
    }
}
