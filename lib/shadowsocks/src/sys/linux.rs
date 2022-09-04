use std::mem::MaybeUninit;

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn get_now_timestamp() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime::now() is before UNIX Epoch!"),
    }
}

#[cfg(target_os = "linux")]
pub fn get_now_timestamp() -> u64 {
    let mut tp = MaybeUninit::<libc::timespec>::uninit();
    let tp = unsafe {
        // CLOCK_MONOTONIC_COARSE -- A faster but less precise version of CLOCK_MONOTONIC
        libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, tp.as_mut_ptr());
        tp.assume_init()
    };

    let sec = tp.tv_sec as u64;
    let nsec = tp.tv_nsec as u64;

    (sec << 32) | ((nsec * 9_223_372_037) >> 31)
}
