use crypto::Aes128Gcm;
use std::time::Instant;

fn main() {
    let total = std::env::var("TOTAL")
        .unwrap_or("100000".into())
        .parse::<i32>()
        .expect("parse total failed");

    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5,
        0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let cipher = Aes128Gcm::new(&key);

    let mut tag_out = [1u8; Aes128Gcm::TAG_LEN];
    let start = Instant::now();
    for _i in 0..total {
        let mut ciphertext = [
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5,
            0xf0,
            // TAG
            // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
    }
    let elapsed = start.elapsed();

    println!(
        "total:   {}\nelapsed: {} ms\nthrpt:   {} MB/s\n",
        total,
        elapsed.as_secs_f64() * 1000.0,
        (total as f64 * (16.0 / 1024.0 / 1024.0)) / elapsed.as_secs_f64()
    )
}
