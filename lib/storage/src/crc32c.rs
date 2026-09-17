// Castagnoli (CRC-32C) polynomial, reflected. slice-by-8 table built at compile
// time; this guards body frames against bit rot, it is not a security checksum.
const POLY: u32 = 0x82F6_3B78;

const fn build() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            k += 1;
        }
        t[0][i] = crc;
        i += 1;
    }
    let mut s = 1;
    while s < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

static TABLE: [[u32; 256]; 8] = build();

pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = TABLE[7][(lo & 0xFF) as usize]
            ^ TABLE[6][((lo >> 8) & 0xFF) as usize]
            ^ TABLE[5][((lo >> 16) & 0xFF) as usize]
            ^ TABLE[4][((lo >> 24) & 0xFF) as usize]
            ^ TABLE[3][(hi & 0xFF) as usize]
            ^ TABLE[2][((hi >> 8) & 0xFF) as usize]
            ^ TABLE[1][((hi >> 16) & 0xFF) as usize]
            ^ TABLE[0][((hi >> 24) & 0xFF) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ TABLE[0][((crc ^ b as u32) & 0xFF) as usize];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    #[test]
    fn known_vectors() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn tail_matches_bytewise() {
        let data: Vec<u8> = (0..137u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in 0..data.len() {
            let mut crc = !0u32;
            for &b in &data[..len] {
                crc = (crc >> 8) ^ super::TABLE[0][((crc ^ b as u32) & 0xFF) as usize];
            }
            assert_eq!(crc32c(&data[..len]), !crc, "len {len}");
        }
    }
}
