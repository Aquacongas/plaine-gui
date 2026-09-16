use crate::error::{Result, WalletError};
use core::fmt;
use core::sync::atomic::{compiler_fence, Ordering};

pub struct Secret32 {
    bytes: [u8; 32],
}

impl Secret32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Secret32 { bytes }
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Clone for Secret32 {
    fn clone(&self) -> Self {
        Secret32 { bytes: self.bytes }
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        // Zero the key on drop. The fence is load-bearing here: without it the
        // compiler is free to drop a write it can prove is never read back.
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}

pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        SecretBytes { bytes }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// a real digest has close to 32 distinct byte values; far fewer is almost
// always a typed-in constant, not entropy
pub const MIN_DISTINCT_BYTES: usize = 8;

pub fn check_seed_material(seed: &[u8; 32]) -> Result<()> {
    if seed.iter().all(|&b| b == 0) {
        return Err(WalletError::refused(
            "seed is all zero bytes; supply real entropy (e.g. `openssl rand -hex 32`)",
        ));
    }
    if seed.iter().all(|&b| b == seed[0]) {
        return Err(WalletError::refused(format!(
            "seed is the single byte 0x{:02x} repeated 32 times; supply real entropy",
            seed[0]
        )));
    }
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in seed.iter() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    if distinct < MIN_DISTINCT_BYTES {
        return Err(WalletError::refused(format!(
            "seed contains only {distinct} distinct byte values (need at least \
             {MIN_DISTINCT_BYTES}); this does not look like random material"
        )));
    }

    let ascending = seed.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let descending = seed.windows(2).all(|w| w[1] == w[0].wrapping_sub(1));
    if ascending || descending {
        return Err(WalletError::refused(
            "seed is a counting sequence, not random material",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_bytes() {
        let s = Secret32::from_bytes([0xAB; 32]);
        let shown = format!("{s:?}");
        assert_eq!(shown, "Secret32(<redacted>)");
        assert!(!shown.contains("ab"));
        let p = SecretBytes::from_vec(b"hunter2".to_vec());
        assert_eq!(format!("{p:?}"), "SecretBytes(<redacted>)");
    }

    #[test]
    fn ct_eq_matches_plain_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn degenerate_seeds_are_refused() {
        assert!(check_seed_material(&[0u8; 32]).is_err());
        assert!(check_seed_material(&[0x42u8; 32]).is_err());
        let mut counter = [0u8; 32];
        for (i, b) in counter.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert!(check_seed_material(&counter).is_err());
        let mut low = [0u8; 32];
        for (i, b) in low.iter_mut().enumerate() {
            *b = (i % 4) as u8;
        }
        assert!(check_seed_material(&low).is_err());
    }

    #[test]
    fn realistic_seed_is_accepted() {
        let seed = plaine_consensus::blake3::hash(b"plaine wallet unit test seed");
        check_seed_material(&seed).expect("a hash digest looks random");
    }
}
