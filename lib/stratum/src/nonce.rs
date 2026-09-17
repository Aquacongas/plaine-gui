use crate::limits::{E1_SPACE, X_BITS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct E1(pub u32);

impl E1 {
    pub fn to_hex(self) -> String {
        format!("{:06x}", self.0 & (E1_SPACE - 1))
    }

    #[inline]
    pub fn owns(self, nonce: u64) -> bool {
        (nonce >> X_BITS) as u32 == self.0
    }

    pub fn compose(self, x: u64) -> u64 {
        debug_assert!(x < (1u64 << X_BITS));
        ((self.0 as u64) << X_BITS) | (x & ((1u64 << X_BITS) - 1))
    }
}

pub trait SliceSource: Send + Sync {
    fn acquire(&self) -> Option<(E1, u32)>;

    fn release(&self, e1: E1, sub: u32, searched: bool);

    fn sub_bits(&self) -> u32 {
        0
    }

    fn live(&self) -> usize;

    // default true: a source that owns its slices forever (the solo node) never
    // revokes. only a pool relaying upstream slices overrides this.
    fn holds(&self, e1: E1, sub: u32) -> bool {
        let _ = (e1, sub);
        true
    }
}

impl SliceSource for std::sync::Mutex<E1Allocator> {
    fn acquire(&self) -> Option<(E1, u32)> {
        self.lock()
            .ok()
            .and_then(|mut a| a.acquire())
            .map(|e| (e, 0))
    }
    fn release(&self, e1: E1, _sub: u32, _searched: bool) {
        if let Ok(mut a) = self.lock() {
            a.release(e1);
        }
    }
    fn live(&self) -> usize {
        self.lock().map(|a| a.live()).unwrap_or(usize::MAX)
    }

    fn holds(&self, _e1: E1, _sub: u32) -> bool {
        true
    }
}

#[inline]
pub fn slice_fixed(e1: E1, sub: u32, sub_bits: u32) -> u64 {
    ((e1.0 as u64) << sub_bits) | (sub as u64)
}

#[inline]
pub fn slice_owns(e1: E1, sub: u32, sub_bits: u32, nonce: u64) -> bool {
    nonce >> (X_BITS - sub_bits) == slice_fixed(e1, sub, sub_bits)
}

#[inline]
pub fn assemble_header(prefix: &[u8; 124], nonce: u64) -> [u8; 132] {
    let mut h = [0u8; 132];
    h[..124].copy_from_slice(prefix);
    h[124..].copy_from_slice(&nonce.to_le_bytes());
    h
}

pub fn parse_nonce_hex(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 {
        return None;
    }
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        let hi = hexval(b[2 * i])?;
        let lo = hexval(b[2 * i + 1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(u64::from_le_bytes(bytes))
}

pub fn nonce_to_hex(n: u64) -> String {
    let mut s = String::with_capacity(16);
    for b in n.to_le_bytes() {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
    }
    s
}

#[inline]
fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub struct E1Allocator {
    bits: Vec<u64>,
    cursor: u32,
    live: usize,
}

impl Default for E1Allocator {
    fn default() -> Self {
        Self::new()
    }
}

impl E1Allocator {
    pub fn new() -> E1Allocator {
        E1Allocator {
            bits: vec![0u64; (E1_SPACE as usize) / 64],
            cursor: 0,
            live: 0,
        }
    }

    pub fn live(&self) -> usize {
        self.live
    }

    pub fn acquire(&mut self) -> Option<E1> {
        // The cursor advances monotonically (wrapping), so a freed slice isn't
        // handed straight back. A reconnecting rig gets a fresh one, and its old,
        // maybe-still-mined nonces can't collide with it.
        for _ in 0..E1_SPACE {
            let v = self.cursor;
            self.cursor = (self.cursor + 1) & (E1_SPACE - 1);
            let (w, b) = (v as usize / 64, v as usize % 64);
            if self.bits[w] & (1u64 << b) == 0 {
                self.bits[w] |= 1u64 << b;
                self.live += 1;
                return Some(E1(v));
            }
        }
        None
    }

    pub fn release(&mut self, e1: E1) {
        let v = (e1.0 & (E1_SPACE - 1)) as usize;
        let (w, b) = (v / 64, v % 64);
        if self.bits[w] & (1u64 << b) != 0 {
            self.bits[w] &= !(1u64 << b);
            self.live -= 1;
        }
    }

    pub const fn resident_bytes() -> usize {
        (E1_SPACE as usize) / 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_example_reproduced() {
        let e1 = E1(0x00A3F2);
        let x = (3u64 << 32) | 42;
        let n = e1.compose(x);
        assert_eq!(n, 0x00A3_F203_0000_002A);
        assert_eq!(nonce_to_hex(n), "2a00000003f2a300");
        assert_eq!(parse_nonce_hex("2a00000003f2a300"), Some(n));
        assert!(e1.owns(n));
        assert_eq!(e1.to_hex(), "00a3f2");
    }

    #[test]
    fn slice_binding_rejects_stolen_share() {
        let victim = E1(0x00A3F2);
        let thief = E1(0x112233);
        let n = victim.compose(42);
        assert!(victim.owns(n));
        assert!(
            !thief.owns(n),
            "a share sniffed off the wire carries the victim's slice"
        );
    }

    #[test]
    fn header_nonce_at_offset_124() {
        let prefix = [0xABu8; 124];
        let h = assemble_header(&prefix, 0x00A3_F203_0000_002A);
        assert_eq!(&h[..124], &prefix[..]);
        assert_eq!(&h[124..], &[0x2A, 0, 0, 0, 0x03, 0xF2, 0xA3, 0x00]);

        assert_eq!(&h[129..132], &[0xF2, 0xA3, 0x00]);
    }

    #[test]
    fn nonce_hex_is_strict() {
        assert_eq!(parse_nonce_hex(""), None);
        assert_eq!(parse_nonce_hex("2a0000000f2a300"), None);
        assert_eq!(parse_nonce_hex("2a00000003f2a3000"), None);
        assert_eq!(parse_nonce_hex("2a00000003f2a30g"), None);
        assert_eq!(parse_nonce_hex("0x00000003f2a300"), None);
        assert!(parse_nonce_hex("2A00000003F2A300").is_some());
    }

    #[test]
    fn allocator_never_reuses_live_slice() {
        let mut a = E1Allocator::new();
        let mut seen = std::collections::HashSet::new();
        let mut held = Vec::new();
        for _ in 0..5000 {
            let e = a.acquire().unwrap();
            assert!(seen.insert(e), "duplicate live E1");
            held.push(e);
        }
        assert_eq!(a.live(), 5000);
        for e in held {
            a.release(e);
        }
        assert_eq!(a.live(), 0);

        let next = a.acquire().unwrap();
        assert_eq!(next.0, 5000, "monotonic cursor, not immediate reuse");
    }

    #[test]
    fn double_release_is_harmless() {
        let mut a = E1Allocator::new();
        let e = a.acquire().unwrap();
        a.release(e);
        a.release(e);
        assert_eq!(a.live(), 0);
    }

    #[test]
    fn node_never_revokes_handed_out_slice() {
        let a: std::sync::Mutex<E1Allocator> = std::sync::Mutex::new(E1Allocator::new());
        let (e1, sub) = SliceSource::acquire(&a).expect("a slice");
        assert_eq!(sub, 0);
        assert!(SliceSource::holds(&a, e1, sub));

        assert!(SliceSource::holds(&a, E1(0x123456), 0));
        SliceSource::release(&a, e1, sub, true);
        assert!(SliceSource::holds(&a, e1, sub));
    }

    #[test]
    fn source_that_loses_slice_reports_via_holds() {
        struct OneSocket {
            held: std::sync::Mutex<Option<E1>>,
            next: std::sync::atomic::AtomicU32,
        }
        impl SliceSource for OneSocket {
            fn acquire(&self) -> Option<(E1, u32)> {
                let e1 = (*self.held.lock().unwrap())?;
                Some((
                    e1,
                    self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                ))
            }
            fn release(&self, _e1: E1, _sub: u32, _searched: bool) {}
            fn sub_bits(&self) -> u32 {
                8
            }
            fn live(&self) -> usize {
                0
            }
            fn holds(&self, e1: E1, _sub: u32) -> bool {
                *self.held.lock().unwrap() == Some(e1)
            }
        }
        let s = OneSocket {
            held: std::sync::Mutex::new(Some(E1(0x0001b5))),
            next: std::sync::atomic::AtomicU32::new(0),
        };
        let (e1, sub) = s.acquire().expect("seated");
        assert!(s.holds(e1, sub));

        *s.held.lock().unwrap() = Some(E1(0x000000));
        assert!(!s.holds(e1, sub), "the grant is no longer this source's");
        assert!(s.holds(E1(0x000000), 7), "and the new one is");
    }

    #[test]
    fn e1_bitmap_is_2_mib() {
        assert_eq!(E1Allocator::resident_bytes(), 2 * 1024 * 1024);
        assert_eq!(crate::limits::E1_BITS + X_BITS, 64);
    }
}
