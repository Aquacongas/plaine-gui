use crate::secret::{Secret32, SecretBytes};

pub const TAG_KDF: &[u8] = b"PLNE-wallet-kdf-v1";

pub const TAG_ENC: &[u8] = b"PLNE-wallet-enc-v1";

pub const TAG_MAC: &[u8] = b"PLNE-wallet-mac-v1";

pub const TAG_SALT: &[u8] = b"PLNE-wallet-salt-v1";

pub const TAG_NONCE: &[u8] = b"PLNE-wallet-nonce-v1";

pub const KDF_BLAKE3_ITER_V1: &str = "blake3-iter-v1";

pub const KDF_NONE: &str = "none";

pub const CIPHER_BLAKE3_CTR_V1: &str = "blake3-ctr-v1";

pub const CIPHER_NONE: &str = "none";

// Work factor for the passphrase KDF. blake3-iter-v1 is not memory-hard:
// iterations raise the cost per guess linearly and do nothing against a GPU.
pub const DEFAULT_ITERS: u64 = 1_200_000;

pub const WARN_BELOW_ITERS: u64 = 200_000;

// ceiling against a mistyped digit; a runaway count looks just like a hang
pub const MAX_ITERS: u64 = 1_000_000_000;

pub const NOTICE_ABOVE_ITERS: u64 = 4 * DEFAULT_ITERS;

fn null_key() -> Secret32 {
    Secret32::from_bytes([0u8; 32])
}

pub fn derive_key(passphrase: &SecretBytes, salt: &[u8; 32], iters: u64) -> Secret32 {
    let mut h = plaine_consensus::blake3::Hasher::new();
    h.update(TAG_KDF);
    h.update(salt);
    h.update(passphrase.expose());
    let mut k = h.finalize();
    // sequential chain: every round folds in the salt and the counter, which
    // is what keeps the work off a parallel machine
    for i in 0..iters {
        let mut h = plaine_consensus::blake3::Hasher::new();
        h.update(TAG_KDF);
        h.update(salt);
        h.update(&i.to_le_bytes());
        h.update(&k);
        k = h.finalize();
    }
    Secret32::from_bytes(k)
}

pub fn effective_key(passphrase: Option<&SecretBytes>, salt: &[u8; 32], iters: u64) -> Secret32 {
    match passphrase {
        Some(p) => derive_key(p, salt, iters),
        None => null_key(),
    }
}

pub fn keystream_block(key: &Secret32, nonce: &[u8; 16], counter: u64) -> [u8; 32] {
    let mut h = plaine_consensus::blake3::Hasher::new();
    h.update(TAG_ENC);
    h.update(key.expose());
    h.update(nonce);
    h.update(&counter.to_le_bytes());
    h.finalize()
}

pub fn xor_seed(key: &Secret32, nonce: &[u8; 16], input: &[u8; 32]) -> [u8; 32] {
    let ks = keystream_block(key, nonce, 0);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = input[i] ^ ks[i];
    }
    out
}

pub fn mac(key: &Secret32, message: &[u8]) -> [u8; 32] {
    let mut h = plaine_consensus::blake3::Hasher::new();
    h.update(TAG_MAC);
    h.update(key.expose());
    h.update(message);
    h.finalize()
}

pub fn derive_salt(seed: &Secret32, created: u64) -> [u8; 32] {
    let mut h = plaine_consensus::blake3::Hasher::new();
    h.update(TAG_SALT);
    h.update(seed.expose());
    h.update(&created.to_le_bytes());
    h.finalize()
}

pub fn derive_nonce(seed: &Secret32, created: u64) -> [u8; 16] {
    let mut h = plaine_consensus::blake3::Hasher::new();
    h.update(TAG_NONCE);
    h.update(seed.expose());
    h.update(&created.to_le_bytes());
    let full = h.finalize();
    let mut n = [0u8; 16];
    n.copy_from_slice(&full[..16]);
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::ct_eq;

    fn pass(s: &str) -> SecretBytes {
        SecretBytes::from_vec(s.as_bytes().to_vec())
    }

    #[test]
    fn derivation_is_deterministic_and_salt_dependent() {
        let salt_a = [0x01u8; 32];
        let salt_b = [0x02u8; 32];
        let k1 = derive_key(&pass("correct horse"), &salt_a, 64);
        let k2 = derive_key(&pass("correct horse"), &salt_a, 64);
        let k3 = derive_key(&pass("correct horse"), &salt_b, 64);
        let k4 = derive_key(&pass("correct horsf"), &salt_a, 64);
        assert_eq!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose(), "the salt must enter the key");
        assert_ne!(k1.expose(), k4.expose(), "the passphrase must enter the key");
    }

    #[test]
    fn iteration_count_changes_the_key() {
        let salt = [0x7Au8; 32];
        let a = derive_key(&pass("x"), &salt, 10);
        let b = derive_key(&pass("x"), &salt, 11);
        assert_ne!(a.expose(), b.expose(), "iters must change the key");
    }

    fn reference_chain(passphrase: &[u8], salt: &[u8; 32], iters: u64) -> [u8; 32] {
        let mut b = Vec::new();
        b.extend_from_slice(TAG_KDF);
        b.extend_from_slice(salt);
        b.extend_from_slice(passphrase);
        let mut k = plaine_consensus::blake3::hash(&b);
        for i in 0..iters {
            let mut b = Vec::new();
            b.extend_from_slice(TAG_KDF);
            b.extend_from_slice(salt);
            b.extend_from_slice(&i.to_le_bytes());
            b.extend_from_slice(&k);
            k = plaine_consensus::blake3::hash(&b);
        }
        k
    }

    #[test]
    fn chain_is_n_salted_hashes() {
        let salt = [0x3Cu8; 32];
        let p = pass("a generated passphrase, not a chosen one");
        for n in [0u64, 1, 2, 3, 17, 64, 255, 256, 1000, 1001, 4096] {
            assert_eq!(
                derive_key(&p, &salt, n).expose(),
                &reference_chain(p.expose(), &salt, n),
                "chain mismatch at {n} iterations"
            );
        }

        let mut seen = std::collections::HashSet::new();
        for n in [0u64, 1, 2, 3, 17, 64, 255, 256, 1000, 1001, 4096] {
            assert!(
                seen.insert(*derive_key(&p, &salt, n).expose()),
                "two different iteration counts produced the same key at {n}"
            );
        }
    }

    #[test]
    fn derive_key_matches_pinned_vector() {
        let salt = [0x11u8; 32];
        let k = derive_key(&pass("plaine kdf known answer"), &salt, WARN_BELOW_ITERS);
        assert_eq!(
            plaine_consensus::hex::encode(k.expose()),
            "2f21c78f1993f4a88506ca5b590d50c579ec85dd319a43113bcaeed044bf3faf",
            "the KDF at {WARN_BELOW_ITERS} iterations no longer matches its frozen vector"
        );
    }

    #[test]
    fn xor_seed_is_its_own_inverse() {
        let key = Secret32::from_bytes([0x5Au8; 32]);
        let nonce = [0x33u8; 16];
        let seed = plaine_consensus::blake3::hash(b"kdf xor test");
        let ct = xor_seed(&key, &nonce, &seed);
        assert_ne!(ct, seed, "ciphertext must not equal plaintext");
        assert_eq!(xor_seed(&key, &nonce, &ct), seed);
    }

    #[test]
    fn nonce_separates_the_keystream() {
        let key = Secret32::from_bytes([0x11u8; 32]);
        assert_ne!(
            keystream_block(&key, &[0u8; 16], 0),
            keystream_block(&key, &[1u8; 16], 0)
        );
        assert_ne!(
            keystream_block(&key, &[0u8; 16], 0),
            keystream_block(&key, &[0u8; 16], 1)
        );
    }

    #[test]
    fn domains_are_separated() {
        let key = Secret32::from_bytes([0x99u8; 32]);
        let m = mac(&key, b"");
        let ks = keystream_block(&key, &[0u8; 16], 0);
        assert_ne!(m, ks);
    }

    #[test]
    fn mac_is_sensitive_to_every_message_byte() {
        let key = Secret32::from_bytes([0x42u8; 32]);
        let base = mac(&key, b"kdf: blake3-iter-v1\nkdf_iters: 1200000\n");
        let down = mac(&key, b"kdf: none\nkdf_iters: 0\n");
        assert!(!ct_eq(&base, &down), "a downgrade must move the MAC");
    }

    #[test]
    fn salt_and_nonce_are_unique_per_seed_and_time() {
        let s1 = Secret32::from_bytes(plaine_consensus::blake3::hash(b"salt seed 1"));
        let s2 = Secret32::from_bytes(plaine_consensus::blake3::hash(b"salt seed 2"));
        assert_ne!(derive_salt(&s1, 100), derive_salt(&s2, 100));
        assert_ne!(derive_salt(&s1, 100), derive_salt(&s1, 101));
        assert_ne!(derive_nonce(&s1, 100), derive_nonce(&s2, 100));

        assert_ne!(&derive_salt(&s1, 100), s1.expose());
    }
}
