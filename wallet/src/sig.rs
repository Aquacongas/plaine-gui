use plaine_consensus::ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::secret::Secret32;

pub fn public_key_of(seed: &Secret32) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed.expose());
    sk.verifying_key().to_bytes()
}

pub fn sign(seed: &Secret32, message: &[u8; 32]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed.expose());
    sk.sign(message).to_bytes()
}

pub fn is_valid_pubkey(bytes: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use plaine_consensus::crypto;

    fn seed(tag: &[u8]) -> Secret32 {
        Secret32::from_bytes(plaine_consensus::blake3::hash(tag))
    }

    #[test]
    fn wallet_signature_verifies_under_consensus() {
        let sk = seed(b"sig.rs basic");
        let pk = public_key_of(&sk);
        let msg = [0x11u8; 32];
        let sig = sign(&sk, &msg);
        crypto::verify_signature(&pk, &msg, &sig).expect("consensus must accept our signature");
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let a = seed(b"sig.rs a");
        let b = seed(b"sig.rs b");
        let msg = [0x22u8; 32];
        let sig = sign(&a, &msg);
        assert!(crypto::verify_signature(&public_key_of(&b), &msg, &sig).is_err());
    }

    #[test]
    fn public_key_is_deterministic_in_the_seed() {
        let a = seed(b"sig.rs deterministic");
        let b = seed(b"sig.rs deterministic");
        assert_eq!(public_key_of(&a), public_key_of(&b));
    }

    #[test]
    fn pubkey_validity_check_rejects_non_points() {
        let good = public_key_of(&seed(b"sig.rs point"));
        assert!(is_valid_pubkey(&good));

        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        assert!(!is_valid_pubkey(&not_a_point));

        assert!(is_valid_pubkey(&[0xFFu8; 32]));
    }
}
