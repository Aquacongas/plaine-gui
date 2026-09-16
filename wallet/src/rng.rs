use crate::error::{Result, WalletError};
use crate::secret::{self, Secret32};

// Milk Sad and Randstorm were wallets whose keys came from a weak or exhausted
// generator. The only source we trust for a 256-bit seed is the kernel:
// getrandom(2) on Linux, BCryptGenRandom on Windows, reached through the
// getrandom crate. No userspace PRNG, no seeding from time or pid.
pub fn generate_seed() -> Result<Secret32> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| {
        WalletError::io(format!(
            "the OS random source is unavailable ({e}); no key was generated. \
             Supply your own entropy instead: \
             openssl rand -hex 32 | plaine-wallet new --seed-stdin ..."
        ))
    })?;

    // A working CSPRNG never hands back all-zero or a counting pattern. If it
    // does, the source is broken, and a broken source is the reason to check
    // rather than mint a key from it. This is the same gate a supplied seed
    // passes through.
    secret::check_seed_material(&bytes)?;

    let seed = Secret32::from_bytes(bytes);
    for b in bytes.iter_mut() {
        *b = 0;
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_seed_is_not_all_zero() {
        let s = generate_seed().expect("the OS rng is reachable in the test environment");
        assert!(
            s.expose().iter().any(|&b| b != 0),
            "a generated seed is never all zero"
        );
    }

    #[test]
    fn two_generated_seeds_differ() {
        let a = generate_seed().unwrap();
        let b = generate_seed().unwrap();
        assert_ne!(a.expose(), b.expose(), "each call draws fresh entropy");
    }
}
