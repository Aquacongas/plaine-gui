fn main() {
    let pk = plaine_consensus::blake3::hash(b"PLAINE FAUCET v1");
    let addr = plaine_consensus::crypto::address_from_pubkey(&pk);
    println!("pubkey  {}", plaine_consensus::hex::encode(&pk));
    println!("address {addr}");
    println!("author  {}", plaine_consensus::hex::encode(b"AUTHOR-KEY-PLACEHOLDER-NOT-REAL2"));
    println!("ckpt    {}", plaine_consensus::hex::encode(b"CHECKPOINT-PLACEHOLDER-NOT-REAL0"));
    println!("genesis_bits 0x{:08x}", plaine_consensus::constants::GENESIS_BITS);
    println!("chain_id {}", plaine_consensus::hex::encode(&plaine_consensus::constants::CHAIN_ID));
    println!("version_base 0x{:08x}", plaine_consensus::constants::VERSION_BASE);
}
