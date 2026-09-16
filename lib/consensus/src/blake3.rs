// dependency-free BLAKE3-256, portable reference form (no SIMD). checked
// against the official test vectors in the tests below; keep it that way rather
// than optimizing, since every hash in the protocol runs through here.
pub const OUT_LEN: usize = 32;

const BLOCK_LEN: usize = 64;

const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// deepest the cv stack can get: one entry per bit of the chunk counter, and
// 2^54 chunks of 1 KiB already covers any input a u64 length can describe.
const MAX_DEPTH: usize = 54;

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for (dst, &src) in permuted.iter_mut().zip(MSG_PERMUTATION.iter()) {
        *dst = m[src];
    }
    *m = permuted;
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    round(&mut state, &block);
    for _ in 0..6 {
        permute(&mut block);
        round(&mut state, &block);
    }

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    let mut out = [0u32; 8];
    out.copy_from_slice(&compression_output[..8]);
    out
}

fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (w, c) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *w = u32::from_le_bytes(c.try_into().expect("chunk is 4 bytes"));
    }
    out
}

struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_hash(&self) -> [u8; OUT_LEN] {
        let words = compress(
            &self.input_chaining_value,
            &self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        let mut out = [0u8; OUT_LEN];
        for (c, w) in out.chunks_exact_mut(4).zip(words.iter().take(8)) {
            c.copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
}

impl ChunkState {
    fn new(chunk_counter: u64) -> Self {
        ChunkState {
            chaining_value: IV,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_le_bytes(&self.block);
                self.chaining_value = first_8_words(compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                ));
                self.blocks_compressed += 1;

                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = core::cmp::min(want, input.len());
            let at = self.block_len as usize;
            self.block[at..at + take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            debug_assert!(self.block_len as usize <= BLOCK_LEN);
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_chaining_value: self.chaining_value,
            block_words: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left: &[u32; 8], right: &[u32; 8]) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(left);
    block_words[8..].copy_from_slice(right);
    Output {
        input_chaining_value: IV,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT,
    }
}

#[derive(Clone)]
pub struct Hasher {
    chunk_state: ChunkState,
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: u8,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Hasher {
            chunk_state: ChunkState::new(0),
            cv_stack: [[0u32; 8]; MAX_DEPTH],
            cv_stack_len: 0,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        debug_assert!((self.cv_stack_len as usize) < MAX_DEPTH);
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        debug_assert!(self.cv_stack_len > 0);
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            new_cv = parent_output(&self.pop_stack(), &new_cv).chaining_value();
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let cv = self.chunk_state.output().chaining_value();
                let total = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(cv, total);
                self.chunk_state = ChunkState::new(total);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = core::cmp::min(want, input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    pub fn finalize(&self) -> [u8; OUT_LEN] {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len as usize;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;

            output = parent_output(
                &self.cv_stack[parent_nodes_remaining],
                &output.chaining_value(),
            );
        }
        output.root_hash()
    }
}

pub fn hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Hasher::new();
    h.update(input);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn vector_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    const VECTORS: [(usize, &str); 35] = [
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
        (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
        (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
        (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"),
        (5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"),
        (6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"),
        (7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"),
        (8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"),
        (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
        (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
        (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
        (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"),
        (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"),
        (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"),
        (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
        (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
        (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
        (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"),
        (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
        (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
        (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
        (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
        (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
        (6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"),
        (7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"),
        (7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"),
        (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
        (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
        (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
        (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
        (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"),
    ];

    #[test]
    fn official_vectors() {
        for (len, expected) in VECTORS {
            let got = hash(&vector_input(len));
            assert_eq!(hex::encode(&got), expected, "official BLAKE3 vector len={len}");
        }
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            hex::encode(&hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn streaming_equals_one_shot() {
        for len in [0usize, 1, 63, 64, 65, 1023, 1024, 1025, 1099, 2049, 8192, 8193, 102400] {
            let input = vector_input(len);
            for split in [1usize, 7, 63, 64, 65, 1024, 1025] {
                let mut h = Hasher::new();
                for part in input.chunks(split) {
                    h.update(part);
                }
                assert_eq!(h.finalize(), hash(&input), "len={len} split={split}");
            }
        }
    }

    #[test]
    fn multi_chunk_note_preimage_1099_bytes() {
        let mut note = Vec::new();
        note.extend_from_slice(b"PLNE-note-v1");

        note.extend_from_slice(&crate::constants::Network::Main.chain_id());
        note.extend_from_slice(&[0xABu8; 32]);
        note.extend_from_slice(&1u128.to_le_bytes());
        note.extend_from_slice(&7u64.to_le_bytes());
        note.push(0x01);
        note.extend_from_slice(&1024u16.to_le_bytes());
        note.extend_from_slice(&[0x5Au8; 1024]);
        assert_eq!(note.len(), 1099);
        assert!(note.len() > CHUNK_LEN, "crosses the chunk boundary");

        let mut h = Hasher::new();
        h.update(b"PLNE-note-v1");
        h.update(&crate::constants::Network::Main.chain_id());
        h.update(&[0xABu8; 32]);
        h.update(&1u128.to_le_bytes());
        h.update(&7u64.to_le_bytes());
        h.update(&[0x01]);
        h.update(&1024u16.to_le_bytes());
        h.update(&[0x5Au8; 1024]);
        assert_eq!(h.finalize(), hash(&note));
    }

    #[test]
    fn one_bit_flip_changes_the_digest() {
        let input = vector_input(3000);
        let base = hash(&input);
        for i in [0usize, 1, 1023, 1024, 1025, 2047, 2999] {
            let mut m = input.clone();
            m[i] ^= 0x01;
            assert_ne!(hash(&m), base, "flip at {i}");
        }
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(Hasher::default().finalize(), Hasher::new().finalize());
    }
}
