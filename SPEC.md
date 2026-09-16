Plaine is honest, censorship-free money open to everyone: built to shut out ASIC
and GPU so every CPU earns for the real power it brings, with a steady reward that
keeps issuance predictable and no supply cap to keep the network secure, while its
inflation falls toward zero with every passing day. No premine, no presale, no
dev fund.

In tribute to Satoshi Nakamoto, and in the author's own name, Plaine stands for
one CPU, one vote.

Nothing promised. Nothing hidden. See for yourself.

# Plaine Technical Specification

A public transfer chain secured by CPU-only proof of work. Isochron gives ASICs and
GPUs no edge over an ordinary processor, so hashpower tracks honest CPU capacity, not
specialized hardware: proof of work stays one CPU, one vote. Accounts with nonces,
ed25519 signatures, flat unbounded emission. No smart contracts, no privacy, no
staking. 51% protection is a reorg-depth limit plus signed checkpoints with a
compile-time sunset.

All multi-byte integers are little-endian unless stated. All hashes are 32-byte
BLAKE3-256 and appear big-endian on the wire and in displays. Notation: `||` is byte
concatenation, `<=`/`>=` are inequalities, `^` is XOR, `>>` is a right shift.

---

## 1. Chain identity

| Constant | Value |
|---|---|
| Ticker | PLNE |
| `MAGIC` | `B7 4E D3 21` |
| `CHAIN_ID` | `50 4C 4E 45` (ASCII "PLNE") |
| `POW_LIMIT` | `2^240 - 1` |
| Genesis `bits` | equal to `POW_LIMIT` (easiest difficulty) |
| Port P2P | 9256 |
| Port RPC | 9257 |
| Port stratum solo | 9258 |
| Port stratum pool | 9259 |

`CHAIN_ID` is part of every transaction signature from block 0, so a signature does not
replay onto a fork with the same address format.

---

## 2. Units and emission

| Constant | Value |
|---|---|
| Decimals | 6, `1 PLNE = 10^6 mile` |
| Smallest unit | mile |
| Balance type | `u128` |
| Emission cap | none (unbounded, disinflationary) |
| Block time | 60 s -> 525960 blocks/year |
| `BLOCK_SUBSIDY` | 200000 mile = 0.2 PLNE, constant forever |
| Annual emission | +105192 PLNE/year |

```
subsidy(0)     = 0
subsidy(h>=1)  = BLOCK_SUBSIDY = 200000 mile
block_reward(h) = subsidy(h)
```

No halving, no decay, no slow start, no supply cap; genesis (height 0) pays 0. Issuance
is a closed form of height, not a header field or state entry:

```
issued_through(height)   = height * BLOCK_SUBSIDY
cumulative_issued(height) = (height - 1) * BLOCK_SUBSIDY
```

Milestones: 1000000 PLNE at height 5000000; 2000000 PLNE at height 10000000.

There is no premine, presale, foundation, or developer fee.

---

## 3. Addresses

bech32m (BIP-350), HRP `plne`. The 20-byte payload is
`BLAKE3-256(pubkey)[:20]`.

---

## 4. Block header

Fixed size, 132 bytes. Integers little-endian, hashes big-endian.

```
offset  size  field
------  ----  --------------------------------------------------
  0       4   version           u32; top 3 bits = 001, low 29 bits signal
  4       8   height            u64
 12      32   prev_hash         BLAKE3-256 of the parent header
 44      32   tx_root           transaction Merkle root
 76      32   ext_root          reserved, must be zero
108       8   time              u64, unix seconds
116       4   bits              compact target
120       4   author_note_len   u32, 0..256
124       8   nonce             u64
------  ----
        132 bytes
```

The PoW preimage is the entire 132-byte header, with the nonce at the tail.

`tx_root` is a real binary Merkle tree, domain-separated:
- leaf: `BLAKE3("PLNE-leaf" || tx)`
- node: `BLAKE3("PLNE-node" || L || R)`
- an odd level duplicates the last node with an explicit length flag (guards CVE-2012-2459).

`ext_root` is the sole extension slot and consensus requires it to be zero.

---

## 5. Transactions

An envelope with the type in the first byte. Unknown types are rejected but must still
parse (length is read so a transaction cannot break block parsing).

| Type | Purpose | Sender |
|---|---|---|
| `0x00` | coinbase | the block's miner |
| `0x01` | transfer | anyone |
| `0x02` | author announcement | holder of `AUTHOR_PUBKEY` only |
| `0x03`..`0xFF` | reserved, rejected | |

### 5.1 Transfer (0x01), 157 bytes

```
field       size   description
type          1    0x01
from_pub     32    ed25519 public key
to           20    recipient address
amount       16    u128, mile
fee          16    u128, mile
nonce         8    u64, sender account nonce
sig          64    ed25519
```

Signed over `BLAKE3("PLNE-tx-v1" || CHAIN_ID || from_pub || to || amount || fee || nonce)`.
`txid = BLAKE3("PLNE-txid" || canonical serialization without the signature)`.

### 5.2 Signature acceptance rules

Ed25519 semantics are fixed exactly; naming the algorithm is not sufficient, because
implementations diverge on edge cases and a divergence is a chain split.

| Rule | Requirement |
|---|---|
| Scheme | RFC 8032 Ed25519 (not ph, not ctx) |
| Scalar `S` | canonically reduced, `S < L`; non-reduced rejected |
| Point encoding `R`, `A` | canonical; `y >= p` rejected |
| Small-order keys/points | rejected |
| Verification equation | cofactorless: `[S]B = R + [k]A` |
| Implementation | `ed25519_dalek::VerifyingKey::verify_strict` (never `verify`) |

`ed25519-dalek` is the consensus crate's only external dependency; BLAKE3, bech32m and
the ASERT math are implemented in-tree. The node links two more, `redb` for storage and
`tokio` for its async runtime. Dependencies are pinned in `Cargo.lock`, not vendored.

### 5.3 Coinbase (0x00)

Carries the block reward, the sum of block fees, and the author note (section 5.5).
`COINBASE_MATURITY = 60` blocks, strictly greater than `MAX_REORG_DEPTH = 30`, so a
reward undone by a reorg cannot already be spent. The relation
`COINBASE_MATURITY > MAX_REORG_DEPTH` is asserted at compile time.

### 5.4 Fees

Consensus minimum is 1 mile (anti-spam). Everything else (relay floor, selection by fee
priority) is mempool policy configured by the operator, not consensus.

### 5.5 Author note (in the coinbase)

The author comment lives in the coinbase transaction, not the header, and reaches the
header through `tx_root`.

```
offset  size  field
  0       1   record_version  u8 = 0x01
  1       1   encoding        u8, display hint, NOT checked by consensus
                              0x00 opaque, 0x01 UTF-8, 0x02 URI, 0x03 app-defined
  2       2   length          u16 LE, 0 <= length <= 256
  4       N   payload         arbitrary bytes
```

Consensus rules: `length <= 256`, payload opaque with no content validation.
UTF-8 validation is not done at consensus level (it would tie consensus to Unicode table
versions and become a split vector). Sanitization happens only at display time, in this
order: strict UTF-8 decode with U+FFFD replacement -> remove C0/C1 -> remove bidi
overrides (U+202A..U+202E, U+2066..U+2069, U+200E, U+200F) -> remove zero-width ->
normalize NFC -> HTML-escape -> insert via `textContent`, never `innerHTML`.

Genesis note, exactly this ASCII string, 51 bytes, no trailing newline,
`encoding = 0x01`:

```
We were told the altitude. We never saw the ground.
```

The genesis builder refuses any other record or encoding.

### 5.6 Author announcement (0x02)

An in-chain message channel usable only by the holder of `AUTHOR_PUBKEY`; sent like an
ordinary transaction, no mining required.

```
field       size   description
type          1    0x02
from_pub     32    ed25519 pubkey; MUST equal AUTHOR_PUBKEY
fee          16    u128, mile
nonce         8    u64, author account nonce
encoding      1    display hint, NOT checked by consensus (values as in 5.5)
length        2    u16 LE, 1 <= length <= 1024
payload       N    arbitrary bytes
sig          64    ed25519
```

Signed over
`BLAKE3("PLNE-note-v1" || CHAIN_ID || from_pub || fee || nonce || encoding || length || payload)`.

Consensus rules: `from_pub == AUTHOR_PUBKEY`; valid signature; `1 <= length <= 1024`;
nonce and fee follow ordinary account rules (replay protection is the account nonce). A
real fee is paid. Payload is opaque, sanitized only at display time (section 5.5). The
announcement key is separate from the checkpoint key, can only write text, and has no
sunset. The public half is embedded in the binary as a default; config overrides only for
rotation.

---

## 6. Proof of work: Isochron v1

Integer-only, program derived per hash from the nonce, 64 KiB scratchpad per thread, no
shared dataset, no floating point anywhere in consensus.

### 6.1 Constants

| Constant | Value |
|---|---|
| `SCRATCH_BYTES` | 65536 (64 KiB), power of two, checked by a `const` assertion |
| `SCRATCH_MASK` | `SCRATCH_BYTES - 8`, applied as an AND mask |
| `PROG_INSTR` | 512 = 32 blocks x 16 slots |
| `LOOPS` | 1024 |
| Registers | 8 x u64 |
| Digest | BLAKE3-256 |
| Multiplier | `0x9E3779B97F4A7C15` |
| `c1`, `c2` | `0x6A09E667`, `0xBB67AE85` |

Per-block 16-slot composition, identical in each of the 32 blocks: 6 ALU, 1
rotate-by-constant, 1 rotate-by-register, 5 memory accesses, 1 multiply, 2 AES rounds.
The whole opcode alphabet is active on every hash (all 6 ALU members, all 4
rotate-by-constant, both rotate-by-register, all 6 memory-access forms, both multiplies,
AES). Counters cycle round-robin over the alphabet, so the opcode histogram is a frozen
constant and the emitted code size is identical for any nonce to the byte. There are no
epochs; the program is rebuilt every hash.

Scratchpad addressing:
```
addr = ((value ^ imm ^ c) * 0x9E3779B97F4A7C15) >> 40 & SCRATCH_MASK
```

### 6.2 Order of one hash

```
1. fill the scratchpad from the header seed
2. fold the scratchpad -> program seed
3. build the program from the seed            (build_program)
4. execute 1024 loops of 512 instructions
5. BLAKE3-256 digest
```

Fill is AES-CTR, every hash, write-only. Row `i` is two rounds of `iso_aesenc` over the
counter block `LE64(seed) || LE64(i XOR ISO_FILL_DOM)`. CTR (not chaining) keeps the cost
throughput-bound and near-equal across microarchitectures; two rounds give complete
diffusion.

The program seed derives from the filled scratchpad via a four-chain AES fold, where each
row is absorbed as the round key of one AES round:

```
acc[j]     = LE64(seed XOR ISO_FILL_DOM) || LE64(~seed XOR j),  j = 0..3
acc[i & 3] = AESENC(acc[i & 3], line_i)                          for each row
t          = AESENC(AESENC(AESENC(acc0, acc1), acc2), acc3)
prog_seed  = LO(AES2(t)) XOR HI(AES2(t))
```

Evaluating a nonce costs at least `3 * SCRATCH_BYTES / 16` = 12288 AES rounds at 64 KiB.

### 6.3 Implementation rules

1. A node never JITs. Its PoW verification is interpreter-only; the node process never
   maps W^X pages. JIT (`plaine_pow_mine()`) links only into the miner. The `pow-sys`
   `jit` and `node` features are mutually exclusive.
2. Program composition is built round-robin over the alphabet, never by sampling.
3. Triples "class + destination + source" are shuffled as whole units.
4. The whole alphabet is active on every hash; no subsets.
5. `SCRATCH_BYTES` is checked to be a power of two at build time.
6. The test-vector file is fixed; on mismatch the node prints `PLATFORM HASH MISMATCH` and
   refuses to mine.
7. Every spread measurement is published with a fixed-nonce control.

ASIC resistance is honest: no CPU algorithm prevents ASICs. The instruction set exists for
GPU resistance. The real lever is obsolescence by emergency fork if an ASIC appears; the
in-chain author announcement (section 5.6) is the fork's un-censorable delivery channel.

---

## 7. Difficulty

ASERT (`aserti3-2d`), integer form.

| Constant | Value |
|---|---|
| `HALF_LIFE` | 3600 s |
| Anchor exponent from | the parent's timestamp (not the candidate's) |
| `MAX_FUTURE_DRIFT` | 600 s |
| `MEDIAN_TIME_SPAN` | 11 blocks |
| Re-anchoring | every 100000 blocks |
| Clamping | resulting target to `[1, POW_LIMIT]`; the exponent is not clamped |

The schedule is absolute: fast-mined blocks are compensated later. Recovery after a
hashrate change is `log2(change) * 3600 s`. The parent-timestamp form resists grinding and
tolerates loose miner clocks.

---

## 8. Consensus limits

| Field | Value |
|---|---|
| `MAX_BLOCK_BYTES` | 1 MiB |
| `MAX_TX_BYTES` | 8 KiB |
| `MAX_TXS_PER_BLOCK` | 4096 |
| `MAX_REORG_DEPTH` | 30, unconditional |
| `COINBASE_MATURITY` | 60 |
| `MAX_P2P_MSG_BYTES` | 8 MiB |
| `MAX_P2P_RESP_BYTES` | 32 MiB |
| `MAX_PEERS` | 128 |
| `MAX_MEMPOOL_TXS` | 20000 |
| `MAX_MEMPOOL_NONCE_GAP` | 256 |
| `MAX_MEMPOOL_TXS_PER_SENDER` | 4096 |
| `MAX_HEADERS_PER_MSG` | 2000 |

---

## 9. 51% protection

Four layers. Layers 1, 2, and 4 require no key; layer 3 is a signed lever with a
compile-time sunset.

### 9.1 Reorg-depth limit

```
depth = height_of_tip - height_of_fork_point
if depth > MAX_REORG_DEPTH: reject
```

`MAX_REORG_DEPTH = 30` (half an hour at 60 s blocks), unconditional. The only permitted
entry deeper than the limit is the signed anchor (9.2).

### 9.2 Deep-reorg recovery via a signed anchor

A reorg deeper than the limit is permitted only if the candidate contains a block matching
the latest signed authoritative anchor:

```
if depth > MAX_REORG_DEPTH:
    permit only if candidate_meets_anchor(auth_anchor, fork_point, new_blocks)
```

An anonymous attacker cannot forge the signature, so protection against unsigned deep
reorgs is complete while an honest lagging node can converge.

### 9.3 Checkpoints

A signed pair "height -> block hash":

```
message   = "plaine-checkpoint-v1|" || height || "|" || hash
signature = ed25519
```

Rules:
1. At block validation: a block at a checkpointed height whose hash does not match is
   rejected.
2. At reorg, reject only a shortening attack:
```
for each checkpointed height h:
    if h >= fork_point and h <= our_tip and h > candidate_tip: reject
```
The crude form `h >= fork_point` would block all forward sync and is forbidden.

Checkpoint control: one key, threshold 1, loaded from config with the public half embedded
as a default (empty config is valid). The signature only rejects reorgs; it never creates,
orders, or censors blocks. `CHECKPOINT_SUNSET_HEIGHT = 525960` is a compile-time constant;
after it, the check returns false unconditionally. Extending it requires a hard fork.

Recommended user guidance: while the hashrate is small, a transaction less than 30 blocks
old can be contested; do not accept large payments at fewer than 30 confirmations.

### 9.4 Deterministic tie-break

On equal accumulated work, the block with the smaller hash (big-endian byte order) wins.

---

## 10. Storage model

- State is a flat table `address -> (balance u128, nonce u64)`. No state Merkle tree, no
  receipts.
- Engine: redb (single-writer, ACID, shadow paging) plus append-only 128 MiB block-body
  segments; the body index stores `(segment, offset, length)`.
- One write transaction per block, atomically; a crash leaves the database on a block
  boundary.
- Reorg is an undo-diff journal 256 blocks deep, not a replay. A reorg deeper than the
  journal falls back to replay from the deepest reachable boundary; deeper than the pruning
  horizon requires resync.
- History: a full node keeps block bodies for the last 525960 blocks (1 year); an archive
  node keeps everything; headers are always kept.

Process model: tokio handles I/O only; consensus runs on system threads. A single
validator thread owns fork choice and state application and holds no lock across I/O; a
single committer thread is the sole writer; a CPU pool of `P = clamp(cores/2, 2, 8)`
threads runs interpreter-only PoW verification and batched ed25519. Any work costlier than 100 us
leaves tokio.

---

## 11. Fork activation

BIP8 in the header version bits (top 3 bits `001`, low 29 bits deployment).

| Constant | Value |
|---|---|
| `SIGNAL_WINDOW` | 10080 blocks (7 days) |
| `SIGNAL_THRESHOLD` | 80% |
| `LOCKIN_GRACE` | 1440 blocks (1 day) |
| `TIMEOUT` | `start + 129600` blocks (90 days) |

`lockinontimeout = true` for all security and consensus-bug fixes; `false` only for
optional economic changes. Blocks below an activation height are validated by the old
rules. A per-fork version constant is frozen forever and never references the node's
current version.

---

## 12. P2P wire protocol

TCP, port 9256, IPv4 and IPv6, one socket per peer, full duplex. Binary
frames only; no HTTP, no polling. Fork choice is a pure function of accumulated work with
the smaller-hash tie-break; float never crosses the wire.

### 12.1 Frame

```
offset  size  field
  0       4   magic     MAGIC
  4       1   cmd       command code
  5       1   flags     must be 0x00 in PROTO_VER = 1
  6       4   length    u32 LE, payload length
 10       N   payload
```

`length` above the per-command cap or above `MAX_P2P_MSG_BYTES` (8 MiB): disconnect and
ban. Bad magic: silent disconnect. There is no per-frame checksum: TCP covers integrity
and every object is content-addressed by its BLAKE3 hash. All payload counters are fixed
u32 LE with a named cap (no varints). Hashes on the wire are 32 bytes big-endian;
`cum_work` is u256 LE (32 bytes), `work(header) = floor(2^256 / (target + 1))`.

### 12.2 Handshake

`HELLO` must be the first message both directions; anything else first disconnects and
bans (1 h). Handshake deadline 10 s. `HELLO` carries `proto_ver` (=1), `min_proto`,
`chain_id`, `services`, a per-process `nonce` (self-connection detection), `time`,
`height`, `tip_hash`, `cum_work`, `listen_port`, and a user agent. A mismatched `chain_id`
disconnects silently and the address is marked foreign for 24 h. The reply is `HELLO_ACK`.
v1 is not encrypted; all consensus data is public and self-authenticated.

### 12.3 Message set

| cmd | name | payload cap | purpose |
|---|---|---|---|
| 0x01 | HELLO | 167 B | handshake |
| 0x02 | HELLO_ACK | 0 | acknowledgement |
| 0x03 | PING | 8 B | nonce |
| 0x04 | PONG | 8 B | echo nonce |
| 0x05 | GETADDR | 0 | request addresses |
| 0x06 | ADDR | 4 + 512x30 B | up to 512 addresses |
| 0x10 | INV | 4 + 4096x33 B | announce objects |
| 0x11 | GETDATA | 4 + 4096x33 B | request objects |
| 0x12 | NOTFOUND | 4 + 4096x33 B | refusal |
| 0x13 | GETHEADERS | 4 + 64x32 + 32 B | locator + stop_hash |
| 0x14 | HEADERS | 4 + 2000x132 B | up to `MAX_HEADERS_PER_MSG` |
| 0x15 | BLOCK | 1 MiB + 4 | block body (reply to GETDATA) |
| 0x16 | TX | 8 KiB | transaction body (reply to GETDATA) |
| 0x17 | MEMPOOL | 16 B | request mempool sync |
| 0x18 | FEEFILTER | 16 B | u128 LE absolute fee floor |
| 0x1A | CHECKPOINT | 1016 B | signed anchor |
| 0x1B | GETCHECKPOINT | 0 | request the anchor |

`0x19` is reserved and unused (no REJECT message; refusals are typed internally and never
reach the wire). INV/GETDATA/NOTFOUND entries are `type u8 (1=TX, 2=BLOCK) || hash 32`.
Unknown `cmd` under `PROTO_VER = 1` is a violation.

### 12.4 Headers-first sync and the interpreter budget

A node never JITs, so verifying one header costs 1.3-3 ms of interpreter; a 2000-header
message is up to 6 s of CPU. Each incoming header passes ordered gates before the
interpreter (each gate costs microseconds):

- G0 dedup: BLAKE3 lookup in the header tree and a 65536-entry rejected-header cache.
- G1 structure: size multiple of 132, count within cap, monotone heights, consistent
  in-batch `prev_hash` chaining.
- G2 context: parent known; `bits` exactly equals `ASERT(parent)`; time in
  `(MTP, now + 600 s]`; fork point no deeper than `MAX_REORG_DEPTH` (exceptions: the branch
  carries the current signed anchor, or the node is in IBD).
- G3 work admission: claimed accumulated work must exceed the tip's, or equal it with a
  lexicographically smaller tip hash (the tie-break). A non-contending branch gets no
  interpreter time.
- G4 budget: surviving headers are verified in height order; the first PoW failure is
  disconnect + 24 h ban. Cost draws from a per-peer bucket `POW_BUDGET` = 100 ms of
  interpreter per 10 s, burst 300 ms; the global non-sync pool is 1 thread, <= 500 ms
  CPU/s. The sync peer is exempt only during IBD.

IBD is defined by number: the tip lags wall clock by more than 12 min, or the best peer
`cum_work` exceeds ours by more than 20 blocks of current difficulty. Disconnected headers
are never stored (an orphan-header store is an OOM hole); the peer gets a GETHEADERS with a
locator. The fork tree holds at most 8 competing tips and 800 non-canonical headers.

---

## 13. Stratum mining protocol

Line-delimited JSON-RPC over TCP, stratum-v1 style, the only mining path (node embeds it
for solo on 9258; the reference pool is 9259). Messages: `mining.subscribe`,
`mining.authorize`, `mining.set_target`, `mining.notify`, `mining.submit`,
`mining.keepalive`, `client.reconnect`.

- Login: `address[.rig_name][+difficulty]`. The address is bech32m, fully validated
  including checksum; it is the pool account key (no registrations).
- Job: the 124-byte header prefix (everything but the nonce), hex.
- Miner-mutable: only the 8 nonce bytes. Not time, not coinbase.
- Target, not difficulty: `mining.set_target` sends the 32-byte big-endian target
  directly. A share is valid iff `bigEndian(BLAKE3-256(header)) <= target`. Display value
  `diff = floor(2^256 / target)`.
- Line length: <= 2 KiB before authorization, <= 8 KiB after. Read deadline 600 s;
  `mining.keepalive` (reply `{"result":true}`) resets only that deadline. Authorization
  within 10 s of accept.

### 13.1 Nonce space

The nonce is u64, little-endian at header offset 124.

```
N = (E1 << 40) | X
    E1  extranonce1, 24 bits, server-assigned per connection
    X   40 bits, rolled by the miner
```

`mining.subscribe` returns `[[notifications], "<fixed-part-hex>", <rolled-bytes>]`; both
the fixed-part length and the rolled-byte count must be read, not assumed. The node hands
6 hex chars and 5 rolled bytes. A server sitting on someone else's slice (a pool on its
node's slice, a proxy) may sub-slice by a whole number of bytes, `s <= 8` bits, giving 8
hex chars and 4 rolled bytes at `s = 8`; exactly one level of sub-slicing is allowed. A
submitted nonce whose top `24 + s` bits do not match the assigned slice is error 25.

Submit carries the nonce as hex in header byte order:
`{"id":N,"method":"mining.submit","params":["login","job_id","<nonce hex>"]}`.

### 13.2 Share verification order (cheap before expensive)

1. Parse line, length check.
2. `job_id` among the connection's 4 live jobs (else error 20/21).
3. Slice: top bits equal the assigned fixed part (else error 25).
4. Duplicate check (per connection+job, cap 256; else error 22).
5. Submit token bucket 3/s, burst 10 (else error 26).
6. Admission: 1 in-check + 1 waiting per connection, round-robin.
7. Interpreter (1.3-3 ms): `digest > job target` is error 23; otherwise accepted at the
   job's served target.
8. If additionally `digest <= network target`, a block is found: the template builder
   joins its prefix to the nonce and body. There is no block-submission RPC method; a pool
   relays a found block via `mining.submit` on the pool-to-node connection carrying the
   nonce's slice.

### 13.3 Error codes

| code | message | banscore |
|---|---|---|
| 20 | unknown job | +2 |
| 21 | stale share | +1 |
| 22 | duplicate share | +25 |
| 23 | low difficulty | +10 |
| 24 | unauthorized / bad address | +25 |
| 25 | nonce out of slice | +50 |
| 26 | throttled | 0 (escalates) |
| 27 | banned | - |
| 28 | server busy | 0 always |
| 29 | unknown method | +5 soft |
| 30 | bad message | +50 |
| 31 | slice revoked | 0 always |

### 13.4 Vardiff and limits

Setpoint 20 s/share (3 shares per block). `MIN_DIFF` 8192, `START_DIFF` 60000 (or the
address last-difficulty cache), `MAX_DIFF` = network difficulty. Fixed difficulty pins via
the `+difficulty` login suffix. Connections: pool 16384 (64/IP), solo 256 (16/IP, operator
ceiling 8192). Banscore is per IP, threshold 100, decay 1 point / 6 s, ban 600 s
escalating x4 up to 86400 s. `client.reconnect` is ignored by conforming miners (a hijack
vector); a server that must move a miner off a dead slice disconnects it (error 31).

### 13.5 Configurable limits

Every limit in 13.4 (and the line/timeout limits in 13) is a default, not a constant.
The `[stratum]` section of the node config overrides each one. Values below are the keys
and what they set; the defaults are the numbers already given above.

Master switch:

- `enforcement` (bool, default true). false turns off all built-in policy at once: no
  bans, no rate limits, no connection caps, no auth/idle/read/write timeouts. Difficulty
  adjustment still runs. Policy is then owned by an external system (fail2ban, a pool
  front end). Individual limits can also be turned off one at a time (below).

Sentinel: for rate limits, caps, throttle and timeouts, a value of 0 means "no limit" /
"never fires". A timeout of 0 never disconnects on that condition.

Connection caps: `max_connections`, `max_per_ip`, `new_conns_per_ip_per_min`,
`global_accept_per_sec`.

Bans and scoring: `bans_enabled` (false disables scoring, bans and throttling),
`ban_threshold` (0 = never ban), `ban_soft_cap`, `ban_decay_secs`, `ban_base_secs`,
`ban_ladder_factor`, `ban_max_secs`, `ban_table_entries`, `garbage_throttle_secs`
(0 = off). Per-error banscore points (13.3) are fixed weights; `ban_threshold` scales
overall sensitivity.

Rate limits: `submit_rate_per_sec`, `submit_burst`, `line_rate_per_sec`, `line_burst`.

Timeouts (secs, 0 = never): `auth_deadline_secs`, `idle_evict_secs`, `read_deadline_secs`,
`write_timeout_secs`, `out_buf_cap_bytes` (0 = unlimited out buffer).

Vardiff is fully configurable. Off switch: `vardiff_enabled` (default true). false turns
off node-side vardiff entirely - every miner runs at a fixed difficulty and the node never
retargets, handing difficulty control to an external system. The fixed value is
`vardiff_fixed_diff`, or `vardiff_start_diff` when that is 0. The `+difficulty` login
suffix still pins a per-miner difficulty either way.

Vardiff bounds and target: `vardiff_setpoint_secs` (0 = auto from the CPU budget),
`vardiff_start_diff`, `vardiff_min_diff`, `vardiff_max_diff` (0 = cap at network
difficulty). Retarget cadence: `vardiff_tick_secs`, `vardiff_retarget_gate_shares`,
`vardiff_retarget_gate_secs`, `vardiff_warmup_shares`, `vardiff_warmup_gate_shares`,
`vardiff_mature_shares`. Per-step clamp and variance band: `vardiff_max_step`,
`vardiff_dead_zone_pct`, `vardiff_mature_zone_pct`, `vardiff_fast_escape_pct` (all x100:
150 = 1.50). Silence: `vardiff_silence_slack` (setpoints of no shares before easing down).
Smoothing: `vardiff_dsps_tau_fast_secs`, `vardiff_dsps_tau_mid_secs`,
`vardiff_dsps_tau_slow_secs` (the three share-rate EMA windows). Rounding grid:
`vardiff_ladder`, an integer array of mantissas x10 (10 = 1.0), 1 to 16 rungs, strictly
increasing.

Difficulty cache and reconnect floor: `diff_cache_entries`, `diff_cache_ttl_secs`,
`reconnect_storm_per_min` (0 = do not pin a floor), `reconnect_storm_window_secs`.

All values are integers; the config file has no floats (SPEC 5.1). Fractions are scaled to
integers: percents (x100) for the zone and escape ratios, mantissa-x10 rungs for the
ladder. Seconds are the unit for durations. The JSON structural limits (depth, member and
element counts) define a well-formed stratum message and are fixed. The per-connection
share pipeline is two deep (one verifying, one queued) and is fixed.

---

## 14. Node RPC (local)

JSON-RPC 2.0 over HTTP, default bind `127.0.0.1:9257`, no authentication on
loopback. On a non-loopback bind the node refuses to start without a static bearer token.
This is the node's local control surface for the wallet and the operator's own
explorer/pool processes; it is not a public service and must not be exposed. Keys are never
held by the node; mining is stratum-only; there is no `getwork`, `getblocktemplate`, or
block-submission method. Object keys are `camelCase`. Closed list of 18 methods:

| Method | Returns |
|---|---|
| `chain_getInfo` | height, tip hash, chainwork, network, version, sync status |
| `chain_getHeaderByHeight` / `chain_getHeaderByHash` | the 132-byte header + meta |
| `chain_getBlockByHeight` / `chain_getBlockByHash` | block at verbosity 0/1/2 |
| `account_get` | balance, nonce, pendingNonce |
| `tx_sendRaw` | hex -> txid or a structured admission error |
| `tx_get` | tx + status (mempool or height + confirmations) |
| `mempool_getInfo` | counts, bytes, current relay floor |
| `mempool_getBySender` | an address's pending transactions |
| `fee_suggest` | fee percentiles over the last 240 blocks |
| `emission_audit` | issued, expected-by-formula at a height |
| `checkpoint_getStatus` | keys, threshold, last anchor, sunset height, ingest state |
| `checkpoint_submit` | apply an offline-signed checkpoint record (reject-only) |
| `author_getNotes` | author announcements from a height, newest first |
| `net_getPeerInfo` | peer list, direction, counters |
| `stratum_getSessions` | live stratum sessions: worker, ip, shares, difficulty, ages |
| `node_getBudgets` | live CPU/queue budget counters |

Amounts are `u128` mile. `emission_audit` lets any third party reconcile actual issuance
with the closed-form formula at any height.
