use crate::constants::*;
use crate::traits::Hash32;
use crate::wire::cmd::Cmd;
use crate::wire::frame::WireError;
use crate::wire::msg::*;

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, i: 0 }
    }
    fn need(&self, n: usize) -> Result<(), WireError> {
        if self.b.len() - self.i < n {
            Err(WireError::Truncated {
                want: n,
                got: self.b.len() - self.i,
            })
        } else {
            Ok(())
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        self.need(n)?;
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn u128(&mut self) -> Result<u128, WireError> {
        let s = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(u128::from_le_bytes(a))
    }
    fn arr32(&mut self) -> Result<[u8; 32], WireError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    fn finish(self) -> Result<(), WireError> {
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(WireError::Malformed("trailing bytes after payload"))
        }
    }

    fn count(&mut self, cap: usize) -> Result<usize, WireError> {
        let n = self.u32()? as usize;
        if n > cap {
            return Err(WireError::TooManyItems { got: n, cap });
        }
        Ok(n)
    }
}

pub fn encode(msg: &Msg) -> Vec<u8> {
    let mut o = Vec::new();
    match msg {
        Msg::Hello(h) => {
            o.extend_from_slice(&h.proto_ver.to_le_bytes());
            o.extend_from_slice(&h.min_proto.to_le_bytes());
            o.extend_from_slice(&h.chain_id);
            o.extend_from_slice(&h.services.to_le_bytes());
            o.extend_from_slice(&h.nonce.to_le_bytes());
            o.extend_from_slice(&h.time.to_le_bytes());
            o.extend_from_slice(&h.height.to_le_bytes());
            o.extend_from_slice(&h.tip_hash);
            o.extend_from_slice(&h.cum_work);
            o.extend_from_slice(&h.listen_port.to_le_bytes());
            let ua = if h.user_agent.len() > UA_MAX {
                &h.user_agent[..UA_MAX]
            } else {
                &h.user_agent[..]
            };
            o.push(ua.len() as u8);
            o.extend_from_slice(ua);
        }
        Msg::HelloAck | Msg::GetAddr | Msg::Mempool | Msg::GetCheckpoint => {}
        Msg::Ping(n) | Msg::Pong(n) => o.extend_from_slice(&n.to_le_bytes()),
        Msg::Addr(v) => {
            o.extend_from_slice(&(v.len() as u32).to_le_bytes());
            for a in v {
                o.extend_from_slice(&a.time.to_le_bytes());
                o.extend_from_slice(&a.services.to_le_bytes());
                o.extend_from_slice(&a.ip);
                o.extend_from_slice(&a.port.to_le_bytes());
            }
        }
        Msg::Inv(v) | Msg::GetData(v) | Msg::NotFound(v) => {
            o.extend_from_slice(&(v.len() as u32).to_le_bytes());
            for it in v {
                o.push(it.kind.code());
                o.extend_from_slice(&it.hash);
            }
        }
        Msg::GetHeaders { locator, stop } => {
            o.extend_from_slice(&(locator.len() as u32).to_le_bytes());
            for h in locator {
                o.extend_from_slice(h);
            }
            o.extend_from_slice(stop);
        }
        Msg::Headers(v) => {
            o.extend_from_slice(&(v.len() as u32).to_le_bytes());
            for h in v {
                o.extend_from_slice(h);
            }
        }
        Msg::Block(b) | Msg::Tx(b) => o.extend_from_slice(b),
        Msg::FeeFilter(f) => o.extend_from_slice(&f.to_le_bytes()),
        Msg::Checkpoint(c) => {
            o.extend_from_slice(&c.height.to_le_bytes());
            o.extend_from_slice(&c.hash);
            o.push(c.sigs.len() as u8);
            for (id, sig) in &c.sigs {
                o.push(*id);
                o.extend_from_slice(sig);
            }
        }
    }
    o
}

pub fn decode(cmd: Cmd, payload: &[u8]) -> Result<Msg, WireError> {
    if payload.len() > cmd.payload_cap() {
        return Err(WireError::Oversize {
            cmd,
            length: payload.len() as u32,
            cap: cmd.payload_cap(),
        });
    }
    let mut c = Cur::new(payload);
    let m = match cmd {
        Cmd::Hello => {
            let proto_ver = c.u16()?;
            let min_proto = c.u16()?;
            let chain_id = c.arr::<4>()?;
            let services = c.u32()?;
            let nonce = c.u64()?;
            let time = c.u64()?;
            let height = c.u64()?;
            let tip_hash = c.arr32()?;
            let cum_work = c.arr32()?;
            let listen_port = c.u16()?;
            let ua_len = c.u8()? as usize;
            if ua_len > UA_MAX {
                return Err(WireError::TooManyItems {
                    got: ua_len,
                    cap: UA_MAX,
                });
            }
            let user_agent = c.take(ua_len)?.to_vec();
            c.finish()?;
            Msg::Hello(Hello {
                proto_ver,
                min_proto,
                chain_id,
                services,
                nonce,
                time,
                height,
                tip_hash,
                cum_work,
                listen_port,
                user_agent,
            })
        }
        Cmd::HelloAck => {
            c.finish()?;
            Msg::HelloAck
        }
        Cmd::GetAddr => {
            c.finish()?;
            Msg::GetAddr
        }
        Cmd::GetCheckpoint => {
            c.finish()?;
            Msg::GetCheckpoint
        }
        Cmd::Mempool => {
            c.finish()?;
            Msg::Mempool
        }
        Cmd::Ping => {
            let n = c.u64()?;
            c.finish()?;
            Msg::Ping(n)
        }
        Cmd::Pong => {
            let n = c.u64()?;
            c.finish()?;
            Msg::Pong(n)
        }
        Cmd::Addr => {
            let n = c.count(ADDR_MSG_MAX)?;
            c.need(n * ADDR_REC_BYTES)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let time = c.u64()?;
                let services = c.u32()?;
                let ip = c.arr::<16>()?;
                let port = c.u16()?;
                v.push(AddrRec {
                    time,
                    services,
                    ip,
                    port,
                });
            }
            c.finish()?;
            Msg::Addr(v)
        }
        Cmd::Inv | Cmd::GetData | Cmd::NotFound => {
            let n = c.count(INV_MAX)?;
            c.need(n * INV_ITEM_BYTES)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let k = c.u8()?;
                let Some(kind) = InvKind::from_code(k) else {
                    return Err(WireError::Malformed("unknown inv type byte"));
                };
                let hash = c.arr32()?;
                v.push(InvItem { kind, hash });
            }
            c.finish()?;
            match cmd {
                Cmd::Inv => Msg::Inv(v),
                Cmd::GetData => Msg::GetData(v),
                _ => Msg::NotFound(v),
            }
        }
        Cmd::GetHeaders => {
            let n = c.count(LOCATOR_MAX)?;
            c.need(n * 32 + 32)?;
            let mut locator = Vec::with_capacity(n);
            for _ in 0..n {
                locator.push(c.arr32()?);
            }
            let stop = c.arr32()?;
            c.finish()?;
            Msg::GetHeaders { locator, stop }
        }
        Cmd::Headers => {
            let n = c.count(MAX_HEADERS_PER_MSG)?;
            c.need(n * HEADER_BYTES)?;
            let mut v: Vec<[u8; HEADER_BYTES]> = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(c.arr::<HEADER_BYTES>()?);
            }
            c.finish()?;
            Msg::Headers(v)
        }
        Cmd::Block => {
            if payload.len() < HEADER_BYTES + 4 {
                return Err(WireError::Truncated {
                    want: HEADER_BYTES + 4,
                    got: payload.len(),
                });
            }
            Msg::Block(payload.to_vec())
        }
        Cmd::Tx => {
            if payload.is_empty() {
                return Err(WireError::Truncated { want: 1, got: 0 });
            }
            Msg::Tx(payload.to_vec())
        }
        Cmd::FeeFilter => {
            let f = c.u128()?;
            c.finish()?;
            Msg::FeeFilter(f)
        }
        Cmd::Checkpoint => {
            let height = c.u64()?;
            let hash = c.arr32()?;
            let n = c.u8()? as usize;
            if n > CHECKPOINT_SIGS_MAX {
                return Err(WireError::TooManyItems {
                    got: n,
                    cap: CHECKPOINT_SIGS_MAX,
                });
            }
            c.need(n * 65)?;
            let mut sigs = Vec::with_capacity(n);
            for _ in 0..n {
                let id = c.u8()?;
                sigs.push((id, c.arr::<64>()?));
            }
            c.finish()?;
            Msg::Checkpoint(CheckpointMsg { height, hash, sigs })
        }
    };
    Ok(m)
}

pub const ZERO_HASH: Hash32 = [0u8; 32];
