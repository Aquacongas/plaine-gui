use crate::constants::*;
use crate::wire::cmd::Cmd;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    BadMagic,
    UnknownCommand(u8),
    NonZeroFlags(u8),
    Oversize { cmd: Cmd, length: u32, cap: usize },
    OversizeAbsolute(u32),
    Truncated { want: usize, got: usize },
    Malformed(&'static str),
    TooManyItems { got: usize, cap: usize },
}

impl WireError {
    pub fn points(&self) -> u32 {
        match self {
            WireError::UnknownCommand(_) => 20,
            _ => 100,
        }
    }

    pub fn is_silent_drop(&self) -> bool {
        matches!(self, WireError::BadMagic)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub cmd: Cmd,
    pub length: u32,
}

pub fn parse_frame_header(
    buf: &[u8; FRAME_HEADER_BYTES],
    magic: &[u8; 4],
) -> Result<FrameHeader, WireError> {
    if &buf[0..4] != magic.as_slice() {
        return Err(WireError::BadMagic);
    }
    let Some(cmd) = Cmd::from_code(buf[4]) else {
        return Err(WireError::UnknownCommand(buf[4]));
    };
    if buf[5] != 0x00 {
        return Err(WireError::NonZeroFlags(buf[5]));
    }
    let length = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
    if length as usize > MAX_P2P_MSG_BYTES {
        return Err(WireError::OversizeAbsolute(length));
    }
    let cap = cmd.payload_cap();
    if length as usize > cap {
        return Err(WireError::Oversize { cmd, length, cap });
    }
    Ok(FrameHeader { cmd, length })
}

pub fn encode_frame(magic: &[u8; 4], cmd: Cmd, payload: &[u8]) -> Vec<u8> {
    debug_assert!(
        payload.len() <= cmd.payload_cap(),
        "encoder produced an over-cap {} frame",
        cmd.name()
    );
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    out.extend_from_slice(magic);
    out.push(cmd.code());
    out.push(0x00);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[derive(Debug, Default)]
pub struct ReadArena {
    buf: Vec<u8>,
}

impl ReadArena {
    pub fn new() -> ReadArena {
        ReadArena { buf: Vec::new() }
    }

    pub fn retained(&self) -> usize {
        self.buf.capacity()
    }

    pub fn take(&mut self, len: usize) -> Vec<u8> {
        if len > ARENA_MAX {
            return vec![0u8; len];
        }
        let mut b = core::mem::take(&mut self.buf);
        b.clear();
        b.resize(len, 0);
        b
    }

    pub fn give(&mut self, mut b: Vec<u8>) {
        if b.capacity() > ARENA_MAX {
            return;
        }
        b.clear();
        self.buf = b;
    }
}

#[derive(Debug)]
pub struct FrameReader {
    magic: [u8; 4],
    pending: Vec<u8>,
}

impl FrameReader {
    pub fn new(magic: [u8; 4]) -> FrameReader {
        FrameReader {
            magic,
            pending: Vec::new(),
        }
    }

    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    pub fn retained(&self) -> usize {
        self.pending.capacity()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<(Cmd, Vec<u8>)>, WireError> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        let r = loop {
            if self.pending.len() < FRAME_HEADER_BYTES {
                break Ok(());
            }
            let mut hdr = [0u8; FRAME_HEADER_BYTES];
            hdr.copy_from_slice(&self.pending[..FRAME_HEADER_BYTES]);

            let fh = match parse_frame_header(&hdr, &self.magic) {
                Ok(fh) => fh,
                Err(e) => break Err(e),
            };
            let total = FRAME_HEADER_BYTES + fh.length as usize;
            if self.pending.len() < total {
                break Ok(());
            }
            let payload = self.pending[FRAME_HEADER_BYTES..total].to_vec();
            self.pending.drain(..total);
            out.push((fh.cmd, payload));
        };
        if self.pending.capacity() > ARENA_MAX && self.pending.len() <= ARENA_MAX {
            self.pending.shrink_to(ARENA_MAX);
        }
        r.map(|()| out)
    }
}
