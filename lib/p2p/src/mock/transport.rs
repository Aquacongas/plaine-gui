use crate::wire::codec::{decode, encode};
use crate::wire::frame::{encode_frame, FrameReader, WireError};
use crate::wire::{Cmd, Msg};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Endpoint {
    magic: [u8; 4],
    reader: FrameReader,
    pub received: HashMap<u8, u64>,
    pub sent: HashMap<u8, u64>,
    pub bytes_in: u64,
}

impl Endpoint {
    pub fn new(magic: [u8; 4]) -> Endpoint {
        Endpoint {
            magic,
            reader: FrameReader::new(magic),
            received: HashMap::new(),
            sent: HashMap::new(),
            bytes_in: 0,
        }
    }

    pub fn send(&mut self, m: &Msg) -> Vec<u8> {
        let cmd = m.cmd();
        *self.sent.entry(cmd.code()).or_insert(0) += 1;
        encode_frame(&self.magic, cmd, &encode(m))
    }

    pub fn recv(&mut self, bytes: &[u8]) -> Result<Vec<Msg>, WireError> {
        self.bytes_in += bytes.len() as u64;
        let frames = self.reader.push(bytes)?;
        let mut out = Vec::with_capacity(frames.len());
        for (cmd, payload) in frames {
            *self.received.entry(cmd.code()).or_insert(0) += 1;
            out.push(decode(cmd, &payload)?);
        }
        Ok(out)
    }

    pub fn count_in(&self, cmd: Cmd) -> u64 {
        self.received.get(&cmd.code()).copied().unwrap_or(0)
    }

    pub fn count_out(&self, cmd: Cmd) -> u64 {
        self.sent.get(&cmd.code()).copied().unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct Duplex {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl Duplex {
    pub fn new(magic: [u8; 4]) -> Duplex {
        Duplex {
            a: Endpoint::new(magic),
            b: Endpoint::new(magic),
        }
    }

    pub fn a_to_b(&mut self, m: &Msg) -> Result<Vec<Msg>, WireError> {
        let bytes = self.a.send(m);
        self.b.recv(&bytes)
    }

    pub fn b_to_a(&mut self, m: &Msg) -> Result<Vec<Msg>, WireError> {
        let bytes = self.b.send(m);
        self.a.recv(&bytes)
    }

    pub fn raw_to_b(&mut self, bytes: &[u8]) -> Result<Vec<Msg>, WireError> {
        self.b.recv(bytes)
    }
}
