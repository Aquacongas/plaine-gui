use crate::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cmd {
    Hello,
    HelloAck,
    Ping,
    Pong,
    GetAddr,
    Addr,
    Inv,
    GetData,
    NotFound,
    GetHeaders,
    Headers,
    Block,
    Tx,
    Mempool,
    FeeFilter,
    Checkpoint,
    GetCheckpoint,
}

impl Cmd {
    pub const fn code(self) -> u8 {
        match self {
            Cmd::Hello => 0x01,
            Cmd::HelloAck => 0x02,
            Cmd::Ping => 0x03,
            Cmd::Pong => 0x04,
            Cmd::GetAddr => 0x05,
            Cmd::Addr => 0x06,
            Cmd::Inv => 0x10,
            Cmd::GetData => 0x11,
            Cmd::NotFound => 0x12,
            Cmd::GetHeaders => 0x13,
            Cmd::Headers => 0x14,
            Cmd::Block => 0x15,
            Cmd::Tx => 0x16,
            Cmd::Mempool => 0x17,
            Cmd::FeeFilter => 0x18,
            Cmd::Checkpoint => 0x1A,
            Cmd::GetCheckpoint => 0x1B,
        }
    }

    pub const fn from_code(c: u8) -> Option<Cmd> {
        match c {
            0x01 => Some(Cmd::Hello),
            0x02 => Some(Cmd::HelloAck),
            0x03 => Some(Cmd::Ping),
            0x04 => Some(Cmd::Pong),
            0x05 => Some(Cmd::GetAddr),
            0x06 => Some(Cmd::Addr),
            0x10 => Some(Cmd::Inv),
            0x11 => Some(Cmd::GetData),
            0x12 => Some(Cmd::NotFound),
            0x13 => Some(Cmd::GetHeaders),
            0x14 => Some(Cmd::Headers),
            0x15 => Some(Cmd::Block),
            0x16 => Some(Cmd::Tx),
            0x17 => Some(Cmd::Mempool),
            0x18 => Some(Cmd::FeeFilter),
            0x1A => Some(Cmd::Checkpoint),
            0x1B => Some(Cmd::GetCheckpoint),
            _ => None,
        }
    }

    pub const fn payload_cap(self) -> usize {
        match self {
            Cmd::Hello => CAP_HELLO,
            Cmd::HelloAck => CAP_HELLO_ACK,
            Cmd::Ping => CAP_PING,
            Cmd::Pong => CAP_PONG,
            Cmd::GetAddr => CAP_GETADDR,
            Cmd::Addr => CAP_ADDR,
            Cmd::Inv | Cmd::GetData | Cmd::NotFound => CAP_INV,
            Cmd::GetHeaders => CAP_GETHEADERS,
            Cmd::Headers => CAP_HEADERS,
            Cmd::Block => CAP_BLOCK,
            Cmd::Tx => CAP_TX,
            Cmd::Mempool => CAP_MEMPOOL,
            Cmd::FeeFilter => CAP_FEEFILTER,
            Cmd::Checkpoint => CAP_CHECKPOINT,
            Cmd::GetCheckpoint => CAP_GETCHECKPOINT,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Cmd::Hello => "HELLO",
            Cmd::HelloAck => "HELLO_ACK",
            Cmd::Ping => "PING",
            Cmd::Pong => "PONG",
            Cmd::GetAddr => "GETADDR",
            Cmd::Addr => "ADDR",
            Cmd::Inv => "INV",
            Cmd::GetData => "GETDATA",
            Cmd::NotFound => "NOTFOUND",
            Cmd::GetHeaders => "GETHEADERS",
            Cmd::Headers => "HEADERS",
            Cmd::Block => "BLOCK",
            Cmd::Tx => "TX",
            Cmd::Mempool => "MEMPOOL",
            Cmd::FeeFilter => "FEEFILTER",
            Cmd::Checkpoint => "CHECKPOINT",
            Cmd::GetCheckpoint => "GETCHECKPOINT",
        }
    }

    pub const fn carries_headers(self) -> bool {
        matches!(self, Cmd::Headers)
    }

    pub const ALL: [Cmd; 17] = [
        Cmd::Hello,
        Cmd::HelloAck,
        Cmd::Ping,
        Cmd::Pong,
        Cmd::GetAddr,
        Cmd::Addr,
        Cmd::Inv,
        Cmd::GetData,
        Cmd::NotFound,
        Cmd::GetHeaders,
        Cmd::Headers,
        Cmd::Block,
        Cmd::Tx,
        Cmd::Mempool,
        Cmd::FeeFilter,
        Cmd::Checkpoint,
        Cmd::GetCheckpoint,
    ];
}
