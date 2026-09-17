use crate::constants::HEADER_BYTES;
use crate::traits::Hash32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub proto_ver: u16,
    pub min_proto: u16,
    pub chain_id: [u8; 4],
    pub services: u32,
    pub nonce: u64,
    pub time: u64,
    pub height: u64,
    pub tip_hash: Hash32,
    pub cum_work: [u8; 32],
    pub listen_port: u16,
    pub user_agent: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvKind {
    Tx,
    Block,
}

impl InvKind {
    pub const fn code(self) -> u8 {
        match self {
            InvKind::Tx => 1,
            InvKind::Block => 2,
        }
    }

    pub const fn from_code(c: u8) -> Option<InvKind> {
        match c {
            1 => Some(InvKind::Tx),
            2 => Some(InvKind::Block),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvItem {
    pub kind: InvKind,
    pub hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrRec {
    pub time: u64,
    pub services: u32,
    pub ip: [u8; 16],
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointMsg {
    pub height: u64,
    pub hash: Hash32,
    pub sigs: Vec<(u8, [u8; 64])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Hello(Hello),
    HelloAck,
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<AddrRec>),
    Inv(Vec<InvItem>),
    GetData(Vec<InvItem>),
    NotFound(Vec<InvItem>),

    GetHeaders { locator: Vec<Hash32>, stop: Hash32 },
    Headers(Vec<[u8; HEADER_BYTES]>),
    Block(Vec<u8>),
    Tx(Vec<u8>),
    Mempool,
    FeeFilter(u128),
    Checkpoint(CheckpointMsg),
    GetCheckpoint,
}

impl Msg {
    pub fn cmd(&self) -> crate::wire::Cmd {
        use crate::wire::Cmd;
        match self {
            Msg::Hello(_) => Cmd::Hello,
            Msg::HelloAck => Cmd::HelloAck,
            Msg::Ping(_) => Cmd::Ping,
            Msg::Pong(_) => Cmd::Pong,
            Msg::GetAddr => Cmd::GetAddr,
            Msg::Addr(_) => Cmd::Addr,
            Msg::Inv(_) => Cmd::Inv,
            Msg::GetData(_) => Cmd::GetData,
            Msg::NotFound(_) => Cmd::NotFound,
            Msg::GetHeaders { .. } => Cmd::GetHeaders,
            Msg::Headers(_) => Cmd::Headers,
            Msg::Block(_) => Cmd::Block,
            Msg::Tx(_) => Cmd::Tx,
            Msg::Mempool => Cmd::Mempool,
            Msg::FeeFilter(_) => Cmd::FeeFilter,
            Msg::Checkpoint(_) => Cmd::Checkpoint,
            Msg::GetCheckpoint => Cmd::GetCheckpoint,
        }
    }
}
