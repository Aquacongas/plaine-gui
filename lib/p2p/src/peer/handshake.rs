use crate::constants::*;
use crate::peer::score::Offence;
use crate::wire::msg::Hello;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Accept,
    ForeignNetwork,
    VersionMismatch,
    SelfConnection,
    ReservedServiceBits,
    Malformed,
}

impl HandshakeOutcome {
    pub fn offence(self) -> Option<Offence> {
        match self {
            HandshakeOutcome::Accept
            | HandshakeOutcome::ForeignNetwork
            | HandshakeOutcome::VersionMismatch
            | HandshakeOutcome::SelfConnection => None,
            HandshakeOutcome::ReservedServiceBits | HandshakeOutcome::Malformed => {
                Some(Offence::Malformed)
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HelloCheck {
    pub chain_id: [u8; 4],
    pub our_nonce: u64,
    pub proto_ver: u16,
    pub min_proto: u16,
    pub now_unix: u64,
}

impl HelloCheck {
    pub fn judge(&self, h: &Hello) -> HandshakeOutcome {
        if h.chain_id != self.chain_id {
            return HandshakeOutcome::ForeignNetwork;
        }
        if h.nonce == self.our_nonce {
            return HandshakeOutcome::SelfConnection;
        }
        if h.min_proto > self.proto_ver || self.min_proto > h.proto_ver {
            return HandshakeOutcome::VersionMismatch;
        }
        if h.services & SERVICE_MBZ_MASK != 0 {
            return HandshakeOutcome::ReservedServiceBits;
        }
        if h.user_agent.len() > UA_MAX {
            return HandshakeOutcome::Malformed;
        }
        HandshakeOutcome::Accept
    }

    pub fn clock_offset(&self, h: &Hello) -> i64 {
        h.time as i64 - self.now_unix as i64
    }

    pub fn clock_offset_notable(&self, h: &Hello) -> bool {
        self.clock_offset(h).abs() > 120
    }
}
