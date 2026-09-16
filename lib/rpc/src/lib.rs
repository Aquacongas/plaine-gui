#![forbid(unsafe_code)]

pub mod http;
pub mod json;
pub mod jsonrpc;
pub mod methods;
pub mod mock;
pub mod notes;
pub mod server;
pub mod views;

pub use jsonrpc::{ErrorCode, RpcError};
pub use server::{check_bind_policy, BindError, RpcConfig, RpcServer, Shutdown, MIN_TOKEN_LEN};
pub use views::{Network, Node, SyncStatus};

pub const VERSION: &str = concat!("plaine-noded/", env!("CARGO_PKG_VERSION"));
