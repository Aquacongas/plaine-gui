use crate::engine::fd::{FdBudget, FdClass, FdLease};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

pub async fn bind(addr: SocketAddr, fd: &Arc<FdBudget>) -> io::Result<(TcpListener, FdLease)> {
    let lease = fd
        .acquire(FdClass::Listener)
        .ok_or_else(|| io::Error::other("FD_LISTENERS exhausted"))?;
    let l = TcpListener::bind(addr).await?;
    Ok((l, lease))
}

pub async fn accept(l: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    l.accept().await
}

pub async fn connect(
    addr: SocketAddr,
    timeout_ms: u64,
    lease: FdLease,
) -> io::Result<(TcpStream, FdLease)> {
    let s = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "CONNECT_TIMEOUT"))??;
    Ok((s, lease))
}

pub fn tune(s: &TcpStream) {
    let _ = s.set_nodelay(true);
}
