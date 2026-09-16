use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    Usage(String),
    Format(String),
    Crypto(String),
    Io(String),
    Refused(String),
}

impl WalletError {
    pub fn usage<S: Into<String>>(s: S) -> Self {
        WalletError::Usage(s.into())
    }
    pub fn format<S: Into<String>>(s: S) -> Self {
        WalletError::Format(s.into())
    }
    pub fn crypto<S: Into<String>>(s: S) -> Self {
        WalletError::Crypto(s.into())
    }
    pub fn io<S: Into<String>>(s: S) -> Self {
        WalletError::Io(s.into())
    }
    pub fn refused<S: Into<String>>(s: S) -> Self {
        WalletError::Refused(s.into())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            WalletError::Usage(_) => 2,
            _ => 1,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            WalletError::Usage(_) => "usage",
            WalletError::Format(_) => "format",
            WalletError::Crypto(_) => "crypto",
            WalletError::Io(_) => "io",
            WalletError::Refused(_) => "refused",
        }
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = match self {
            WalletError::Usage(s)
            | WalletError::Format(s)
            | WalletError::Crypto(s)
            | WalletError::Io(s)
            | WalletError::Refused(s) => s,
        };
        write!(f, "{}: {}", self.kind(), body)
    }
}

impl std::error::Error for WalletError {}

pub type Result<T> = core::result::Result<T, WalletError>;
