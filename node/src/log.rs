use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::LogLevel;

static LEVEL: AtomicU8 = AtomicU8::new(2);

fn code(level: LogLevel) -> u8 {
    match level {
        LogLevel::Error => 0,
        LogLevel::Warn => 1,
        LogLevel::Info => 2,
        LogLevel::Debug => 3,
        LogLevel::Trace => 4,
    }
}

pub fn set_level(level: LogLevel) {
    LEVEL.store(code(level), Ordering::Relaxed);
}

pub fn enabled(level: LogLevel) -> bool {
    code(level) <= LEVEL.load(Ordering::Relaxed)
}

pub fn log(level: LogLevel, target: &str, message: &str) {
    if !enabled(level) {
        return;
    }
    let line = format!("{} {} {:<8} {}\n", timestamp(), level.label(), target, message);
    let mut err = std::io::stderr().lock();

    let _ = err.write_all(line.as_bytes());
}

pub fn security(target: &str, message: impl AsRef<str>) {
    let line = format!(
        "{} SECURITY {:<8} {}\n",
        timestamp(),
        target,
        message.as_ref()
    );
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(line.as_bytes());
}

pub fn error(target: &str, message: impl AsRef<str>) {
    log(LogLevel::Error, target, message.as_ref());
}

pub fn warn(target: &str, message: impl AsRef<str>) {
    log(LogLevel::Warn, target, message.as_ref());
}

pub fn info(target: &str, message: impl AsRef<str>) {
    log(LogLevel::Info, target, message.as_ref());
}

#[allow(dead_code)]
pub fn debug(target: &str, message: impl AsRef<str>) {
    log(LogLevel::Debug, target, message.as_ref());
}

#[allow(dead_code)]
pub fn trace(target: &str, message: impl AsRef<str>) {
    log(LogLevel::Trace, target, message.as_ref());
}

pub fn blank() {
    if enabled(LogLevel::Info) {
        let _ = std::io::stderr().lock().write_all(b"\n");
    }
}

pub fn timestamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format_unix(secs)
}

pub fn format_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// days-since-epoch to civil (y, m, d) without a date library; Hinnant's algorithm,
// with march-based years so the leap day falls at the end.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn human_duration(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m{:02}s", secs / 60, secs % 60),
        3600..=86_399 => format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600),
    }
}

pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_utc_iso8601() {
        assert_eq!(format_unix(1_620_000_000), "2021-05-03T00:00:00Z");

        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix(1_709_164_800), "2024-02-29T00:00:00Z");

        assert_eq!(format_unix(1_735_689_599), "2024-12-31T23:59:59Z");
    }

    #[test]
    fn durations_read_as_durations() {
        assert_eq!(human_duration(4), "4s");
        assert_eq!(human_duration(432), "7m12s");
        assert_eq!(human_duration(7_440), "2h04m");
        assert_eq!(human_duration(196_000), "2d 6h");
    }

    #[test]
    fn big_numbers_get_separators() {
        assert_eq!(thousands(525_960), "525,960");
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn level_filter_filters() {
        set_level(LogLevel::Warn);
        assert!(enabled(LogLevel::Error));
        assert!(enabled(LogLevel::Warn));
        assert!(!enabled(LogLevel::Info));
        assert!(!enabled(LogLevel::Trace));
        set_level(LogLevel::Info);
        assert!(enabled(LogLevel::Info));
        assert!(!enabled(LogLevel::Debug));
    }
}
