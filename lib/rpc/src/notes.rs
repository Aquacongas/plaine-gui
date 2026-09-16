#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedNote {
    pub hex: String,
    pub text: String,
    pub valid_utf8: bool,
    pub sanitized_chars: usize,
}

pub fn render(payload: &[u8]) -> RenderedNote {
    let hex = plaine_consensus::hex::encode(payload);
    let valid_utf8 = core::str::from_utf8(payload).is_ok();
    let decoded = String::from_utf8_lossy(payload);
    let mut text = String::with_capacity(decoded.len());
    let mut sanitized = 0usize;
    for c in decoded.chars() {
        if is_stripped(c) {
            sanitized += 1;
            continue;
        }
        // count lossy U+FFFD as sanitized, but only when the input really was bad utf-8
        if c == '\u{FFFD}' && !valid_utf8 {
            sanitized += 1;
        }
        text.push(c);
    }
    RenderedNote { hex, text, valid_utf8, sanitized_chars: sanitized }
}

// author notes are attacker-controlled and end up in terminals and logs. strip what lets them
// lie: C0/C1 and DEL, bidi overrides (trojan-source), zero-width and line-separator chars.
fn is_stripped(c: char) -> bool {
    let u = c as u32;
    matches!(u,
        0x00..=0x1f | 0x7f                                      // C0 controls + DEL
        | 0x80..=0x9f                                           // C1 controls
        | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069   // bidi overrides
        | 0x200b..=0x200d | 0x2060..=0x2064 | 0xfeff | 0x00ad   // zero-width / soft hyphen
        | 0x2028 | 0x2029                                       // line / paragraph separators
    )
}

pub fn for_log(payload: &[u8], max_chars: usize) -> String {
    let r = render(payload);
    let mut s: String = r.text.chars().take(max_chars).collect();
    if r.text.chars().count() > max_chars {
        s.push_str(" ...[truncated, full text via author_getNotes]");
    }
    if !r.valid_utf8 {
        s.push_str(" [not valid UTF-8; hex is canonical]");
    }
    if s.trim().is_empty() {
        return format!("<{} bytes, nothing printable>", payload.len());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_passes_through_untouched() {
        let r = render(b"Isochron v2 activates at height 600000");
        assert_eq!(r.text, "Isochron v2 activates at height 600000");
        assert!(r.valid_utf8);
        assert_eq!(r.sanitized_chars, 0);
        assert_eq!(r.hex, plaine_consensus::hex::encode(b"Isochron v2 activates at height 600000"));
    }

    #[test]
    fn terminal_escapes_cannot_reach_a_terminal() {
        let evil = b"\x1b[2J\x1b[31mALL YOUR BLOCKS\x1b[0m";
        let r = render(evil);
        assert!(!r.text.contains('\u{1b}'));
        assert_eq!(r.text, "[2J[31mALL YOUR BLOCKS[0m");
        assert!(r.sanitized_chars >= 3);

        assert_eq!(r.hex, plaine_consensus::hex::encode(evil));
    }

    #[test]
    fn carriage_returns_cannot_forge_a_log_line() {
        let r = render(b"benign\r2020-01-01T00:00:00Z ERROR chain corrupted, wipe your datadir");
        assert!(!r.text.contains('\r'));
        assert!(!r.text.contains('\n'));
        assert!(r.text.starts_with("benign2020"));
    }

    #[test]
    fn trojan_source_bidi_overrides_are_removed() {
        let s = "pay \u{202e}0001 to attacker\u{202c}";
        let r = render(s.as_bytes());
        assert!(!r.text.contains('\u{202e}'));
        assert!(!r.text.contains('\u{202c}'));
        assert_eq!(r.sanitized_chars, 2);
    }

    #[test]
    fn c1_controls_and_unicode_line_separators_cannot_forge_a_second_line() {
        for c in ['\u{85}', '\u{80}', '\u{9b}', '\u{9f}'] {
            let s = format!("paid{c}node: everything is fine");
            let r = render(s.as_bytes());
            assert!(!r.text.contains(c), "C1 U+{:04X} survived: {:?}", c as u32, r.text);
            assert_eq!(r.sanitized_chars, 1, "U+{:04X}", c as u32);
        }

        for c in ['\u{2028}', '\u{2029}'] {
            let s = format!("paid{c}node: everything is fine");
            let r = render(s.as_bytes());
            assert!(!r.text.contains(c), "U+{:04X} survived: {:?}", c as u32, r.text);
            assert_eq!(r.sanitized_chars, 1, "U+{:04X}", c as u32);
        }

        let r = render("caf\u{e9}".as_bytes());
        assert_eq!(r.text, "caf\u{e9}");
        assert_eq!(r.sanitized_chars, 0);
    }

    #[test]
    fn zero_width_characters_that_hide_text_are_removed() {
        let s = "plaine\u{200b}.\u{feff}org";
        let r = render(s.as_bytes());
        assert_eq!(r.text, "plaine.org");
        assert_eq!(r.sanitized_chars, 2);
    }

    #[test]
    fn invalid_utf8_is_salvaged_and_flagged_rather_than_dropped() {
        let r = render(&[0xff, 0xfe, b'h', b'i']);
        assert!(!r.valid_utf8);
        assert!(r.text.ends_with("hi"));
        assert!(r.sanitized_chars > 0);
        assert_eq!(r.hex, "fffe6869");
    }

    #[test]
    fn a_payload_of_pure_control_bytes_does_not_print_as_nothing() {
        let line = for_log(&[0x1b, 0x07, 0x00], 80);
        assert!(line.contains("nothing printable"), "{line}");
    }

    #[test]
    fn truncation_is_visible() {
        let long = "A".repeat(300);
        let line = for_log(long.as_bytes(), 80);
        assert!(line.contains("truncated"));
        assert_eq!(line.chars().filter(|c| *c == 'A').count(), 80);
    }
}
