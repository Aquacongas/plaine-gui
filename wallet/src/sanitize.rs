pub struct Preview {
    pub valid_utf8: bool,
    pub text: String,
    pub removed: usize,
}

pub fn preview(payload: &[u8]) -> Preview {
    let Ok(s) = core::str::from_utf8(payload) else {
        return Preview {
            valid_utf8: false,
            text: String::new(),
            removed: 0,
        };
    };
    let mut out = String::with_capacity(s.len());
    let mut removed = 0usize;
    for c in s.chars() {
        if is_stripped(c) {
            removed += 1;
        } else {
            out.push(c);
        }
    }
    Preview {
        valid_utf8: true,
        text: out,
        removed,
    }
}

fn is_stripped(c: char) -> bool {
    let u = c as u32;

    // C0 and C1 control blocks, plus DEL
    if u < 0x20 || u == 0x7F || (0x80..=0x9F).contains(&u) {
        return true;
    }

    // bidi marks and overrides, zero-width chars, interlinear and tag blocks:
    // anything that can render a payload as something other than what it says
    matches!(
        u,
        0x200E | 0x200F | 0x061C
            | 0x202A..=0x202E
            | 0x2066..=0x2069
            | 0x200B | 0x200C | 0x200D | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0xE0000..=0xE007F
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_survives_untouched() {
        let p = preview(b"The Times 03/Jan/2009 Chancellor on brink");
        assert!(p.valid_utf8);
        assert_eq!(p.text, "The Times 03/Jan/2009 Chancellor on brink");
        assert_eq!(p.removed, 0);
    }

    #[test]
    fn invalid_utf8_is_reported_not_guessed() {
        let p = preview(&[0xFF, 0xFE, 0x00]);
        assert!(!p.valid_utf8);
        assert!(p.text.is_empty());
    }

    #[test]
    fn bidi_override_is_stripped() {
        let payload = "pay alice\u{202E}reverse".as_bytes();
        let p = preview(payload);
        assert!(p.valid_utf8);
        assert_eq!(p.text, "pay alicereverse");
        assert_eq!(p.removed, 1);
    }

    #[test]
    fn zero_width_and_controls_are_stripped() {
        let payload = "a\u{200B}b\u{0007}c\u{FEFF}d\ne".as_bytes();
        let p = preview(payload);
        assert_eq!(p.text, "abcde");
        assert_eq!(p.removed, 4);
    }

    #[test]
    fn non_ascii_text_is_preserved() {
        let p = preview("message accentue\u{0301}".as_bytes());
        assert!(p.valid_utf8);
        assert_eq!(p.text, "message accentue\u{0301}");
    }
}
