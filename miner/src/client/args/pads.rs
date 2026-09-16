use crate::pad::PadPages;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ask {
    #[default]
    Auto,
    Force,
    Never,
}

impl Ask {
    pub fn wanted(self) -> bool {
        !matches!(self, Ask::Never)
    }

    pub fn describe(self, got: PadPages) -> String {
        match (self, got.is_huge()) {
            (_, true) => format!("{} pages", got.tag()),
            (Ask::Never, false) => "ordinary pages (--no-huge-pages)".to_string(),
            (Ask::Force, false) => {
                "ordinary pages - requested huge pages but did not get them".to_string()
            }
            (Ask::Auto, false) => "ordinary pages".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_try_then_fall_back() {
        assert_eq!(Ask::default(), Ask::Auto);
        assert!(Ask::Auto.wanted());
        assert!(Ask::Force.wanted(), "--huge-pages is the same request as the default");
        assert!(!Ask::Never.wanted(), "--no-huge-pages is the A/B control arm");
    }

    #[test]
    fn unmet_request_is_reported() {
        assert!(Ask::Force.describe(PadPages::Base).contains("did not get them"));
        assert!(!Ask::Auto.describe(PadPages::Base).contains("did not get them"));
        assert!(Ask::Never.describe(PadPages::Base).contains("--no-huge-pages"));

        assert_eq!(Ask::Auto.describe(PadPages::HugeTlb), "2M/hugetlb pages");
        assert_eq!(Ask::Force.describe(PadPages::Transparent), "2M/thp pages");
    }
}
