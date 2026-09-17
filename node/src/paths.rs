use std::path::{Path, PathBuf};

pub const CONFIG_FILENAME: &str = "noded.toml";

pub const LOCK_FILENAME: &str = "noded.lock";

pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            if !appdata.is_empty() {
                return PathBuf::from(appdata).join("Plaine");
            }
        }
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            if !profile.is_empty() {
                return PathBuf::from(profile)
                    .join("AppData")
                    .join("Roaming")
                    .join("Plaine");
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join(".plaine");
            }
        }
    }
    PathBuf::from("plaine-data")
}

// only bare `~` and a `~/` (or `~\`) prefix expand; `~user` is left literal since
// we do not resolve other users' home directories.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        return home_dir().unwrap_or_else(|| PathBuf::from(path));
    }
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub chain_dir: PathBuf,
    pub config_file: PathBuf,
    pub lock_file: PathBuf,
    pub segments_dir: PathBuf,
    pub database_file: PathBuf,
    pub peers_file: PathBuf,
}

impl Paths {
    pub fn resolve(data_dir: &Path, config_override: Option<&Path>) -> Paths {
        let chain_dir = data_dir.to_path_buf();
        Paths {
            config_file: config_override
                .map(Path::to_path_buf)
                .unwrap_or_else(|| data_dir.join(CONFIG_FILENAME)),
            lock_file: chain_dir.join(LOCK_FILENAME),
            segments_dir: chain_dir.join("segments"),
            database_file: chain_dir.join("chain.redb"),
            peers_file: chain_dir.join("peers.dat"),
            chain_dir,
            data_dir: data_dir.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dir_is_platform_shaped() {
        let d = default_data_dir();
        let s = d.to_string_lossy().to_string();
        #[cfg(windows)]
        assert!(
            s.ends_with("Plaine"),
            "windows default should be ...\\Plaine, got {s}"
        );
        #[cfg(not(windows))]
        assert!(
            s.ends_with(".plaine"),
            "unix default should be ~/.plaine, got {s}"
        );
    }

    #[test]
    fn tilde_prefix_is_expanded() {
        let p = expand_tilde("~/.plaine");
        assert!(!p.to_string_lossy().starts_with('~'), "got {p:?}");
        assert!(p.ends_with(".plaine"));
    }

    #[test]
    fn tilde_user_left_alone() {
        assert_eq!(expand_tilde("~backup/data"), PathBuf::from("~backup/data"));
    }

    #[test]
    fn absolute_path_untouched() {
        assert_eq!(
            expand_tilde("/var/lib/plaine"),
            PathBuf::from("/var/lib/plaine")
        );
        assert_eq!(expand_tilde(r"C:\plaine"), PathBuf::from(r"C:\plaine"));
    }

    #[test]
    fn chain_lives_in_data_dir() {
        let base = PathBuf::from("/data/plaine");
        let main = Paths::resolve(&base, None);
        assert_eq!(main.database_file, base.join("chain.redb"));
        assert_eq!(main.config_file, base.join(CONFIG_FILENAME));
        assert_eq!(main.chain_dir, base);
    }

    #[test]
    fn explicit_config_path_wins() {
        let p = Paths::resolve(
            &PathBuf::from("/data/plaine"),
            Some(Path::new("/etc/plaine/noded.toml")),
        );
        assert_eq!(p.config_file, PathBuf::from("/etc/plaine/noded.toml"));

        assert_eq!(
            p.database_file,
            PathBuf::from("/data/plaine").join("chain.redb")
        );
    }
}
