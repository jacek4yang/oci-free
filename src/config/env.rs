use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// An immutable snapshot of the environment a command runs in.
///
/// Environment access is injected rather than read directly from `std::env` at
/// each call site so configuration resolution stays deterministic and testable
/// without mutating process-global state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    vars: BTreeMap<String, String>,
}

impl Environment {
    /// Capture the current process environment.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            vars: std::env::vars().collect(),
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars
            .get(key)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Resolve the user's home directory.
    ///
    /// `HOME` is checked first so a POSIX-style override keeps working on every
    /// platform, then the Windows `USERPROFILE` variable.
    #[must_use]
    pub fn home_dir(&self) -> Option<PathBuf> {
        self.get("HOME")
            .or_else(|| self.get("USERPROFILE"))
            .map(PathBuf::from)
    }

    /// Expand a leading `~` in a configured path using [`Environment::home_dir`].
    #[must_use]
    pub fn expand_home(&self, path: &Path) -> PathBuf {
        let Some(text) = path.to_str() else {
            return path.to_path_buf();
        };
        let remainder = match text.strip_prefix('~') {
            Some("") => "",
            Some(rest) if rest.starts_with('/') || rest.starts_with('\\') => &rest[1..],
            _ => return path.to_path_buf(),
        };
        let Some(home) = self.home_dir() else {
            return path.to_path_buf();
        };
        if remainder.is_empty() {
            home
        } else {
            home.join(remainder)
        }
    }
}

impl<K, V> FromIterator<(K, V)> for Environment
where
    K: Into<String>,
    V: Into<String>,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self {
            vars: iter
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::Environment;

    #[test]
    fn blank_variables_are_treated_as_unset() {
        let env: Environment = [("OCI_CLI_PROFILE", "   ")].into_iter().collect();
        assert_eq!(env.get("OCI_CLI_PROFILE"), None);
    }

    #[test]
    fn values_are_trimmed() {
        let env: Environment = [("OCI_CLI_PROFILE", " ADMIN \n")].into_iter().collect();
        assert_eq!(env.get("OCI_CLI_PROFILE"), Some("ADMIN"));
    }

    #[test]
    fn home_prefers_posix_variable_then_windows_variable() {
        let posix: Environment = [("HOME", "/home/alice"), ("USERPROFILE", "C:\\Users\\alice")]
            .into_iter()
            .collect();
        assert_eq!(posix.home_dir(), Some(PathBuf::from("/home/alice")));

        let windows: Environment = [("USERPROFILE", "C:\\Users\\alice")].into_iter().collect();
        assert_eq!(windows.home_dir(), Some(PathBuf::from("C:\\Users\\alice")));

        assert_eq!(Environment::default().home_dir(), None);
    }

    #[test]
    fn expands_tilde_paths() {
        let env: Environment = [("HOME", "/home/alice")].into_iter().collect();
        assert_eq!(
            env.expand_home(Path::new("~/.oci/key.pem")),
            PathBuf::from("/home/alice/.oci/key.pem")
        );
        assert_eq!(
            env.expand_home(Path::new("~")),
            PathBuf::from("/home/alice")
        );
    }

    #[test]
    fn leaves_other_paths_untouched() {
        let env: Environment = [("HOME", "/home/alice")].into_iter().collect();
        for path in ["/etc/oci/key.pem", "relative/key.pem", "~user/key.pem"] {
            assert_eq!(env.expand_home(Path::new(path)), PathBuf::from(path));
        }
    }

    #[test]
    fn unresolvable_home_leaves_the_path_untouched() {
        let env = Environment::default();
        assert_eq!(
            env.expand_home(Path::new("~/.oci/key.pem")),
            PathBuf::from("~/.oci/key.pem")
        );
    }
}
