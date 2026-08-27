use std::collections::BTreeMap;

use thiserror::Error;

/// Name of the profile that owns entries appearing before the first section
/// header, matching the OCI configuration file convention.
pub const DEFAULT_PROFILE: &str = "DEFAULT";

/// A parsed OCI configuration file: profile name to key/value entries.
pub type Profiles = BTreeMap<String, BTreeMap<String, String>>;

/// Parse the INI-style OCI configuration file format.
///
/// The format is deliberately handled by a small local parser instead of a
/// general INI crate: OCI files are simple, and a strict parser that rejects
/// duplicate keys catches copy/paste mistakes that would otherwise silently
/// select the wrong credentials.
pub fn parse(text: &str) -> Result<Profiles, IniError> {
    let mut profiles = Profiles::new();
    let mut current = DEFAULT_PROFILE.to_owned();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| IniError::UnterminatedSection {
                    line: line_number,
                    text: line.to_owned(),
                })?
                .trim();
            if name.is_empty() {
                return Err(IniError::EmptySectionName { line: line_number });
            }
            current = name.to_owned();
            profiles.entry(current.clone()).or_default();
            continue;
        }

        // Values such as `key_content` are base64 and may contain `=`, so only
        // the first separator is significant.
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| IniError::MalformedEntry {
                line: line_number,
                text: line.to_owned(),
            })?;
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(IniError::MalformedEntry {
                line: line_number,
                text: line.to_owned(),
            });
        }

        let entries = profiles.entry(current.clone()).or_default();
        if entries.contains_key(&key) {
            return Err(IniError::DuplicateKey {
                line: line_number,
                profile: current.clone(),
                key,
            });
        }
        entries.insert(key, value.trim().to_owned());
    }

    Ok(profiles)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IniError {
    #[error("line {line}: section header is not terminated with ']'")]
    UnterminatedSection { line: usize, text: String },
    #[error("line {line}: section header has an empty profile name")]
    EmptySectionName { line: usize },
    #[error("line {line}: expected 'key = value'")]
    MalformedEntry { line: usize, text: String },
    #[error("line {line}: profile [{profile}] defines '{key}' more than once")]
    DuplicateKey {
        line: usize,
        profile: String,
        key: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_PROFILE, IniError, parse};

    #[test]
    fn parses_profiles_comments_and_whitespace() {
        let text = "\
# a comment
; another comment
[DEFAULT]
user = ocid1.user.oc1..aaaa
  fingerprint=8d:54:09

[ADMIN]
region = eu-frankfurt-1
";
        let profiles = parse(text).expect("configuration should parse");
        assert_eq!(profiles.len(), 2);
        assert_eq!(
            profiles[DEFAULT_PROFILE]["user"],
            "ocid1.user.oc1..aaaa".to_owned()
        );
        assert_eq!(profiles[DEFAULT_PROFILE]["fingerprint"], "8d:54:09");
        assert_eq!(profiles["ADMIN"]["region"], "eu-frankfurt-1");
    }

    #[test]
    fn entries_before_the_first_section_belong_to_default() {
        let profiles = parse("region = us-ashburn-1\n").expect("configuration should parse");
        assert_eq!(profiles[DEFAULT_PROFILE]["region"], "us-ashburn-1");
    }

    #[test]
    fn keys_are_case_insensitive_but_values_are_preserved() {
        let profiles = parse("Key_File = ~/.oci/Key.PEM\n").expect("configuration should parse");
        assert_eq!(profiles[DEFAULT_PROFILE]["key_file"], "~/.oci/Key.PEM");
    }

    #[test]
    fn only_the_first_separator_splits_an_entry() {
        let profiles = parse("key_content = QUJDRA==\n").expect("configuration should parse");
        assert_eq!(profiles[DEFAULT_PROFILE]["key_content"], "QUJDRA==");
    }

    #[test]
    fn an_empty_section_is_preserved() {
        let profiles = parse("[EMPTY]\n").expect("configuration should parse");
        assert!(profiles["EMPTY"].is_empty());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let error = parse("[DEFAULT]\nregion = a-b-1\nregion = c-d-1\n")
            .expect_err("duplicate keys should be rejected");
        assert_eq!(
            error,
            IniError::DuplicateKey {
                line: 3,
                profile: DEFAULT_PROFILE.to_owned(),
                key: "region".to_owned(),
            }
        );
    }

    #[test]
    fn malformed_lines_are_rejected_with_line_numbers() {
        assert!(matches!(
            parse("[DEFAULT\n"),
            Err(IniError::UnterminatedSection { line: 1, .. })
        ));
        assert!(matches!(
            parse("[]\n"),
            Err(IniError::EmptySectionName { line: 1 })
        ));
        assert!(matches!(
            parse("[DEFAULT]\nnonsense\n"),
            Err(IniError::MalformedEntry { line: 2, .. })
        ));
        assert!(matches!(
            parse("= value\n"),
            Err(IniError::MalformedEntry { line: 1, .. })
        ));
    }


    #[test]
    fn parse_errors_do_not_echo_raw_configuration_lines() {
        let secret_line = "pass_phrase hunter2";
        let error = parse(&format!("[DEFAULT]\n{secret_line}\n"))
            .expect_err("malformed secret line should be rejected");
        assert!(!error.to_string().contains("hunter2"));
        assert!(!error.to_string().contains(secret_line));
    }
}
