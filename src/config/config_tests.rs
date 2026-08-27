#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Config, ConfigError, ConfigOptions, Environment};

    const VALID_PROFILE: &str = "\
[DEFAULT]
user = ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z
tenancy = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a
fingerprint = 8D:54:09:96:82:C3:B4:33:42:F9:31:40:70:6A:34:8C
key_file = ~/.oci/oci_api_key.pem
region = us-ashburn-1

[ADMIN]
user = ocid1.user.oc1..aaaaaaaaadminuserid9q1w2e
tenancy = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a
fingerprint = 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00
key_file = /keys/admin.pem
region = eu-frankfurt-1
";

    /// `VALID_PROFILE` with a pass phrase added to the DEFAULT profile.
    fn with_default_pass_phrase() -> String {
        VALID_PROFILE.replace(
            "region = us-ashburn-1\n",
            "region = us-ashburn-1\npass_phrase = hunter2\n",
        )
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        config_file: PathBuf,
    }

    impl Fixture {
        fn new(contents: &str) -> Self {
            let dir = tempfile::tempdir().expect("temporary directory");
            let home = dir.path().to_path_buf();
            let config_file = home.join(".oci").join("config");
            std::fs::create_dir_all(config_file.parent().expect("parent"))
                .expect("create .oci directory");
            std::fs::write(&config_file, contents).expect("write configuration file");
            Self {
                _dir: dir,
                home,
                config_file,
            }
        }

        fn env(&self) -> Environment {
            [("HOME", self.home.display().to_string())]
                .into_iter()
                .collect()
        }
    }

    #[test]
    fn loads_the_default_profile_from_the_home_directory() {
        let fixture = Fixture::new(VALID_PROFILE);
        let config = Config::load(&fixture.env(), &ConfigOptions::default())
            .expect("configuration should load");

        assert_eq!(config.origin.profile, "DEFAULT");
        assert_eq!(
            config.origin.file.as_deref(),
            Some(fixture.config_file.as_path())
        );
        assert!(config.origin.env_overrides.is_empty());
        assert_eq!(config.region.as_str(), "us-ashburn-1");
        assert_eq!(config.user.resource_type(), "user");
        assert_eq!(config.tenancy.resource_type(), "tenancy");
        assert_eq!(
            config.fingerprint.as_str(),
            "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c"
        );
        assert_eq!(
            config.key_file,
            fixture.home.join(".oci").join("oci_api_key.pem")
        );
        assert!(config.pass_phrase.is_none());
    }

    #[test]
    fn selects_a_profile_from_options_then_environment() {
        let fixture = Fixture::new(VALID_PROFILE);

        let from_options = Config::load(
            &fixture.env(),
            &ConfigOptions {
                profile: Some("ADMIN".to_owned()),
                ..ConfigOptions::default()
            },
        )
        .expect("configuration should load");
        assert_eq!(from_options.region.as_str(), "eu-frankfurt-1");

        let env: Environment = [
            ("HOME", fixture.home.display().to_string()),
            ("OCI_CLI_PROFILE", "ADMIN".to_owned()),
        ]
        .into_iter()
        .collect();
        let from_env =
            Config::load(&env, &ConfigOptions::default()).expect("configuration should load");
        assert_eq!(from_env.region.as_str(), "eu-frankfurt-1");
        assert_eq!(from_env.key_file, PathBuf::from("/keys/admin.pem"));
    }

    #[test]
    fn named_profiles_inherit_missing_values_from_default() {
        let fixture = Fixture::new(
            "[DEFAULT]\n\
             tenancy = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a\n\
             region = us-ashburn-1\n\
             \n\
             [ADMIN]\n\
             user = ocid1.user.oc1..aaaaaaaaadminuserid9q1w2e\n\
             fingerprint = 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00\n\
             key_file = /keys/admin.pem\n",
        );

        let config = Config::load(
            &fixture.env(),
            &ConfigOptions {
                profile: Some("ADMIN".to_owned()),
                ..ConfigOptions::default()
            },
        )
        .expect("named profile should inherit DEFAULT values");

        assert_eq!(config.tenancy.resource_type(), "tenancy");
        assert_eq!(config.region.as_str(), "us-ashburn-1");
        assert_eq!(
            config.user.as_str(),
            "ocid1.user.oc1..aaaaaaaaadminuserid9q1w2e"
        );
        assert_eq!(config.key_file, PathBuf::from("/keys/admin.pem"));
    }

    #[test]
    fn environment_overrides_win_and_are_recorded() {
        let fixture = Fixture::new(VALID_PROFILE);
        let env: Environment = [
            ("HOME", fixture.home.display().to_string()),
            ("OCI_CLI_REGION", "ap-tokyo-1".to_owned()),
        ]
        .into_iter()
        .collect();

        let config = Config::load(&env, &ConfigOptions::default()).expect("configuration loads");
        assert_eq!(config.region.as_str(), "ap-tokyo-1");
        assert_eq!(config.origin.env_overrides, vec!["region".to_owned()]);
    }

    #[test]
    fn loads_without_a_configuration_file_when_the_environment_is_complete() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let env: Environment = [
            ("HOME", dir.path().display().to_string()),
            (
                "OCI_CLI_USER",
                "ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z".to_owned(),
            ),
            (
                "OCI_CLI_TENANCY",
                "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a".to_owned(),
            ),
            (
                "OCI_CLI_FINGERPRINT",
                "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c".to_owned(),
            ),
            ("OCI_CLI_KEY_FILE", "/keys/api.pem".to_owned()),
            ("OCI_CLI_REGION", "us-ashburn-1".to_owned()),
        ]
        .into_iter()
        .collect();

        let config = Config::load(&env, &ConfigOptions::default()).expect("configuration loads");
        assert_eq!(config.key_file, PathBuf::from("/keys/api.pem"));
        assert_eq!(config.origin.env_overrides.len(), 5);
        assert_eq!(config.origin.file, None);
        assert_eq!(config.redacted().config_file, None);
    }

    #[test]
    fn an_explicitly_requested_configuration_file_must_exist() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let missing = dir.path().join("absent");
        let error = Config::load(
            &Environment::default(),
            &ConfigOptions {
                config_file: Some(missing.clone()),
                ..ConfigOptions::default()
            },
        )
        .expect_err("a missing explicit file is fatal");

        assert!(matches!(error, ConfigError::ConfigFileNotFound { .. }));
        assert!(error.remediation().contains("--config-file"));
    }

    #[test]
    fn a_missing_profile_lists_the_available_profiles() {
        let fixture = Fixture::new(VALID_PROFILE);
        let error = Config::load(
            &fixture.env(),
            &ConfigOptions {
                profile: Some("STAGING".to_owned()),
                ..ConfigOptions::default()
            },
        )
        .expect_err("unknown profile is fatal");

        match &error {
            ConfigError::ProfileNotFound { available, .. } => {
                assert_eq!(available, &["ADMIN".to_owned(), "DEFAULT".to_owned()]);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(error.remediation().contains("ADMIN"));
    }

    #[test]
    fn a_missing_field_names_both_remediation_paths() {
        let fixture = Fixture::new("[DEFAULT]\nregion = us-ashburn-1\n");
        let error =
            Config::load(&fixture.env(), &ConfigOptions::default()).expect_err("user is required");

        assert!(matches!(
            error,
            ConfigError::MissingField { field: "user", .. }
        ));
        let remediation = error.remediation();
        assert!(remediation.contains("[DEFAULT]"));
        assert!(remediation.contains("OCI_CLI_USER"));
    }

    #[test]
    fn a_first_run_without_a_configuration_file_says_to_create_it() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let env: Environment = [("HOME", dir.path().display().to_string())]
            .into_iter()
            .collect();

        let error =
            Config::load(&env, &ConfigOptions::default()).expect_err("no configuration is present");
        let remediation = error.remediation();
        assert!(remediation.starts_with("create "), "got: {remediation}");
        assert!(remediation.contains(".oci"));
        assert!(remediation.contains("OCI_CLI_USER"));
    }

    #[test]
    fn swapped_user_and_tenancy_are_reported_clearly() {
        let fixture = Fixture::new(
            "[DEFAULT]
user = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a
tenancy = ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z
fingerprint = 8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c
key_file = /keys/api.pem
region = us-ashburn-1
",
        );
        let error = Config::load(&fixture.env(), &ConfigOptions::default())
            .expect_err("a tenancy OCID is not a user OCID");
        assert!(error.to_string().contains("swapped"), "got: {error}");
    }

    #[test]
    fn malformed_ocid_values_are_not_echoed_in_errors() {
        const SENSITIVE_VALUE: &str =
            "ocidX.user.oc1..aaaaaaaaexampleuseridshouldnotappearinoutput";
        let fixture = Fixture::new(&format!(
            "[DEFAULT]\nuser = {SENSITIVE_VALUE}\ntenancy = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a\nfingerprint = 8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c\nkey_file = /keys/api.pem\nregion = us-ashburn-1\n"
        ));

        let error = Config::load(&fixture.env(), &ConfigOptions::default())
            .expect_err("malformed OCID should be rejected");
        let rendered = error.to_string();
        assert!(!rendered.contains(SENSITIVE_VALUE));
        assert!(!rendered.contains("shouldnotappearinoutput"));
    }

    #[test]
    fn unsupported_authentication_modes_fail_closed() {
        for field in ["security_token_file", "delegation_token_file"] {
            let fixture = Fixture::new(&format!(
                "[DEFAULT]
user = ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z
tenancy = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a
fingerprint = 8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c
key_file = /keys/api.pem
region = us-ashburn-1
{field} = /tokens/token
"
            ));
            let error = Config::load(&fixture.env(), &ConfigOptions::default())
                .expect_err("unsupported authentication must fail closed");
            assert!(matches!(
                error,
                ConfigError::UnsupportedAuthentication { .. }
            ));
        }
    }

    #[test]
    fn key_content_only_profiles_explain_the_limitation() {
        let fixture = Fixture::new(
            "[DEFAULT]
user = ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z
tenancy = ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a
fingerprint = 8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c
key_content = QUJDRA==
region = us-ashburn-1
",
        );
        let error = Config::load(&fixture.env(), &ConfigOptions::default())
            .expect_err("key_content is not supported yet");
        assert!(matches!(
            error,
            ConfigError::UnsupportedAuthentication {
                field: "key_content",
                ..
            }
        ));
    }

    #[test]
    fn redaction_hides_identifiers_and_the_pass_phrase() {
        let fixture = Fixture::new(&with_default_pass_phrase());
        let config =
            Config::load(&fixture.env(), &ConfigOptions::default()).expect("configuration loads");

        let redacted = config.redacted();
        let rendered = serde_json::to_string(&redacted).expect("redacted config serializes");
        assert!(redacted.pass_phrase_configured);
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("aaaaaaaaexampleuserid4m2p8z"));
        assert!(!rendered.contains("aaaaaaaaexampletenancyid7xk3q7a"));
        assert!(rendered.contains("8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c"));
        assert_eq!(redacted.tenancy, "ocid1.tenancy.oc1..\u{2026}xk3q7a");
    }

    #[test]
    fn debug_output_never_contains_the_pass_phrase() {
        let fixture = Fixture::new(&with_default_pass_phrase());
        let config =
            Config::load(&fixture.env(), &ConfigOptions::default()).expect("configuration loads");
        assert!(!format!("{config:?}").contains("hunter2"));
    }

    #[test]
    fn tilde_paths_are_expanded_relative_to_home() {
        let fixture = Fixture::new(VALID_PROFILE);
        let config =
            Config::load(&fixture.env(), &ConfigOptions::default()).expect("configuration loads");
        assert!(config.key_file.is_absolute());
        assert!(!config.key_file.starts_with(Path::new("~")));
    }
}
