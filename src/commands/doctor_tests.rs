#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{CheckStatus, DoctorReport, render_human, render_json, run};
    use crate::{
        auth::key::testing::{FIXTURE_FINGERPRINT, pkcs8_pem},
        config::{ConfigOptions, Environment},
    };

    const TENANCY: &str = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a";
    const USER: &str = "ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z";

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
    }

    impl Fixture {
        /// Build a home directory containing an OCI configuration and key file.
        fn new(fingerprint: &str, write_key: bool) -> Self {
            let dir = tempfile::tempdir().expect("temporary directory");
            let home = dir.path().to_path_buf();
            let oci = home.join(".oci");
            std::fs::create_dir_all(&oci).expect("create .oci directory");

            let key_file = oci.join("oci_api_key.pem");
            if write_key {
                std::fs::write(&key_file, pkcs8_pem()).expect("write key file");
                restrict(&key_file);
            }

            std::fs::write(
                oci.join("config"),
                format!(
                    "[DEFAULT]\nuser = {USER}\ntenancy = {TENANCY}\nfingerprint = {fingerprint}\n\
                     key_file = {}\nregion = us-ashburn-1\n",
                    key_file.display()
                ),
            )
            .expect("write configuration file");

            Self { _dir: dir, home }
        }

        fn env(&self) -> Environment {
            [("HOME", self.home.display().to_string())]
                .into_iter()
                .collect()
        }

        fn report(&self) -> DoctorReport {
            run(&self.env(), &ConfigOptions::default())
        }
    }

    #[cfg(unix)]
    fn restrict(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict key file permissions");
    }

    #[cfg(not(unix))]
    fn restrict(_path: &Path) {}

    fn status_of<'a>(report: &'a DoctorReport, id: &str) -> &'a super::Check {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .unwrap_or_else(|| panic!("check {id} should be present"))
    }

    #[test]
    fn a_correct_setup_passes_every_offline_check() {
        let fixture = Fixture::new(FIXTURE_FINGERPRINT, true);
        let report = fixture.report();

        assert!(report.is_healthy(), "{}", render_human(&report));
        for id in [
            "configuration",
            "private_key",
            "key_fingerprint",
            "request_signing",
        ] {
            assert_eq!(
                status_of(&report, id).status,
                CheckStatus::Pass,
                "check {id}"
            );
        }
        // The offline phase stands on its own: `run` performs no live checks,
        // and a clean local report must read as `pass` rather than being
        // downgraded by checks that have not run yet.
        assert!(
            report
                .checks
                .iter()
                .all(|check| !check.id.starts_with("live_")),
            "`run` must not perform live checks"
        );
        assert_eq!(report.status, CheckStatus::Pass);
    }

    #[test]
    fn a_mismatched_fingerprint_fails_with_the_derived_value() {
        let fixture = Fixture::new("11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00", true);
        let report = fixture.report();

        assert!(!report.is_healthy());
        let check = status_of(&report, "key_fingerprint");
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains(FIXTURE_FINGERPRINT));
        assert!(
            check
                .remediation
                .as_deref()
                .expect("remediation")
                .contains(FIXTURE_FINGERPRINT)
        );
        // Signing must also refuse a mismatched pair rather than sign anyway.
        assert_eq!(
            status_of(&report, "request_signing").status,
            CheckStatus::Fail
        );
    }

    #[test]
    fn a_missing_key_file_skips_the_dependent_checks() {
        let fixture = Fixture::new(FIXTURE_FINGERPRINT, false);
        let report = fixture.report();

        assert!(!report.is_healthy());
        assert_eq!(status_of(&report, "private_key").status, CheckStatus::Fail);
        for id in ["key_fingerprint", "request_signing"] {
            assert_eq!(status_of(&report, id).status, CheckStatus::Skipped);
        }
    }

    #[test]
    fn a_missing_configuration_reports_one_failure_and_skips_the_rest() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let env: Environment = [("HOME", dir.path().display().to_string())]
            .into_iter()
            .collect();

        let report = run(&env, &ConfigOptions::default());
        assert_eq!(report.status, CheckStatus::Fail);
        assert_eq!(
            status_of(&report, "configuration").status,
            CheckStatus::Fail
        );
        assert!(report.config.is_none());
        for id in [
            "key_file_permissions",
            "private_key",
            "key_fingerprint",
            "request_signing",
        ] {
            assert_eq!(
                status_of(&report, id).status,
                CheckStatus::Skipped,
                "check {id}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_warns_without_failing() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new(FIXTURE_FINGERPRINT, true);
        let key_file = fixture.home.join(".oci").join("oci_api_key.pem");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644))
            .expect("relax key file permissions");

        let report = fixture.report();
        let check = status_of(&report, "key_file_permissions");
        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(report.status, CheckStatus::Warn);
        assert!(
            check
                .remediation
                .as_deref()
                .expect("remediation")
                .contains("chmod 600")
        );
        assert!(
            report.is_healthy(),
            "a permission warning must not be fatal"
        );
    }

    #[test]
    fn an_environment_only_setup_is_not_described_as_coming_from_a_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let key_file = dir.path().join("oci_api_key.pem");
        std::fs::write(&key_file, pkcs8_pem()).expect("write key file");
        restrict(&key_file);

        let env: Environment = [
            ("HOME", dir.path().display().to_string()),
            ("OCI_CLI_USER", USER.to_owned()),
            ("OCI_CLI_TENANCY", TENANCY.to_owned()),
            ("OCI_CLI_FINGERPRINT", FIXTURE_FINGERPRINT.to_owned()),
            ("OCI_CLI_KEY_FILE", key_file.display().to_string()),
            ("OCI_CLI_REGION", "us-ashburn-1".to_owned()),
        ]
        .into_iter()
        .collect();

        let report = run(&env, &ConfigOptions::default());
        assert!(report.is_healthy(), "{}", render_human(&report));
        let detail = &status_of(&report, "configuration").detail;
        assert!(
            detail.contains("no configuration file found"),
            "got: {detail}"
        );
        assert!(detail.contains("from the environment"), "got: {detail}");
        assert!(detail.contains("us-ashburn-1"), "got: {detail}");
    }

    #[test]
    fn json_output_is_redacted_and_versioned() {
        let fixture = Fixture::new(FIXTURE_FINGERPRINT, true);
        let report = fixture.report();
        let json = render_json(&report).expect("report serializes");

        assert!(json.contains(&format!("\"schema\": \"{}\"", super::SCHEMA)));
        assert!(!json.contains("aaaaaaaaexampletenancyid7xk3q7a"));
        assert!(!json.contains("PRIVATE KEY"));
        assert!(json.contains(FIXTURE_FINGERPRINT));
    }

    #[test]
    fn human_output_lists_every_check_and_its_remediation() {
        let fixture = Fixture::new("11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00", true);
        let rendered = render_human(&fixture.report());

        assert!(rendered.contains("Key fingerprint"));
        assert!(rendered.contains("next: "));
        assert!(rendered.contains("Fix the failures above"));
        assert!(!rendered.contains("PRIVATE KEY"));
    }

    #[test]
    fn no_rendering_leaks_full_identifiers() {
        let fixture = Fixture::new(FIXTURE_FINGERPRINT, true);
        let report = fixture.report();
        let rendered = format!(
            "{} {} {report:?}",
            render_human(&report),
            render_json(&report).expect("report serializes")
        );

        assert!(!rendered.contains(TENANCY));
        assert!(!rendered.contains(USER));
    }
}
