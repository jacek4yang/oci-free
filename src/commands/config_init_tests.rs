//! `config init` tests.
//!
//! The properties that matter: an existing profile is never silently replaced,
//! a fingerprint that does not match the key is refused rather than written,
//! and nothing secret reaches the file.

use super::*;
use crate::{
    auth::key::testing::{FIXTURE_FINGERPRINT, pkcs8_pem},
    config::ConfigOptions,
};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let home = dir.path().to_path_buf();
        std::fs::create_dir_all(home.join(".oci")).expect("oci dir");
        let key = home.join(".oci/oci_api_key.pem");
        std::fs::write(&key, pkcs8_pem()).expect("write key");
        Self {
            _dir: dir,
            home,
            key,
        }
    }

    fn env(&self) -> Environment {
        [("HOME", self.home.display().to_string())]
            .into_iter()
            .collect()
    }

    fn config_file(&self) -> PathBuf {
        self.home.join(".oci/config")
    }

    fn request(&self) -> InitRequest {
        InitRequest {
            profile: None,
            config_file: None,
            tenancy: Some("ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a".to_owned()),
            user: Some("ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z".to_owned()),
            region: Some("us-ashburn-1".to_owned()),
            fingerprint: None,
            key_file: Some(self.key.clone()),
            force: false,
            interactive: false,
        }
    }
}

#[tokio::test]
async fn writes_a_usable_profile_that_loads_back() {
    let fixture = Fixture::new();
    let result = init(&fixture.env(), &fixture.request())
        .await
        .expect("init succeeds");

    assert_eq!(result.profile, "DEFAULT");
    assert!(!result.replaced_existing);
    assert!(
        result
            .validated
            .iter()
            .any(|check| check.contains("derived from the private key"))
    );

    // The proof that it worked: the configuration loads through the normal path.
    let config = Config::load(&fixture.env(), &ConfigOptions::default()).expect("config loads");
    assert_eq!(config.region.to_string(), "us-ashburn-1");
    assert_eq!(config.fingerprint.to_string(), FIXTURE_FINGERPRINT);
    assert_eq!(config.key_file, fixture.key);
}

/// The private key must never be copied into the configuration file.
#[tokio::test]
async fn no_secret_material_reaches_the_configuration_file() {
    let fixture = Fixture::new();
    init(&fixture.env(), &fixture.request())
        .await
        .expect("init succeeds");

    let written = std::fs::read_to_string(fixture.config_file()).expect("read config");
    assert!(written.contains("key_file="));
    assert!(!written.contains("PRIVATE KEY"));
    for line in pkcs8_pem()
        .lines()
        .filter(|line| !line.starts_with("-----"))
    {
        assert!(
            !written.contains(line),
            "key material leaked into the configuration file"
        );
    }
}

/// Overwriting a profile could orphan the only reference to a private key.
#[tokio::test]
async fn an_existing_profile_is_never_silently_replaced() {
    let fixture = Fixture::new();
    init(&fixture.env(), &fixture.request())
        .await
        .expect("first init succeeds");

    let error = init(&fixture.env(), &fixture.request())
        .await
        .expect_err("a second init must refuse");
    assert!(error.message().contains("already exists"));
    assert!(error.remediation().contains("--force"));

    let mut forced = fixture.request();
    forced.force = true;
    let result = init(&fixture.env(), &forced)
        .await
        .expect("--force replaces it");
    assert!(result.replaced_existing);
}

/// Other profiles in the file must survive an init.
#[tokio::test]
async fn writing_one_profile_preserves_the_others() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.config_file(),
        "[OTHER]\nuser=ocid1.user.oc1..aaaaaaaaother\nregion=eu-frankfurt-1\n",
    )
    .expect("seed config");

    init(&fixture.env(), &fixture.request())
        .await
        .expect("init succeeds");

    let written = std::fs::read_to_string(fixture.config_file()).expect("read config");
    assert!(written.contains("[OTHER]"));
    assert!(written.contains("eu-frankfurt-1"));
    assert!(written.contains("[DEFAULT]"));
}

/// A fingerprint that does not match the key would make every request fail with
/// an opaque authentication error, so it is caught here.
#[tokio::test]
async fn a_fingerprint_that_disagrees_with_the_key_is_refused() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.fingerprint = Some("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff".to_owned());

    let error = init(&fixture.env(), &request)
        .await
        .expect_err("a mismatch must be refused");
    assert!(error.message().contains("does not match"));
    assert!(
        error
            .context()
            .expect("context")
            .contains(FIXTURE_FINGERPRINT)
    );
    assert!(
        !fixture.config_file().exists(),
        "nothing may be written when validation fails"
    );
}

#[tokio::test]
async fn a_matching_fingerprint_is_accepted() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.fingerprint = Some(FIXTURE_FINGERPRINT.to_owned());

    let result = init(&fixture.env(), &request).await.expect("init succeeds");
    assert!(
        result
            .validated
            .iter()
            .any(|check| check.contains("matches the private key"))
    );
}

#[tokio::test]
async fn malformed_ocids_are_refused_with_specific_guidance() {
    let fixture = Fixture::new();

    let mut swapped = fixture.request();
    swapped.tenancy = Some("ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z".to_owned());
    let error = init(&fixture.env(), &swapped)
        .await
        .expect_err("a user OCID is not a tenancy OCID");
    assert!(error.remediation().contains("ocid1.tenancy."));

    let mut nonsense = fixture.request();
    nonsense.user = Some("not-an-ocid".to_owned());
    assert!(init(&fixture.env(), &nonsense).await.is_err());
}

#[tokio::test]
async fn a_missing_key_file_is_a_warning_not_a_failure() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.key_file = Some(fixture.home.join(".oci/absent.pem"));
    request.fingerprint = Some(FIXTURE_FINGERPRINT.to_owned());

    let result = init(&fixture.env(), &request)
        .await
        .expect("init still succeeds");
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("could not be read")),
        "{:?}",
        result.warnings
    );
}

/// Without a key to derive from, and no fingerprint supplied, there is nothing
/// to write and no terminal to ask.
#[tokio::test]
async fn a_non_interactive_run_missing_a_value_names_the_flag() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.region = None;

    let error = init(&fixture.env(), &request)
        .await
        .expect_err("must refuse");
    assert!(error.remediation().contains("--region"));
}

#[cfg(unix)]
#[tokio::test]
async fn the_configuration_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let result = init(&fixture.env(), &fixture.request())
        .await
        .expect("init succeeds");
    assert!(result.owner_only_permissions);

    let mode = std::fs::metadata(fixture.config_file())
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode & 0o077, 0, "mode {mode:04o} exposes the file");
}

#[tokio::test]
async fn config_show_redacts_the_tenancy_and_never_prints_a_secret() {
    let fixture = Fixture::new();
    init(&fixture.env(), &fixture.request())
        .await
        .expect("init succeeds");

    let config = show(&fixture.env(), &ConfigOptions::default()).expect("show succeeds");
    let rendered = render_show(&config);
    assert!(
        rendered.contains('\u{2026}'),
        "the tenancy must be redacted"
    );
    assert!(!rendered.contains("aaaaaaaaexampletenancyid"));
    assert!(rendered.contains(FIXTURE_FINGERPRINT));
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn key_advice_points_at_the_console_and_needs_no_toolchain() {
    let advice = key_advice();
    assert!(!advice.is_empty());
    let joined = advice.join(" ");
    assert!(joined.contains("API key"));
    for tool in ["openssl", "python", "oci setup"] {
        assert!(
            !joined.to_ascii_lowercase().contains(tool),
            "the advice must not require {tool}"
        );
    }
}
