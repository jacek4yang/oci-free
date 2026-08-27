//! OCI service endpoint construction.
//!
//! OCI services do not all use one hostname shape. Identity and Core use the
//! realm-domain form (`identity.{region}.{realm-domain}`), while Limits and
//! Usage use an additional `oci` label
//! (`limits.{region}.oci.{realm-domain}`). The service owns that choice here so
//! callers cannot accidentally reconstruct an authority with the wrong rule.
//!
//! The realm domain is *not* derived from the region name: it comes from the
//! realm, which this client reads out of the tenancy OCID
//! (`ocid1.tenancy.oc1..` -> `oc1`).
//!
//! Deriving the realm from the caller's own tenancy rather than a region table
//! matters for safety. A region table would have to guess a domain for any
//! region it has not heard of, and guessing wrong means sending a signed
//! `Authorization` header to a host Oracle does not control. Unknown realms
//! therefore fail closed.

use std::fmt;

use url::Url;

use crate::{
    domain::{ocid::Ocid, region::Region},
    error::{Error, ErrorKind, Result},
};

/// The OCI services this product talks to.
///
/// Deliberately not exhaustive: oci-free is not a general SDK, so a service is
/// added here only when a command needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// Tenancy, users, region subscriptions, availability domains.
    Identity,
    /// Compute, virtual networking, and block storage all share the `iaas` host.
    Core,
    /// Service limits and resource availability.
    Limits,
    /// Usage and cost reporting.
    Usage,
}

impl Service {
    /// The hostname prefix Oracle assigns to this service.
    #[must_use]
    pub fn host_prefix(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            // Compute, VCN and block storage are all served by `iaas`.
            Self::Core => "iaas",
            Self::Limits => "limits",
            Self::Usage => "usageapi",
        }
    }

    /// The hostname construction rule Oracle documents for this service.
    ///
    /// Oracle's generated SDK clients are the machine-readable provenance for
    /// these service-specific templates:
    ///
    /// * <https://github.com/oracle/oci-python-sdk/blob/master/src/oci/limits/limits_client.py>
    /// * <https://github.com/oracle/oci-python-sdk/blob/master/src/oci/usage_api/usageapi_client.py>
    #[must_use]
    pub(crate) fn endpoint_style(self) -> EndpointStyle {
        match self {
            Self::Identity | Self::Core => EndpointStyle::RealmDomain,
            Self::Limits | Self::Usage => EndpointStyle::OciRealmDomain,
        }
    }

    /// Human-readable service name used in diagnostics.
    #[must_use]
    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::Core => "Core",
            Self::Limits => "Limits",
            Self::Usage => "Usage",
        }
    }

    /// The API version path segment used by this service.
    #[must_use]
    pub fn api_version(self) -> &'static str {
        match self {
            Self::Identity | Self::Core => "20160918",
            // Oracle names the Limits API reference 20181025, but the current
            // generated clients send these operations under /20190729.
            Self::Limits => "20190729",
            Self::Usage => "20200107",
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.host_prefix())
    }
}

/// A service-specific OCI hostname construction rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointStyle {
    /// `{service}.{region}.{realm-domain}`
    RealmDomain,
    /// `{service}.{region}.oci.{realm-domain}`
    OciRealmDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RealmEndpoints {
    domain: &'static str,
    /// The label is optional by design. If Oracle adds a realm whose service
    /// template has not been verified, Identity/Core can remain available
    /// while Limits/Usage refuse before any signed request is sent.
    oci_subdomain: Option<&'static str>,
}

const fn verified_realm(domain: &'static str) -> RealmEndpoints {
    RealmEndpoints {
        domain,
        oci_subdomain: Some("oci"),
    }
}

/// Endpoint components for an OCI realm.
///
/// Domains are kept in sync with Oracle's generated SDK realm definitions.
/// The Limits and Usage clients use `oci.{secondLevelDomain}` for these realms:
/// <https://github.com/oracle/oci-python-sdk/blob/master/src/oci/regions_definitions.py>
fn realm_endpoints(realm: &str) -> Option<RealmEndpoints> {
    match realm {
        "oc1" => Some(verified_realm("oraclecloud.com")),
        // US and UK government realms.
        "oc2" | "oc3" => Some(verified_realm("oraclegovcloud.com")),
        "oc4" => Some(verified_realm("oraclegovcloud.uk")),
        "oc8" => Some(verified_realm("oraclecloud8.com")),
        "oc9" => Some(verified_realm("oraclecloud9.com")),
        "oc10" => Some(verified_realm("oraclecloud10.com")),
        "oc14" => Some(verified_realm("oraclecloud14.com")),
        "oc15" => Some(verified_realm("oraclecloud15.com")),
        "oc19" => Some(verified_realm("oraclecloud.eu")),
        "oc20" => Some(verified_realm("oraclecloud20.com")),
        "oc21" => Some(verified_realm("oraclecloud21.com")),
        "oc23" => Some(verified_realm("oraclecloud23.com")),
        "oc24" => Some(verified_realm("oraclecloud24.com")),
        "oc26" => Some(verified_realm("oraclecloud26.com")),
        "oc29" => Some(verified_realm("oraclecloud29.com")),
        "oc35" => Some(verified_realm("oraclecloud35.com")),
        "oc42" => Some(verified_realm("oraclecloud42.com")),
        "oc51" => Some(verified_realm("oraclecloud51.com")),
        "oc52" => Some(verified_realm("oraclecloud52.com")),
        _ => None,
    }
}

/// The DNS domain for an OCI realm.
///
/// Sourced from Oracle's published realm list. Realms absent from this table
/// are rejected rather than guessed.
#[must_use]
pub fn realm_domain(realm: &str) -> Option<&'static str> {
    realm_endpoints(realm).map(|endpoints| endpoints.domain)
}

/// Resolves service URLs for one tenancy and region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointResolver {
    realm: String,
    domain: &'static str,
    oci_subdomain: Option<&'static str>,
    region: Region,
    /// Test-only authority override, used to point the transport at an
    /// in-process mock server. Compiled out of release builds entirely, so no
    /// production path can redirect a signed request away from OCI.
    #[cfg(test)]
    authority_override: Option<String>,
}

impl EndpointResolver {
    /// Build a resolver from the tenancy OCID's realm and a region.
    pub fn new(tenancy: &Ocid, region: Region) -> Result<Self> {
        let realm = tenancy.realm();
        let endpoints = realm_endpoints(realm).ok_or_else(|| {
            Error::new(
                ErrorKind::Configuration,
                format!("unrecognised OCI realm `{realm}` in the tenancy OCID"),
            )
            .with_context(
                "oci-free refuses to guess a hostname for an unknown realm, because a wrong \
                 guess would send signed credentials to a host Oracle does not control",
            )
            .with_remediation(
                "check that `tenancy` is correct; if this realm is genuinely new, please file an \
                 issue so it can be added",
            )
        })?;

        Ok(Self {
            realm: realm.to_owned(),
            domain: endpoints.domain,
            oci_subdomain: endpoints.oci_subdomain,
            region,
            #[cfg(test)]
            authority_override: None,
        })
    }

    /// Send every request for this resolver to `authority` instead of OCI.
    #[cfg(test)]
    pub fn override_authority_for_tests(&mut self, authority: &str) {
        self.authority_override = Some(authority.to_owned());
    }

    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    #[must_use]
    pub fn region(&self) -> &Region {
        &self.region
    }

    /// The same resolver pointed at a different region in the same realm.
    #[must_use]
    pub fn in_region(&self, region: Region) -> Self {
        Self {
            realm: self.realm.clone(),
            domain: self.domain,
            oci_subdomain: self.oci_subdomain,
            region,
            #[cfg(test)]
            authority_override: self.authority_override.clone(),
        }
    }

    /// The host for a service, for example `iaas.us-ashburn-1.oraclecloud.com`.
    ///
    /// An unverified realm/service convention is an error rather than a
    /// guessed authority. No request has been built or signed at this point.
    pub fn host(&self, service: Service) -> Result<String> {
        #[cfg(test)]
        if let Some(authority) = &self.authority_override {
            return Ok(authority.clone());
        }

        match service.endpoint_style() {
            EndpointStyle::RealmDomain => Ok(format!(
                "{}.{}.{}",
                service.host_prefix(),
                self.region,
                self.domain
            )),
            EndpointStyle::OciRealmDomain => {
                let subdomain = self.oci_subdomain.ok_or_else(|| {
                    Error::configuration(format!(
                        "oci-free does not know a safe {} endpoint for OCI realm {}",
                        service.display_name(),
                        self.realm
                    ))
                    .with_context(
                        "the realm/service hostname convention has not been verified; no request was sent",
                    )
                    .with_remediation(
                        "check Oracle's current service endpoint documentation and file an issue with the realm and service",
                    )
                })?;
                Ok(format!(
                    "{}.{}.{}.{}",
                    service.host_prefix(),
                    self.region,
                    subdomain,
                    self.domain
                ))
            }
        }
    }

    /// Build a URL for `path`, which must already be percent-encoded and must
    /// start with `/`.
    pub fn url(&self, service: Service, path: &str) -> Result<Url> {
        validate_request_path(path)?;
        let base = format!("https://{}", self.host(service)?);
        let joined = format!("{base}{path}");
        Url::parse(&joined).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("could not build a request URL for {service}"),
            )
            .with_context(error.to_string())
        })
    }

    /// Build a versioned URL, prefixing the service's API version segment.
    pub fn versioned_url(&self, service: Service, path: &str) -> Result<Url> {
        validate_request_path(path)?;
        self.url(service, &format!("/{}{path}", service.api_version()))
    }
}

/// Refuse path forms that could be interpreted as another authority, conceal
/// part of the signed target, or be rewritten while parsing. All production
/// callers use fixed paths and append user data through `Url::query_pairs_mut`.
fn validate_request_path(path: &str) -> Result<()> {
    let invalid_reason = if !path.starts_with('/') {
        Some("the request path must start with `/`")
    } else if path.starts_with("//") {
        Some("a request path must not be a network-path reference starting with `//`")
    } else if path.contains('\\') {
        Some("a request path must not contain backslashes")
    } else if path.contains('#') {
        Some("a request path must not contain a URL fragment")
    } else if path
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        Some("a request path must be percent-encoded and contain no whitespace")
    } else {
        None
    };

    invalid_reason.map_or(Ok(()), |reason| {
        Err(Error::invalid_input("refused an invalid OCI request path")
            .with_context(reason)
            .with_remediation("use a percent-encoded absolute path beginning with one `/`"))
    })
}

#[cfg(test)]
mod tests {
    use super::{EndpointResolver, EndpointStyle, Service, realm_domain};
    use crate::domain::{ocid::Ocid, region::Region};

    fn resolver(tenancy: &str, region: &str) -> EndpointResolver {
        EndpointResolver::new(
            &tenancy.parse::<Ocid>().expect("tenancy OCID"),
            region.parse::<Region>().expect("region"),
        )
        .expect("resolver")
    }

    const OC1_TENANCY: &str = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a";

    fn host(resolver: &EndpointResolver, service: Service) -> String {
        resolver.host(service).expect("known service endpoint")
    }

    #[test]
    fn commercial_services_select_their_documented_endpoint_style() {
        assert_eq!(
            Service::Identity.endpoint_style(),
            EndpointStyle::RealmDomain
        );
        assert_eq!(Service::Core.endpoint_style(), EndpointStyle::RealmDomain);
        assert_eq!(
            Service::Limits.endpoint_style(),
            EndpointStyle::OciRealmDomain
        );
        assert_eq!(
            Service::Usage.endpoint_style(),
            EndpointStyle::OciRealmDomain
        );
    }

    #[test]
    fn commercial_limits_and_usage_use_oci_subdomain() {
        for region in ["us-sanjose-1", "us-ashburn-1", "ap-tokyo-1"] {
            let resolver = resolver(OC1_TENANCY, region);
            assert_eq!(
                host(&resolver, Service::Identity),
                format!("identity.{region}.oraclecloud.com")
            );
            assert_eq!(
                host(&resolver, Service::Core),
                format!("iaas.{region}.oraclecloud.com")
            );
            assert_eq!(
                host(&resolver, Service::Limits),
                format!("limits.{region}.oci.oraclecloud.com")
            );
            assert_eq!(
                host(&resolver, Service::Usage),
                format!("usageapi.{region}.oci.oraclecloud.com")
            );
        }
    }

    /// This exact hostname was validated after the old form returned NXDOMAIN
    /// in a real commercial tenancy.
    #[test]
    fn san_jose_usage_endpoint_matches_live_validated_hostname() {
        let resolver = resolver(OC1_TENANCY, "us-sanjose-1");
        let usage = host(&resolver, Service::Usage);
        let limits = host(&resolver, Service::Limits);

        assert_eq!(usage, "usageapi.us-sanjose-1.oci.oraclecloud.com");
        assert_ne!(usage, "usageapi.us-sanjose-1.oraclecloud.com");
        assert_eq!(limits, "limits.us-sanjose-1.oci.oraclecloud.com");
        assert_ne!(limits, "limits.us-sanjose-1.oraclecloud.com");
    }

    /// Compute, networking and block storage share one host; a regression here
    /// would silently point half the adapters at a non-existent service.
    #[test]
    fn core_services_share_the_iaas_host() {
        assert_eq!(Service::Core.host_prefix(), "iaas");
        assert_eq!(Service::Core.api_version(), "20160918");
    }

    #[test]
    fn versioned_urls_include_the_api_version() {
        let resolver = resolver(OC1_TENANCY, "eu-frankfurt-1");
        let core = resolver
            .versioned_url(Service::Core, "/instances?compartmentId=x")
            .expect("url");
        assert_eq!(
            core.as_str(),
            "https://iaas.eu-frankfurt-1.oraclecloud.com/20160918/instances?compartmentId=x"
        );
        assert_eq!(core.scheme(), "https");

        let limits = resolver
            .versioned_url(Service::Limits, "/limitValues?compartmentId=x")
            .expect("limits url");
        assert_eq!(
            limits.as_str(),
            "https://limits.eu-frankfurt-1.oci.oraclecloud.com/20190729/limitValues?compartmentId=x"
        );

        let usage = resolver
            .versioned_url(Service::Usage, "/usage")
            .expect("usage url");
        assert_eq!(
            usage.as_str(),
            "https://usageapi.eu-frankfurt-1.oci.oraclecloud.com/20200107/usage"
        );
    }

    #[test]
    fn unversioned_urls_use_the_same_service_specific_authority() {
        let resolver = resolver(OC1_TENANCY, "ap-tokyo-1");
        let url = resolver
            .url(Service::Limits, "/health")
            .expect("unversioned URL");
        assert_eq!(
            url.as_str(),
            "https://limits.ap-tokyo-1.oci.oraclecloud.com/health"
        );
    }

    #[test]
    fn malformed_request_paths_are_refused_before_a_url_is_built() {
        let resolver = resolver(OC1_TENANCY, "us-ashburn-1");
        for path in [
            "instances",
            "//untrusted.example/instances",
            "/\\untrusted.example/instances",
            "/instances#unsigned-fragment",
            "/instances?display name=not-encoded",
            "/instances\nforged-header",
        ] {
            let error = resolver
                .url(Service::Core, path)
                .expect_err("malformed path must fail closed");
            assert_eq!(error.kind(), crate::error::ErrorKind::InvalidInput);
            assert!(error.message().contains("invalid OCI request path"));
            resolver
                .versioned_url(Service::Core, path)
                .expect_err("versioned malformed path must also fail closed");
        }
    }

    #[test]
    fn every_url_is_https() {
        let resolver = resolver(OC1_TENANCY, "ap-tokyo-1");
        for service in [
            Service::Identity,
            Service::Core,
            Service::Limits,
            Service::Usage,
        ] {
            let url = resolver.versioned_url(service, "/x").expect("url");
            assert_eq!(url.scheme(), "https", "{service} must be https");
        }
    }

    /// The realm comes from the tenancy, not the region, so a government
    /// tenancy resolves to a government domain.
    #[test]
    fn realm_is_taken_from_the_tenancy_ocid() {
        let gov = resolver("ocid1.tenancy.oc2..aaaaaaaagovtenancy", "us-langley-1");
        assert_eq!(gov.realm(), "oc2");
        assert_eq!(
            host(&gov, Service::Identity),
            "identity.us-langley-1.oraclegovcloud.com"
        );
        assert_eq!(
            host(&gov, Service::Core),
            "iaas.us-langley-1.oraclegovcloud.com"
        );
        assert_eq!(
            host(&gov, Service::Limits),
            "limits.us-langley-1.oci.oraclegovcloud.com"
        );
        assert_eq!(
            host(&gov, Service::Usage),
            "usageapi.us-langley-1.oci.oraclegovcloud.com"
        );
    }

    #[test]
    fn sovereign_realm_uses_its_domain_with_the_service_specific_style() {
        let sovereign = resolver(
            "ocid1.tenancy.oc19..aaaaaaaasovereigntenancy",
            "eu-madrid-2",
        );
        assert_eq!(
            host(&sovereign, Service::Core),
            "iaas.eu-madrid-2.oraclecloud.eu"
        );
        assert_eq!(
            host(&sovereign, Service::Limits),
            "limits.eu-madrid-2.oci.oraclecloud.eu"
        );
        assert_eq!(
            host(&sovereign, Service::Usage),
            "usageapi.eu-madrid-2.oci.oraclecloud.eu"
        );
    }

    /// A future realm can be enabled for established endpoint styles without
    /// silently guessing the service styles whose template is still unknown.
    #[test]
    fn an_unverified_realm_service_style_fails_before_building_a_url() {
        let resolver = EndpointResolver {
            realm: "oc-test".to_owned(),
            domain: "example.invalid",
            oci_subdomain: None,
            region: "test-region-1".parse::<Region>().expect("region"),
            authority_override: None,
        };

        assert_eq!(
            host(&resolver, Service::Identity),
            "identity.test-region-1.example.invalid"
        );
        let error = resolver
            .versioned_url(Service::Limits, "/limitValues")
            .expect_err("an unverified service authority must be refused");
        assert!(error.message().contains("Limits"));
        assert!(error.message().contains("oc-test"));
        assert!(
            error
                .context()
                .expect("context")
                .contains("no request was sent")
        );
    }

    /// Fail closed: never invent a hostname for a realm we do not know, because
    /// a signed Authorization header would be sent to it.
    #[test]
    fn unknown_realms_are_refused() {
        let error = EndpointResolver::new(
            &"ocid1.tenancy.oc999..aaaaaaaaunknownrealm"
                .parse::<Ocid>()
                .expect("ocid"),
            "us-ashburn-1".parse::<Region>().expect("region"),
        )
        .expect_err("an unknown realm must be refused");
        assert!(error.message().contains("oc999"));
        assert!(!error.remediation().is_empty());
    }

    #[test]
    fn every_oracle_sdk_realm_domain_is_allowlisted_exactly() {
        let expected = [
            ("oc1", "oraclecloud.com"),
            ("oc2", "oraclegovcloud.com"),
            ("oc3", "oraclegovcloud.com"),
            ("oc4", "oraclegovcloud.uk"),
            ("oc8", "oraclecloud8.com"),
            ("oc9", "oraclecloud9.com"),
            ("oc10", "oraclecloud10.com"),
            ("oc14", "oraclecloud14.com"),
            ("oc15", "oraclecloud15.com"),
            ("oc19", "oraclecloud.eu"),
            ("oc20", "oraclecloud20.com"),
            ("oc21", "oraclecloud21.com"),
            ("oc23", "oraclecloud23.com"),
            ("oc24", "oraclecloud24.com"),
            ("oc26", "oraclecloud26.com"),
            ("oc29", "oraclecloud29.com"),
            ("oc35", "oraclecloud35.com"),
            ("oc42", "oraclecloud42.com"),
            ("oc51", "oraclecloud51.com"),
            ("oc52", "oraclecloud52.com"),
        ];
        for (realm, domain) in expected {
            assert_eq!(realm_domain(realm), Some(domain), "realm {realm}");
        }
        assert_eq!(realm_domain("nope"), None);
    }

    #[test]
    fn region_can_be_switched_within_the_realm() {
        let home = resolver(OC1_TENANCY, "us-ashburn-1");
        let other = home.in_region("uk-london-1".parse::<Region>().expect("region"));
        assert_eq!(other.realm(), "oc1");
        assert_eq!(
            host(&other, Service::Core),
            "iaas.uk-london-1.oraclecloud.com"
        );
    }
}
