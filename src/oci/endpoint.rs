//! OCI service endpoint construction.
//!
//! OCI hostnames follow `https://{service}.{region}.{realm-domain}`. The realm
//! domain is *not* derived from the region name: it comes from the realm, which
//! this client reads out of the tenancy OCID (`ocid1.tenancy.oc1..` -> `oc1`).
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

    /// The API version path segment used by this service.
    #[must_use]
    pub fn api_version(self) -> &'static str {
        match self {
            Self::Identity | Self::Core => "20160918",
            Self::Limits => "20181025",
            Self::Usage => "20200107",
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.host_prefix())
    }
}

/// The DNS domain for an OCI realm.
///
/// Sourced from Oracle's published realm list. Realms absent from this table
/// are rejected rather than guessed.
#[must_use]
pub fn realm_domain(realm: &str) -> Option<&'static str> {
    match realm {
        "oc1" => Some("oraclecloud.com"),
        // US and UK government realms.
        "oc2" | "oc3" => Some("oraclegovcloud.com"),
        "oc4" => Some("oraclegovcloud.uk"),
        "oc8" => Some("oraclecloud8.com"),
        "oc9" => Some("oraclecloud9.com"),
        "oc10" => Some("oraclecloud10.com"),
        "oc14" => Some("oraclecloud14.com"),
        "oc15" => Some("oraclecloud15.com"),
        "oc19" => Some("oraclecloud.eu"),
        "oc20" => Some("oraclecloud20.com"),
        "oc21" => Some("oraclecloud21.com"),
        "oc23" => Some("oraclecloud23.com"),
        "oc24" => Some("oraclecloud24.com"),
        "oc26" => Some("oraclecloud26.com"),
        "oc29" => Some("oraclecloud29.com"),
        "oc35" => Some("oraclecloud35.com"),
        _ => None,
    }
}

/// Resolves service URLs for one tenancy and region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointResolver {
    realm: String,
    domain: &'static str,
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
        let domain = realm_domain(realm).ok_or_else(|| {
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
            domain,
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
            region,
            #[cfg(test)]
            authority_override: self.authority_override.clone(),
        }
    }

    /// The host for a service, for example `iaas.us-ashburn-1.oraclecloud.com`.
    #[must_use]
    pub fn host(&self, service: Service) -> String {
        #[cfg(test)]
        if let Some(authority) = &self.authority_override {
            return authority.clone();
        }
        format!("{}.{}.{}", service.host_prefix(), self.region, self.domain)
    }

    /// Build a URL for `path`, which must already be percent-encoded and must
    /// start with `/`.
    pub fn url(&self, service: Service, path: &str) -> Result<Url> {
        let base = format!("https://{}", self.host(service));
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
        self.url(service, &format!("/{}{path}", service.api_version()))
    }
}

#[cfg(test)]
mod tests {
    use super::{EndpointResolver, Service, realm_domain};
    use crate::domain::{ocid::Ocid, region::Region};

    fn resolver(tenancy: &str, region: &str) -> EndpointResolver {
        EndpointResolver::new(
            &tenancy.parse::<Ocid>().expect("tenancy OCID"),
            region.parse::<Region>().expect("region"),
        )
        .expect("resolver")
    }

    const OC1_TENANCY: &str = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a";

    #[test]
    fn builds_commercial_realm_hosts() {
        let resolver = resolver(OC1_TENANCY, "us-ashburn-1");
        assert_eq!(
            resolver.host(Service::Identity),
            "identity.us-ashburn-1.oraclecloud.com"
        );
        assert_eq!(
            resolver.host(Service::Core),
            "iaas.us-ashburn-1.oraclecloud.com"
        );
        assert_eq!(
            resolver.host(Service::Limits),
            "limits.us-ashburn-1.oraclecloud.com"
        );
        assert_eq!(
            resolver.host(Service::Usage),
            "usageapi.us-ashburn-1.oraclecloud.com"
        );
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
        let url = resolver
            .versioned_url(Service::Core, "/instances?compartmentId=x")
            .expect("url");
        assert_eq!(
            url.as_str(),
            "https://iaas.eu-frankfurt-1.oraclecloud.com/20160918/instances?compartmentId=x"
        );
        assert_eq!(url.scheme(), "https");
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
            gov.host(Service::Identity),
            "identity.us-langley-1.oraclegovcloud.com"
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
    fn known_realm_domains_are_distinct_where_expected() {
        assert_eq!(realm_domain("oc1"), Some("oraclecloud.com"));
        assert_eq!(realm_domain("oc4"), Some("oraclegovcloud.uk"));
        assert_eq!(realm_domain("oc19"), Some("oraclecloud.eu"));
        assert_eq!(realm_domain("nope"), None);
    }

    #[test]
    fn region_can_be_switched_within_the_realm() {
        let home = resolver(OC1_TENANCY, "us-ashburn-1");
        let other = home.in_region("uk-london-1".parse::<Region>().expect("region"));
        assert_eq!(other.realm(), "oc1");
        assert_eq!(
            other.host(Service::Core),
            "iaas.uk-london-1.oraclecloud.com"
        );
    }
}
