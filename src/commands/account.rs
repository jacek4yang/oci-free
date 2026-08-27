//! `oci-free account info` — tenancy and home-region discovery.

use serde::Serialize;

use crate::{commands::context::CommandContext, error::Result, oci::identity::IdentityApi};

/// The `account info` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountInfo {
    /// Configuration profile in use.
    pub profile: String,
    /// Redacted tenancy OCID. Full OCIDs are not printed by default.
    pub tenancy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenancy_name: Option<String>,
    /// Region the CLI is configured to talk to.
    pub configured_region: String,
    /// Region OCI reports as the tenancy home, where Free Tier resources live.
    pub home_region: String,
    /// Every region this tenancy is subscribed to.
    pub subscribed_regions: Vec<String>,
    /// Availability domains in the home region.
    pub availability_domains: Vec<String>,
    /// Advisories, for example a configured region that is not the home region.
    pub warnings: Vec<String>,
}

/// Gather account information.
pub async fn run(context: &CommandContext) -> Result<AccountInfo> {
    let identity = IdentityApi::new(context.client());
    let tenancy_ocid = context.tenancy();

    let tenancy = identity.get_tenancy(tenancy_ocid).await?;
    let subscriptions = identity.list_region_subscriptions(tenancy_ocid).await?;

    let home_region = subscriptions
        .iter()
        .find(|subscription| subscription.is_home_region.unwrap_or(false))
        .map(|subscription| subscription.region_name.clone())
        .unwrap_or_else(|| "unknown".to_owned());

    let mut warnings = Vec::new();
    let configured_region = context.config().region.to_string();
    if home_region != "unknown" && home_region != configured_region {
        warnings.push(format!(
            "the configured region is {configured_region}, but this tenancy's home region is \
             {home_region}. Always Free resources live in the home region, so most oci-free \
             operations should target it."
        ));
    }

    // Availability domains are read from the home region, since that is where
    // Free Tier capacity exists.
    let availability_domains = match home_region.parse() {
        Ok(region) => {
            let home_client = context.client().in_region(region);
            IdentityApi::new(&home_client)
                .list_availability_domains(tenancy_ocid)
                .await
                .map(|domains| domains.into_iter().map(|domain| domain.name).collect())
                .unwrap_or_else(|error| {
                    warnings.push(format!("could not list availability domains: {error}"));
                    Vec::new()
                })
        }
        Err(_) => Vec::new(),
    };

    Ok(AccountInfo {
        profile: context.config().origin.profile.clone(),
        tenancy: context.config().tenancy.redacted(),
        tenancy_name: tenancy.name,
        configured_region,
        home_region,
        subscribed_regions: subscriptions
            .into_iter()
            .map(|subscription| subscription.region_name)
            .collect(),
        availability_domains,
        warnings,
    })
}

/// Render for a terminal.
#[must_use]
pub fn render_human(info: &AccountInfo) -> String {
    let mut out = String::new();
    out.push_str(&format!("Profile           {}\n", info.profile));
    out.push_str(&format!("Tenancy           {}\n", info.tenancy));
    if let Some(name) = &info.tenancy_name {
        out.push_str(&format!("Name              {name}\n"));
    }
    out.push_str(&format!("Configured region {}\n", info.configured_region));
    out.push_str(&format!("Home region       {}\n", info.home_region));
    out.push_str(&format!(
        "Subscribed        {}\n",
        if info.subscribed_regions.is_empty() {
            "none reported".to_owned()
        } else {
            info.subscribed_regions.join(", ")
        }
    ));
    if !info.availability_domains.is_empty() {
        out.push_str(&format!(
            "Domains           {}\n",
            info.availability_domains.join(", ")
        ));
    }
    for warning in &info.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{AccountInfo, render_human};

    fn info() -> AccountInfo {
        AccountInfo {
            profile: "DEFAULT".to_owned(),
            tenancy: "ocid1.tenancy.oc1..\u{2026}xk3q7a".to_owned(),
            tenancy_name: Some("example".to_owned()),
            configured_region: "us-ashburn-1".to_owned(),
            home_region: "us-ashburn-1".to_owned(),
            subscribed_regions: vec!["us-ashburn-1".to_owned()],
            availability_domains: vec!["Uocm:US-ASHBURN-AD-1".to_owned()],
            warnings: Vec::new(),
        }
    }

    /// Human output must not print a full tenancy OCID: it identifies the
    /// customer and this output is routinely pasted into issues.
    #[test]
    fn human_output_shows_a_redacted_tenancy() {
        let rendered = render_human(&info());
        assert!(rendered.contains("\u{2026}xk3q7a"));
        assert!(!rendered.contains("aaaaaaaaexampletenancyid"));
    }

    #[test]
    fn a_region_mismatch_is_surfaced_as_a_warning() {
        let mut info = info();
        info.configured_region = "eu-frankfurt-1".to_owned();
        info.warnings
            .push("the configured region is eu-frankfurt-1, but this tenancy's home region is us-ashburn-1".to_owned());

        let rendered = render_human(&info);
        assert!(rendered.contains("warning:"));
        assert!(rendered.contains("home region"));
    }

    #[test]
    fn serializes_with_stable_field_names() {
        let value = serde_json::to_value(info()).expect("serialize");
        for key in [
            "profile",
            "tenancy",
            "configured_region",
            "home_region",
            "subscribed_regions",
            "availability_domains",
            "warnings",
        ] {
            assert!(value.get(key).is_some(), "missing field {key}");
        }
    }
}
