//! Launch-selection tests.
//!
//! The flexible-shape checks matter most: OCI's per-OCPU memory ratio is the
//! constraint users trip over, and a validator that rounded generously could
//! approve a configuration that exceeds the free allowance.

use super::*;
use crate::oci::compute::{MemoryOptions, OcpuOptions, ShapeBillingType};

fn arm_flex() -> Shape {
    Shape {
        shape: "VM.Standard.A1.Flex".to_owned(),
        billing_type: ShapeBillingType::AlwaysFree,
        ocpus: None,
        memory_in_g_bs: None,
        processor_description: Some("Ampere Altra".to_owned()),
        is_flexible: Some(true),
        ocpu_options: Some(OcpuOptions {
            min: Some(1.0),
            max: Some(80.0),
        }),
        memory_options: Some(MemoryOptions {
            min_in_g_bs: Some(1.0),
            max_in_g_bs: Some(512.0),
            min_per_ocpu_in_gbs: Some(1.0),
            max_per_ocpu_in_gbs: Some(64.0),
        }),
    }
}

fn micro() -> Shape {
    Shape {
        shape: "VM.Standard.E2.1.Micro".to_owned(),
        billing_type: ShapeBillingType::AlwaysFree,
        ocpus: Some(1.0),
        memory_in_g_bs: Some(1.0),
        processor_description: Some("AMD EPYC".to_owned()),
        is_flexible: Some(false),
        ocpu_options: None,
        memory_options: None,
    }
}

fn image(id: &str, name: &str, os: Option<&str>, version: Option<&str>, created: &str) -> Image {
    Image {
        id: id.to_owned(),
        display_name: Some(name.to_owned()),
        operating_system: os.map(str::to_owned),
        operating_system_version: version.map(str::to_owned),
        lifecycle_state: Some("AVAILABLE".to_owned()),
        time_created: Some(created.to_owned()),
    }
}

// -- flexible shapes --------------------------------------------------------

#[test]
fn a_valid_flexible_configuration_is_accepted() {
    let selection = validate_shape_config(&arm_flex(), Some((2.0, 12.0))).expect("valid");
    assert_eq!(selection.ocpus, 2.0);
    assert_eq!(selection.memory_gb, 12.0);
    assert!(selection.is_flexible);
    assert_eq!(
        selection.to_string(),
        "VM.Standard.A1.Flex with 2 OCPU and 12 GB"
    );
}

/// Without a request, take the smallest valid configuration. Defaulting
/// upwards could consume the whole shared allowance on the first launch.
#[test]
fn no_request_takes_the_shape_minimum() {
    let selection = validate_shape_config(&arm_flex(), None).expect("valid");
    assert_eq!(selection.ocpus, 1.0);
    assert_eq!(selection.memory_gb, 1.0);
    assert!(selection.notes.iter().any(|note| note.contains("minimum")));
}

#[test]
fn ocpu_counts_outside_the_shape_bounds_are_refused() {
    for ocpus in [0.5, 0.0, 81.0, 1000.0] {
        let error = validate_shape_config(&arm_flex(), Some((ocpus, 6.0)))
            .expect_err("must refuse {ocpus} OCPU");
        assert!(
            error.message().contains("OCPU"),
            "unhelpful message for {ocpus}: {}",
            error.message()
        );
    }
}

#[test]
fn memory_outside_the_absolute_bounds_is_refused() {
    let error =
        validate_shape_config(&arm_flex(), Some((8.0, 600.0))).expect_err("600 GB is too much");
    assert!(error.context().expect("context").contains("512"));
}

/// The ratio constraint: 1 OCPU with 24 GB is inside both individual ranges
/// and still invalid, because A1 allows at most 64 GB per OCPU only from a
/// higher core count. This test pins the smaller side of the rule.
#[test]
fn the_per_ocpu_memory_ratio_is_enforced() {
    let mut shape = arm_flex();
    shape.memory_options = Some(MemoryOptions {
        min_in_g_bs: Some(1.0),
        max_in_g_bs: Some(512.0),
        min_per_ocpu_in_gbs: Some(1.0),
        max_per_ocpu_in_gbs: Some(6.0),
    });

    // 6 GB per OCPU is exactly the ceiling and must be allowed.
    assert!(validate_shape_config(&shape, Some((2.0, 12.0))).is_ok());

    let error = validate_shape_config(&shape, Some((1.0, 12.0)))
        .expect_err("12 GB on 1 OCPU exceeds 6 GB per OCPU");
    assert!(error.context().expect("context").contains("per OCPU"));
    assert!(error.remediation().contains("--ocpus"));

    let too_little = validate_shape_config(&shape, Some((4.0, 2.0)))
        .expect_err("2 GB across 4 OCPU is below the per-OCPU minimum");
    assert!(too_little.context().expect("context").contains("at least"));
}

/// The boundary values must be accepted, and one step past them refused. A
/// validator that rounded generously here would approve excess capacity.
#[test]
fn shape_bounds_are_inclusive_and_not_rounded() {
    let shape = arm_flex();
    assert!(validate_shape_config(&shape, Some((1.0, 1.0))).is_ok());
    assert!(validate_shape_config(&shape, Some((80.0, 512.0))).is_ok());
    assert!(validate_shape_config(&shape, Some((80.001, 512.0))).is_err());
    assert!(validate_shape_config(&shape, Some((80.0, 512.001))).is_err());
    assert!(validate_shape_config(&shape, Some((0.999, 4.0))).is_err());
}

/// A value arriving as 1.9999999999999998 must not be rejected as out of range.
#[test]
fn float_representation_noise_does_not_change_the_verdict() {
    let shape = arm_flex();
    let selection =
        validate_shape_config(&shape, Some((1.0 - 1e-12, 1.0 - 1e-12))).expect("noise absorbed");
    assert!(selection.ocpus > 0.0);
}

#[test]
fn non_finite_and_negative_sizes_are_refused() {
    let shape = arm_flex();
    for (ocpus, memory) in [
        (f64::NAN, 6.0),
        (f64::INFINITY, 6.0),
        (2.0, f64::NAN),
        (-1.0, 6.0),
        (2.0, -6.0),
    ] {
        assert!(
            validate_shape_config(&shape, Some((ocpus, memory))).is_err(),
            "({ocpus}, {memory}) must be refused"
        );
    }
}

/// A shape OCI calls flexible but describes without bounds cannot be validated,
/// so it is refused rather than sent optimistically.
#[test]
fn a_flexible_shape_without_bounds_is_refused() {
    let mut shape = arm_flex();
    shape.ocpu_options = None;
    let error = validate_shape_config(&shape, Some((2.0, 12.0))).expect_err("must refuse");
    assert!(error.message().contains("no OCPU bounds"));

    let mut no_max = arm_flex();
    no_max.ocpu_options = Some(OcpuOptions {
        min: Some(1.0),
        max: None,
    });
    assert!(validate_shape_config(&no_max, Some((2.0, 12.0))).is_err());
}

/// Missing memory bounds are a gap, not a licence to invent limits: the size is
/// forwarded and the gap is recorded as a note.
#[test]
fn missing_memory_bounds_are_noted_rather_than_invented() {
    let mut shape = arm_flex();
    shape.memory_options = None;
    let selection = validate_shape_config(&shape, Some((2.0, 12.0))).expect("accepted");
    assert!(
        selection
            .notes
            .iter()
            .any(|note| note.contains("no memory bounds"))
    );
}

// -- fixed shapes -----------------------------------------------------------

#[test]
fn a_fixed_shape_uses_ocis_reported_size() {
    let selection = validate_shape_config(&micro(), None).expect("valid");
    assert_eq!(selection.ocpus, 1.0);
    assert_eq!(selection.memory_gb, 1.0);
    assert!(!selection.is_flexible);
}

#[test]
fn a_fixed_shape_cannot_be_resized() {
    let error = validate_shape_config(&micro(), Some((2.0, 4.0))).expect_err("must refuse");
    assert!(error.message().contains("fixed-size"));
    assert!(error.context().expect("context").contains("1 OCPU"));
    assert!(error.remediation().contains("flexible"));
}

/// Asking for exactly what the shape already is should not be an error.
#[test]
fn requesting_the_fixed_size_exactly_is_accepted() {
    assert!(validate_shape_config(&micro(), Some((1.0, 1.0))).is_ok());
}

#[test]
fn a_fixed_shape_with_no_reported_size_is_refused() {
    let mut shape = micro();
    shape.ocpus = None;
    let error = validate_shape_config(&shape, None).expect_err("must refuse");
    assert!(error.message().contains("did not report a size"));
}

// -- image selection --------------------------------------------------------

fn catalogue() -> Vec<Image> {
    vec![
        image(
            "ocid1.image.oc1.iad.ubuntu2404",
            "Canonical-Ubuntu-24.04-aarch64-2026.07.15-0",
            Some("Canonical Ubuntu"),
            Some("24.04"),
            "2026-07-15T00:00:00Z",
        ),
        image(
            "ocid1.image.oc1.iad.ol8",
            "Oracle-Linux-8.10-aarch64-2026.06.30-0",
            Some("Oracle Linux"),
            Some("8"),
            "2026-06-30T00:00:00Z",
        ),
        image(
            "ocid1.image.oc1.iad.ol9old",
            "Oracle-Linux-9-aarch64-2026.01.10-0",
            Some("Oracle Linux"),
            Some("9"),
            "2026-01-10T00:00:00Z",
        ),
        image(
            "ocid1.image.oc1.iad.ol9new",
            "Oracle-Linux-9-aarch64-2026.08.01-0",
            Some("Oracle Linux"),
            Some("9"),
            "2026-08-01T00:00:00Z",
        ),
    ]
}

#[test]
fn the_default_image_is_the_newest_of_the_preferred_family() {
    let images = catalogue();
    let chosen = default_image(&images).expect("a default");
    assert_eq!(chosen.id, "ocid1.image.oc1.iad.ol9new");
}

#[test]
fn ranking_prefers_family_then_version_then_recency() {
    let images = catalogue();
    let ranked: Vec<&str> = rank_images(&images)
        .iter()
        .map(|image| image.id.as_str())
        .collect();
    assert_eq!(
        ranked,
        vec![
            "ocid1.image.oc1.iad.ol9new",
            "ocid1.image.oc1.iad.ol9old",
            "ocid1.image.oc1.iad.ol8",
            "ocid1.image.oc1.iad.ubuntu2404",
        ]
    );
}

/// Only images OCI reports as launchable may be offered.
#[test]
fn unavailable_images_are_excluded() {
    let mut images = catalogue();
    images[3].lifecycle_state = Some("DISABLED".to_owned());
    let chosen = default_image(&images).expect("a default");
    assert_eq!(chosen.id, "ocid1.image.oc1.iad.ol9old");
    assert_eq!(rank_images(&images).len(), 3);
}

/// A specialised image launches fine but is a poor unattended default.
#[test]
fn specialised_variants_are_not_offered_as_defaults() {
    let mut images = catalogue();
    images.push(image(
        "ocid1.image.oc1.iad.devel",
        "Oracle-Linux-9-Cloud Developer-2026.08.20-0",
        Some("Oracle Linux"),
        Some("9"),
        "2026-08-20T00:00:00Z",
    ));
    images.push(image(
        "ocid1.image.oc1.iad.gpu",
        "Oracle-Linux-9-GPU-2026.08.21-0",
        Some("Oracle Linux"),
        Some("9"),
        "2026-08-21T00:00:00Z",
    ));

    let chosen = default_image(&images).expect("a default");
    assert_eq!(
        chosen.id, "ocid1.image.oc1.iad.ol9new",
        "a newer specialised image must not displace the plain platform image"
    );
    assert!(
        rank_images(&images)
            .iter()
            .all(|image| !image.id.contains("gpu"))
    );
}

/// Ranking must not depend on the order OCI happened to return, or the
/// recommended default would drift between runs.
#[test]
fn ranking_is_stable_regardless_of_input_order() {
    let forward = catalogue();
    let mut reversed = catalogue();
    reversed.reverse();

    let a: Vec<&str> = rank_images(&forward)
        .iter()
        .map(|image| image.id.as_str())
        .collect();
    let b: Vec<&str> = rank_images(&reversed)
        .iter()
        .map(|image| image.id.as_str())
        .collect();
    assert_eq!(a, b);
}

#[test]
fn an_empty_catalogue_has_no_default() {
    assert!(default_image(&[]).is_none());
    assert!(image_choices(&[]).is_empty());
}

#[test]
fn choices_mark_exactly_one_default() {
    let choices = image_choices(&catalogue());
    assert_eq!(choices.iter().filter(|choice| choice.is_default).count(), 1);
    assert!(choices[0].is_default);
    assert_eq!(choices[0].operating_system.as_deref(), Some("Oracle Linux"));
}

/// An image with no metadata at all must still be offered rather than crashing
/// the selection.
#[test]
fn images_with_missing_metadata_still_rank() {
    let bare = Image {
        id: "ocid1.image.oc1.iad.bare".to_owned(),
        display_name: None,
        operating_system: None,
        operating_system_version: None,
        lifecycle_state: None,
        time_created: None,
    };
    let choices = image_choices(std::slice::from_ref(&bare));
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].name, "ocid1.image.oc1.iad.bare");
    assert!(choices[0].is_default);
}

#[test]
fn quantities_render_without_a_misleading_decimal() {
    assert_eq!(format_quantity(2.0), "2");
    assert_eq!(format_quantity(0.5), "0.50");
    assert_eq!(format_quantity(1.9999999999999998), "2");
}
