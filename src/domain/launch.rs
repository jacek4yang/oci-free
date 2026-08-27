//! Launch-time choices: which image, and how big.
//!
//! Both decisions are pure functions over live OCI metadata so they can be
//! tested exhaustively without a network. Nothing here hard-codes an image
//! OCID, an availability domain, or a shape name as the authoritative free
//! rule — Oracle replaces platform images constantly and shape names change,
//! so a pinned value rots into either a launch failure or, worse, a silently
//! wrong billing assumption.

use std::fmt;

use serde::Serialize;

use crate::{
    domain::time::UtcDateTime,
    error::{Error, Result},
    oci::compute::{Image, Shape},
};

/// Tolerance for comparing OCPU and memory quantities.
///
/// Matches `domain::capacity`: large enough to absorb JSON float
/// representation error, far too small to hide a real overrun.
const TOLERANCE: f64 = 1e-9;

/// Operating systems oci-free will pick by default, best first.
///
/// A general-purpose platform image with a long support window and no extra
/// licensing. Anything outside this list is still offered when the user asks
/// for it; it is simply not chosen automatically.
const PREFERRED_OPERATING_SYSTEMS: [&str; 2] = ["Oracle Linux", "Canonical Ubuntu"];

/// Substrings in a display name that mark a specialised image variant.
///
/// These images launch fine but are not a sensible unattended default: they
/// carry extra software, need a GPU shape, or expect a licence.
const SPECIALISED_MARKERS: [&str; 4] = ["GPU", "Cloud Developer", "Marketplace", "Oracle Database"];

/// A validated OCPU and memory selection for a launch.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ShapeSelection {
    pub shape: String,
    pub ocpus: f64,
    pub memory_gb: f64,
    pub is_flexible: bool,
    /// Advisories that do not prevent the launch.
    pub notes: Vec<String>,
}

impl fmt::Display for ShapeSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} with {} OCPU and {} GB",
            self.shape,
            format_quantity(self.ocpus),
            format_quantity(self.memory_gb)
        )
    }
}

/// Render a quantity without a misleading trailing `.0`.
#[must_use]
pub fn format_quantity(value: f64) -> String {
    if (value - value.round()).abs() < TOLERANCE {
        format!("{}", value.round() as i64)
    } else {
        format!("{value:.2}")
    }
}

/// Validate a requested size against a shape's own constraints.
///
/// `requested` is `None` to accept the shape's defaults, which is what an
/// interactive user who does not care gets.
pub fn validate_shape_config(
    shape: &Shape,
    requested: Option<(f64, f64)>,
) -> Result<ShapeSelection> {
    if shape.is_flexible() {
        validate_flexible(shape, requested)
    } else {
        validate_fixed(shape, requested)
    }
}

fn validate_fixed(shape: &Shape, requested: Option<(f64, f64)>) -> Result<ShapeSelection> {
    let (Some(ocpus), Some(memory_gb)) = (shape.ocpus, shape.memory_in_g_bs) else {
        return Err(Error::malformed_response(format!(
            "OCI did not report a size for the fixed shape {}",
            shape.shape
        ))
        .with_context(
            "a fixed shape's OCPU and memory come from OCI; without them the launch cannot be \
             proven to fit the free allowance",
        ));
    };

    if let Some((wanted_ocpus, wanted_memory)) = requested
        && (!close(wanted_ocpus, ocpus) || !close(wanted_memory, memory_gb))
    {
        return Err(Error::invalid_input(format!(
            "{} is a fixed-size shape and cannot be resized",
            shape.shape
        ))
        .with_context(format!(
            "it is always {} OCPU and {} GB; the request asked for {} OCPU and {} GB",
            format_quantity(ocpus),
            format_quantity(memory_gb),
            format_quantity(wanted_ocpus),
            format_quantity(wanted_memory)
        ))
        .with_remediation(format!(
            "drop --ocpus and --memory, or choose a flexible shape instead of {}",
            shape.shape
        )));
    }

    Ok(ShapeSelection {
        shape: shape.shape.clone(),
        ocpus,
        memory_gb,
        is_flexible: false,
        notes: Vec::new(),
    })
}

fn validate_flexible(shape: &Shape, requested: Option<(f64, f64)>) -> Result<ShapeSelection> {
    let ocpu_options = shape.ocpu_options.ok_or_else(|| {
        Error::malformed_response(format!(
            "OCI reported {} as flexible but supplied no OCPU bounds",
            shape.shape
        ))
        .with_context(
            "without the bounds oci-free cannot tell whether a configuration is valid, so it \
             refuses rather than guessing",
        )
    })?;

    let min_ocpus = ocpu_options.min.unwrap_or(1.0);
    let max_ocpus = ocpu_options.max.ok_or_else(|| {
        Error::malformed_response(format!(
            "OCI reported no maximum OCPU count for {}",
            shape.shape
        ))
    })?;

    let memory_options = shape.memory_options;
    let mut notes = Vec::new();

    let (ocpus, memory_gb) = match requested {
        Some(pair) => pair,
        None => {
            // With nothing requested, take the smallest valid configuration.
            // The plan then shows it and the user can raise it deliberately;
            // starting from the minimum can never over-consume the allowance.
            let ocpus = min_ocpus;
            let memory = memory_options
                .and_then(|options| options.min_in_g_bs)
                .unwrap_or(ocpus);
            notes.push(format!(
                "no size was requested, so the shape's minimum of {} OCPU and {} GB was used",
                format_quantity(ocpus),
                format_quantity(memory)
            ));
            (ocpus, memory)
        }
    };

    check_finite(ocpus, "OCPU count")?;
    check_finite(memory_gb, "memory size")?;

    if ocpus + TOLERANCE < min_ocpus || ocpus > max_ocpus + TOLERANCE {
        return Err(Error::invalid_input(format!(
            "{} OCPU is outside what {} allows",
            format_quantity(ocpus),
            shape.shape
        ))
        .with_context(format!(
            "OCI reports this shape as accepting {} to {} OCPU",
            format_quantity(min_ocpus),
            format_quantity(max_ocpus)
        ))
        .with_remediation(format!(
            "choose an OCPU count between {} and {}",
            format_quantity(min_ocpus),
            format_quantity(max_ocpus)
        )));
    }

    if let Some(options) = memory_options {
        if let Some(min) = options.min_in_g_bs
            && memory_gb + TOLERANCE < min
        {
            return Err(memory_error(
                shape,
                memory_gb,
                format!("at least {} GB", format_quantity(min)),
            ));
        }
        if let Some(max) = options.max_in_g_bs
            && memory_gb > max + TOLERANCE
        {
            return Err(memory_error(
                shape,
                memory_gb,
                format!("at most {} GB", format_quantity(max)),
            ));
        }
        // The per-OCPU ratio is the constraint users trip over most: OCI
        // rejects 1 OCPU with 24 GB even though both figures are individually
        // inside the shape's overall bounds.
        if let Some(min_per_ocpu) = options.min_per_ocpu_in_gbs
            && memory_gb + TOLERANCE < min_per_ocpu * ocpus
        {
            return Err(memory_error(
                shape,
                memory_gb,
                format!(
                    "at least {} GB for {} OCPU ({} GB per OCPU)",
                    format_quantity(min_per_ocpu * ocpus),
                    format_quantity(ocpus),
                    format_quantity(min_per_ocpu)
                ),
            ));
        }
        if let Some(max_per_ocpu) = options.max_per_ocpu_in_gbs
            && memory_gb > max_per_ocpu * ocpus + TOLERANCE
        {
            return Err(memory_error(
                shape,
                memory_gb,
                format!(
                    "at most {} GB for {} OCPU ({} GB per OCPU)",
                    format_quantity(max_per_ocpu * ocpus),
                    format_quantity(ocpus),
                    format_quantity(max_per_ocpu)
                ),
            ));
        }
    } else {
        notes.push(format!(
            "OCI reported no memory bounds for {}; the requested size is sent as-is and OCI will \
             reject it if it is invalid",
            shape.shape
        ));
    }

    Ok(ShapeSelection {
        shape: shape.shape.clone(),
        ocpus,
        memory_gb,
        is_flexible: true,
        notes,
    })
}

fn memory_error(shape: &Shape, requested: f64, expectation: String) -> Error {
    Error::invalid_input(format!(
        "{} GB is not a valid memory size for {}",
        format_quantity(requested),
        shape.shape
    ))
    .with_context(format!("OCI requires {expectation}"))
    .with_remediation("adjust --memory, or change --ocpus so the ratio is valid")
}

fn check_finite(value: f64, what: &str) -> Result<()> {
    if !value.is_finite() || value <= 0.0 {
        return Err(
            Error::invalid_input(format!("the {what} must be a positive number"))
                .with_context(format!("got {value}")),
        );
    }
    Ok(())
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= TOLERANCE
}

/// One image offered to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageChoice {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Whether oci-free would pick this one on its own.
    pub is_default: bool,
}

/// Rank compatible images, best default first.
///
/// The caller has already asked OCI to filter by shape and lifecycle state, so
/// everything here is launchable. Ranking only decides which is the sensible
/// unattended choice.
#[must_use]
pub fn rank_images(images: &[Image]) -> Vec<&Image> {
    let mut usable: Vec<&Image> = images.iter().filter(|image| is_usable(image)).collect();

    usable.sort_by(|a, b| {
        family_rank(a)
            .cmp(&family_rank(b))
            .then_with(|| version_rank(b).total_cmp(&version_rank(a)))
            .then_with(|| created_at(b).cmp(&created_at(a)))
            // A stable final key, so two images with identical metadata do not
            // swap places between runs and change the recommended default.
            .then_with(|| a.id.cmp(&b.id))
    });
    usable
}

/// The image oci-free recommends, if any is usable.
#[must_use]
pub fn default_image(images: &[Image]) -> Option<&Image> {
    rank_images(images).first().copied()
}

/// Build the user-facing choice list.
#[must_use]
pub fn image_choices(images: &[Image]) -> Vec<ImageChoice> {
    let ranked = rank_images(images);
    ranked
        .iter()
        .enumerate()
        .map(|(index, image)| ImageChoice {
            id: image.id.clone(),
            name: image
                .display_name
                .clone()
                .unwrap_or_else(|| image.id.clone()),
            operating_system: image.operating_system.clone(),
            operating_system_version: image.operating_system_version.clone(),
            created: image.time_created.clone(),
            is_default: index == 0,
        })
        .collect()
}

/// Whether an image is launchable and not a specialised variant.
fn is_usable(image: &Image) -> bool {
    let available = image
        .lifecycle_state
        .as_deref()
        .is_none_or(|state| state.eq_ignore_ascii_case("AVAILABLE"));
    if !available {
        return false;
    }
    let name = image.display_name.as_deref().unwrap_or_default();
    let os = image.operating_system.as_deref().unwrap_or_default();
    !SPECIALISED_MARKERS
        .iter()
        .any(|marker| name.contains(marker) || os.contains(marker))
}

/// Lower is better. Anything outside the preferred list sorts last.
fn family_rank(image: &Image) -> usize {
    let os = image.operating_system.as_deref().unwrap_or_default();
    PREFERRED_OPERATING_SYSTEMS
        .iter()
        .position(|preferred| os == *preferred)
        .unwrap_or(PREFERRED_OPERATING_SYSTEMS.len())
}

/// A numeric version for ordering, so `9` beats `8` and `24.04` beats `22.04`.
fn version_rank(image: &Image) -> f64 {
    image
        .operating_system_version
        .as_deref()
        .and_then(|version| version.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn created_at(image: &Image) -> Option<UtcDateTime> {
    image
        .time_created
        .as_deref()
        .and_then(UtcDateTime::parse_rfc3339)
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod launch_tests;
