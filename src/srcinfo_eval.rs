use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use regex::Regex;
use srcinfo::{Package, Srcinfo};
use url::Url;

pub use crate::evaluation::{Evaluation, EvaluationName, RiskLevel};

pub fn evaluate_srcinfo_diff(
	previous: &Srcinfo,
	proposed: &Srcinfo,
	patterns: &[Regex],
) -> Vec<Evaluation> {
	let pkgbase = previous.base.pkgbase.clone();
	let mut evals = vec![
		evaluate_epoch(previous, proposed, pkgbase.clone()),
		evaluate_makedepends(previous, proposed, pkgbase.clone()),
		evaluate_checkdepends(previous, proposed, pkgbase.clone()),
		evaluate_valid_pgp_keys(previous, proposed, pkgbase.clone()),
		evaluate_no_extract(previous, proposed, pkgbase.clone()),
		evaluate_package_set(previous, proposed, pkgbase.clone()),
		evaluate_insecure_checksum(previous, proposed, pkgbase.clone()),
		evaluate_checksum_consistency(previous, proposed, pkgbase.clone()),
		evaluate_source(previous, proposed, patterns, pkgbase.clone()),
		evaluate_checksum_skip(previous, proposed, pkgbase.clone()),
		evaluate_pkgver(previous, proposed, pkgbase.clone()),
		evaluate_pkgrel(previous, proposed, pkgbase.clone()),
		evaluate_unexplained_update(previous, proposed, pkgbase),
	];

	let prev_pkgs: HashMap<String, &Package> = previous
		.pkgs
		.iter()
		.map(|p| (p.pkgname.clone(), p))
		.collect();
	let proposed_pkgs: HashMap<String, &Package> = proposed
		.pkgs
		.iter()
		.map(|p| (p.pkgname.clone(), p))
		.collect();

	for (pkgname, prev_pkg) in &prev_pkgs {
		if let Some(proposed_pkg) = proposed_pkgs.get(pkgname) {
			evals.push(evaluate_depends(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_optdepends(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_provides(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_conflicts(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_replaces(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_install(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_url(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_pkgdesc(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_changelog(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_arch(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_license(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_groups(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_backup(prev_pkg, proposed_pkg, pkgname.clone()));
			evals.push(evaluate_options(prev_pkg, proposed_pkg, pkgname.clone()));
		}
	}

	evals
}

fn evaluate_epoch(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	let prev_epoch = previous.epoch();
	let new_epoch = proposed.epoch();

	if prev_epoch == new_epoch {
		Evaluation {
			name: EvaluationName::Epoch,
			pkgname,
			description: format!("Epoch unchanged ({})", epoch_display(prev_epoch)),
			risk: RiskLevel::Low,
			modified: false,
		}
	} else {
		Evaluation {
			name: EvaluationName::Epoch,
			pkgname,
			description: format!(
				"Epoch changed from {} to {}",
				epoch_display(prev_epoch),
				epoch_display(new_epoch)
			),
			risk: RiskLevel::High,
			modified: true,
		}
	}
}

fn epoch_display(epoch: Option<&str>) -> &str {
	epoch.unwrap_or("None")
}

/// Compares two version strings segment-by-segment, splitting on '.'.
/// Each segment is compared numerically if both parse as u64, otherwise lexicographically.
/// Returns Ordering::Less if a < b, Ordering::Greater if a > b, Ordering::Equal otherwise.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
	let a_parts: Vec<&str> = a.split('.').collect();
	let b_parts: Vec<&str> = b.split('.').collect();
	let len = a_parts.len().max(b_parts.len());
	for i in 0..len {
		let a_seg = a_parts.get(i).copied().unwrap_or("0");
		let b_seg = b_parts.get(i).copied().unwrap_or("0");
		let ord = match (a_seg.parse::<u64>(), b_seg.parse::<u64>()) {
			(Ok(a_n), Ok(b_n)) => a_n.cmp(&b_n),
			_ => a_seg.cmp(b_seg),
		};
		if ord != std::cmp::Ordering::Equal {
			return ord;
		}
	}
	std::cmp::Ordering::Equal
}

#[derive(Debug, PartialEq, Eq)]
enum PkgverStyle {
	/// Single numeric segment with 8+ digits, e.g. `20260308`
	Timestamp,
	/// Dotted version where the first segment has 4+ digits, e.g. `2026.03.08`
	Date,
	/// Dotted version with a short numeric first segment (< 4 digits) and 2+ segments,
	/// e.g. `3.14`, `1.9.3`, `1.0.0_rc1`, `1.0.0.alpha`
	Semver,
	/// A single short numeric value, e.g. `42`
	SingleNumber,
	/// Anything else, e.g. `r123`
	Other,
}

fn detect_pkgver_style(s: &str) -> PkgverStyle {
	let parts: Vec<&str> = s.split('.').collect();
	match parts.as_slice() {
		[] => PkgverStyle::Other,
		[single] => {
			if single.chars().all(|c| c.is_ascii_digit()) {
				if single.len() >= 8 {
					PkgverStyle::Timestamp
				} else {
					PkgverStyle::SingleNumber
				}
			} else {
				PkgverStyle::Other
			}
		}
		[first, ..] => {
			if first.len() >= 4 && first.chars().all(|c| c.is_ascii_digit()) {
				PkgverStyle::Date
			} else if first.len() < 4 && first.chars().all(|c| c.is_ascii_digit()) {
				PkgverStyle::Semver
			} else {
				PkgverStyle::Other
			}
		}
	}
}

fn evaluate_pkgver(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	let prev_ver = &previous.base.pkgver;
	let new_ver = &proposed.base.pkgver;

	if prev_ver == new_ver {
		return Evaluation {
			name: EvaluationName::Pkgver,
			pkgname,
			description: format!("pkgver unchanged ({})", prev_ver),
			risk: RiskLevel::Low,
			modified: false,
		};
	}

	if new_ver.is_empty()
		|| !new_ver
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
	{
		return Evaluation {
			name: EvaluationName::Pkgver,
			pkgname,
			description: format!(
				"pkgver changed from {} to {} — new value contains invalid characters (only [a-zA-Z0-9._] allowed)",
				prev_ver, new_ver
			),
			risk: RiskLevel::High,
			modified: true,
		};
	}

	let prev_style = detect_pkgver_style(prev_ver);
	let new_style = detect_pkgver_style(new_ver);
	let style_changed = prev_style != new_style;

	match new_style {
		PkgverStyle::Timestamp | PkgverStyle::Date | PkgverStyle::SingleNumber => {
			if compare_versions(new_ver, prev_ver) == std::cmp::Ordering::Less {
				return Evaluation {
					name: EvaluationName::Pkgver,
					pkgname,
					description: format!("pkgver decreased from {} to {}", prev_ver, new_ver),
					risk: RiskLevel::High,
					modified: true,
				};
			}
			if style_changed {
				return Evaluation {
					name: EvaluationName::Pkgver,
					pkgname,
					description: format!(
						"pkgver changed from {} to {} — version style changed ({:?} to {:?})",
						prev_ver, new_ver, prev_style, new_style
					),
					risk: RiskLevel::Medium,
					modified: true,
				};
			}
			Evaluation {
				name: EvaluationName::Pkgver,
				pkgname,
				description: format!("pkgver changed from {} to {}", prev_ver, new_ver),
				risk: RiskLevel::Low,
				modified: true,
			}
		}
		PkgverStyle::Semver => {
			if compare_versions(new_ver, prev_ver) == std::cmp::Ordering::Less {
				return Evaluation {
					name: EvaluationName::Pkgver,
					pkgname,
					description: format!("pkgver decreased from {} to {}", prev_ver, new_ver),
					risk: RiskLevel::High,
					modified: true,
				};
			}
			// Major version bump: only meaningful if the previous version is also semver
			let prev_major = prev_ver
				.split('.')
				.next()
				.and_then(|s| s.parse::<u64>().ok());
			let new_major = new_ver
				.split('.')
				.next()
				.and_then(|s| s.parse::<u64>().ok());
			if let (Some(p), Some(n)) = (prev_major, new_major) {
				if n > p {
					return Evaluation {
						name: EvaluationName::Pkgver,
						pkgname,
						description: format!(
							"pkgver major version bumped from {} to {}",
							prev_ver, new_ver
						),
						risk: RiskLevel::Medium,
						modified: true,
					};
				}
			}
			if style_changed {
				return Evaluation {
					name: EvaluationName::Pkgver,
					pkgname,
					description: format!(
						"pkgver changed from {} to {} — version style changed ({:?} to {:?})",
						prev_ver, new_ver, prev_style, new_style
					),
					risk: RiskLevel::Medium,
					modified: true,
				};
			}
			Evaluation {
				name: EvaluationName::Pkgver,
				pkgname,
				description: format!("pkgver changed from {} to {}", prev_ver, new_ver),
				risk: RiskLevel::Low,
				modified: true,
			}
		}
		PkgverStyle::Other => {
			if new_ver.as_str() < prev_ver.as_str() {
				return Evaluation {
					name: EvaluationName::Pkgver,
					pkgname,
					description: format!("pkgver decreased from {} to {}", prev_ver, new_ver),
					risk: RiskLevel::High,
					modified: true,
				};
			}
			if style_changed {
				return Evaluation {
					name: EvaluationName::Pkgver,
					pkgname,
					description: format!(
						"pkgver changed from {} to {} — version style changed ({:?} to {:?})",
						prev_ver, new_ver, prev_style, new_style
					),
					risk: RiskLevel::Medium,
					modified: true,
				};
			}
			Evaluation {
				name: EvaluationName::Pkgver,
				pkgname,
				description: format!("pkgver changed from {} to {}", prev_ver, new_ver),
				risk: RiskLevel::Low,
				modified: true,
			}
		}
	}
}

fn evaluate_pkgrel(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	let prev_rel = &previous.base.pkgrel;
	let new_rel = &proposed.base.pkgrel;

	if prev_rel == new_rel {
		return Evaluation {
			name: EvaluationName::Pkgrel,
			pkgname,
			description: format!("pkgrel unchanged ({})", prev_rel),
			risk: RiskLevel::Low,
			modified: false,
		};
	}

	let prev_int = prev_rel.parse::<u64>().ok();
	let new_int = new_rel.parse::<u64>().ok();

	// Not a positive integer (includes 0, floats like 1.1, non-numeric)
	match new_int {
		None | Some(0) => {
			return Evaluation {
				name: EvaluationName::Pkgrel,
				pkgname,
				description: format!(
					"pkgrel changed from {} to {} — new value is not a positive integer",
					prev_rel, new_rel
				),
				risk: RiskLevel::Medium,
				modified: true,
			};
		}
		_ => {}
	}

	// Both are positive integers — check for decrease
	if let (Some(p), Some(n)) = (prev_int, new_int) {
		if n < p {
			return Evaluation {
				name: EvaluationName::Pkgrel,
				pkgname,
				description: format!("pkgrel decreased from {} to {}", prev_rel, new_rel),
				risk: RiskLevel::High,
				modified: true,
			};
		}
	}

	Evaluation {
		name: EvaluationName::Pkgrel,
		pkgname,
		description: format!("pkgrel changed from {} to {}", prev_rel, new_rel),
		risk: RiskLevel::Low,
		modified: true,
	}
}

fn evaluate_unexplained_update(
	previous: &Srcinfo,
	proposed: &Srcinfo,
	pkgname: String,
) -> Evaluation {
	let ver_unchanged = previous.base.pkgver == proposed.base.pkgver;
	let rel_unchanged = previous.base.pkgrel == proposed.base.pkgrel;

	if ver_unchanged && rel_unchanged {
		Evaluation {
			name: EvaluationName::UnexplainedUpdate,
			pkgname,
			description: "pkgver and pkgrel are both unchanged — unusual for a PKGBUILD update"
				.to_string(),
			risk: RiskLevel::Medium,
			modified: true,
		}
	} else {
		Evaluation {
			name: EvaluationName::UnexplainedUpdate,
			pkgname,
			description: "pkgver or pkgrel changed, as expected".to_string(),
			risk: RiskLevel::Low,
			modified: false,
		}
	}
}

fn diff_description(added: &[String], removed: &[String]) -> String {
	[
		(!added.is_empty()).then(|| format!("added: {}", added.join(", "))),
		(!removed.is_empty()).then(|| format!("removed: {}", removed.join(", "))),
	]
	.into_iter()
	.flatten()
	.collect::<Vec<_>>()
	.join("; ")
}

trait Diffable {
	fn to_diff_values(self) -> Vec<String>;
}

impl Diffable for Vec<String> {
	fn to_diff_values(self) -> Vec<String> {
		self
	}
}

impl Diffable for &srcinfo::ArchVecs {
	fn to_diff_values(self) -> Vec<String> {
		self.iter()
			.flat_map(|av| {
				let arch = av.arch();
				av.iter().map(move |val| match arch {
					// Square brackets are intentional here. [] are not valid package names, thus preventing type-confusion attacks
					Some(a) => format!("{}[{}]", val, a),
					None => val.to_string(),
				})
			})
			.collect()
	}
}

fn evaluate_package_set(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	let prev_names: Vec<String> = previous.pkgs.iter().map(|p| p.pkgname.clone()).collect();
	let proposed_names: Vec<String> = proposed.pkgs.iter().map(|p| p.pkgname.clone()).collect();
	evaluate_array_field(
		EvaluationName::PackageSet,
		pkgname,
		"Package set",
		prev_names,
		proposed_names,
		RiskLevel::High,
	)
}

fn evaluate_array_field(
	name: EvaluationName,
	pkgname: String,
	field_name: &str,
	prev_values: impl Diffable,
	new_values: impl Diffable,
	risk_if_modified: RiskLevel,
) -> Evaluation {
	let prev: HashSet<String> = prev_values.to_diff_values().into_iter().collect();
	let new: HashSet<String> = new_values.to_diff_values().into_iter().collect();

	let mut added: Vec<String> = new.difference(&prev).cloned().collect();
	let mut removed: Vec<String> = prev.difference(&new).cloned().collect();
	added.sort_unstable();
	removed.sort_unstable();

	if added.is_empty() && removed.is_empty() {
		Evaluation {
			name,
			pkgname,
			description: format!("{} unchanged", field_name),
			risk: RiskLevel::Low,
			modified: false,
		}
	} else {
		Evaluation {
			name,
			pkgname,
			description: format!(
				"{} changed ({})",
				field_name,
				diff_description(&added, &removed)
			),
			risk: risk_if_modified,
			modified: true,
		}
	}
}

fn evaluate_makedepends(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::MakeDepends,
		pkgname,
		"makedepends",
		&previous.base.makedepends,
		&proposed.base.makedepends,
		RiskLevel::Medium,
	)
}

fn evaluate_checkdepends(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::CheckDepends,
		pkgname,
		"checkdepends",
		&previous.base.checkdepends,
		&proposed.base.checkdepends,
		RiskLevel::Medium,
	)
}

fn evaluate_valid_pgp_keys(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::ValidPgpKeys,
		pkgname,
		"validpgpkeys",
		previous.base.valid_pgp_keys.clone(),
		proposed.base.valid_pgp_keys.clone(),
		RiskLevel::High,
	)
}

fn evaluate_no_extract(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::NoExtract,
		pkgname,
		"noextract",
		previous.base.no_extract.clone(),
		proposed.base.no_extract.clone(),
		RiskLevel::Low,
	)
}

fn has_real_checksums(vecs: &srcinfo::ArchVecs) -> bool {
	vecs.iter()
		.flat_map(|av| av.iter())
		.any(|v| !v.is_empty() && v != "SKIP")
}

fn evaluate_insecure_checksum(
	previous: &Srcinfo,
	proposed: &Srcinfo,
	pkgname: String,
) -> Evaluation {
	let prev_insecure =
		has_real_checksums(&previous.base.md5sums) || has_real_checksums(&previous.base.sha1sums);
	let proposed_insecure =
		has_real_checksums(&proposed.base.md5sums) || has_real_checksums(&proposed.base.sha1sums);

	if proposed_insecure {
		Evaluation {
			name: EvaluationName::InsecureChecksum,
			pkgname,
			description:
				"md5sums or sha1sums are used — these algorithms are cryptographically broken"
					.to_string(),
			risk: RiskLevel::High,
			modified: !prev_insecure,
		}
	} else {
		Evaluation {
			name: EvaluationName::InsecureChecksum,
			pkgname,
			description: "No insecure checksums (md5/sha1) present".to_string(),
			risk: RiskLevel::Low,
			modified: prev_insecure,
		}
	}
}

// Returns a description of the first checksum array inconsistency found, or
// `None` if all arrays are consistent (equal length, SKIP at the same indices).
fn checksums_inconsistency(srcinfo: &Srcinfo) -> Option<String> {
	let checksum_fields: &[(&str, &srcinfo::ArchVecs)] = &[
		("sha224sums", &srcinfo.base.sha224sums),
		("sha256sums", &srcinfo.base.sha256sums),
		("sha384sums", &srcinfo.base.sha384sums),
		("sha512sums", &srcinfo.base.sha512sums),
		("b2sums", &srcinfo.base.b2sums),
	];

	// Group non-empty (field_name, values) pairs by architecture key.
	let mut by_arch: BTreeMap<String, Vec<(&str, Vec<String>)>> = BTreeMap::new();

	for (field_name, arch_vecs) in checksum_fields {
		for arch_vec in arch_vecs.iter() {
			let values: Vec<String> = arch_vec.iter().map(|s| s.to_string()).collect();
			if !values.is_empty() {
				let arch_key = arch_vec.arch().unwrap_or("").to_string();
				by_arch
					.entry(arch_key)
					.or_default()
					.push((field_name, values));
			}
		}
	}

	for (arch_key, field_entries) in &by_arch {
		if field_entries.len() < 2 {
			continue;
		}

		let arch_label = if arch_key.is_empty() {
			String::new()
		} else {
			format!(" (arch={})", arch_key)
		};

		let first_len = field_entries[0].1.len();
		for (field_name, values) in field_entries.iter().skip(1) {
			if values.len() != first_len {
				return Some(format!(
					"checksum arrays{} have different lengths: {} has {} {} but {} has {}",
					arch_label,
					field_entries[0].0,
					first_len,
					if first_len == 1 { "entry" } else { "entries" },
					field_name,
					values.len(),
				));
			}
		}

		for i in 0..first_len {
			let skip_fields: Vec<&str> = field_entries
				.iter()
				.filter(|(_, vals)| vals[i] == "SKIP")
				.map(|(name, _)| *name)
				.collect();
			let non_skip_fields: Vec<&str> = field_entries
				.iter()
				.filter(|(_, vals)| vals[i] != "SKIP")
				.map(|(name, _)| *name)
				.collect();
			if !skip_fields.is_empty() && !non_skip_fields.is_empty() {
				return Some(format!(
					"SKIP mismatch at source index {}{}: {} use SKIP but {} do not",
					i,
					arch_label,
					skip_fields.join(", "),
					non_skip_fields.join(", "),
				));
			}
		}
	}

	None
}

fn evaluate_checksum_consistency(
	previous: &Srcinfo,
	proposed: &Srcinfo,
	pkgname: String,
) -> Evaluation {
	let prev_error = checksums_inconsistency(previous);
	let proposed_error = checksums_inconsistency(proposed);

	match proposed_error {
		Some(msg) => Evaluation {
			name: EvaluationName::ChecksumConsistency,
			pkgname,
			description: format!("Checksum arrays are inconsistent: {}", msg),
			risk: RiskLevel::High,
			modified: prev_error.is_none(),
		},
		None => Evaluation {
			name: EvaluationName::ChecksumConsistency,
			pkgname,
			description: "Checksum arrays are consistent".to_string(),
			risk: RiskLevel::Low,
			modified: prev_error.is_some(),
		},
	}
}

fn strip_source_prefix(entry: &str) -> &str {
	if let Some(pos) = entry.find("::") {
		&entry[pos + 2..]
	} else {
		entry
	}
}

/// Returns `true` if `pattern` successfully pairs `old_url` with `new_url`
/// as a clean version bump:
///
/// - Both URLs must match the pattern.
/// - If the pattern has a `version` named group, the captured value in
///   `new_url` must equal `new_pkgver` exactly.
/// - All other named groups must be identical between old and new.
///
/// Patterns without a `version` group are treated as domain-level trust
/// overrides: if both URLs match, the change is considered low risk regardless
/// of what specifically changed.
fn matches_source_pattern(pattern: &Regex, old_url: &str, new_url: &str, new_pkgver: &str) -> bool {
	let old_caps = match pattern.captures(old_url) {
		Some(c) => c,
		None => return false,
	};
	let new_caps = match pattern.captures(new_url) {
		Some(c) => c,
		None => return false,
	};

	let has_version_group = pattern.capture_names().flatten().any(|n| n == "version");

	if has_version_group {
		match new_caps.name("version") {
			Some(v) if v.as_str() == new_pkgver => {}
			_ => return false,
		}
	}

	// All non-version named groups must be identical between old and new.
	for name in pattern.capture_names().flatten() {
		if name == "version" {
			continue;
		}
		let old_val = old_caps.name(name).map(|m| m.as_str()).unwrap_or("");
		let new_val = new_caps.name(name).map(|m| m.as_str()).unwrap_or("");
		if old_val != new_val {
			return false;
		}
	}

	true
}

fn source_entries_by_arch(arch_vecs: &srcinfo::ArchVecs) -> BTreeMap<String, Vec<String>> {
	let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
	for av in arch_vecs.iter() {
		let key = av.arch().unwrap_or("").to_string();
		let values: Vec<String> = av.iter().map(|s| s.to_string()).collect();
		if !values.is_empty() {
			map.entry(key).or_default().extend(values);
		}
	}
	map
}

fn evaluate_source(
	previous: &Srcinfo,
	proposed: &Srcinfo,
	patterns: &[Regex],
	pkgname: String,
) -> Evaluation {
	let prev_by_arch = source_entries_by_arch(&previous.base.source);
	let new_by_arch = source_entries_by_arch(&proposed.base.source);

	let all_arches: BTreeSet<String> = prev_by_arch
		.keys()
		.chain(new_by_arch.keys())
		.cloned()
		.collect();

	let new_pkgver = &proposed.base.pkgver;
	let empty: Vec<String> = vec![];

	for arch_key in &all_arches {
		let prev_vals = prev_by_arch.get(arch_key).unwrap_or(&empty);
		let new_vals = new_by_arch.get(arch_key).unwrap_or(&empty);

		let arch_label = if arch_key.is_empty() {
			String::new()
		} else {
			format!(" (arch={})", arch_key)
		};

		if prev_vals.len() != new_vals.len() {
			return Evaluation {
				name: EvaluationName::Source,
				pkgname,
				description: format!(
					"Source count changed from {} to {}{}",
					prev_vals.len(),
					new_vals.len(),
					arch_label,
				),
				risk: RiskLevel::High,
				modified: true,
			};
		}

		for i in 0..prev_vals.len() {
			let old_entry = &prev_vals[i];
			let new_entry = &new_vals[i];

			if old_entry == new_entry {
				continue;
			}

			let old_url = strip_source_prefix(old_entry);
			let new_url = strip_source_prefix(new_entry);

			let matched = patterns
				.iter()
				.any(|p| matches_source_pattern(p, old_url, new_url, new_pkgver));

			if !matched {
				return Evaluation {
					name: EvaluationName::Source,
					pkgname,
					description: format!(
						"Source changed with no matching pattern{}: {} -> {}",
						arch_label, old_url, new_url,
					),
					risk: RiskLevel::High,
					modified: true,
				};
			}
		}
	}

	let any_changed = all_arches.iter().any(|arch| {
		prev_by_arch.get(arch).unwrap_or(&empty) != new_by_arch.get(arch).unwrap_or(&empty)
	});

	Evaluation {
		name: EvaluationName::Source,
		pkgname,
		description: if any_changed {
			"Source URLs changed consistently with pkgver bump".to_string()
		} else {
			"Sources unchanged".to_string()
		},
		risk: RiskLevel::Low,
		modified: any_changed,
	}
}

fn is_local_source(url: &str) -> bool {
	!url.contains("://")
}

// Consulting any one checksum array is sufficient because evaluate_checksum_consistency
// already guarantees all arrays agree on which positions are SKIP.
fn first_checksum_values(srcinfo: &Srcinfo, arch_key: &str) -> Vec<String> {
	let checksum_fields: &[&srcinfo::ArchVecs] = &[
		&srcinfo.base.sha256sums,
		&srcinfo.base.sha512sums,
		&srcinfo.base.b2sums,
		&srcinfo.base.sha384sums,
		&srcinfo.base.sha224sums,
	];
	for arch_vecs in checksum_fields {
		for av in arch_vecs.iter() {
			if av.arch().unwrap_or("") == arch_key {
				let vals: Vec<String> = av.iter().map(|s| s.to_string()).collect();
				if !vals.is_empty() {
					return vals;
				}
			}
		}
	}
	vec![]
}

fn has_checksum_skip_issue(srcinfo: &Srcinfo) -> bool {
	let by_arch = source_entries_by_arch(&srcinfo.base.source);
	for (arch_key, vals) in &by_arch {
		let checksums = first_checksum_values(srcinfo, arch_key);
		for (i, entry) in vals.iter().enumerate() {
			let url = strip_source_prefix(entry);
			let cksum = checksums.get(i).map(|s| s.as_str()).unwrap_or("");
			if is_local_source(url) {
				if cksum == "SKIP" || cksum.is_empty() {
					return true;
				}
			} else if cksum == "SKIP" {
				return true;
			}
		}
	}
	false
}

fn evaluate_checksum_skip(previous: &Srcinfo, proposed: &Srcinfo, pkgname: String) -> Evaluation {
	let prev_by_arch = source_entries_by_arch(&previous.base.source);
	let new_by_arch = source_entries_by_arch(&proposed.base.source);

	let all_arches: BTreeSet<String> = prev_by_arch
		.keys()
		.chain(new_by_arch.keys())
		.cloned()
		.collect();

	let empty_sources: Vec<String> = vec![];

	for arch_key in &all_arches {
		let prev_srcs = prev_by_arch.get(arch_key).unwrap_or(&empty_sources);
		let new_srcs = new_by_arch.get(arch_key).unwrap_or(&empty_sources);

		let prev_cksums = first_checksum_values(previous, arch_key);
		let new_cksums = first_checksum_values(proposed, arch_key);

		let arch_label = if arch_key.is_empty() {
			String::new()
		} else {
			format!(" (arch={})", arch_key)
		};

		for (i, new_entry) in new_srcs.iter().enumerate() {
			let new_url = strip_source_prefix(new_entry);
			let new_cksum = new_cksums.get(i).map(|s| s.as_str()).unwrap_or("");

			if is_local_source(new_url) {
				let new_is_skip = new_cksum == "SKIP" || new_cksum.is_empty();

				if new_is_skip {
					let prev_also_skip = prev_srcs
						.get(i)
						.map(|prev_entry| {
							let prev_url = strip_source_prefix(prev_entry);
							let prev_cksum = prev_cksums.get(i).map(|s| s.as_str()).unwrap_or("");
							prev_url == new_url && (prev_cksum == "SKIP" || prev_cksum.is_empty())
						})
						.unwrap_or(false);

					return Evaluation {
						name: EvaluationName::ChecksumSkip,
						pkgname,
						description: format!(
							"Local file '{}' has SKIP checksum — local files must have a real checksum{}",
							new_url, arch_label,
						),
						risk: RiskLevel::High,
						modified: !prev_also_skip,
					};
				}

				// Local file with a real checksum: flag if it changed vs prev.
				if let Some(prev_entry) = prev_srcs.get(i) {
					let prev_url = strip_source_prefix(prev_entry);
					let prev_cksum = prev_cksums.get(i).map(|s| s.as_str()).unwrap_or("");
					if is_local_source(prev_url)
						&& prev_url == new_url
						&& prev_cksum != "SKIP"
						&& !prev_cksum.is_empty()
						&& prev_cksum != new_cksum
					{
						return Evaluation {
							name: EvaluationName::ChecksumSkip,
							pkgname,
							description: format!(
								"Local file '{}' checksum changed — the file may have been modified{}",
								new_url, arch_label,
							),
							risk: RiskLevel::High,
							modified: true,
						};
					}
				}
			} else {
				// Remote sources: only the explicit SKIP token is flagged; an
				// absent checksum array is not.
				if new_cksum != "SKIP" {
					continue;
				}

				let prev_cksum: Option<&str> = prev_srcs
					.get(i)
					.map(|_| prev_cksums.get(i).map(|s| s.as_str()).unwrap_or(""));

				// prev_cksum is None when this source index didn't exist before
				// (source count increased). evaluate_source also flags this, but
				// a new remote source with SKIP is itself a checksum concern.
				if prev_cksum.is_none() {
					return Evaluation {
						name: EvaluationName::ChecksumSkip,
						pkgname,
						description: format!(
							"New remote source '{}' has SKIP checksum{}",
							new_url, arch_label,
						),
						risk: RiskLevel::High,
						modified: true,
					};
				}

				if prev_cksum.is_some_and(|c| c != "SKIP" && !c.is_empty()) {
					return Evaluation {
						name: EvaluationName::ChecksumSkip,
						pkgname,
						description: format!(
							"Remote source '{}' previously had a checksum but now has SKIP{}",
							new_url, arch_label,
						),
						risk: RiskLevel::High,
						modified: true,
					};
				}
			}
		}
	}

	Evaluation {
		name: EvaluationName::ChecksumSkip,
		pkgname,
		description: "Checksum verification OK".to_string(),
		risk: RiskLevel::Low,
		modified: has_checksum_skip_issue(previous) && !has_checksum_skip_issue(proposed),
	}
}

fn evaluate_depends(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Depends,
		pkgname,
		"depends",
		&prev_pkg.depends,
		&proposed_pkg.depends,
		RiskLevel::Medium,
	)
}

fn evaluate_optdepends(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::OptDepends,
		pkgname,
		"optdepends",
		&prev_pkg.optdepends,
		&proposed_pkg.optdepends,
		RiskLevel::Medium,
	)
}

fn evaluate_provides(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Provides,
		pkgname,
		"provides",
		&prev_pkg.provides,
		&proposed_pkg.provides,
		RiskLevel::High,
	)
}

fn evaluate_conflicts(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Conflicts,
		pkgname,
		"conflicts",
		&prev_pkg.conflicts,
		&proposed_pkg.conflicts,
		RiskLevel::Medium,
	)
}
fn evaluate_replaces(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Replaces,
		pkgname,
		"replaces",
		&prev_pkg.replaces,
		&proposed_pkg.replaces,
		RiskLevel::High,
	)
}

fn optional_field_display(val: &Option<String>) -> &str {
	val.as_deref().unwrap_or("None")
}

fn evaluate_optional_string_field(
	name: EvaluationName,
	pkgname: String,
	field_name: &str,
	prev: &Option<String>,
	proposed: &Option<String>,
	risk_if_modified: RiskLevel,
) -> Evaluation {
	if prev == proposed {
		Evaluation {
			name,
			pkgname,
			description: format!(
				"{} unchanged ({})",
				field_name,
				optional_field_display(prev)
			),
			risk: RiskLevel::Low,
			modified: false,
		}
	} else {
		Evaluation {
			name,
			pkgname,
			description: format!(
				"{} changed from '{}' to '{}'",
				field_name,
				optional_field_display(prev),
				optional_field_display(proposed)
			),
			risk: risk_if_modified,
			modified: true,
		}
	}
}

fn evaluate_install(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_optional_string_field(
		EvaluationName::Install,
		pkgname,
		"install",
		&prev_pkg.install,
		&proposed_pkg.install,
		RiskLevel::High,
	)
}

fn evaluate_url(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	let prev = &prev_pkg.url;
	let proposed = &proposed_pkg.url;

	let proposed_invalid = proposed
		.as_deref()
		.map(|s| Url::parse(s).is_err())
		.unwrap_or(false);

	if proposed_invalid {
		return Evaluation {
			name: EvaluationName::Url,
			pkgname,
			description: format!(
				"url '{}' is not a valid URI",
				optional_field_display(proposed)
			),
			risk: RiskLevel::High,
			modified: prev != proposed,
		};
	}

	evaluate_optional_string_field(
		EvaluationName::Url,
		pkgname,
		"url",
		prev,
		proposed,
		RiskLevel::High,
	)
}

fn evaluate_pkgdesc(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_optional_string_field(
		EvaluationName::Pkgdesc,
		pkgname,
		"pkgdesc",
		&prev_pkg.pkgdesc,
		&proposed_pkg.pkgdesc,
		RiskLevel::Low,
	)
}

fn evaluate_changelog(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_optional_string_field(
		EvaluationName::Changelog,
		pkgname,
		"changelog",
		&prev_pkg.changelog,
		&proposed_pkg.changelog,
		RiskLevel::Low,
	)
}

fn evaluate_arch(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Arch,
		pkgname,
		"arch",
		prev_pkg.arch.clone(),
		proposed_pkg.arch.clone(),
		RiskLevel::High,
	)
}

fn evaluate_license(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::License,
		pkgname,
		"license",
		prev_pkg.license.clone(),
		proposed_pkg.license.clone(),
		RiskLevel::High,
	)
}

fn evaluate_groups(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Groups,
		pkgname,
		"groups",
		prev_pkg.groups.clone(),
		proposed_pkg.groups.clone(),
		RiskLevel::High,
	)
}

fn evaluate_backup(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	evaluate_array_field(
		EvaluationName::Backup,
		pkgname,
		"backup",
		prev_pkg.backup.clone(),
		proposed_pkg.backup.clone(),
		RiskLevel::Low,
	)
}

fn option_risk(option: &str) -> RiskLevel {
	let base = option.strip_prefix('!').unwrap_or(option);
	match base {
		"staticlibs" | "makeflags" | "buildflags" => RiskLevel::High,
		"lto" | "debug" | "emptydirs" => RiskLevel::Medium,
		_ => RiskLevel::Low,
	}
}

fn max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel {
	match (a, b) {
		(RiskLevel::High, _) | (_, RiskLevel::High) => RiskLevel::High,
		(RiskLevel::Medium, _) | (_, RiskLevel::Medium) => RiskLevel::Medium,
		_ => RiskLevel::Low,
	}
}

fn evaluate_options(prev_pkg: &Package, proposed_pkg: &Package, pkgname: String) -> Evaluation {
	let prev: HashSet<String> = prev_pkg.options.iter().cloned().collect();
	let new: HashSet<String> = proposed_pkg.options.iter().cloned().collect();

	let mut added: Vec<String> = new.difference(&prev).cloned().collect();
	let mut removed: Vec<String> = prev.difference(&new).cloned().collect();
	added.sort_unstable();
	removed.sort_unstable();

	if added.is_empty() && removed.is_empty() {
		return Evaluation {
			name: EvaluationName::Options,
			pkgname,
			description: "options unchanged".to_string(),
			risk: RiskLevel::Low,
			modified: false,
		};
	}

	let risk = added
		.iter()
		.chain(removed.iter())
		.map(|opt| option_risk(opt))
		.fold(RiskLevel::Low, max_risk);

	Evaluation {
		name: EvaluationName::Options,
		pkgname,
		description: format!("options changed ({})", diff_description(&added, &removed)),
		risk,
		modified: true,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	const BASE_SRCINFO: &str = "\
pkgbase = example
\tpkgdesc = An example package
\tpkgver = 1.0.0
\tpkgrel = 1
\tarch = x86_64
\tsha256sums = SKIP

pkgname = example
\tpkgdesc = An example package
";

	fn parse_base() -> Srcinfo {
		Srcinfo::from_str(BASE_SRCINFO)
			.expect("BASE_SRCINFO must be a valid .SRCINFO for tests to work")
	}

	fn with_modification(modify: impl FnOnce(&mut Srcinfo)) -> Srcinfo {
		let mut srcinfo = parse_base();
		modify(&mut srcinfo);
		srcinfo
	}

	fn find_eval<'a>(
		evaluations: &'a [Evaluation],
		name: EvaluationName,
		pkgname: &str,
	) -> &'a Evaluation {
		evaluations
			.iter()
			.find(|e| e.name == name && e.pkgname == pkgname)
			.unwrap_or_else(|| {
				panic!(
					"Expected evaluation '{:?}' for '{}' not found. Available: {:?}",
					name,
					pkgname,
					evaluations
						.iter()
						.map(|e| (&e.name, &e.pkgname))
						.collect::<Vec<_>>()
				)
			})
	}

	struct EpochCase {
		name: &'static str,
		previous: fn(&mut Srcinfo),
		proposed: fn(&mut Srcinfo),
		risk: RiskLevel,
		modified: bool,
	}

	#[test]
	fn test_epoch() {
		let cases = [
			EpochCase {
				name: "unchanged_both_none",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			EpochCase {
				name: "unchanged_both_set",
				previous: |s| s.base.epoch = Some("1".to_string()),
				proposed: |s| s.base.epoch = Some("1".to_string()),
				risk: RiskLevel::Low,
				modified: false,
			},
			EpochCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.base.epoch = Some("1".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
			EpochCase {
				name: "removed",
				previous: |s| s.base.epoch = Some("1".to_string()),
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
			EpochCase {
				name: "incremented",
				previous: |s| s.base.epoch = Some("1".to_string()),
				proposed: |s| s.base.epoch = Some("2".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Epoch, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	struct ArrayFieldCase {
		name: &'static str,
		previous: fn(&mut Srcinfo),
		proposed: fn(&mut Srcinfo),
		risk: RiskLevel,
		modified: bool,
	}

	fn pkg_archvec(values: Vec<&str>) -> srcinfo::ArchVec {
		srcinfo::ArchVec::with_values(
			None::<String>,
			values.into_iter().map(|s| s.to_string()).collect(),
		)
	}

	fn archvecs(values: Vec<&str>) -> srcinfo::ArchVecs {
		vec![pkg_archvec(values)].into()
	}

	fn pkg_archvec_for(arch: &str, values: Vec<&str>) -> srcinfo::ArchVec {
		srcinfo::ArchVec::with_values(
			Some(arch.to_string()),
			values.into_iter().map(|s| s.to_string()).collect(),
		)
	}

	fn archvecs_for(arch: &str, values: Vec<&str>) -> srcinfo::ArchVecs {
		vec![pkg_archvec_for(arch, values)].into()
	}

	const SPLIT_SRCINFO: &str = "\
pkgbase = example
\tpkgdesc = An example package
\tpkgver = 1.0.0
\tpkgrel = 1
\tarch = x86_64
\tsha256sums = SKIP

pkgname = example
\tpkgdesc = An example package

pkgname = example-extra
\tpkgdesc = An example extra package
";

	#[test]
	fn test_detect_pkgver_style() {
		assert_eq!(detect_pkgver_style("20260308"), PkgverStyle::Timestamp);
		assert_eq!(detect_pkgver_style("20250101"), PkgverStyle::Timestamp);
		assert_eq!(detect_pkgver_style("2026.03.08"), PkgverStyle::Date);
		assert_eq!(detect_pkgver_style("2025.12.01"), PkgverStyle::Date);
		assert_eq!(detect_pkgver_style("1.0.0"), PkgverStyle::Semver);
		assert_eq!(detect_pkgver_style("3.14"), PkgverStyle::Semver);
		assert_eq!(detect_pkgver_style("4.0"), PkgverStyle::Semver);
		assert_eq!(detect_pkgver_style("42"), PkgverStyle::SingleNumber);
		assert_eq!(detect_pkgver_style("1"), PkgverStyle::SingleNumber);
		assert_eq!(detect_pkgver_style("r123"), PkgverStyle::Other);
		assert_eq!(detect_pkgver_style("1.0.0_rc1"), PkgverStyle::Semver);
		assert_eq!(detect_pkgver_style("1.0.0.alpha"), PkgverStyle::Semver);
	}

	#[test]
	fn test_package_set() {
		struct PackageSetCase {
			name: &'static str,
			previous: &'static str,
			proposed: &'static str,
			risk: RiskLevel,
			modified: bool,
		}

		let cases = [
			PackageSetCase {
				name: "unchanged",
				previous: BASE_SRCINFO,
				proposed: BASE_SRCINFO,
				risk: RiskLevel::Low,
				modified: false,
			},
			PackageSetCase {
				name: "package_added",
				previous: BASE_SRCINFO,
				proposed: SPLIT_SRCINFO,
				risk: RiskLevel::High,
				modified: true,
			},
			PackageSetCase {
				name: "package_removed",
				previous: SPLIT_SRCINFO,
				proposed: BASE_SRCINFO,
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = Srcinfo::from_str(case.previous).unwrap();
			let proposed = Srcinfo::from_str(case.proposed).unwrap();
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::PackageSet, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_depends() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].depends = archvecs(vec!["glibc", "openssl"]),
				proposed: |s| s.pkgs[0].depends = archvecs(vec!["glibc", "openssl"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].depends = archvecs(vec!["glibc", "openssl"]),
				proposed: |s| s.pkgs[0].depends = archvecs(vec!["openssl", "glibc"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |s| s.pkgs[0].depends = archvecs(vec!["glibc"]),
				proposed: |s| s.pkgs[0].depends = archvecs(vec!["glibc", "openssl"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].depends = archvecs(vec!["glibc", "openssl"]),
				proposed: |s| s.pkgs[0].depends = archvecs(vec!["glibc"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Depends, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_makedepends() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.base.makedepends = archvecs(vec!["cmake", "python"]),
				proposed: |s| s.base.makedepends = archvecs(vec!["python", "cmake"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |s| s.base.makedepends = archvecs(vec!["cmake"]),
				proposed: |s| s.base.makedepends = archvecs(vec!["cmake", "python"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.base.makedepends = archvecs(vec!["cmake", "python"]),
				proposed: |s| s.base.makedepends = archvecs(vec!["cmake"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::MakeDepends, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_checkdepends() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.base.checkdepends = archvecs(vec!["check", "bats"]),
				proposed: |s| s.base.checkdepends = archvecs(vec!["bats", "check"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.base.checkdepends = archvecs(vec!["check"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::CheckDepends, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_valid_pgp_keys() {
		const FP_A: &str = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
		const FP_B: &str = "1111111111111111111111111111111111111111";

		struct ValidPgpKeysCase {
			name: &'static str,
			previous_keys: &'static [&'static str],
			proposed_keys: &'static [&'static str],
			risk: RiskLevel,
			modified: bool,
		}

		let cases = [
			ValidPgpKeysCase {
				name: "unchanged_empty",
				previous_keys: &[],
				proposed_keys: &[],
				risk: RiskLevel::Low,
				modified: false,
			},
			ValidPgpKeysCase {
				name: "unchanged_same",
				previous_keys: &[FP_A],
				proposed_keys: &[FP_A],
				risk: RiskLevel::Low,
				modified: false,
			},
			ValidPgpKeysCase {
				name: "reordered_no_change",
				previous_keys: &[FP_A, FP_B],
				proposed_keys: &[FP_B, FP_A],
				risk: RiskLevel::Low,
				modified: false,
			},
			ValidPgpKeysCase {
				name: "key_added",
				previous_keys: &[],
				proposed_keys: &[FP_A],
				risk: RiskLevel::High,
				modified: true,
			},
			ValidPgpKeysCase {
				name: "key_removed",
				previous_keys: &[FP_A],
				proposed_keys: &[],
				risk: RiskLevel::High,
				modified: true,
			},
			ValidPgpKeysCase {
				name: "key_replaced",
				previous_keys: &[FP_A],
				proposed_keys: &[FP_B],
				risk: RiskLevel::High,
				modified: true,
			},
			ValidPgpKeysCase {
				name: "key_added_to_existing",
				previous_keys: &[FP_A],
				proposed_keys: &[FP_A, FP_B],
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(|s| {
				s.base.valid_pgp_keys = case.previous_keys.iter().map(|k| k.to_string()).collect();
			});
			let proposed = with_modification(|s| {
				s.base.valid_pgp_keys = case.proposed_keys.iter().map(|k| k.to_string()).collect();
			});
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::ValidPgpKeys, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_no_extract() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_with_entries",
				previous: |s| s.base.no_extract = vec!["foo.zip".to_string()],
				proposed: |s| s.base.no_extract = vec!["foo.zip".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "entry_added",
				previous: |_| {},
				proposed: |s| s.base.no_extract = vec!["foo.zip".to_string()],
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "entry_removed",
				previous: |s| s.base.no_extract = vec!["foo.zip".to_string()],
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "entry_replaced",
				previous: |s| s.base.no_extract = vec!["foo.zip".to_string()],
				proposed: |s| s.base.no_extract = vec!["bar.zip".to_string()],
				risk: RiskLevel::Low,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::NoExtract, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_optdepends() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].optdepends = archvecs(vec!["foo: for foo", "bar: for bar"]),
				proposed: |s| s.pkgs[0].optdepends = archvecs(vec!["bar: for bar", "foo: for foo"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].optdepends = archvecs(vec!["foo: for foo"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::OptDepends, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_provides() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].provides = archvecs(vec!["libfoo", "libbar"]),
				proposed: |s| s.pkgs[0].provides = archvecs(vec!["libbar", "libfoo"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].provides = archvecs(vec!["libfoo"]),
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].provides = archvecs(vec!["libfoo"]),
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Provides, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_conflicts() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].conflicts = archvecs(vec!["foo", "bar"]),
				proposed: |s| s.pkgs[0].conflicts = archvecs(vec!["bar", "foo"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].conflicts = archvecs(vec!["foo"]),
				risk: RiskLevel::Medium,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Conflicts, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_replaces() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].replaces = archvecs(vec!["old-foo", "old-bar"]),
				proposed: |s| s.pkgs[0].replaces = archvecs(vec!["old-bar", "old-foo"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].replaces = archvecs(vec!["old-foo"]),
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].replaces = archvecs(vec!["old-foo"]),
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Replaces, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_pkgver() {
		struct PkgverCase {
			name: &'static str,
			previous: fn(&mut Srcinfo),
			proposed: fn(&mut Srcinfo),
			risk: RiskLevel,
			modified: bool,
		}

		let cases = [
			PkgverCase {
				name: "unchanged",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			PkgverCase {
				name: "normal_bump",
				previous: |_| {},
				proposed: |s| s.base.pkgver = "1.0.1".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "hyphen_invalid",
				previous: |_| {},
				proposed: |s| s.base.pkgver = "1.0.0-beta".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "space_invalid",
				previous: |_| {},
				proposed: |s| s.base.pkgver = "1.0 0".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "decrease",
				previous: |s| s.base.pkgver = "2.0.0".to_string(),
				proposed: |s| s.base.pkgver = "1.0.0".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "minor_decrease",
				previous: |s| s.base.pkgver = "1.5.0".to_string(),
				proposed: |s| s.base.pkgver = "1.4.9".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "date_bump",
				previous: |s| s.base.pkgver = "20260101".to_string(),
				proposed: |s| s.base.pkgver = "20260308".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "dotted_date_bump",
				previous: |s| s.base.pkgver = "2025.12.01".to_string(),
				proposed: |s| s.base.pkgver = "2026.03.08".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "underscore_valid",
				previous: |_| {},
				proposed: |s| s.base.pkgver = "1.0.0_rc1".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "two_segment_bump",
				previous: |s| s.base.pkgver = "3.13".to_string(),
				proposed: |s| s.base.pkgver = "3.14".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "two_segment_major_bump",
				previous: |s| s.base.pkgver = "3.14".to_string(),
				proposed: |s| s.base.pkgver = "4.0".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgverCase {
				name: "two_segment_decrease",
				previous: |s| s.base.pkgver = "3.14".to_string(),
				proposed: |s| s.base.pkgver = "3.13".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "two_segment_major_decrease",
				previous: |s| s.base.pkgver = "4.0".to_string(),
				proposed: |s| s.base.pkgver = "3.14".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "three_segment_major_bump",
				previous: |s| s.base.pkgver = "1.9.3".to_string(),
				proposed: |s| s.base.pkgver = "2.0.0".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgverCase {
				name: "three_segment_minor_bump_not_medium",
				previous: |s| s.base.pkgver = "1.9.3".to_string(),
				proposed: |s| s.base.pkgver = "1.10.0".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "date_major_bump_not_medium",
				previous: |s| s.base.pkgver = "2025.12.01".to_string(),
				proposed: |s| s.base.pkgver = "2026.03.08".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "other_style_increase",
				previous: |s| s.base.pkgver = "r123".to_string(),
				proposed: |s| s.base.pkgver = "r124".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "other_style_decrease",
				previous: |s| s.base.pkgver = "r124".to_string(),
				proposed: |s| s.base.pkgver = "r123".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "timestamp_bump",
				previous: |s| s.base.pkgver = "20250101".to_string(),
				proposed: |s| s.base.pkgver = "20260308".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "timestamp_decrease",
				previous: |s| s.base.pkgver = "20260308".to_string(),
				proposed: |s| s.base.pkgver = "20250101".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "single_number_bump",
				previous: |s| s.base.pkgver = "41".to_string(),
				proposed: |s| s.base.pkgver = "42".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgverCase {
				name: "single_number_decrease",
				previous: |s| s.base.pkgver = "42".to_string(),
				proposed: |s| s.base.pkgver = "41".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "style_change_semver_to_date",
				previous: |s| s.base.pkgver = "1.9.3".to_string(),
				proposed: |s| s.base.pkgver = "2026.03.08".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgverCase {
				name: "style_change_semver_to_timestamp",
				previous: |s| s.base.pkgver = "1.9.3".to_string(),
				proposed: |s| s.base.pkgver = "20260308".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgverCase {
				name: "style_change_semver_to_other",
				previous: |s| s.base.pkgver = "1.9.3".to_string(),
				proposed: |s| s.base.pkgver = "r200".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgverCase {
				name: "style_change_date_to_semver",
				previous: |s| s.base.pkgver = "2026.03.08".to_string(),
				proposed: |s| s.base.pkgver = "1.0.0".to_string(),
				// version also decreases, so High takes priority
				risk: RiskLevel::High,
				modified: true,
			},
			PkgverCase {
				name: "style_change_timestamp_to_semver",
				previous: |s| s.base.pkgver = "20260308".to_string(),
				proposed: |s| s.base.pkgver = "1.0.0".to_string(),
				// version also decreases, so High takes priority
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Pkgver, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_pkgrel() {
		struct PkgrelCase {
			name: &'static str,
			previous: fn(&mut Srcinfo),
			proposed: fn(&mut Srcinfo),
			risk: RiskLevel,
			modified: bool,
		}

		let cases = [
			PkgrelCase {
				name: "unchanged",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			PkgrelCase {
				name: "normal_increment",
				previous: |_| {},
				proposed: |s| s.base.pkgrel = "2".to_string(),
				risk: RiskLevel::Low,
				modified: true,
			},
			PkgrelCase {
				name: "zero_invalid",
				previous: |_| {},
				proposed: |s| s.base.pkgrel = "0".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgrelCase {
				name: "float_like",
				previous: |_| {},
				proposed: |s| s.base.pkgrel = "1.1".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgrelCase {
				name: "non_numeric",
				previous: |_| {},
				proposed: |s| s.base.pkgrel = "abc".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgrelCase {
				name: "negative",
				previous: |_| {},
				proposed: |s| s.base.pkgrel = "-1".to_string(),
				risk: RiskLevel::Medium,
				modified: true,
			},
			PkgrelCase {
				name: "decrease",
				previous: |s| s.base.pkgrel = "5".to_string(),
				proposed: |s| s.base.pkgrel = "2".to_string(),
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Pkgrel, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_unexplained_update() {
		struct UnexplainedCase {
			name: &'static str,
			previous: fn(&mut Srcinfo),
			proposed: fn(&mut Srcinfo),
			risk: RiskLevel,
			modified: bool,
		}

		let cases = [
			UnexplainedCase {
				name: "both_unchanged",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Medium,
				modified: true,
			},
			UnexplainedCase {
				name: "pkgver_changed",
				previous: |_| {},
				proposed: |s| s.base.pkgver = "1.0.1".to_string(),
				risk: RiskLevel::Low,
				modified: false,
			},
			UnexplainedCase {
				name: "pkgrel_changed",
				previous: |_| {},
				proposed: |s| s.base.pkgrel = "2".to_string(),
				risk: RiskLevel::Low,
				modified: false,
			},
			UnexplainedCase {
				name: "both_changed",
				previous: |_| {},
				proposed: |s| {
					s.base.pkgver = "2.0.0".to_string();
					s.base.pkgrel = "1".to_string();
				},
				risk: RiskLevel::Low,
				modified: false,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::UnexplainedUpdate, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_install() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_none",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].install = Some("pkg.install".to_string()),
				proposed: |s| s.pkgs[0].install = Some("pkg.install".to_string()),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].install = Some("pkg.install".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].install = Some("pkg.install".to_string()),
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].install = Some("old.install".to_string()),
				proposed: |s| s.pkgs[0].install = Some("new.install".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Install, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_url() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_none",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].url = Some("https://example.com".to_string()),
				proposed: |s| s.pkgs[0].url = Some("https://example.com".to_string()),
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].url = Some("https://example.com".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].url = Some("https://example.com".to_string()),
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].url = Some("https://example.com".to_string()),
				proposed: |s| s.pkgs[0].url = Some("https://other.com".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "invalid_url_unchanged",
				previous: |s| s.pkgs[0].url = Some("not-a-url".to_string()),
				proposed: |s| s.pkgs[0].url = Some("not-a-url".to_string()),
				risk: RiskLevel::High,
				modified: false,
			},
			ArrayFieldCase {
				name: "invalid_url_changed",
				previous: |s| s.pkgs[0].url = Some("https://example.com".to_string()),
				proposed: |s| s.pkgs[0].url = Some("not-a-url".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "no_scheme_slashes",
				previous: |_| {},
				proposed: |s| s.pkgs[0].url = Some("example.com".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Url, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_pkgdesc() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].pkgdesc = Some("Old description".to_string()),
				proposed: |s| s.pkgs[0].pkgdesc = Some("New description".to_string()),
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "added",
				previous: |s| s.pkgs[0].pkgdesc = None,
				proposed: |s| s.pkgs[0].pkgdesc = Some("New description".to_string()),
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].pkgdesc = Some("Old description".to_string()),
				proposed: |s| s.pkgs[0].pkgdesc = None,
				risk: RiskLevel::Low,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Pkgdesc, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_changelog() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_none",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].changelog = Some("ChangeLog".to_string()),
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].changelog = Some("ChangeLog".to_string()),
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].changelog = Some("ChangeLog".to_string()),
				proposed: |s| s.pkgs[0].changelog = Some("CHANGES".to_string()),
				risk: RiskLevel::Low,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Changelog, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_arch() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].arch = vec!["x86_64".to_string()],
				proposed: |s| s.pkgs[0].arch = vec!["x86_64".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].arch = vec!["x86_64".to_string(), "aarch64".to_string()],
				proposed: |s| s.pkgs[0].arch = vec!["aarch64".to_string(), "x86_64".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |s| s.pkgs[0].arch = vec!["x86_64".to_string()],
				proposed: |s| s.pkgs[0].arch = vec!["x86_64".to_string(), "aarch64".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].arch = vec!["x86_64".to_string(), "aarch64".to_string()],
				proposed: |s| s.pkgs[0].arch = vec!["x86_64".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].arch = vec!["x86_64".to_string()],
				proposed: |s| s.pkgs[0].arch = vec!["aarch64".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Arch, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_license() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].license = vec!["MIT".to_string()],
				proposed: |s| s.pkgs[0].license = vec!["MIT".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].license = vec!["MIT".to_string(), "Apache-2.0".to_string()],
				proposed: |s| s.pkgs[0].license = vec!["Apache-2.0".to_string(), "MIT".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |s| s.pkgs[0].license = vec!["MIT".to_string()],
				proposed: |s| s.pkgs[0].license = vec!["MIT".to_string(), "Apache-2.0".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].license = vec!["MIT".to_string(), "Apache-2.0".to_string()],
				proposed: |s| s.pkgs[0].license = vec!["MIT".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].license = vec!["MIT".to_string()],
				proposed: |s| s.pkgs[0].license = vec!["GPL-3.0".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::License, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_groups() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].groups = vec!["base-devel".to_string()],
				proposed: |s| s.pkgs[0].groups = vec!["base-devel".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| {
					s.pkgs[0].groups = vec!["base-devel".to_string(), "extra".to_string()]
				},
				proposed: |s| {
					s.pkgs[0].groups = vec!["extra".to_string(), "base-devel".to_string()]
				},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].groups = vec!["base-devel".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].groups = vec!["base-devel".to_string()],
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].groups = vec!["base-devel".to_string()],
				proposed: |s| s.pkgs[0].groups = vec!["extra".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Groups, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_backup() {
		let cases = [
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()],
				proposed: |s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| {
					s.pkgs[0].backup = vec!["etc/foo.conf".to_string(), "etc/bar.conf".to_string()]
				},
				proposed: |s| {
					s.pkgs[0].backup = vec!["etc/bar.conf".to_string(), "etc/foo.conf".to_string()]
				},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()],
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "removed",
				previous: |s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()],
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "changed",
				previous: |s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()],
				proposed: |s| s.pkgs[0].backup = vec!["etc/bar.conf".to_string()],
				risk: RiskLevel::Low,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Backup, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}

		// Verify description contains diff details when modified
		let previous = with_modification(|s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()]);
		let proposed = with_modification(|s| s.pkgs[0].backup = vec!["etc/bar.conf".to_string()]);
		let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
		let eval = find_eval(&evals, EvaluationName::Backup, "example");
		assert!(
			eval.description.contains("etc/bar.conf") && eval.description.contains("etc/foo.conf"),
			"description should mention both added and removed paths, got: {}",
			eval.description
		);
	}

	#[test]
	fn test_options() {
		let cases = [
			// Unchanged
			ArrayFieldCase {
				name: "unchanged_empty",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "unchanged_same",
				previous: |s| s.pkgs[0].options = vec!["strip".to_string(), "docs".to_string()],
				proposed: |s| s.pkgs[0].options = vec!["strip".to_string(), "docs".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			ArrayFieldCase {
				name: "reordered_no_change",
				previous: |s| s.pkgs[0].options = vec!["strip".to_string(), "docs".to_string()],
				proposed: |s| s.pkgs[0].options = vec!["docs".to_string(), "strip".to_string()],
				risk: RiskLevel::Low,
				modified: false,
			},
			// Low-risk changes
			ArrayFieldCase {
				name: "add_low_risk",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["!strip".to_string()],
				risk: RiskLevel::Low,
				modified: true,
			},
			ArrayFieldCase {
				name: "remove_low_risk",
				previous: |s| s.pkgs[0].options = vec!["zipman".to_string()],
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: true,
			},
			// Medium-risk changes
			ArrayFieldCase {
				name: "add_lto",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["lto".to_string()],
				risk: RiskLevel::Medium,
				modified: true,
			},
			ArrayFieldCase {
				name: "add_debug",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["debug".to_string()],
				risk: RiskLevel::Medium,
				modified: true,
			},
			ArrayFieldCase {
				name: "add_emptydirs",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["emptydirs".to_string()],
				risk: RiskLevel::Medium,
				modified: true,
			},
			ArrayFieldCase {
				name: "add_negated_medium",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["!lto".to_string()],
				risk: RiskLevel::Medium,
				modified: true,
			},
			// High-risk changes
			ArrayFieldCase {
				name: "add_buildflags",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["buildflags".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "add_negated_buildflags",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["!buildflags".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "add_makeflags",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["makeflags".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "add_staticlibs",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["staticlibs".to_string()],
				risk: RiskLevel::High,
				modified: true,
			},
			// Max-risk wins when multiple options change
			ArrayFieldCase {
				name: "mixed_low_and_high",
				previous: |_| {},
				proposed: |s| {
					s.pkgs[0].options = vec!["!strip".to_string(), "!buildflags".to_string()]
				},
				risk: RiskLevel::High,
				modified: true,
			},
			ArrayFieldCase {
				name: "mixed_low_and_medium",
				previous: |_| {},
				proposed: |s| s.pkgs[0].options = vec!["docs".to_string(), "lto".to_string()],
				risk: RiskLevel::Medium,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::Options, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}

		// Description lists all changed options
		let previous =
			with_modification(|s| s.pkgs[0].options = vec!["lto".to_string(), "strip".to_string()]);
		let proposed = with_modification(|s| {
			s.pkgs[0].options = vec!["strip".to_string(), "!buildflags".to_string()]
		});
		let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
		let eval = find_eval(&evals, EvaluationName::Options, "example");
		assert!(
			eval.description.contains("!buildflags") && eval.description.contains("lto"),
			"description should mention added '!buildflags' and removed 'lto', got: {}",
			eval.description
		);
	}

	#[test]
	fn test_insecure_checksum() {
		struct InsecureChecksumCase {
			name: &'static str,
			previous: fn(&mut Srcinfo),
			proposed: fn(&mut Srcinfo),
			risk: RiskLevel,
			modified: bool,
		}

		let cases = [
			InsecureChecksumCase {
				name: "no_checksums",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			InsecureChecksumCase {
				name: "skip_only_not_insecure",
				previous: |_| {},
				proposed: |s| s.base.md5sums = archvecs(vec!["SKIP"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			InsecureChecksumCase {
				name: "md5_introduced",
				previous: |_| {},
				proposed: |s| s.base.md5sums = archvecs(vec!["d41d8cd98f00b204e9800998ecf8427e"]),
				risk: RiskLevel::High,
				modified: true,
			},
			InsecureChecksumCase {
				name: "sha1_introduced",
				previous: |_| {},
				proposed: |s| {
					s.base.sha1sums = archvecs(vec!["da39a3ee5e6b4b0d3255bfef95601890afd80709"])
				},
				risk: RiskLevel::High,
				modified: true,
			},
			InsecureChecksumCase {
				name: "md5_unchanged",
				previous: |s| s.base.md5sums = archvecs(vec!["d41d8cd98f00b204e9800998ecf8427e"]),
				proposed: |s| s.base.md5sums = archvecs(vec!["d41d8cd98f00b204e9800998ecf8427e"]),
				risk: RiskLevel::High,
				modified: false,
			},
			InsecureChecksumCase {
				name: "md5_removed",
				previous: |s| s.base.md5sums = archvecs(vec!["d41d8cd98f00b204e9800998ecf8427e"]),
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: true,
			},
			InsecureChecksumCase {
				name: "md5_replaced_with_skip",
				previous: |s| s.base.md5sums = archvecs(vec!["d41d8cd98f00b204e9800998ecf8427e"]),
				proposed: |s| s.base.md5sums = archvecs(vec!["SKIP"]),
				risk: RiskLevel::Low,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::InsecureChecksum, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_checksum_consistency() {
		struct ConsistencyCase {
			name: &'static str,
			previous: fn(&mut Srcinfo),
			proposed: fn(&mut Srcinfo),
			risk: RiskLevel,
			modified: bool,
			description_contains: Option<&'static str>,
		}

		let cases = [
			ConsistencyCase {
				name: "no_checksums",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "single_type_only",
				previous: |s| s.base.sha256sums = archvecs(vec!["aaaa"]),
				proposed: |s| s.base.sha256sums = archvecs(vec!["aaaa"]),
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "two_types_same_length_no_skip",
				previous: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "bbbb"]);
					s.base.sha512sums = archvecs(vec!["cccc", "dddd"]);
				},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "bbbb"]);
					s.base.sha512sums = archvecs(vec!["cccc", "dddd"]);
				},
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "two_types_skip_at_same_index",
				previous: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "SKIP"]);
					s.base.sha512sums = archvecs(vec!["cccc", "SKIP"]);
				},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "SKIP"]);
					s.base.sha512sums = archvecs(vec!["cccc", "SKIP"]);
				},
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "length_mismatch",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					s.base.sha512sums = archvecs(vec!["cccc", "dddd"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: None,
			},
			ConsistencyCase {
				name: "skip_mismatch_at_index_0",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					s.base.sha512sums = archvecs(vec!["SKIP"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: None,
			},
			ConsistencyCase {
				name: "skip_mismatch_at_index_1",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "SKIP"]);
					s.base.sha512sums = archvecs(vec!["cccc", "dddd"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: None,
			},
			ConsistencyCase {
				name: "skip_mismatch_reversed",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "bbbb"]);
					s.base.sha512sums = archvecs(vec!["SKIP", "dddd"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: None,
			},
			ConsistencyCase {
				name: "unchanged_inconsistency",
				previous: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					s.base.sha512sums = archvecs(vec!["SKIP"]);
				},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					s.base.sha512sums = archvecs(vec!["SKIP"]);
				},
				risk: RiskLevel::High,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "inconsistency_fixed",
				previous: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					s.base.sha512sums = archvecs(vec!["SKIP"]);
				},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					s.base.sha512sums = archvecs(vec!["cccc"]);
				},
				risk: RiskLevel::Low,
				modified: true,
				description_contains: None,
			},
			ConsistencyCase {
				name: "all_skip_consistent",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["SKIP"]);
					s.base.sha512sums = archvecs(vec!["SKIP"]);
				},
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "three_types_one_length_mismatch",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs(vec!["aaaa", "bbbb"]);
					s.base.sha512sums = archvecs(vec!["cccc", "dddd"]);
					s.base.b2sums = archvecs(vec!["eeee"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: None,
			},
			// ---- arch-specific cases -------------------------------------------
			ConsistencyCase {
				name: "arch_specific_two_types_consistent",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs_for("x86_64", vec!["aaaa", "bbbb"]);
					s.base.sha512sums = archvecs_for("x86_64", vec!["cccc", "dddd"]);
				},
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			ConsistencyCase {
				name: "arch_specific_length_mismatch",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs_for("x86_64", vec!["aaaa"]);
					s.base.sha512sums = archvecs_for("x86_64", vec!["cccc", "dddd"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
			ConsistencyCase {
				name: "arch_specific_skip_mismatch",
				previous: |_| {},
				proposed: |s| {
					s.base.sha256sums = archvecs_for("x86_64", vec!["aaaa"]);
					s.base.sha512sums = archvecs_for("x86_64", vec!["SKIP"]);
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
			ConsistencyCase {
				name: "generic_ok_arch_specific_inconsistent",
				previous: |_| {},
				proposed: |s| {
					// Generic arch: only sha256sums present, no comparison possible.
					s.base.sha256sums = archvecs(vec!["aaaa"]);
					// x86_64: sha256 and sha512 have a length mismatch.
					s.base.sha512sums = archvecs_for("x86_64", vec!["cccc", "dddd"]);
					s.base.sha256sums = vec![
						pkg_archvec(vec!["aaaa"]),
						pkg_archvec_for("x86_64", vec!["eeee"]),
					]
					.into();
				},
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::ChecksumConsistency, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
			if let Some(expected) = case.description_contains {
				assert!(
					eval.description.contains(expected),
					"case: {} — expected description to contain {:?}, got: {:?}",
					case.name,
					expected,
					eval.description,
				);
			}
		}
	}

	#[test]
	fn test_source() {
		let github_archive = Regex::new(
			r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/archive/v?(?P<version>[^/]+)\.tar\.gz",
		)
		.unwrap();
		let github_release =
			Regex::new(r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/releases/download/v?(?P<version>[^/]+)/[^/]+")
				.unwrap();
		let trust_all = Regex::new(r"https://trusted-mirror\.example\.com/.+").unwrap();

		// Helper: build srcinfo with specific pkgver and source entries.
		let make = |pkgver: &str, sources: &[&str]| {
			let mut s = parse_base();
			s.base.pkgver = pkgver.to_string();
			s.base.source = archvecs(sources.to_vec());
			s
		};

		// Workaround: closures capturing locals can't be fn pointers, so we use
		// a direct loop instead of the struct-based pattern used elsewhere.

		struct SourceCase<'a> {
			name: &'a str,
			prev_pkgver: &'a str,
			prev_sources: &'a [&'a str],
			new_pkgver: &'a str,
			new_sources: &'a [&'a str],
			patterns: &'a [Regex],
			risk: RiskLevel,
			modified: bool,
		}

		let gh_archive = std::slice::from_ref(&github_archive);
		let _gh_release = std::slice::from_ref(&github_release);
		let trust = std::slice::from_ref(&trust_all);
		let all_patterns = &[github_archive.clone(), github_release.clone()][..];

		let cases: &[SourceCase] = &[
			SourceCase {
				name: "no_sources_unchanged",
				prev_pkgver: "1.0.0",
				prev_sources: &[],
				new_pkgver: "1.0.0",
				new_sources: &[],
				patterns: &[],
				risk: RiskLevel::Low,
				modified: false,
			},
			SourceCase {
				name: "sources_identical",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				new_pkgver: "1.0.0",
				new_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::Low,
				modified: false,
			},
			SourceCase {
				name: "count_increased",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &[
					"https://github.com/foo/bar/archive/v2.0.0.tar.gz",
					"https://github.com/foo/bar/archive/v2.0.0-extra.tar.gz",
				],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "count_decreased",
				prev_pkgver: "1.0.0",
				prev_sources: &[
					"https://github.com/foo/bar/archive/v1.0.0.tar.gz",
					"https://github.com/foo/bar/archive/v1.0.0-extra.tar.gz",
				],
				new_pkgver: "2.0.0",
				new_sources: &["https://github.com/foo/bar/archive/v2.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "version_bump_matches_pkgver",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &["https://github.com/foo/bar/archive/v2.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::Low,
				modified: true,
			},
			SourceCase {
				name: "version_does_not_match_pkgver",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &["https://github.com/foo/bar/archive/v3.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "repo_changed",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &["https://github.com/foo/other/archive/v2.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "owner_changed",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &["https://github.com/attacker/bar/archive/v2.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "no_pattern_matches",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://example.com/custom/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &["https://example.com/custom/v2.0.0.tar.gz"],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "trust_all_pattern_no_version_group",
				prev_pkgver: "1.0.0",
				prev_sources: &["https://trusted-mirror.example.com/v1.0.0.tar.gz"],
				new_pkgver: "2.0.0",
				new_sources: &["https://trusted-mirror.example.com/v2.0.0.tar.gz"],
				patterns: trust,
				risk: RiskLevel::Low,
				modified: true,
			},
			SourceCase {
				name: "multiple_sources_all_consistent",
				prev_pkgver: "1.0.0",
				prev_sources: &[
					"https://github.com/foo/bar/archive/v1.0.0.tar.gz",
					"https://github.com/foo/bar/releases/download/v1.0.0/bar-1.0.0.tar.gz",
				],
				new_pkgver: "2.0.0",
				new_sources: &[
					"https://github.com/foo/bar/archive/v2.0.0.tar.gz",
					"https://github.com/foo/bar/releases/download/v2.0.0/bar-2.0.0.tar.gz",
				],
				patterns: all_patterns,
				risk: RiskLevel::Low,
				modified: true,
			},
			SourceCase {
				name: "multiple_sources_one_inconsistent",
				prev_pkgver: "1.0.0",
				prev_sources: &[
					"https://github.com/foo/bar/archive/v1.0.0.tar.gz",
					"https://example.com/patch.diff",
				],
				new_pkgver: "2.0.0",
				new_sources: &[
					"https://github.com/foo/bar/archive/v2.0.0.tar.gz",
					"https://evil.example.com/patch.diff",
				],
				patterns: gh_archive,
				risk: RiskLevel::High,
				modified: true,
			},
			SourceCase {
				name: "name_prefix_stripped_before_matching",
				prev_pkgver: "1.0.0",
				prev_sources: &[
					"bar-1.0.0.tar.gz::https://github.com/foo/bar/archive/v1.0.0.tar.gz",
				],
				new_pkgver: "2.0.0",
				new_sources: &[
					"bar-2.0.0.tar.gz::https://github.com/foo/bar/archive/v2.0.0.tar.gz",
				],
				patterns: gh_archive,
				risk: RiskLevel::Low,
				modified: true,
			},
		];

		for case in cases {
			let previous = make(case.prev_pkgver, case.prev_sources);
			let proposed = make(case.new_pkgver, case.new_sources);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, case.patterns);
			let eval = find_eval(&evals, EvaluationName::Source, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	#[test]
	fn test_source_arch_specific() {
		let github_archive = Regex::new(
			r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/archive/v?(?P<version>[^/]+)\.tar\.gz",
		)
		.unwrap();

		// Helper: build srcinfo with arch-specific source entries.
		let make_arch = |pkgver: &str, arch: &str, sources: &[&str]| {
			let mut s = parse_base();
			s.base.pkgver = pkgver.to_string();
			s.base.source = archvecs_for(arch, sources.to_vec());
			s
		};

		struct ArchSourceCase<'a> {
			name: &'a str,
			prev: Srcinfo,
			proposed: Srcinfo,
			patterns: &'a [Regex],
			risk: RiskLevel,
			modified: bool,
			description_contains: Option<&'a str>,
		}

		let gh = std::slice::from_ref(&github_archive);

		let cases = [
			// Arch-specific source unchanged — no risk, not modified.
			ArchSourceCase {
				name: "arch_source_unchanged",
				prev: make_arch(
					"1.0.0",
					"x86_64",
					&["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				),
				proposed: make_arch(
					"1.0.0",
					"x86_64",
					&["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				),
				patterns: gh,
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			// Arch-specific source count increases — high risk with arch label.
			ArchSourceCase {
				name: "arch_source_count_increased",
				prev: make_arch("1.0.0", "x86_64", &[]),
				proposed: make_arch(
					"2.0.0",
					"x86_64",
					&["https://github.com/foo/bar/archive/v2.0.0.tar.gz"],
				),
				patterns: gh,
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
			// Arch-specific version bump matches pkgver and pattern — low risk.
			ArchSourceCase {
				name: "arch_source_version_bump_matches",
				prev: make_arch(
					"1.0.0",
					"x86_64",
					&["https://github.com/foo/bar/archive/v1.0.0.tar.gz"],
				),
				proposed: make_arch(
					"2.0.0",
					"x86_64",
					&["https://github.com/foo/bar/archive/v2.0.0.tar.gz"],
				),
				patterns: gh,
				risk: RiskLevel::Low,
				modified: true,
				description_contains: None,
			},
			// Arch-specific URL changed but no pattern matches — high risk with arch label.
			ArchSourceCase {
				name: "arch_source_no_pattern_match",
				prev: make_arch(
					"1.0.0",
					"x86_64",
					&["https://example.com/custom/v1.0.0.tar.gz"],
				),
				proposed: make_arch(
					"2.0.0",
					"x86_64",
					&["https://example.com/custom/v2.0.0.tar.gz"],
				),
				patterns: gh,
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
		];

		for case in &cases {
			let evals = evaluate_srcinfo_diff(&case.prev, &case.proposed, case.patterns);
			let eval = find_eval(&evals, EvaluationName::Source, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
			if let Some(expected) = case.description_contains {
				assert!(
					eval.description.contains(expected),
					"case: {} — expected description to contain {:?}, got: {:?}",
					case.name,
					expected,
					eval.description,
				);
			}
		}
	}

	/// Build a Srcinfo with a specific source list and a parallel sha256sums
	/// list.  Pass `None` for `checksums` to omit the checksum field entirely.
	fn make_with_checksums(sources: &[&str], checksums: Option<&[&str]>) -> Srcinfo {
		let mut s = parse_base();
		s.base.source = if sources.is_empty() {
			srcinfo::ArchVecs::default()
		} else {
			archvecs(sources.to_vec())
		};
		s.base.sha256sums = match checksums {
			None => srcinfo::ArchVecs::default(),
			Some(cs) => archvecs(cs.to_vec()),
		};
		s
	}

	#[test]
	fn test_checksum_skip() {
		struct Case<'a> {
			name: &'a str,
			prev_sources: &'a [&'a str],
			prev_checksums: Option<&'a [&'a str]>,
			new_sources: &'a [&'a str],
			new_checksums: Option<&'a [&'a str]>,
			risk: RiskLevel,
			modified: bool,
		}

		let cases: &[Case] = &[
			// ---- baseline / clean cases ----------------------------------------
			Case {
				name: "no_sources",
				prev_sources: &[],
				prev_checksums: None,
				new_sources: &[],
				new_checksums: None,
				risk: RiskLevel::Low,
				modified: false,
			},
			Case {
				name: "remote_real_checksum_unchanged",
				prev_sources: &["https://example.com/foo-1.0.tar.gz"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &["https://example.com/foo-1.0.tar.gz"],
				new_checksums: Some(&["abc123"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			Case {
				name: "local_file_real_checksum_unchanged",
				prev_sources: &["my-patch.patch"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &["my-patch.patch"],
				new_checksums: Some(&["abc123"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			// ---- local file issues ---------------------------------------------
			// Local file with SKIP — newly introduced.
			Case {
				name: "local_file_skip_introduced",
				prev_sources: &[],
				prev_checksums: None,
				new_sources: &["my-patch.patch"],
				new_checksums: Some(&["SKIP"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// Same local file already had SKIP in the previously accepted version.
			Case {
				name: "local_file_skip_unchanged",
				prev_sources: &["my-patch.patch"],
				prev_checksums: Some(&["SKIP"]),
				new_sources: &["my-patch.patch"],
				new_checksums: Some(&["SKIP"]),
				risk: RiskLevel::High,
				modified: false,
			},
			// Local file with no checksum array at all (absent ≡ SKIP for local).
			Case {
				name: "local_file_no_checksum_array",
				prev_sources: &[],
				prev_checksums: None,
				new_sources: &["my-patch.patch"],
				new_checksums: None,
				risk: RiskLevel::High,
				modified: true,
			},
			// Local file with `localname::` prefix and SKIP.
			Case {
				name: "local_file_with_prefix_skip",
				prev_sources: &[],
				prev_checksums: None,
				new_sources: &["renamed.patch::my-patch.patch"],
				new_checksums: Some(&["SKIP"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// Local file checksum changed — potential tamper.
			Case {
				name: "local_file_checksum_changed",
				prev_sources: &["my-patch.patch"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &["my-patch.patch"],
				new_checksums: Some(&["def456"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// Local SKIP was fixed → now low risk but marked as modified.
			Case {
				name: "local_file_skip_fixed",
				prev_sources: &["my-patch.patch"],
				prev_checksums: Some(&["SKIP"]),
				new_sources: &["my-patch.patch"],
				new_checksums: Some(&["abc123"]),
				risk: RiskLevel::Low,
				modified: true,
			},
			// Mixed: remote OK, local SKIP — the local issue is caught.
			Case {
				name: "mixed_remote_ok_local_skip",
				prev_sources: &[],
				prev_checksums: None,
				new_sources: &["https://example.com/foo.tar.gz", "my-patch.patch"],
				new_checksums: Some(&["abc123", "SKIP"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// ---- remote SKIP issues --------------------------------------------
			// Remote source had a real checksum, now SKIP.
			Case {
				name: "remote_real_to_skip",
				prev_sources: &["https://example.com/foo-1.0.tar.gz"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &["https://example.com/foo-2.0.tar.gz"],
				new_checksums: Some(&["SKIP"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// New remote source (count increased) with SKIP.
			Case {
				name: "new_remote_source_with_skip",
				prev_sources: &["https://example.com/foo-1.0.tar.gz"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &[
					"https://example.com/foo-1.0.tar.gz",
					"https://example.com/extra.tar.gz",
				],
				new_checksums: Some(&["abc123", "SKIP"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// Remote with `localname::` prefix: real → SKIP.
			Case {
				name: "remote_with_prefix_real_to_skip",
				prev_sources: &["foo-1.0.tar.gz::https://example.com/foo-1.0.tar.gz"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &["foo-2.0.tar.gz::https://example.com/foo-2.0.tar.gz"],
				new_checksums: Some(&["SKIP"]),
				risk: RiskLevel::High,
				modified: true,
			},
			// Remote already SKIP in prev, still SKIP — no regression.
			Case {
				name: "remote_skip_unchanged",
				prev_sources: &["https://example.com/foo.tar.gz"],
				prev_checksums: Some(&["SKIP"]),
				new_sources: &["https://example.com/foo.tar.gz"],
				new_checksums: Some(&["SKIP"]),
				risk: RiskLevel::Low,
				modified: false,
			},
			// Remote SKIP fixed → low risk, modified.
			Case {
				name: "remote_skip_fixed",
				prev_sources: &["https://example.com/foo.tar.gz"],
				prev_checksums: Some(&["SKIP"]),
				new_sources: &["https://example.com/foo.tar.gz"],
				new_checksums: Some(&["abc123"]),
				risk: RiskLevel::Low,
				modified: true,
			},
			// Absent checksum array on a remote source is NOT treated as SKIP.
			Case {
				name: "remote_absent_checksum_not_flagged",
				prev_sources: &["https://example.com/foo-1.0.tar.gz"],
				prev_checksums: Some(&["abc123"]),
				new_sources: &["https://example.com/foo-2.0.tar.gz"],
				new_checksums: None,
				risk: RiskLevel::Low,
				modified: false,
			},
		];

		for case in cases {
			let previous = make_with_checksums(case.prev_sources, case.prev_checksums);
			let proposed = make_with_checksums(case.new_sources, case.new_checksums);
			let evals = evaluate_srcinfo_diff(&previous, &proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::ChecksumSkip, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}

	/// Build a Srcinfo with arch-specific sources and sha256sums.
	/// Pass `None` for `checksums` to omit the checksum field entirely.
	fn make_arch_with_checksums(
		arch: &str,
		sources: &[&str],
		checksums: Option<&[&str]>,
	) -> Srcinfo {
		let mut s = parse_base();
		s.base.source = if sources.is_empty() {
			srcinfo::ArchVecs::default()
		} else {
			archvecs_for(arch, sources.to_vec())
		};
		s.base.sha256sums = match checksums {
			None => srcinfo::ArchVecs::default(),
			Some(cs) => archvecs_for(arch, cs.to_vec()),
		};
		s
	}

	#[test]
	fn test_checksum_skip_arch_specific() {
		struct Case<'a> {
			name: &'a str,
			prev: Srcinfo,
			proposed: Srcinfo,
			risk: RiskLevel,
			modified: bool,
			description_contains: Option<&'a str>,
		}

		let cases = [
			// Arch-specific remote source with a real checksum — no issue.
			Case {
				name: "arch_remote_real_checksum_ok",
				prev: make_arch_with_checksums(
					"x86_64",
					&["https://example.com/foo-1.0.tar.gz"],
					Some(&["abc123"]),
				),
				proposed: make_arch_with_checksums(
					"x86_64",
					&["https://example.com/foo-1.0.tar.gz"],
					Some(&["abc123"]),
				),
				risk: RiskLevel::Low,
				modified: false,
				description_contains: None,
			},
			// Arch-specific local file with SKIP — flagged with arch label.
			Case {
				name: "arch_local_skip_introduced",
				prev: make_arch_with_checksums("x86_64", &[], None),
				proposed: make_arch_with_checksums("x86_64", &["my-patch.patch"], Some(&["SKIP"])),
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
			// Arch-specific remote source had real checksum, now SKIP — flagged with arch label.
			Case {
				name: "arch_remote_real_to_skip",
				prev: make_arch_with_checksums(
					"x86_64",
					&["https://example.com/foo-1.0.tar.gz"],
					Some(&["abc123"]),
				),
				proposed: make_arch_with_checksums(
					"x86_64",
					&["https://example.com/foo-2.0.tar.gz"],
					Some(&["SKIP"]),
				),
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
			// Arch-specific new remote source with SKIP — flagged with arch label.
			Case {
				name: "arch_new_remote_source_with_skip",
				prev: make_arch_with_checksums("x86_64", &[], None),
				proposed: make_arch_with_checksums(
					"x86_64",
					&["https://example.com/foo.tar.gz"],
					Some(&["SKIP"]),
				),
				risk: RiskLevel::High,
				modified: true,
				description_contains: Some("(arch=x86_64)"),
			},
		];

		for case in &cases {
			let evals = evaluate_srcinfo_diff(&case.prev, &case.proposed, &[]);
			let eval = find_eval(&evals, EvaluationName::ChecksumSkip, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
			if let Some(expected) = case.description_contains {
				assert!(
					eval.description.contains(expected),
					"case: {} — expected description to contain {:?}, got: {:?}",
					case.name,
					expected,
					eval.description,
				);
			}
		}
	}
}
