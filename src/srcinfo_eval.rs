use std::collections::{HashMap, HashSet};

use srcinfo::{Package, Srcinfo};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
	Low,
	Medium,
	High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationName {
	Epoch,
	PackageSet,
	CheckDepends,
	MakeDepends,
	Depends,
	OptDepends,
	Provides,
	Conflicts,
	Replaces,
	Pkgver,
	Pkgrel,
	UnexplainedUpdate,
	Install,
	Url,
	Pkgdesc,
	Changelog,
	Arch,
	License,
	Groups,
	Backup,
	Options,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
	pub name: EvaluationName,
	pub pkgname: String,
	pub description: String,
	pub risk: RiskLevel,
	pub modified: bool,
}

pub fn evaluate_srcinfo_diff(previous: &Srcinfo, proposed: &Srcinfo) -> Vec<Evaluation> {
	let pkgbase = previous.base.pkgbase.clone();
	let mut evals = vec![
		evaluate_epoch(previous, proposed, pkgbase.clone()),
		evaluate_makedepends(previous, proposed, pkgbase.clone()),
		evaluate_checkdepends(previous, proposed, pkgbase.clone()),
		evaluate_package_set(previous, proposed, pkgbase.clone()),
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
\tmd5sums = SKIP

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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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

	const SPLIT_SRCINFO: &str = "\
pkgbase = example
\tpkgdesc = An example package
\tpkgver = 1.0.0
\tpkgrel = 1
\tarch = x86_64
\tmd5sums = SKIP

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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
			let eval = find_eval(&evals, EvaluationName::CheckDepends, "example");
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
			let eval = find_eval(&evals, EvaluationName::Backup, "example");
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}

		// Verify description contains diff details when modified
		let previous = with_modification(|s| s.pkgs[0].backup = vec!["etc/foo.conf".to_string()]);
		let proposed = with_modification(|s| s.pkgs[0].backup = vec!["etc/bar.conf".to_string()]);
		let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
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
		let evals = evaluate_srcinfo_diff(&previous, &proposed);
		let eval = find_eval(&evals, EvaluationName::Options, "example");
		assert!(
			eval.description.contains("!buildflags") && eval.description.contains("lto"),
			"description should mention added '!buildflags' and removed 'lto', got: {}",
			eval.description
		);
	}
}
