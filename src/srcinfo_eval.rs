use std::collections::{HashMap, HashSet};

use srcinfo::{Package, Srcinfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
	Low,
	#[allow(dead_code)]
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
		evaluate_package_set(previous, proposed, pkgbase),
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
}
