use crate::config::RuaConfig;
use crate::evaluation::{Evaluation, RiskLevel};
use crate::git_utils;
use crate::pkgbuild_eval;
use crate::rua_paths::RuaPaths;
use crate::srcinfo_eval;
use crate::terminal_util;
use crate::wrapped;
use colored::Colorize;
use srcinfo::Srcinfo;
use std::path::Path;
use std::str::FromStr;

/// How auto-merge should behave for a run.
pub enum AutoMergeMode {
	/// Auto-merge is disabled (`--no-auto-merge`).
	Disabled,
	/// Auto-merge is enabled with the given threshold. Config `auto_merge = false`
	/// entries are respected.
	Enabled(RiskLevel),
	/// Auto-merge is force-enabled (`--auto-merge`): config `auto_merge = false`
	/// entries are ignored. Overrides both per-package and any future global config.
	Forced(RiskLevel),
}

enum SrcinfoValidation {
	Matches,
	Mismatch,
	GenerationFailed(String),
}

fn validate_upstream_srcinfo(
	upstream_srcinfo: &Srcinfo,
	upstream_pkgbuild: &str,
) -> SrcinfoValidation {
	let tmp_dir = tempfile::TempDir::new().expect("Failed to create temp directory");

	let pkgbuild_path = tmp_dir.path().join("PKGBUILD");
	std::fs::write(&pkgbuild_path, upstream_pkgbuild)
		.expect("Failed to write PKGBUILD to temp directory");

	let tmp_dir_str = tmp_dir
		.path()
		.to_str()
		.expect("Temp directory path is not valid UTF-8");

	let generated_srcinfo = match wrapped::generate_srcinfo(tmp_dir_str) {
		Ok(s) => s,
		Err(e) => return SrcinfoValidation::GenerationFailed(e),
	};

	if *upstream_srcinfo == generated_srcinfo {
		SrcinfoValidation::Matches
	} else {
		SrcinfoValidation::Mismatch
	}
}

fn print_evaluation(eval: &Evaluation, passes: bool, cli_threshold: RiskLevel) {
	let risk_str = format!("{:?}", eval.risk).to_uppercase();
	let modified_str = if eval.modified { " MODIFIED" } else { "" };

	if !passes {
		eprintln!(
			"  [{}{}] {}/{:?}: {}",
			risk_str.red(),
			modified_str.red(),
			eval.pkgname,
			eval.name,
			eval.description,
		);
	} else if eval.risk >= cli_threshold {
		eprintln!(
			"  [{}{}] {}/{:?}: {}",
			risk_str.yellow(),
			modified_str.yellow(),
			eval.pkgname,
			eval.name,
			eval.description,
		);
	} else {
		eprintln!(
			"  [{}{}] {}/{:?}: {}",
			risk_str, modified_str, eval.pkgname, eval.name, eval.description,
		);
	}
}

/// Returns `true` if `eval` is within the allowed risk threshold for `pkgbase`.
///
/// Resolution order (first match wins):
/// 1. `packages.<pkgbase>.evaluations.<name>.threshold`
/// 2. `evaluations.<name>.threshold`
/// 3. `cli_threshold`
pub fn evaluation_passes(
	eval: &Evaluation,
	config: &RuaConfig,
	pkgbase: &str,
	cli_threshold: RiskLevel,
) -> bool {
	let threshold = config
		.packages
		.get(pkgbase)
		.and_then(|p| p.evaluations.get(&eval.name))
		.and_then(|e| e.threshold)
		.or_else(|| config.evaluations.get(&eval.name).and_then(|e| e.threshold))
		.unwrap_or(cli_threshold);

	eval.risk <= threshold
}

/// Attempts to auto-merge upstream changes for `pkgbase`. Returns `true` if the merge
/// completed successfully and no further review is needed.
pub fn try_auto_merge(
	dir: &Path,
	pkgbase: &str,
	rua_paths: &RuaPaths,
	mode: &AutoMergeMode,
) -> bool {
	let (cli_threshold, force) = match mode {
		AutoMergeMode::Disabled => return false,
		AutoMergeMode::Enabled(t) => (*t, false),
		AutoMergeMode::Forced(t) => (*t, true),
	};

	if git_utils::is_upstream_merged(dir, rua_paths) {
		eprintln!(
			"Auto-merge: upstream is already merged for {}, proceeding to manual review.",
			pkgbase
		);
		return false;
	}

	let config = RuaConfig::load(&rua_paths.config_file);

	if !force && config.packages.get(pkgbase).and_then(|p| p.auto_merge) == Some(false) {
		eprintln!("Auto-merge: disabled for {} via config, skipping.", pkgbase);
		return false;
	}

	let patterns = config.compiled_source_patterns(pkgbase);

	let upstream_srcinfo_text = git_utils::show_file(dir, "upstream/master", ".SRCINFO", rua_paths);
	let upstream_srcinfo = Srcinfo::from_str(&upstream_srcinfo_text)
		.unwrap_or_else(|e| panic!("Failed to parse .SRCINFO provided by AUR:\nError: {}", e));

	let upstream_pkgbuild = git_utils::show_file(dir, "upstream/master", "PKGBUILD", rua_paths);

	match validate_upstream_srcinfo(&upstream_srcinfo, &upstream_pkgbuild) {
		SrcinfoValidation::GenerationFailed(reason) => {
			eprintln!(
				"Auto-merge: could not generate SRCINFO for {}, skipping auto-merge.\n{}",
				pkgbase, reason
			);
			return false;
		}
		SrcinfoValidation::Mismatch => {
			eprintln!(
				"Auto-merge: upstream .SRCINFO does not match the locally generated SRCINFO for {}.",
				pkgbase
			);
			eprintln!("Would you like to proceed anyway? [y/N]");
			if terminal_util::read_line_lowercase() != "y" {
				// Return false rather than exiting: the caller will fall through to the
				// manual review loop so the user can inspect the mismatch themselves.
				return false;
			}
		}
		SrcinfoValidation::Matches => {}
	}

	let prev_srcinfo_text = match git_utils::try_show_file(dir, "HEAD", ".SRCINFO", rua_paths) {
		Some(t) => t,
		None => {
			eprintln!(
				"Auto-merge: no previous .SRCINFO found in HEAD for {}, skipping auto-merge.",
				pkgbase
			);
			return false;
		}
	};

	let previous_srcinfo = Srcinfo::from_str(&prev_srcinfo_text).unwrap_or_else(|e| {
		panic!(
			"Failed to parse previous .SRCINFO from HEAD for {}:\n{}",
			pkgbase, e
		)
	});

	let mut evaluations =
		srcinfo_eval::evaluate_srcinfo_diff(&previous_srcinfo, &upstream_srcinfo, &patterns);

	if let Some(prev_pkgbuild) = git_utils::try_show_file(dir, "HEAD", "PKGBUILD", rua_paths) {
		evaluations.extend(pkgbuild_eval::evaluate_pkgbuild_diff(
			&prev_pkgbuild,
			&upstream_pkgbuild,
			&upstream_srcinfo.base.pkgbase,
		));
	}

	eprintln!(
		"Auto-merge: risk evaluations for {} ({} check{}):",
		pkgbase,
		evaluations.len(),
		if evaluations.len() == 1 { "" } else { "s" }
	);

	let all_pass = evaluations.iter().fold(true, |acc, eval| {
		let passes = evaluation_passes(eval, &config, pkgbase, cli_threshold);
		print_evaluation(eval, passes, cli_threshold);
		acc && passes
	});

	if !all_pass {
		eprintln!(
			"Auto-merge: blocked for {} due to the checks marked above.",
			pkgbase
		);
		return false;
	}

	if evaluations.is_empty() {
		eprintln!("Auto-merge: no changes detected for {}, merging.", pkgbase);
	} else {
		eprintln!("Auto-merge: all checks passed for {}, merging.", pkgbase);
	}

	git_utils::merge_upstream(dir, rua_paths);

	if git_utils::is_upstream_merged(dir, rua_paths) {
		return true;
	}

	eprintln!(
		"Auto-merge: merge failed for {}, falling back to manual review.",
		pkgbase
	);
	false
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::{EvaluationConfig, PackageConfig, RuaConfig};
	use crate::evaluation::{EvaluationName, RiskLevel};

	fn make_eval(name: EvaluationName, risk: RiskLevel) -> Evaluation {
		Evaluation {
			name,
			pkgname: "testpkg".to_string(),
			description: "test".to_string(),
			risk,
			modified: true,
		}
	}

	#[test]
	fn passes_when_risk_at_cli_threshold() {
		let eval = make_eval(EvaluationName::Pkgver, RiskLevel::Low);
		assert!(evaluation_passes(
			&eval,
			&RuaConfig::default(),
			"anypkg",
			RiskLevel::Low
		));
	}

	#[test]
	fn fails_when_risk_above_cli_threshold() {
		let eval = make_eval(EvaluationName::Install, RiskLevel::High);
		assert!(!evaluation_passes(
			&eval,
			&RuaConfig::default(),
			"anypkg",
			RiskLevel::Low
		));
	}

	#[test]
	fn global_evaluation_override_allows_higher_risk() {
		let eval = make_eval(EvaluationName::Install, RiskLevel::High);
		let mut config = RuaConfig::default();
		config.evaluations.insert(
			EvaluationName::Install,
			EvaluationConfig {
				threshold: Some(RiskLevel::High),
			},
		);
		assert!(evaluation_passes(&eval, &config, "anypkg", RiskLevel::Low));
	}

	#[test]
	fn global_evaluation_override_can_tighten() {
		let eval = make_eval(EvaluationName::Pkgver, RiskLevel::Medium);
		let mut config = RuaConfig::default();
		config.evaluations.insert(
			EvaluationName::Pkgver,
			EvaluationConfig {
				threshold: Some(RiskLevel::Low),
			},
		);
		assert!(!evaluation_passes(
			&eval,
			&config,
			"anypkg",
			RiskLevel::Medium
		));
	}

	#[test]
	fn per_package_override_takes_precedence_over_global() {
		let eval = make_eval(EvaluationName::Source, RiskLevel::High);
		let mut config = RuaConfig::default();
		config.evaluations.insert(
			EvaluationName::Source,
			EvaluationConfig {
				threshold: Some(RiskLevel::Medium),
			},
		);
		config.packages.insert(
			"firefox".to_string(),
			PackageConfig {
				sources: vec![],
				evaluations: [(
					EvaluationName::Source,
					EvaluationConfig {
						threshold: Some(RiskLevel::High),
					},
				)]
				.into(),
				auto_merge: None,
			},
		);
		assert!(evaluation_passes(&eval, &config, "firefox", RiskLevel::Low));
	}

	#[test]
	fn per_package_override_does_not_affect_other_packages() {
		let eval = make_eval(EvaluationName::Install, RiskLevel::High);
		let mut config = RuaConfig::default();
		config.packages.insert(
			"firefox".to_string(),
			PackageConfig {
				sources: vec![],
				evaluations: [(
					EvaluationName::Install,
					EvaluationConfig {
						threshold: Some(RiskLevel::High),
					},
				)]
				.into(),
				auto_merge: None,
			},
		);
		assert!(!evaluation_passes(
			&eval,
			&config,
			"chromium",
			RiskLevel::Low
		));
	}

	#[test]
	fn medium_risk_passes_medium_threshold() {
		let eval = make_eval(EvaluationName::MakeDepends, RiskLevel::Medium);
		assert!(evaluation_passes(
			&eval,
			&RuaConfig::default(),
			"anypkg",
			RiskLevel::Medium
		));
	}

	#[test]
	fn high_risk_fails_medium_threshold() {
		let eval = make_eval(EvaluationName::Epoch, RiskLevel::High);
		assert!(!evaluation_passes(
			&eval,
			&RuaConfig::default(),
			"anypkg",
			RiskLevel::Medium
		));
	}
}
