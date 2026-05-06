use crate::config::RuaConfig;
use crate::evaluation::{Evaluation, RiskLevel};
use crate::git_utils;
use crate::pkgbuild_eval;
use crate::rua_paths::RuaPaths;
use crate::srcinfo_eval;
use crate::terminal_util;
use crate::wrapped;
use colored::Colorize;
use lazy_static::lazy_static;
use regex::Regex;
use srcinfo::Srcinfo;
use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

pub enum AutoMergeMode {
	Disabled,
	/// Config `auto_merge = false` entries are respected.
	Enabled(RiskLevel),
	/// Ignores `auto_merge = false` config entries; equivalent to `--auto-merge` flag.
	Forced(RiskLevel),
}

enum SrcinfoValidation {
	Matches,
	Mismatch,
	GenerationFailed(String),
}

fn should_touch_file(name: &str) -> bool {
	lazy_static! {
		// All printable ASCII characters except '/'
		static ref VALID: Regex = Regex::new(r"^(?:[\x21-\x7E&&[^/]]){1,255}$").unwrap();
	}

	if !VALID.is_match(name) {
		return false;
	}

	let name_lower = name.to_ascii_lowercase();
	!matches!(
		name_lower.as_str(),
		"." | ".." | "pkgbuild" | ".srcinfo" | "pkgbuild.static"
	)
}

fn touch_files(srcinfo: &Srcinfo, dir: &Path) -> Result<(), String> {
	let names: HashSet<&str> = std::iter::once(&srcinfo.pkg)
		.chain(srcinfo.pkgs.iter())
		.flat_map(|pkg| {
			[pkg.install.as_deref(), pkg.changelog.as_deref()]
				.into_iter()
				.flatten()
		})
		.filter(|name| should_touch_file(name))
		.collect();

	for name in names {
		std::fs::write(dir.join(name), b"")
			.map_err(|e| format!("Failed to touch file {}: {}", name, e))?;
	}
	Ok(())
}

fn validate_upstream_srcinfo(
	upstream_srcinfo: &Srcinfo,
	upstream_pkgbuild: &str,
) -> SrcinfoValidation {
	let tmp_dir = tempfile::TempDir::new().expect("Failed to create temp directory");

	if let Err(e) = touch_files(upstream_srcinfo, tmp_dir.path()) {
		return SrcinfoValidation::GenerationFailed(e);
	}

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

pub(crate) fn print_evaluation(eval: &Evaluation, passes: bool, cli_threshold: RiskLevel) {
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

pub(crate) enum EvalPairOutcome {
	Success(Vec<Evaluation>),
	/// Normal for early commits that pre-date SRCINFO.
	AbsentSrcinfo,
	/// `.SRCINFO` exists but failed to parse — indicates corruption or tampering.
	MalformedSrcinfo(String),
}

pub(crate) fn evaluate_srcinfo_texts(
	old_srcinfo_text: &str,
	new_srcinfo_text: &str,
	old_pkgbuild: Option<&str>,
	new_pkgbuild: Option<&str>,
	config: &RuaConfig,
) -> Result<Vec<Evaluation>, String> {
	let old_srcinfo = Srcinfo::from_str(old_srcinfo_text)
		.map_err(|e| format!("failed to parse old .SRCINFO: {}", e))?;
	let new_srcinfo = Srcinfo::from_str(new_srcinfo_text)
		.map_err(|e| format!("failed to parse new .SRCINFO: {}", e))?;

	let pkgbase = &new_srcinfo.base.pkgbase;
	let patterns = config.compiled_source_patterns(pkgbase);

	let mut evaluations =
		srcinfo_eval::evaluate_srcinfo_diff(&old_srcinfo, &new_srcinfo, &patterns);

	if let (Some(old_pb), Some(new_pb)) = (old_pkgbuild, new_pkgbuild) {
		evaluations.extend(pkgbuild_eval::evaluate_pkgbuild_diff(
			old_pb, new_pb, pkgbase,
		));
	}

	Ok(evaluations)
}

/// Single source of truth for evaluation logic shared between `try_auto_merge`
/// and `action_evaluate`. Both callers stay in sync by only changing this function.
pub(crate) fn evaluate_ref_pair(
	dir: &Path,
	old_ref: &str,
	new_ref: &str,
	config: &RuaConfig,
	rua_paths: &RuaPaths,
) -> EvalPairOutcome {
	let old_srcinfo_text = match git_utils::try_show_file(dir, old_ref, ".SRCINFO", rua_paths) {
		Some(t) => t,
		None => return EvalPairOutcome::AbsentSrcinfo,
	};
	let new_srcinfo_text = match git_utils::try_show_file(dir, new_ref, ".SRCINFO", rua_paths) {
		Some(t) => t,
		None => return EvalPairOutcome::AbsentSrcinfo,
	};

	let old_pkgbuild = git_utils::try_show_file(dir, old_ref, "PKGBUILD", rua_paths);
	let new_pkgbuild = git_utils::try_show_file(dir, new_ref, "PKGBUILD", rua_paths);

	match evaluate_srcinfo_texts(
		&old_srcinfo_text,
		&new_srcinfo_text,
		old_pkgbuild.as_deref(),
		new_pkgbuild.as_deref(),
		config,
	) {
		Ok(evals) => EvalPairOutcome::Success(evals),
		Err(e) => EvalPairOutcome::MalformedSrcinfo(e),
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

	// Security check specific to live auto-merge; skipped in history replay.
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
				// Caller falls through to manual review so the user can inspect the mismatch.
				return false;
			}
		}
		SrcinfoValidation::Matches => {}
	}

	let evaluations = match evaluate_ref_pair(dir, "HEAD", "upstream/master", &config, rua_paths) {
		EvalPairOutcome::Success(evals) => evals,
		EvalPairOutcome::AbsentSrcinfo => {
			eprintln!(
				"Auto-merge: no previous .SRCINFO found in HEAD for {}, skipping auto-merge.",
				pkgbase
			);
			return false;
		}
		EvalPairOutcome::MalformedSrcinfo(err) => {
			eprintln!(
				"Auto-merge: .SRCINFO parse error for {}, skipping auto-merge: {}",
				pkgbase, err
			);
			return false;
		}
	};

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

	// -------------------------------------------------------------------------
	// should_touch_file
	// -------------------------------------------------------------------------

	#[test]
	fn touch_file_valid_typical_install() {
		assert!(should_touch_file("miniconda3.install"));
	}

	#[test]
	fn touch_file_valid_typical_changelog() {
		assert!(should_touch_file("package.changelog"));
	}

	#[test]
	fn touch_file_valid_single_char() {
		assert!(should_touch_file("a"));
	}

	#[test]
	fn touch_file_valid_dot_prefixed() {
		// A name like ".install" is a hidden file but still valid.
		assert!(should_touch_file(".install"));
	}

	#[test]
	fn touch_file_valid_255_bytes() {
		// Exactly at the NAME_MAX limit.
		let name = "a".repeat(255);
		assert!(should_touch_file(&name));
	}

	#[test]
	fn touch_file_valid_all_printable_ascii_chars() {
		// Spot-check a name using a variety of printable ASCII characters.
		assert!(should_touch_file("foo-bar_baz.v2~install"));
	}

	// --- Slash (path separator) ---

	#[test]
	fn touch_file_rejects_parent_dir_traversal() {
		assert!(!should_touch_file("../evil"));
	}

	#[test]
	fn touch_file_rejects_subdir_path() {
		assert!(!should_touch_file("foo/bar.install"));
	}

	#[test]
	fn touch_file_rejects_absolute_path() {
		assert!(!should_touch_file("/etc/passwd"));
	}

	// --- Empty / dot / double-dot ---

	#[test]
	fn touch_file_rejects_empty_string() {
		assert!(!should_touch_file(""));
	}

	#[test]
	fn touch_file_rejects_single_dot() {
		assert!(!should_touch_file("."));
	}

	#[test]
	fn touch_file_rejects_double_dot() {
		assert!(!should_touch_file(".."));
	}

	// --- Length ---

	#[test]
	fn touch_file_rejects_256_bytes() {
		let name = "a".repeat(256);
		assert!(!should_touch_file(&name));
	}

	// --- Invalid bytes ---

	#[test]
	fn touch_file_rejects_space() {
		// Space (0x20) is one below the accepted range \x21-\x7E.
		assert!(!should_touch_file("foo bar"));
	}

	#[test]
	fn touch_file_rejects_del() {
		// DEL (0x7F) is one above the accepted range \x21-\x7E.
		assert!(!should_touch_file("foo\x7fbar"));
	}

	#[test]
	fn touch_file_rejects_non_ascii() {
		// Any byte > 0x7F is rejected; U+00A0 (non-breaking space) is representative.
		assert!(!should_touch_file("foo\u{00A0}bar"));
	}

	// --- Reserved names (case-insensitive) ---

	#[test]
	fn touch_file_rejects_pkgbuild() {
		assert!(!should_touch_file("PkGbUiLd"));
	}

	#[test]
	fn touch_file_rejects_srcinfo() {
		assert!(!should_touch_file(".SrCiNfO"));
	}

	#[test]
	fn touch_file_rejects_pkgbuild_static() {
		assert!(!should_touch_file("PkGbUiLd.StAtIc"));
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

	const VALID_SRCINFO: &str = "\
pkgbase = testpkg
\tpkgver = 1.0.0
\tpkgrel = 1
\tarch = x86_64

pkgname = testpkg
";

	#[test]
	fn evaluate_srcinfo_texts_valid_inputs_return_ok() {
		let result = evaluate_srcinfo_texts(
			VALID_SRCINFO,
			VALID_SRCINFO,
			None,
			None,
			&RuaConfig::default(),
		);
		assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
	}

	#[test]
	fn evaluate_srcinfo_texts_malformed_old_returns_err_mentioning_old() {
		let result = evaluate_srcinfo_texts(
			"this is not valid srcinfo !!!",
			VALID_SRCINFO,
			None,
			None,
			&RuaConfig::default(),
		);
		let err = result.expect_err("expected Err for malformed old .SRCINFO");
		assert!(
			err.contains("old .SRCINFO"),
			"error message should mention 'old .SRCINFO', got: {}",
			err
		);
	}

	#[test]
	fn evaluate_srcinfo_texts_malformed_new_returns_err_mentioning_new() {
		let result = evaluate_srcinfo_texts(
			VALID_SRCINFO,
			"this is not valid srcinfo !!!",
			None,
			None,
			&RuaConfig::default(),
		);
		let err = result.expect_err("expected Err for malformed new .SRCINFO");
		assert!(
			err.contains("new .SRCINFO"),
			"error message should mention 'new .SRCINFO', got: {}",
			err
		);
	}

	#[test]
	fn evaluate_srcinfo_texts_missing_pkgbuild_still_produces_srcinfo_evals() {
		let result = evaluate_srcinfo_texts(
			VALID_SRCINFO,
			VALID_SRCINFO,
			None,
			None,
			&RuaConfig::default(),
		);
		let evals = result.expect("expected Ok with no PKGBUILDs");
		assert!(
			!evals.is_empty(),
			"should still have SRCINFO evaluations even without PKGBUILDs"
		);
		assert!(
			!evals.iter().any(|e| matches!(
				e.name,
				EvaluationName::PkgbuildFunction
					| EvaluationName::PkgbuildCustomVariable
					| EvaluationName::PkgbuildBareCode
			)),
			"should have no PKGBUILD evaluations when PKGBUILDs are absent"
		);
	}
}
