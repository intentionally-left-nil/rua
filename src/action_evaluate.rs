use crate::auto_merge;
use crate::config::RuaConfig;
use crate::evaluation::RiskLevel;
use crate::git_utils;
use crate::rua_paths::RuaPaths;

fn resolve_range(range: Option<&str>) -> String {
	match range {
		None => "upstream/master".to_string(),
		Some(r) => r.replace("HEAD", "upstream/master"),
	}
}

pub fn action_evaluate(
	pkgbase: &str,
	threshold: RiskLevel,
	range: Option<&str>,
	rua_paths: &RuaPaths,
) {
	let dir = rua_paths.review_dir(pkgbase);
	if !dir.exists() {
		eprintln!(
			"Error: no review directory found for '{}'. \
Run 'rua install {}' first to clone the repo.",
			pkgbase, pkgbase
		);
		std::process::exit(1);
	}

	let range_or_ref = resolve_range(range);
	let commits = git_utils::list_commits(&dir, &range_or_ref, rua_paths);

	if commits.len() < 2 {
		eprintln!(
			"Not enough commits in '{}' to evaluate (found {}, need at least 2).",
			range_or_ref,
			commits.len()
		);
		return;
	}

	let config = RuaConfig::load(&rua_paths.config_file);
	let pairs = commits.windows(2);
	let total = commits.len() - 1;
	let mut would_merge: usize = 0;
	let mut skipped: usize = 0;

	for (i, window) in pairs.enumerate() {
		let old_ref = &window[0];
		let new_ref = &window[1];
		let short = &new_ref[..new_ref.len().min(8)];

		eprintln!("\n[{}/{}] {}", i + 1, total, short);

		match auto_merge::evaluate_ref_pair(&dir, old_ref, new_ref, &config, rua_paths) {
			auto_merge::EvalPairOutcome::AbsentSrcinfo => {
				eprintln!("  Skipped: .SRCINFO absent at one or both refs.");
				skipped += 1;
			}
			auto_merge::EvalPairOutcome::MalformedSrcinfo(err) => {
				eprintln!("  Skipped: .SRCINFO failed to parse: {}", err);
				skipped += 1;
			}
			auto_merge::EvalPairOutcome::Success(evaluations) => {
				if evaluations.is_empty() {
					eprintln!("  No file changes detected.");
					would_merge += 1;
					continue;
				}

				let all_pass = evaluations.iter().fold(true, |acc, eval| {
					let passes = auto_merge::evaluation_passes(eval, &config, pkgbase, threshold);
					auto_merge::print_evaluation(eval, passes, threshold);
					acc && passes
				});

				if all_pass {
					eprintln!("  -> Would auto-merge");
					would_merge += 1;
				} else {
					eprintln!("  -> Would BLOCK (manual review required)");
				}
			}
		}
	}

	let evaluated = total - skipped;
	eprintln!(
		"\nSummary for '{}': {}/{} evaluated commits would have auto-merged \
({} skipped, missing .SRCINFO).",
		pkgbase, would_merge, evaluated, skipped
	);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_resolve_range_none_defaults_to_upstream_master() {
		assert_eq!(resolve_range(None), "upstream/master");
	}

	#[test]
	fn test_resolve_range_head_replaced() {
		assert_eq!(
			resolve_range(Some("HEAD~3..HEAD")),
			"upstream/master~3..upstream/master"
		);
	}

	#[test]
	fn test_resolve_range_bare_head() {
		assert_eq!(resolve_range(Some("HEAD")), "upstream/master");
	}

	#[test]
	fn test_resolve_range_head_suffix_only() {
		assert_eq!(resolve_range(Some("HEAD~5")), "upstream/master~5");
	}

	#[test]
	fn test_resolve_range_no_head_unchanged() {
		assert_eq!(
			resolve_range(Some("upstream/master~3..upstream/master")),
			"upstream/master~3..upstream/master"
		);
	}

	#[test]
	fn test_resolve_range_sha_unchanged() {
		assert_eq!(resolve_range(Some("abc123..def456")), "abc123..def456");
	}
}
