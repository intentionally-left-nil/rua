use crate::cli_args::AutoMerge;
use crate::config::RuaConfig;
use crate::git_utils;
use crate::pkgbuild_eval;
use crate::rua_paths::RuaPaths;
use crate::srcinfo_eval;
use crate::terminal_util;
use crate::wrapped;
use colored::Colorize;
use log::debug;
use srcinfo::Srcinfo;
use std::path::Path;
use std::str::FromStr;

enum SrcinfoValidation {
	/// SRCINFO was generated successfully and matches upstream.
	Matches,
	/// SRCINFO was generated successfully but does not match upstream.
	Mismatch,
	/// SRCINFO could not be generated (e.g. bwrap/makepkg failure).
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

pub fn review_repo(dir: &Path, pkgbase: &str, rua_paths: &RuaPaths, auto_merge: AutoMerge) {
	let mut dir_contents = dir.read_dir().unwrap_or_else(|err| {
		panic!(
			"{}:{} Failed to read directory for reviewing, {}",
			file!(),
			line!(),
			err
		)
	});
	if dir_contents.next().is_none() {
		debug!("Directory {:?} is empty, using git clone", &dir);
		git_utils::init_repo(pkgbase, dir, rua_paths);
	} else {
		debug!("Directory {:?} is not empty, fetching new version", &dir);
		git_utils::fetch(dir, rua_paths);
	}

	let build_dir = rua_paths.build_dir(pkgbase);
	if build_dir.exists() && git_utils::is_upstream_merged(dir, rua_paths) {
		eprintln!("WARNING: your AUR repo is up-to-date.");
		eprintln!(
			"If you continue, the build directory will be removed and the build will be re-run."
		);
		eprintln!("If you don't want that, consider resolving the situation manually,");
		let build_dir = terminal_util::escape_bash_arg(
			build_dir
				.to_str()
				.unwrap_or_else(|| panic!("Failed to stringify build directory {:?}", build_dir)),
		);
		eprintln!("for example:    rua builddir {}", build_dir);
		eprintln!();
	}

	if auto_merge != AutoMerge::off {
		if git_utils::is_upstream_merged(dir, rua_paths) {
			eprintln!(
				"Auto-merge: upstream is already merged for {}, skipping auto-merge evaluation.",
				pkgbase
			);
		} else {
			let config = RuaConfig::load(&rua_paths.config_file);
			let patterns = config.compiled_source_patterns(pkgbase);
			let upstream_srcinfo_text =
				git_utils::show_file(dir, "upstream/master", ".SRCINFO", rua_paths);
			let upstream_srcinfo = Srcinfo::from_str(&upstream_srcinfo_text).unwrap_or_else(|e| {
				panic!("Failed to parse .SRCINFO provided by AUR:\nError: {}", e)
			});

			let upstream_pkgbuild =
				git_utils::show_file(dir, "upstream/master", "PKGBUILD", rua_paths);

			match validate_upstream_srcinfo(&upstream_srcinfo, &upstream_pkgbuild) {
				SrcinfoValidation::GenerationFailed(reason) => {
					eprintln!(
						"Auto-merge: could not generate SRCINFO for {}, skipping auto-merge.\n{}",
						pkgbase, reason
					);
				}
				SrcinfoValidation::Mismatch => {
					eprintln!(
						"Auto-merge: upstream .SRCINFO does not match the locally generated SRCINFO \
					for {}.",
						pkgbase
					);
					eprintln!("Would you like to proceed anyway? [y/N]");
					let input = terminal_util::read_line_lowercase();
					if input != "y" {
						eprintln!("Aborting.");
						std::process::exit(1);
					}
				}
				SrcinfoValidation::Matches => {
					match git_utils::try_show_file(dir, "HEAD", ".SRCINFO", rua_paths) {
						None => {
							eprintln!(
								"Auto-merge: no previous .SRCINFO found in HEAD for {}, \
								skipping auto-merge.",
								pkgbase
							);
						}
						Some(prev_text) => {
							let previous_srcinfo =
								Srcinfo::from_str(&prev_text).unwrap_or_else(|e| {
									panic!(
										"Failed to parse previous .SRCINFO from HEAD for {}:\n{}",
										pkgbase, e
									)
								});
							let mut evaluations = srcinfo_eval::evaluate_srcinfo_diff(
								&previous_srcinfo,
								&upstream_srcinfo,
								&patterns,
							);

							if let Some(prev_pkgbuild) =
								git_utils::try_show_file(dir, "HEAD", "PKGBUILD", rua_paths)
							{
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
							for eval in &evaluations {
								eprintln!(
									"  [{}{}] {}/{:?}: {}",
									format!("{:?}", eval.risk).to_uppercase(),
									if eval.modified { " MODIFIED" } else { "" },
									eval.pkgname,
									eval.name,
									eval.description,
								);
							}
							eprintln!(
								"Note: auto-merge decision is not yet fully implemented, \
								proceeding with manual review."
							);
						}
					}
				}
			}
		}
	}

	loop {
		eprintln!("\nReviewing {:?}. ", dir);
		let is_upstream_merged = git_utils::is_upstream_merged(dir, rua_paths);
		let identical_to_upstream =
			is_upstream_merged && git_utils::identical_to_upstream(dir, rua_paths);
		if is_upstream_merged {
			eprint!(
				"{}{}, ",
				"[S]".bold().green(),
				"=run shellcheck on PKGBUILD".green()
			);
			if identical_to_upstream {
				eprint!("{}, ", "[D]=(identical to upstream, empty diff)".dimmed());
			} else {
				eprint!("{}{}, ", "[D]".bold().green(), "=view your changes".green());
			};
		} else {
			eprint!(
				"{}{}, ",
				"[D]".bold().green(),
				"=view upstream changes since your last review".green()
			);
			eprint!(
				"{}{}, ",
				"[M]".bold().yellow(),
				"=accept/merge upstream changes".yellow()
			);
			eprint!(
				"{}, ",
				"[S]=(shellcheck not available until you merge)".dimmed()
			);
		}
		eprint!(
			"{}{}, ",
			"[T]".bold().cyan(),
			"=run shell to edit/inspect".cyan()
		);
		if is_upstream_merged {
			eprint!("{}{}. ", "[O]".bold().red(), "=ok, use package".red());
		} else {
			eprint!(
				"{}",
				"[O]=(cannot use the package until you merge) ".dimmed()
			);
		}
		let user_input = terminal_util::read_line_lowercase();

		if &user_input == "t" {
			eprintln!("Changes that you make will be merged with upstream updates in future.");
			eprintln!("Exit the shell with `logout` or Ctrl-D...");
			terminal_util::run_env_command(dir, "SHELL", "bash", &[]);
		} else if &user_input == "s" && is_upstream_merged {
			if let Err(err) = wrapped::shellcheck(&Some(dir.join("PKGBUILD"))) {
				eprintln!("{}", err);
			};
		} else if &user_input == "d" && is_upstream_merged {
			git_utils::show_upstream_diff(dir, false, rua_paths);
		} else if &user_input == "d" && !is_upstream_merged {
			git_utils::show_upstream_diff(dir, true, rua_paths);
		} else if &user_input == "m" && !is_upstream_merged {
			git_utils::merge_upstream(dir, rua_paths);
		} else if &user_input == "o" && is_upstream_merged {
			break;
		}
	}
}
