use crate::git_utils;
use crate::rua_paths::RuaPaths;
use crate::terminal_util;
use crate::wrapped;
use colored::Colorize;
use log::debug;
use std::collections::HashSet;
use std::path::Path;

pub fn review_repo(
	dir: &Path,
	pkgbase: &str,
	rua_paths: &RuaPaths,
	cached_pkgs: &mut HashSet<String>,
) {
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

	let is_upstream_merged = git_utils::is_upstream_merged(dir, rua_paths);
	let current_head = git_utils::head_short_rev(dir, rua_paths);
	let underlying_sha = rua_paths.build_dir_rev(pkgbase);
	let reusable = current_head.as_deref() == underlying_sha.as_deref()
		&& is_upstream_merged
		&& build_dir_contains_built_package(rua_paths, pkgbase);

	if reusable {
		loop {
			eprint!("Use existing build (same commit)? [R]=rebuild, [C]=use cached. ");
			let input = terminal_util::read_line_lowercase();
			if &input == "c" {
				cached_pkgs.insert(pkgbase.to_string());
				return;
			}
			if &input == "r" {
				break;
			}
			break;
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
	cached_pkgs.insert(pkgbase.to_string());
}

fn build_dir_contains_built_package(rua_paths: &RuaPaths, pkgbase: &str) -> bool {
	let build_dir = match std::fs::read_dir(&rua_paths.build_dir(pkgbase)) {
		Ok(d) => d,
		Err(_) => return false,
	};
	build_dir.filter_map(|e| e.ok()).any(|e| {
		e.path()
			.file_name()
			.and_then(|n| n.to_str())
			.map_or(false, |n| n.ends_with(&rua_paths.makepkg_pkgext))
	})
}
