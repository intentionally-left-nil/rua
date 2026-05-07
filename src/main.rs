mod action_builddir;
mod action_evaluate;
mod action_install;
mod action_search;
mod action_upgrade;
mod alpm_wrapper;
mod aur_rpc_utils;
mod auto_merge;
mod cli_args;
mod config;
mod config_edit;
mod evaluation;
mod git_utils;
mod pacman;
mod pkgbuild_eval;
mod print_format;
mod print_package_info;
mod print_package_table;
mod reviewing;
mod rua_environment;
mod rua_paths;
mod srcinfo_eval;
mod srcinfo_to_pkgbuild;
mod tar_check;
mod terminal_util;
mod wrapped;

use crate::print_package_info::info;
use crate::wrapped::shellcheck;
use auto_merge::AutoMergeMode;
use cli_args::Action;
use cli_args::AutoMergeThreshold;
use cli_args::CliArgs;
use evaluation::RiskLevel;
use std::collections::HashSet;
use std::process::exit;
use structopt::StructOpt;

fn main() {
	let cli_args: CliArgs = CliArgs::from_args();
	rua_environment::prepare_environment(&cli_args);
	match &cli_args.action {
		Action::Info { ref target } => {
			info(target, false).unwrap();
		}
		Action::Install {
			asdeps,
			offline,
			target,
		} => {
			let paths = rua_paths::RuaPaths::initialize_paths();
			// The `install` subcommand has no auto-merge flags; auto-merge is intentionally
			// disabled here. Upgrades go through `upgrade_real` which passes the user's mode.
			action_install::install(target, &paths, *offline, *asdeps, &AutoMergeMode::Disabled);
		}
		Action::Builddir {
			offline,
			force,
			target,
		} => {
			let paths = rua_paths::RuaPaths::initialize_paths();
			action_builddir::action_builddir(target, &paths, *offline, *force);
		}
		Action::Search { target } => action_search::action_search(target),
		Action::Shellcheck { target } => {
			let result = shellcheck(target);
			result
				.map_err(|err| {
					eprintln!("{}", err);
					exit(1);
				})
				.ok();
		}
		Action::Tarcheck { target } => {
			tar_check::tar_check_unwrap(
				target,
				target.to_str().expect("target is not valid UTF-8"),
			);
			eprintln!("Finished checking package: {:?}", target);
		}
		Action::Evaluate {
			target,
			threshold,
			range,
		} => {
			let paths = rua_paths::RuaPaths::initialize_paths();
			let threshold_level = match threshold {
				AutoMergeThreshold::low => RiskLevel::Low,
				AutoMergeThreshold::medium => RiskLevel::Medium,
				AutoMergeThreshold::high => RiskLevel::High,
			};
			action_evaluate::action_evaluate(target, threshold_level, range.as_deref(), &paths);
		}
		Action::Upgrade {
			devel,
			printonly,
			auto_merge,
			no_auto_merge,
			auto_merge_threshold,
			ignored,
			packages,
		} => {
			let ignored_set = ignored
				.iter()
				.flat_map(|i| i.split(','))
				.collect::<HashSet<&str>>();
			let only_packages: HashSet<&str> = packages.iter().map(String::as_str).collect();
			if *auto_merge && *no_auto_merge {
				eprintln!("Error: --auto-merge and --no-auto-merge cannot be used together.");
				exit(1);
			}
			let threshold = match auto_merge_threshold {
				AutoMergeThreshold::low => RiskLevel::Low,
				AutoMergeThreshold::medium => RiskLevel::Medium,
				AutoMergeThreshold::high => RiskLevel::High,
			};
			let mode = if *no_auto_merge {
				AutoMergeMode::Disabled
			} else if *auto_merge {
				AutoMergeMode::Forced(threshold)
			} else {
				AutoMergeMode::Enabled(threshold)
			};
			let result = if *printonly {
				action_upgrade::upgrade_printonly(*devel, &ignored_set, &only_packages)
			} else {
				let paths = rua_paths::RuaPaths::initialize_paths();
				action_upgrade::upgrade_real(*devel, &paths, &ignored_set, &only_packages, &mode)
			};
			if let Err(e) = result {
				eprintln!("{}", e);
				exit(1);
			}
		}
	};
}
