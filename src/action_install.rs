use crate::alpm_wrapper::new_alpm_wrapper;
use crate::aur_rpc_utils;
use crate::git_utils;
use crate::pacman;
use crate::reviewing;
use crate::rua_paths::RuaPaths;
use crate::tar_check;
use crate::terminal_util;
use crate::wrapped;
use fs_extra::dir::CopyOptions;
use indexmap::IndexMap;
use indexmap::IndexSet;
use itertools::Itertools;
use log::debug;
use log::trace;
use std::collections::HashSet;
use std::fs;
use std::fs::ReadDir;
use std::path::PathBuf;

pub fn install(targets: &[String], rua_paths: &RuaPaths, is_offline: bool, asdeps: bool) {
	let alpm = new_alpm_wrapper();
	let (split_to_raur, pacman_deps, split_to_depth) =
		aur_rpc_utils::recursive_info(targets, &*alpm).unwrap_or_else(|err| {
			panic!("Failed to fetch info from AUR, {}", err);
		});
	let split_to_pkgbase: IndexMap<String, String> = split_to_raur
		.iter()
		.map(|(split, raur)| (split.to_string(), raur.package_base.to_string()))
		.collect();
	let not_found = split_to_depth
		.keys()
		.filter(|pkg| !split_to_raur.contains_key(*pkg))
		.collect_vec();
	if !not_found.is_empty() {
		eprintln!(
			"Need to install packages: {:?}, but they are not found on AUR.",
			not_found
		);
		std::process::exit(1)
	}

	show_install_summary(&pacman_deps, &split_to_depth);
	let mut cached_pkgs: HashSet<String> = HashSet::new();
	for pkgbase in split_to_pkgbase.values().collect::<HashSet<_>>() {
		let dir = rua_paths.review_dir(pkgbase);
		fs::create_dir_all(&dir).unwrap_or_else(|err| {
			panic!("Failed to create repository dir for {}, {}", pkgbase, err)
		});
		reviewing::review_repo(&dir, pkgbase, rua_paths, &mut cached_pkgs);
	}
	pacman::ensure_pacman_packages_installed(pacman_deps);
	let pkgbases_for_cleanup: HashSet<String> = split_to_pkgbase.values().cloned().collect();
	install_all(
		rua_paths,
		split_to_depth,
		split_to_pkgbase,
		is_offline,
		asdeps,
		&cached_pkgs,
	);
	for pkgbase in &pkgbases_for_cleanup {
		ensure_build_dir_removed(rua_paths, pkgbase);
	}
}

fn ensure_build_dir_removed(rua_paths: &RuaPaths, pkgbase: &str) {
	let p = rua_paths.build_dir(pkgbase);
	if !p.exists() {
		return;
	}
	let meta = match fs::symlink_metadata(&p) {
		Ok(m) => m,
		Err(_) => return,
	};
	if meta.file_type().is_symlink() {
		if let Ok(canonical) = fs::canonicalize(&p) {
			rm_rf::ensure_removed(&canonical).unwrap_or_else(|err| {
				panic!("Failed to remove build dir target {:?}, {}", canonical, err)
			});
		}
		fs::remove_file(&p)
			.unwrap_or_else(|err| panic!("Failed to remove build dir symlink {:?}, {}", p, err));
	} else if meta.file_type().is_dir() {
		rm_rf::ensure_removed(&p)
			.unwrap_or_else(|err| panic!("Failed to remove build dir {:?}, {}", p, err));
	}
}

fn create_build_dir(rua_paths: &RuaPaths, pkgbase: &str, short_rev: &str) -> PathBuf {
	ensure_build_dir_removed(rua_paths, pkgbase);
	let rev_dir = rua_paths
		.global_build_dir
		.join(format!("{}-{}", pkgbase, short_rev));
	rm_rf::ensure_removed(&rev_dir)
		.unwrap_or_else(|err| panic!("Failed to remove existing rev dir {:?}, {}", &rev_dir, err));
	std::fs::create_dir_all(&rev_dir)
		.unwrap_or_else(|err| panic!("Failed to create build dir {:?}, {}", &rev_dir, err));
	let rev_dir_name = rev_dir
		.file_name()
		.expect("rev_dir has no file name")
		.to_str()
		.expect("rev_dir name not UTF-8")
		.to_string();
	let symlink_path = rua_paths.build_dir(pkgbase);
	std::os::unix::fs::symlink(&rev_dir_name, &symlink_path).unwrap_or_else(|err| {
		panic!(
			"Failed to create symlink {:?} -> {:?}, {}",
			symlink_path, rev_dir_name, err
		)
	});
	symlink_path
}

fn build_dir_has_pkg_files(rua_paths: &RuaPaths, pkgbase: &str) -> bool {
	let build_dir = rua_paths.build_dir(pkgbase);
	let read_dir = match fs::read_dir(&build_dir) {
		Ok(d) => d,
		Err(_) => return false,
	};
	read_dir.filter_map(|e| e.ok()).any(|e| {
		e.path()
			.file_name()
			.and_then(|n| n.to_str())
			.map_or(false, |n| n.ends_with(&rua_paths.makepkg_pkgext))
	})
}

fn show_install_summary(pacman_deps: &IndexSet<String>, aur_packages: &IndexMap<String, i32>) {
	if pacman_deps.len() + aur_packages.len() == 1 {
		return;
	}
	if !pacman_deps.is_empty() {
		eprintln!("\nIn order to install all targets, the following pacman packages will need to be installed:");
		eprintln!(
			"{}",
			pacman_deps.iter().map(|s| format!("  {}", s)).join("\n")
		);
	};
	eprintln!("\nAnd the following AUR packages will need to be built and installed:");
	let mut aur_packages = aur_packages.iter().collect::<Vec<_>>();
	aur_packages.sort_by_key(|pair| -*pair.1);
	for (aur, dep) in &aur_packages {
		debug!("depth {}: {}", dep, aur);
	}
	eprintln!(
		"{}\n",
		aur_packages.iter().map(|s| format!("  {}", s.0)).join("\n")
	);
	loop {
		eprint!("Proceed? [O]=ok, Ctrl-C=abort. ");
		let string = terminal_util::read_line_lowercase();
		if &string == "o" {
			break;
		}
	}
}

fn install_all(
	rua_paths: &RuaPaths,
	split_to_depth: IndexMap<String, i32>,
	split_to_pkgbase: IndexMap<String, String>,
	offline: bool,
	asdeps: bool,
	cached_pkgs: &HashSet<String>,
) {
	let archive_whitelist = split_to_depth
		.iter()
		.map(|(split, _depth)| split.as_str())
		.collect::<IndexSet<_>>();
	trace!("All expected split packages: {:?}", archive_whitelist);
	// get a list of (pkgbase, depth)
	let packages = split_to_pkgbase.iter().map(|(split, pkgbase)| {
		let depth = split_to_depth
			.get(split)
			.expect("Internal error: split package doesn't have recursive depth");
		(pkgbase.to_string(), *depth, split.to_string())
	});
	// sort pairs in descending depth order
	let packages = packages.sorted_by_key(|(_pkgbase, depth, _split)| -depth);
	// Note that a pkgbase can appear at multiple depths because
	// multiple split pkgnames can be at multiple depths.
	// In this case, we only take the first occurrence of pkgbase,
	// which would be the maximum depth because of sort order.
	// We only take one occurrence because we want the package to only be built once.
	let packages: Vec<(String, i32, String)> = packages
		.unique_by(|(pkgbase, _depth, _split)| pkgbase.to_string())
		.collect::<Vec<_>>();
	// once we have a collection of pkgname-s and their depth, proceed straightforwardly.
	for (depth, packages) in &packages.iter().chunk_by(|(_pkgbase, depth, _split)| *depth) {
		let packages = packages.collect::<Vec<&(String, i32, String)>>();
		for (pkgbase, _depth, _split) in &packages {
			let review_dir = rua_paths.review_dir(pkgbase);
			let short_rev = git_utils::head_short_rev(&review_dir, rua_paths)
				.unwrap_or_else(|| "head".to_string());
			let use_cache = cached_pkgs.contains(pkgbase.as_str())
				&& rua_paths.build_dir_rev(pkgbase).as_deref() == Some(short_rev.as_str())
				&& build_dir_has_pkg_files(rua_paths, pkgbase);
			if !use_cache {
				let symlink_path = create_build_dir(rua_paths, pkgbase, &short_rev);
				let mut copy_opts = CopyOptions::new();
				copy_opts.content_only = true;
				fs_extra::dir::copy(&review_dir, &symlink_path, &copy_opts).unwrap_or_else(|err| {
					panic!(
						"failed to copy reviewed dir {:?} to build dir {:?}, error is {}",
						&review_dir, &symlink_path, err
					)
				});
				rm_rf::ensure_removed(symlink_path.join(".git")).unwrap_or_else(|err| {
					panic!("Failed to remove {:?}, {}", symlink_path.join(".git"), err)
				});
				wrapped::build_directory(
					symlink_path.to_str().expect("Non-UTF8 directory name"),
					rua_paths,
					offline,
					false,
				);
			}
		}
		for (pkgbase, _depth, _split) in &packages {
			check_tars_and_move(pkgbase, rua_paths, &archive_whitelist);
		}
		// This relation between split_name and the archive file is not actually correct here.
		// Instead, all archive files of some group will be bound to one split name only here.
		// This is probably still good enough for install verification though --
		// and we only use this relation for this purpose. Feel free to improve, if you want...
		let mut files_to_install: Vec<(String, PathBuf)> = Vec::new();
		for (pkgbase, _depth, split) in &packages {
			let checked_tars = rua_paths.checked_tars_dir(pkgbase);
			let read_dir_iterator = fs::read_dir(checked_tars).unwrap_or_else(|e| {
				panic!(
					"Failed to read 'checked_tars' directory for {}, {}",
					pkgbase, e
				)
			});

			for file in read_dir_iterator {
				files_to_install.push((
					split.to_string(),
					file.expect("Failed to access checked_tars dir").path(),
				));
			}
		}
		pacman::ensure_aur_packages_installed(files_to_install, asdeps || depth > 0);
	}
}

pub fn check_tars_and_move(name: &str, rua_paths: &RuaPaths, archive_whitelist: &IndexSet<&str>) {
	debug!("checking tars and moving for package {}", name);
	let build_dir = rua_paths.build_dir(name);
	let dir_items: ReadDir = build_dir.read_dir().unwrap_or_else(|err| {
		panic!(
			"Failed to read directory contents for {:?}, {}",
			&build_dir, err
		)
	});
	let dir_items = dir_items.map(|f| f.expect("Failed to open file for tar_check analysis"));
	let mut dir_items = dir_items
		.map(|file| {
			let file_name = file.file_name();
			let file_name = file_name
				.into_string()
				.expect("Non-UTF8 characters in tar file name");
			(file, file_name)
		})
		.filter(|(_, name)| name.ends_with(&rua_paths.makepkg_pkgext))
		.collect::<Vec<_>>();
	let dir_items_names = dir_items
		.iter()
		.map(|(_, name)| name.as_str())
		.collect_vec();
	let common_suffix_length = tar_check::common_suffix_length(&dir_items_names, archive_whitelist);
	dir_items
		.retain(|(_, name)| archive_whitelist.contains(&name[..name.len() - common_suffix_length]));
	trace!("Files filtered for tar checking: {:?}", &dir_items);
	for (file, _file_name) in dir_items.iter() {
		let path = file.path();
		tar_check::tar_check_unwrap(
			&path,
			path.to_str().expect("Non-UTF8 characters in build path"),
		);
	}
	debug!("all package (tar) files checked, moving them");
	let checked_tars_dir = rua_paths.checked_tars_dir(name);
	rm_rf::ensure_removed(&checked_tars_dir).unwrap_or_else(|err| {
		panic!(
			"Failed to clean checked tar files dir {:?}, {}",
			checked_tars_dir, err,
		)
	});
	fs::create_dir_all(&checked_tars_dir).unwrap_or_else(|err| {
		panic!(
			"Failed to create checked_tars dir {:?}, {}",
			&checked_tars_dir, err
		);
	});

	for (file, file_name) in dir_items {
		let src = &file.path();
		let dst = &checked_tars_dir.join(file_name);

		fs::rename(src, dst)
			.or_else(|err| {
				// We want to make the "move" operation as fast as possible.
				// First we attempt to do it in one single system call, "rename".
				//
				// That might fail if the XDG directories ~/.cache/rua and /.local/share/
				// live on different devices (or your XDG directories do, if you defined them).
				// In that, and only in that case, we try to copy the file and remove upon completion.

				// References:
				// RUA pull request: https://github.com/vn971/rua/pull/109
				// coreutils copying: https://github.com/coreutils/coreutils/blob/9b4bb9d28a6a5f84c407f795d518726fd7902121/src/copy.c#L2466

				if err.raw_os_error() != Some(libc::EXDEV) {
					// EXDEV (invalid cross-device link) gets aggregated into io::ErrorKind::Other
					return Err(err);
				}

				// can't move across disks, copy & delete instead
				fs::copy(src, dst)?;
				let _ = fs::remove_file(src);

				Ok(())
			})
			.unwrap_or_else(|e| {
				panic!(
					"Failed to move {:?} (build artifact) to {:?}, {}",
					&file, &checked_tars_dir, e,
				)
			});
	}
}
