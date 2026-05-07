use std::fs;
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item, Table, Value};

const HINT_HEADER: &str = "# rua-source-hint-start";
const HINT_FOOTER: &str = "# rua-source-hint-end";

/// Prepares the config file for editing by ensuring `[packages.<pkgbase>]` exists
/// with a `sources` key and instructional comments showing the old and new URLs.
///
/// If the user has previously triggered an edit for this package, the old hint block
/// is replaced (not duplicated). All other user content is preserved verbatim.
pub fn prepare_sources_for_edit(config_path: &Path, pkgbase: &str, old_url: &str, new_url: &str) {
	let content = if config_path.exists() {
		fs::read_to_string(config_path).unwrap_or_default()
	} else {
		String::new()
	};

	let result = prepare_sources_in_text(&content, pkgbase, old_url, new_url);

	if let Some(parent) = config_path.parent() {
		fs::create_dir_all(parent).ok();
	}
	fs::write(config_path, result).unwrap_or_else(|e| {
		eprintln!("Failed to write config file {:?}: {}", config_path, e);
	});
}

/// Pure function that transforms config text. Testable without filesystem.
fn prepare_sources_in_text(content: &str, pkgbase: &str, old_url: &str, new_url: &str) -> String {
	let mut doc: DocumentMut = content.parse().unwrap_or_else(|_| DocumentMut::new());

	// Ensure [packages.<pkgbase>] exists.
	if !doc.contains_key("packages") {
		let mut t = Table::new();
		t.set_implicit(true);
		doc.insert("packages", Item::Table(t));
	}
	let packages = match doc["packages"].as_table_mut() {
		Some(t) => t,
		None => {
			eprintln!(
				"Warning: 'packages' key in config is not a table; cannot prepare sources for edit."
			);
			return content.to_owned();
		}
	};
	packages.set_implicit(true);

	if !packages.contains_key(pkgbase) {
		packages.insert(pkgbase, Item::Table(Table::new()));
	}
	let pkg = match packages[pkgbase].as_table_mut() {
		Some(t) => t,
		None => {
			eprintln!(
				"Warning: 'packages.{}' in config is not a table; cannot prepare sources for edit.",
				pkgbase
			);
			return content.to_owned();
		}
	};

	// Ensure sources key exists.
	if !pkg.contains_key("sources") {
		pkg.insert("sources", Item::Value(Value::Array(Array::new())));
	}

	// Build the new hint block.
	let hint_block = format!(
		"{}\n\
		 # previous url: {}\n\
		 # new url: {}\n\
		 # Add a source pattern regex that matches both URLs above, then save.\n\
		 {}\n",
		HINT_HEADER, old_url, new_url, HINT_FOOTER
	);

	// Read the existing key prefix, strip any previous hint block, append new one.
	let mut key = pkg.key_mut("sources").unwrap();
	let existing_prefix = key
		.leaf_decor()
		.prefix()
		.and_then(|p| p.as_str())
		.unwrap_or("")
		.to_owned();

	let cleaned = strip_hint_block(&existing_prefix);
	let new_prefix = format!("{}{}", cleaned, hint_block);

	key.leaf_decor_mut().set_prefix(new_prefix);

	doc.to_string()
}

/// Remove a previous hint block (between HINT_HEADER and HINT_FOOTER inclusive)
/// from a decor prefix string, preserving everything else.
fn strip_hint_block(prefix: &str) -> String {
	let mut result = String::new();
	let mut in_hint = false;

	for line in prefix.lines() {
		if line.trim() == HINT_HEADER {
			in_hint = true;
			continue;
		}
		if line.trim() == HINT_FOOTER {
			in_hint = false;
			continue;
		}
		if !in_hint {
			result.push_str(line);
			result.push('\n');
		}
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fresh_empty_config() {
		let result = prepare_sources_in_text(
			"",
			"proton-mail-bin",
			"https://proton.me/download/mail/linux/1.12.1/ProtonMail-desktop-beta.deb",
			"https://proton.me/download/mail/linux/1.13.0/ProtonMail-desktop-beta.deb",
		);
		println!("{}", result);
		assert!(result.contains("[packages.proton-mail-bin]"));
		assert!(result.contains("sources = []"));
		assert!(result.contains("# previous url: https://proton.me/download/mail/linux/1.12.1/ProtonMail-desktop-beta.deb"));
		assert!(result.contains(
			"# new url: https://proton.me/download/mail/linux/1.13.0/ProtonMail-desktop-beta.deb"
		));
		assert!(result.contains(HINT_HEADER));
		assert!(result.contains(HINT_FOOTER));
	}

	#[test]
	fn existing_config_no_package_section() {
		let input = "\
sources = [
    'https://github\\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/archive/v?(?P<version>[^/]+)\\.tar\\.gz',
]
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://old.example.com/1.0.tar.gz",
			"https://new.example.com/2.0.tar.gz",
		);
		println!("{}", result);
		// Original content preserved.
		assert!(result.contains("'https://github\\.com"));
		// New section added.
		assert!(result.contains("[packages.my-pkg]"));
		assert!(result.contains("# previous url: https://old.example.com/1.0.tar.gz"));
	}

	#[test]
	fn existing_package_section_no_sources() {
		let input = "\
[packages.my-pkg]
auto_merge = false
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://old.example.com/1.0.tar.gz",
			"https://new.example.com/2.0.tar.gz",
		);
		println!("{}", result);
		assert!(result.contains("[packages.my-pkg]"));
		assert!(result.contains("auto_merge = false"));
		assert!(result.contains("sources = []"));
		assert!(result.contains("# previous url: https://old.example.com/1.0.tar.gz"));
	}

	#[test]
	fn existing_package_section_with_sources() {
		let input = "\
[packages.my-pkg]
sources = [
    'https://example\\.com/(?P<version>[^/]+)/file\\.tar\\.gz',
]
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://old.example.com/1.0.tar.gz",
			"https://new.example.com/2.0.tar.gz",
		);
		println!("{}", result);
		// Existing sources preserved.
		assert!(result.contains("'https://example\\.com/(?P<version>[^/]+)/file\\.tar\\.gz'"));
		// Hint block inserted.
		assert!(result.contains("# previous url: https://old.example.com/1.0.tar.gz"));
		// No duplicate sources key.
		assert_eq!(result.matches("sources").count(), 1);
	}

	#[test]
	fn repeated_edit_replaces_hint_block() {
		let input = "\
[packages.my-pkg]
# rua-source-hint-start
# previous url: https://old.example.com/1.0.tar.gz
# new url: https://old.example.com/2.0.tar.gz
# Add a source pattern regex that matches both URLs above, then save.
# rua-source-hint-end
sources = []
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://old.example.com/2.0.tar.gz",
			"https://old.example.com/3.0.tar.gz",
		);
		println!("{}", result);
		// Old hints gone.
		assert!(!result.contains("1.0.tar.gz"));
		// New hints present.
		assert!(result.contains("# previous url: https://old.example.com/2.0.tar.gz"));
		assert!(result.contains("# new url: https://old.example.com/3.0.tar.gz"));
		// Only one hint block.
		assert_eq!(result.matches(HINT_HEADER).count(), 1);
		assert_eq!(result.matches(HINT_FOOTER).count(), 1);
	}

	#[test]
	fn preserves_user_comments() {
		let input = "\
# My custom config
sources = [
    'https://github\\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/archive/v?(?P<version>[^/]+)\\.tar\\.gz',
]

# This package is special
[packages.my-pkg]
# I disabled auto-merge because reasons
auto_merge = false
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://old.example.com/1.0.tar.gz",
			"https://new.example.com/2.0.tar.gz",
		);
		println!("{}", result);
		assert!(result.contains("# My custom config"));
		assert!(result.contains("# This package is special"));
		assert!(result.contains("# I disabled auto-merge because reasons"));
	}

	#[test]
	fn preserves_user_comments_mixed_with_hint() {
		let input = "\
[packages.my-pkg]
# user added this manually
# rua-source-hint-start
# previous url: old
# new url: new
# Add a source pattern regex that matches both URLs above, then save.
# rua-source-hint-end
sources = [
    'https://example\\.com/(?P<version>[^/]+)\\.tar\\.gz',
]
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://updated.example.com/1.0.tar.gz",
			"https://updated.example.com/2.0.tar.gz",
		);
		println!("{}", result);
		assert!(result.contains("# user added this manually"));
		assert!(result.contains("# previous url: https://updated.example.com/1.0.tar.gz"));
		assert!(!result.contains("# previous url: old"));
		// User's existing source patterns preserved.
		assert!(result.contains("'https://example\\.com/(?P<version>[^/]+)\\.tar\\.gz'"));
	}

	#[test]
	fn does_not_affect_other_package_sections() {
		let input = "\
[packages.other-pkg]
auto_merge = false

[packages.my-pkg]
sources = []
";
		let result = prepare_sources_in_text(
			input,
			"my-pkg",
			"https://old.example.com/1.0.tar.gz",
			"https://new.example.com/2.0.tar.gz",
		);
		println!("{}", result);
		assert!(result.contains("[packages.other-pkg]"));
		assert!(result.contains("auto_merge = false"));
	}
}
