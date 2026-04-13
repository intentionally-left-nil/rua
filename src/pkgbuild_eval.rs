use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Parser;

use crate::evaluation::{Evaluation, EvaluationName, RiskLevel};

/// PKGBUILD variable names that correspond to fields emitted in .SRCINFO.
/// Changes to these are already validated by srcinfo_eval, so we skip them here.
const SRCINFO_VARS: &[&str] = &[
	"pkgname",
	"pkgbase",
	"pkgver",
	"pkgrel",
	"epoch",
	"pkgdesc",
	"url",
	"install",
	"changelog",
	"arch",
	"groups",
	"license",
	"noextract",
	"options",
	"backup",
	"validpgpkeys",
	"depends",
	"makedepends",
	"checkdepends",
	"optdepends",
	"provides",
	"conflicts",
	"replaces",
	"source",
	"b2sums",
	"sha512sums",
	"sha384sums",
	"sha256sums",
	"sha224sums",
	"sha1sums",
	"md5sums",
	"cksums",
];

/// Architecture names recognised by makepkg as valid `arch` array values.
/// Only variables with one of these exact suffixes (e.g. `source_x86_64`,
/// `depends_aarch64`) are treated as arch-specific SRCINFO variants.
/// An arbitrary suffix like `source_evil` is still flagged as a custom variable.
const KNOWN_ARCHS: &[&str] = &[
	"x86_64",
	"i686",
	"pentium4",
	"aarch64",
	"armv7h",
	"armv6h",
	"arm",
	"riscv64",
	"loong64",
	"powerpc",
	"powerpc64le",
	"mips64",
	"mips64el",
];

fn is_srcinfo_var(name: &str) -> bool {
	if SRCINFO_VARS.contains(&name) {
		return true;
	}
	for arch in KNOWN_ARCHS {
		if let Some(base) = name.strip_suffix(arch).and_then(|s| s.strip_suffix('_')) {
			if SRCINFO_VARS.contains(&base) {
				return true;
			}
		}
	}
	false
}

struct ParsedPkgbuild {
	functions: BTreeMap<String, String>,
	custom_variables: BTreeMap<String, String>,
	bare_code: Vec<String>,
}

fn parse_pkgbuild(source: &str) -> ParsedPkgbuild {
	let mut parser = Parser::new();
	let language: tree_sitter::Language = tree_sitter_bash::LANGUAGE.into();
	parser
		.set_language(&language)
		.expect("Failed to load tree-sitter-bash grammar");

	let tree = parser
		.parse(source, None)
		.expect("tree-sitter failed to produce a parse tree");
	let root = tree.root_node();

	let mut functions = BTreeMap::new();
	let mut custom_variables = BTreeMap::new();
	let mut bare_code = Vec::new();

	let mut cursor = root.walk();
	for child in root.named_children(&mut cursor) {
		match child.kind() {
			"comment" => {}
			"function_definition" => {
				if let Some(name_node) = child.child_by_field_name("name") {
					let name = &source[name_node.byte_range()];
					let body = source[child.byte_range()].to_string();
					functions.insert(name.to_string(), body);
				}
			}
			"variable_assignment" => {
				if let Some(name_node) = child.child_by_field_name("name") {
					let name = &source[name_node.byte_range()];
					if !is_srcinfo_var(name) {
						let value = source[child.byte_range()].to_string();
						custom_variables.insert(name.to_string(), value);
					}
				}
			}
			_ => {
				let text = source[child.byte_range()].trim().to_string();
				if !text.is_empty() {
					bare_code.push(text);
				}
			}
		}
	}

	ParsedPkgbuild {
		functions,
		custom_variables,
		bare_code,
	}
}

/// PKGBUILDs larger than this will not be parsed. A file this size is already
/// far beyond any legitimate package; attempting to parse it could consume
/// disproportionate memory.
const MAX_PKGBUILD_BYTES: usize = 1024 * 1024; // 1 MiB

/// Compare the PKGBUILD at the previous (`old`) and proposed (`new`) revisions
/// and return a list of [`Evaluation`]s covering:
///
/// * [`EvaluationName::PkgbuildFunction`] – one entry for every bash function
///   that appears in either version. Risk is `High` when modified. Function
///   bodies are compared as raw source text, so whitespace and comment changes
///   inside a function body are intentionally flagged.
///
/// * [`EvaluationName::PkgbuildCustomVariable`] – one entry for every
///   non-SRCINFO variable whose value changed, was added, or was removed.
///   Risk is `Medium`. Unchanged custom variables are not emitted.
///
/// * [`EvaluationName::PkgbuildBareCode`] – one entry when top-level
///   executable code outside functions and variable assignments exists in
///   either version. Risk is `High` when modified.
///
/// If either PKGBUILD exceeds [`MAX_PKGBUILD_BYTES`], a single `High`-risk
/// [`EvaluationName::PkgbuildBareCode`] evaluation is returned instead of
/// attempting a full parse. A byte-equality check is still performed so that
/// an oversized but unchanged file is reported as `Low` risk / not modified.
pub fn evaluate_pkgbuild_diff(
	old_pkgbuild: &str,
	new_pkgbuild: &str,
	pkgbase: &str,
) -> Vec<Evaluation> {
	let old_len = old_pkgbuild.len();
	let new_len = new_pkgbuild.len();
	if old_len > MAX_PKGBUILD_BYTES || new_len > MAX_PKGBUILD_BYTES {
		let modified = old_pkgbuild != new_pkgbuild;
		let description = format!(
			"PKGBUILD too large to analyze (old: {} bytes, new: {} bytes); {}",
			old_len,
			new_len,
			if modified {
				"contents changed, manual review required"
			} else {
				"contents unchanged"
			},
		);
		return vec![Evaluation {
			name: EvaluationName::PkgbuildBareCode,
			pkgname: pkgbase.to_string(),
			description,
			risk: if modified {
				RiskLevel::High
			} else {
				RiskLevel::Low
			},
			modified,
		}];
	}

	let old = parse_pkgbuild(old_pkgbuild);
	let new = parse_pkgbuild(new_pkgbuild);

	let mut evaluations = Vec::new();

	let all_function_names: BTreeSet<&String> =
		old.functions.keys().chain(new.functions.keys()).collect();

	for func_name in all_function_names {
		let old_body = old.functions.get(func_name);
		let new_body = new.functions.get(func_name);

		let modified = old_body != new_body;
		let (risk, description) = match (old_body, new_body, modified) {
			(None, Some(_), _) => (RiskLevel::High, format!("{}() added", func_name)),
			(Some(_), None, _) => (RiskLevel::High, format!("{}() removed", func_name)),
			(_, _, true) => (RiskLevel::High, format!("{}() changed", func_name)),
			_ => (RiskLevel::Low, format!("{}() unchanged", func_name)),
		};

		evaluations.push(Evaluation {
			name: EvaluationName::PkgbuildFunction,
			pkgname: pkgbase.to_string(),
			description,
			risk,
			modified,
		});
	}

	let all_var_names: BTreeSet<&String> = old
		.custom_variables
		.keys()
		.chain(new.custom_variables.keys())
		.collect();

	for var_name in all_var_names {
		let old_val = old.custom_variables.get(var_name);
		let new_val = new.custom_variables.get(var_name);

		if old_val == new_val {
			continue;
		}

		let description = match (old_val, new_val) {
			(None, Some(_)) => format!("{} added", var_name),
			(Some(_), None) => format!("{} removed", var_name),
			_ => format!("{} changed", var_name),
		};

		evaluations.push(Evaluation {
			name: EvaluationName::PkgbuildCustomVariable,
			pkgname: pkgbase.to_string(),
			description,
			risk: RiskLevel::Medium,
			modified: true,
		});
	}

	if !old.bare_code.is_empty() || !new.bare_code.is_empty() {
		let modified = old.bare_code != new.bare_code;
		let (risk, description) = if !modified {
			(
				RiskLevel::Low,
				"Bare code (outside functions) present but unchanged".to_string(),
			)
		} else if old.bare_code.is_empty() {
			(
				RiskLevel::High,
				"Bare code (outside functions) added".to_string(),
			)
		} else if new.bare_code.is_empty() {
			(
				RiskLevel::High,
				"Bare code (outside functions) removed".to_string(),
			)
		} else {
			(
				RiskLevel::High,
				"Bare code (outside functions) changed".to_string(),
			)
		};

		evaluations.push(Evaluation {
			name: EvaluationName::PkgbuildBareCode,
			pkgname: pkgbase.to_string(),
			description,
			risk,
			modified,
		});
	}

	evaluations
}

#[cfg(test)]
mod tests {
	use super::*;

	const BASE_PKGBUILD: &str = r#"# Maintainer: Someone <someone@example.com>
pkgname=example
pkgver=1.0.0
pkgrel=1
pkgdesc="An example package"
arch=('x86_64')
url="https://example.com"
license=('MIT')
source=("https://example.com/$pkgname-$pkgver.tar.gz")
sha256sums=('abcdef1234567890')

prepare() {
	cd "$srcdir/$pkgname-$pkgver"
	patch -p1 < ../fix.patch
}

build() {
	cd "$srcdir/$pkgname-$pkgver"
	./configure --prefix=/usr
	make
}

check() {
	cd "$srcdir/$pkgname-$pkgver"
	make test
}

package() {
	cd "$srcdir/$pkgname-$pkgver"
	make DESTDIR="$pkgdir" install
}
"#;

	fn with_text_change(from: &str, to: &str) -> String {
		BASE_PKGBUILD.replacen(from, to, 1)
	}

	fn find_eval<'a>(
		evaluations: &'a [Evaluation],
		name: EvaluationName,
		desc_contains: &str,
	) -> &'a Evaluation {
		evaluations
			.iter()
			.find(|e| e.name == name && e.description.contains(desc_contains))
			.unwrap_or_else(|| {
				panic!(
					"Expected evaluation {:?} containing '{}' not found in: {:#?}",
					name,
					desc_contains,
					evaluations
						.iter()
						.map(|e| (&e.name, &e.description))
						.collect::<Vec<_>>()
				)
			})
	}

	#[test]
	fn test_unchanged_produces_no_modified_evals() {
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, BASE_PKGBUILD, "example");
		let modified: Vec<_> = evals.iter().filter(|e| e.modified).collect();
		assert!(
			modified.is_empty(),
			"Expected no modified evaluations for unchanged PKGBUILD, got: {:#?}",
			modified
		);
	}

	#[test]
	fn test_unchanged_emits_function_evals_for_all_functions() {
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, BASE_PKGBUILD, "example");
		for func in &["prepare", "build", "check", "package"] {
			let e = find_eval(&evals, EvaluationName::PkgbuildFunction, func);
			assert!(!e.modified, "{func}() should not be modified");
			assert_eq!(e.risk, RiskLevel::Low);
		}
	}

	#[test]
	fn test_comment_change_produces_no_evals() {
		let new = with_text_change(
			"# Maintainer: Someone <someone@example.com>",
			"# Maintainer: New Person <new@example.com>",
		);
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let modified: Vec<_> = evals.iter().filter(|e| e.modified).collect();
		assert!(
			modified.is_empty(),
			"Comment-only change should produce no modified evaluations, got: {:#?}",
			modified
		);
	}

	#[test]
	fn test_function_body_changed() {
		let new = with_text_change(
			"make DESTDIR=\"$pkgdir\" install",
			"make DESTDIR=\"$pkgdir\" install\n\tinstall -Dm644 LICENSE \"$pkgdir/usr/share/licenses/$pkgname/LICENSE\"",
		);
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildFunction, "package");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
		assert!(
			e.description.contains("changed"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_function_added() {
		let new = BASE_PKGBUILD.to_string()
			+ "\nverify() {\n\tgpg --verify \"$srcdir/$pkgname-$pkgver.tar.gz.sig\"\n}\n";
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildFunction, "verify");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
		assert!(
			e.description.contains("added"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_function_removed() {
		let new = with_text_change(
			"\ncheck() {\n\tcd \"$srcdir/$pkgname-$pkgver\"\n\tmake test\n}\n",
			"",
		);
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildFunction, "check");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
		assert!(
			e.description.contains("removed"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_prepare_function_changed() {
		let new = with_text_change(
			"patch -p1 < ../fix.patch",
			"patch -p1 < ../fix.patch\n\tpatch -p1 < ../evil.patch",
		);
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildFunction, "prepare");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}

	#[test]
	fn test_split_package_function_added() {
		let new = BASE_PKGBUILD.to_string()
			+ "\npackage_lib() {\n\tmake -C lib DESTDIR=\"$pkgdir\" install\n}\n";
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildFunction, "package_lib");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
		assert!(
			e.description.contains("added"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_custom_helper_function_changed() {
		let old = BASE_PKGBUILD.to_string() + "\n_build_lib() {\n\tmake -C lib\n}\n";
		let new = BASE_PKGBUILD.to_string() + "\n_build_lib() {\n\tmake -C lib CFLAGS=-O3\n}\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildFunction, "_build_lib");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}

	#[test]
	fn test_custom_array_variable_changed() {
		let old = BASE_PKGBUILD.to_string() + "\n_patches=()\n";
		let new = BASE_PKGBUILD.to_string() + "\n_patches=(fix.patch evil.patch)\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildCustomVariable, "_patches");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::Medium);
	}

	#[test]
	fn test_custom_variable_changed() {
		let old = BASE_PKGBUILD.to_string() + "\n_basekernver=5.15\n";
		let new = BASE_PKGBUILD.to_string() + "\n_basekernver=6.1\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let e = find_eval(
			&evals,
			EvaluationName::PkgbuildCustomVariable,
			"_basekernver",
		);
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::Medium);
		assert!(
			e.description.contains("changed"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_custom_variable_added() {
		let new = BASE_PKGBUILD.to_string() + "\n_gitcommit=abc1234\n";
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildCustomVariable, "_gitcommit");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::Medium);
		assert!(
			e.description.contains("added"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_custom_variable_removed() {
		let old = BASE_PKGBUILD.to_string() + "\n_gitcommit=abc1234\n";
		let evals = evaluate_pkgbuild_diff(&old, BASE_PKGBUILD, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildCustomVariable, "_gitcommit");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::Medium);
		assert!(
			e.description.contains("removed"),
			"description: {}",
			e.description
		);
	}

	#[test]
	fn test_custom_variable_unchanged_not_emitted() {
		let old = BASE_PKGBUILD.to_string() + "\n_basekernver=5.15\n";
		let new = BASE_PKGBUILD.to_string() + "\n_basekernver=5.15\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let found = evals.iter().any(|e| {
			e.name == EvaluationName::PkgbuildCustomVariable
				&& e.description.contains("_basekernver")
		});
		assert!(
			!found,
			"Unchanged custom variable should not produce an evaluation"
		);
	}

	#[test]
	fn test_srcinfo_variable_change_not_evaluated() {
		let new = with_text_change("pkgver=1.0.0", "pkgver=2.0.0");
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let found = evals
			.iter()
			.any(|e| e.name == EvaluationName::PkgbuildCustomVariable);
		assert!(
			!found,
			"SRCINFO variables (pkgver) must not produce PkgbuildCustomVariable evaluations"
		);
	}

	#[test]
	fn test_arch_specific_srcinfo_variable_not_evaluated() {
		let old =
			BASE_PKGBUILD.to_string() + "\nsource_x86_64=(\"https://example.com/x86.tar.gz\")\n";
		let new = BASE_PKGBUILD.to_string()
			+ "\nsource_x86_64=(\"https://example.com/x86-2.0.tar.gz\")\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let found = evals.iter().any(|e| {
			e.name == EvaluationName::PkgbuildCustomVariable
				&& e.description.contains("source_x86_64")
		});
		assert!(
			!found,
			"Arch-specific SRCINFO variables must not produce PkgbuildCustomVariable evaluations"
		);
	}

	/// A variable whose name begins with an SRCINFO var name but uses an
	/// arbitrary (non-arch) suffix must still be treated as a custom variable.
	#[test]
	fn test_srcinfo_var_with_unknown_suffix_is_flagged() {
		let old = BASE_PKGBUILD.to_string() + "\nsource_evil=https://evil.example.com\n";
		let new = BASE_PKGBUILD.to_string() + "\nsource_evil=https://very-evil.example.com\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let e = find_eval(
			&evals,
			EvaluationName::PkgbuildCustomVariable,
			"source_evil",
		);
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::Medium);
	}

	#[test]
	fn test_depends_with_unknown_suffix_is_flagged() {
		let old = BASE_PKGBUILD.to_string() + "\ndepends_injection=(old)\n";
		let new = BASE_PKGBUILD.to_string() + "\ndepends_injection=(new)\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let e = find_eval(
			&evals,
			EvaluationName::PkgbuildCustomVariable,
			"depends_injection",
		);
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::Medium);
	}

	#[test]
	fn test_bare_code_added() {
		let new = BASE_PKGBUILD.to_string() + "\necho \"Injected command\"\n";
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildBareCode, "added");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}

	#[test]
	fn test_bare_code_removed() {
		let old = BASE_PKGBUILD.to_string() + "\necho \"Old injected command\"\n";
		let evals = evaluate_pkgbuild_diff(&old, BASE_PKGBUILD, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildBareCode, "removed");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}

	#[test]
	fn test_bare_code_changed() {
		let old = BASE_PKGBUILD.to_string() + "\necho \"old\"\n";
		let new = BASE_PKGBUILD.to_string() + "\necho \"new\"\n";
		let evals = evaluate_pkgbuild_diff(&old, &new, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildBareCode, "changed");
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}

	#[test]
	fn test_bare_code_unchanged_is_low_risk() {
		let pkgbuild_with_bare = BASE_PKGBUILD.to_string() + "\necho \"stable code\"\n";
		let evals = evaluate_pkgbuild_diff(&pkgbuild_with_bare, &pkgbuild_with_bare, "example");
		let e = find_eval(&evals, EvaluationName::PkgbuildBareCode, "unchanged");
		assert!(!e.modified);
		assert_eq!(e.risk, RiskLevel::Low);
	}

	#[test]
	fn test_no_bare_code_produces_no_bare_code_eval() {
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, BASE_PKGBUILD, "example");
		let found = evals
			.iter()
			.any(|e| e.name == EvaluationName::PkgbuildBareCode);
		assert!(
			!found,
			"PKGBUILD with no bare code should produce no PkgbuildBareCode evaluation"
		);
	}

	#[test]
	fn test_pkgbase_propagated_to_all_evals() {
		let new = with_text_change(
			"make DESTDIR=\"$pkgdir\" install",
			"make DESTDIR=\"$pkgdir\" install\n\ttouch \"$pkgdir/injected\"",
		);
		let evals = evaluate_pkgbuild_diff(BASE_PKGBUILD, &new, "mypkg");
		for eval in &evals {
			assert_eq!(eval.pkgname, "mypkg", "pkgname mismatch on {:?}", eval);
		}
	}

	#[test]
	fn test_oversized_pkgbuild_changed_is_high_risk() {
		let big: String = "x".repeat(MAX_PKGBUILD_BYTES + 1);
		let bigger: String = "y".repeat(MAX_PKGBUILD_BYTES + 1);
		let evals = evaluate_pkgbuild_diff(&big, &bigger, "example");
		assert_eq!(evals.len(), 1);
		let e = &evals[0];
		assert_eq!(e.name, EvaluationName::PkgbuildBareCode);
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}

	#[test]
	fn test_oversized_pkgbuild_unchanged_is_low_risk() {
		let big: String = "x".repeat(MAX_PKGBUILD_BYTES + 1);
		let evals = evaluate_pkgbuild_diff(&big, &big, "example");
		assert_eq!(evals.len(), 1);
		let e = &evals[0];
		assert_eq!(e.name, EvaluationName::PkgbuildBareCode);
		assert!(!e.modified);
		assert_eq!(e.risk, RiskLevel::Low);
	}

	#[test]
	fn test_one_oversized_pkgbuild_is_high_risk() {
		let normal = BASE_PKGBUILD.to_string();
		let big: String = "x".repeat(MAX_PKGBUILD_BYTES + 1);
		let evals = evaluate_pkgbuild_diff(&normal, &big, "example");
		assert_eq!(evals.len(), 1);
		let e = &evals[0];
		assert!(e.modified);
		assert_eq!(e.risk, RiskLevel::High);
	}
}
