use crate::evaluation::{EvaluationName, RiskLevel};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
pub struct EvaluationConfig {
	pub threshold: Option<RiskLevel>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RuaConfig {
	#[serde(default)]
	pub sources: Vec<String>,
	#[serde(default)]
	pub evaluations: HashMap<EvaluationName, EvaluationConfig>,
	#[serde(default)]
	pub packages: HashMap<String, PackageConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PackageConfig {
	#[serde(default)]
	pub sources: Vec<String>,
	#[serde(default)]
	pub evaluations: HashMap<EvaluationName, EvaluationConfig>,
	/// Set to `false` to disable auto-merge for this package entirely.
	/// Use `--no-auto-merge` on the command line to disable globally for a run.
	pub auto_merge: Option<bool>,
}

impl RuaConfig {
	pub fn load(config_path: &Path) -> RuaConfig {
		if !config_path.exists() {
			return RuaConfig::default();
		}
		let text = match std::fs::read_to_string(config_path) {
			Ok(t) => t,
			Err(e) => {
				eprintln!(
					"Warning: failed to read config file {:?}: {}",
					config_path, e
				);
				return RuaConfig::default();
			}
		};
		match toml::from_str(&text) {
			Ok(c) => c,
			Err(e) => {
				eprintln!(
					"Warning: failed to parse config file {:?}: {}",
					config_path, e
				);
				RuaConfig::default()
			}
		}
	}

	/// Returns compiled regex patterns for `pkgbase`, merging global patterns
	/// with any per-package overrides. Invalid regex strings are skipped with a warning.
	pub fn compiled_source_patterns(&self, pkgbase: &str) -> Vec<Regex> {
		self.sources
			.iter()
			.map(String::as_str)
			.chain(
				self.packages
					.get(pkgbase)
					.map(|p| p.sources.iter().map(String::as_str))
					.into_iter()
					.flatten(),
			)
			.filter_map(|s| match Regex::new(s) {
				Ok(r) => Some(r),
				Err(e) => {
					eprintln!("Warning: invalid source pattern {:?}: {}", s, e);
					None
				}
			})
			.collect()
	}
}
