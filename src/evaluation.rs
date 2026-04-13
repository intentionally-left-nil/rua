use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
	Low,
	Medium,
	High,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationName {
	// --- SRCINFO fields ------------------------------------------------------
	Epoch,
	PackageSet,
	CheckDepends,
	MakeDepends,
	Depends,
	OptDepends,
	Provides,
	Conflicts,
	Replaces,
	Pkgver,
	Pkgrel,
	UnexplainedUpdate,
	Install,
	Url,
	Pkgdesc,
	Changelog,
	Arch,
	License,
	Groups,
	Backup,
	Options,
	ValidPgpKeys,
	NoExtract,
	InsecureChecksum,
	ChecksumConsistency,
	Source,
	ChecksumSkip,
	// --- PKGBUILD structure --------------------------------------------------
	/// A change to a bash function defined in the PKGBUILD (`prepare`, `build`, `check`, `package`, etc.)
	PkgbuildFunction,
	/// A change to a custom variable in the PKGBUILD (e.g. `_basekernver`) not covered by SRCINFO
	PkgbuildCustomVariable,
	/// Top-level code in the PKGBUILD outside of variable assignments and function definitions
	PkgbuildBareCode,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
	pub name: EvaluationName,
	pub pkgname: String,
	pub description: String,
	pub risk: RiskLevel,
	pub modified: bool,
}
