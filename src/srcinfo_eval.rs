use srcinfo::Srcinfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
	Low,
	#[allow(dead_code)]
	Medium,
	High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationName {
	Epoch,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
	pub name: EvaluationName,
	pub description: String,
	pub risk: RiskLevel,
	pub modified: bool,
}

pub fn evaluate_srcinfo_diff(previous: &Srcinfo, proposed: &Srcinfo) -> Vec<Evaluation> {
	vec![evaluate_epoch(previous, proposed)]
}

fn evaluate_epoch(previous: &Srcinfo, proposed: &Srcinfo) -> Evaluation {
	let prev_epoch = previous.epoch();
	let new_epoch = proposed.epoch();

	if prev_epoch == new_epoch {
		Evaluation {
			name: EvaluationName::Epoch,
			description: format!("Epoch unchanged ({})", epoch_display(prev_epoch)),
			risk: RiskLevel::Low,
			modified: false,
		}
	} else {
		Evaluation {
			name: EvaluationName::Epoch,
			description: format!(
				"Epoch changed from {} to {}",
				epoch_display(prev_epoch),
				epoch_display(new_epoch)
			),
			risk: RiskLevel::High,
			modified: true,
		}
	}
}

fn epoch_display(epoch: Option<&str>) -> &str {
	epoch.unwrap_or("None")
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	const BASE_SRCINFO: &str = "\
pkgbase = example
\tpkgdesc = An example package
\tpkgver = 1.0.0
\tpkgrel = 1
\tarch = x86_64
\tmd5sums = SKIP

pkgname = example
\tpkgdesc = An example package
";

	fn parse_base() -> Srcinfo {
		Srcinfo::from_str(BASE_SRCINFO)
			.expect("BASE_SRCINFO must be a valid .SRCINFO for tests to work")
	}

	fn with_modification(modify: impl FnOnce(&mut Srcinfo)) -> Srcinfo {
		let mut srcinfo = parse_base();
		modify(&mut srcinfo);
		srcinfo
	}

	fn find_eval(evaluations: &[Evaluation], name: EvaluationName) -> &Evaluation {
		evaluations
			.iter()
			.find(|e| e.name == name)
			.unwrap_or_else(|| {
				panic!(
					"Expected evaluation '{:?}' not found. Available evaluations: {:?}",
					name,
					evaluations.iter().map(|e| &e.name).collect::<Vec<_>>()
				)
			})
	}

	struct EpochCase {
		name: &'static str,
		previous: fn(&mut Srcinfo),
		proposed: fn(&mut Srcinfo),
		risk: RiskLevel,
		modified: bool,
	}

	#[test]
	fn test_epoch() {
		let cases = [
			EpochCase {
				name: "unchanged_both_none",
				previous: |_| {},
				proposed: |_| {},
				risk: RiskLevel::Low,
				modified: false,
			},
			EpochCase {
				name: "unchanged_both_set",
				previous: |s| s.base.epoch = Some("1".to_string()),
				proposed: |s| s.base.epoch = Some("1".to_string()),
				risk: RiskLevel::Low,
				modified: false,
			},
			EpochCase {
				name: "added",
				previous: |_| {},
				proposed: |s| s.base.epoch = Some("1".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
			EpochCase {
				name: "removed",
				previous: |s| s.base.epoch = Some("1".to_string()),
				proposed: |_| {},
				risk: RiskLevel::High,
				modified: true,
			},
			EpochCase {
				name: "incremented",
				previous: |s| s.base.epoch = Some("1".to_string()),
				proposed: |s| s.base.epoch = Some("2".to_string()),
				risk: RiskLevel::High,
				modified: true,
			},
		];

		for case in &cases {
			let previous = with_modification(case.previous);
			let proposed = with_modification(case.proposed);
			let evals = evaluate_srcinfo_diff(&previous, &proposed);
			let eval = find_eval(&evals, EvaluationName::Epoch);
			assert_eq!(eval.risk, case.risk, "case: {}", case.name);
			assert_eq!(eval.modified, case.modified, "case: {}", case.name);
		}
	}
}
