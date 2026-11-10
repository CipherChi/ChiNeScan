use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FindingInput {
    pub severity: String,
    pub confidence: f64,
    pub age_days: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModuleInput {
    pub module: String,
    pub checks_completed: u32,
    pub checks_total: u32,
    pub findings: Vec<FindingInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FindingBreakdown {
    pub severity: String,
    pub severity_weight: f64,
    pub confidence: f64,
    pub age_days: f64,
    pub decay_factor: f64,
    pub penalty: f64,
    pub explanation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScoreResult {
    pub module: String,
    pub inputs: ModuleInput,
    pub score: Option<u8>,
    pub checks_completed: u32,
    pub checks_total: u32,
    pub checks_not_assessed: u32,
    pub coverage_fraction: f64,
    pub coverage_penalty: f64,
    pub finding_penalty: f64,
    pub findings: Vec<FindingBreakdown>,
    pub formula: String,
    pub why_this_score: String,
}

fn weight(severity: &str) -> f64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 40.0,
        "high" => 25.0,
        "medium" => 14.0,
        "low" => 6.0,
        "info" => 2.0,
        _ => 0.0,
    }
}

pub fn score(input: ModuleInput) -> ScoreResult {
    let explicit_inputs = input.clone();
    let total = input.checks_total.max(input.checks_completed);
    let not_assessed = total.saturating_sub(input.checks_completed);
    let coverage = if total == 0 {
        0.0
    } else {
        (input.checks_completed as f64 / total as f64).clamp(0.0, 1.0)
    };
    let breakdown: Vec<FindingBreakdown> = input
        .findings
        .iter()
        .map(|f| {
            let w = weight(&f.severity);
            let confidence = f.confidence.clamp(0.0, 1.0);
            let age = f.age_days.max(0.0);
            let decay = 2_f64.powf(-age / 60.0);
            let penalty = w * confidence * decay;
            FindingBreakdown {
                severity: f.severity.clone(),
                severity_weight: w,
                confidence,
                age_days: age,
                decay_factor: decay,
                penalty,
                explanation: format!(
                    "{} severity × {:.2} confidence × {:.3} 60-day half-life decay",
                    f.severity, confidence, decay
                ),
            }
        })
        .collect();
    let finding_penalty = breakdown.iter().map(|f| f.penalty).sum::<f64>().min(100.0);
    let coverage_penalty = 50.0 * (1.0 - coverage);
    let scored = input.checks_completed > 0 && total > 0;
    let score = scored.then(|| {
        (100.0 - finding_penalty - coverage_penalty)
            .round()
            .clamp(0.0, 100.0) as u8
    });
    let why = if let Some(value) = score {
        format!("Score {value}/100 = 100 - {:.1} finding penalty - {:.1} coverage penalty. Based on {} checks, {} not assessed.", finding_penalty, coverage_penalty, input.checks_completed, not_assessed)
    } else {
        format!(
            "Not scored: no completed assessment. Based on 0 checks, {} not assessed.",
            total
        )
    };
    ScoreResult { module: input.module, inputs: explicit_inputs, score, checks_completed: input.checks_completed, checks_total: total, checks_not_assessed: not_assessed, coverage_fraction: coverage, coverage_penalty, finding_penalty, findings: breakdown, formula: "weights: critical=40, high=25, medium=14, low=6, info=2; clamp(round(100 - sum(severity_weight × confidence × 2^(-age_days/60)) - 50 × (1 - checks_completed/checks_total)), 0, 100); not scored until at least one check completes".into(), why_this_score: why }
}

pub fn score_json(request: &str) -> Result<String, serde_json::Error> {
    let modules: Vec<ModuleInput> = serde_json::from_str(request)?;
    serde_json::to_string(&modules.into_iter().map(score).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn coverage_and_missing_assessment_are_explicit() {
        let result = score(ModuleInput {
            module: "Code Assessment".into(),
            checks_completed: 1,
            checks_total: 4,
            findings: vec![],
        });
        assert_eq!(result.score, Some(63));
        assert_eq!(result.checks_not_assessed, 3);
        assert_eq!(result.inputs.checks_total, 4);
        assert!(result
            .why_this_score
            .contains("Based on 1 checks, 3 not assessed"));
        assert_eq!(
            score(ModuleInput {
                module: "Modules".into(),
                checks_completed: 0,
                checks_total: 0,
                findings: vec![]
            })
            .score,
            None
        );
    }

    proptest! {
        #[test]
        fn increasing_finding_severity_never_raises_score(
            existing in prop::collection::vec((0u8..=100, 0u8..=4), 0..15),
            lower_severity in 0u8..=4,
            severity_delta in 0u8..=4,
            confidence in 0.0f64..=1.0,
            age in 0.0f64..=3650.0
        ) {
            let names = ["info", "low", "medium", "high", "critical"];
            let findings: Vec<_> = existing.iter().map(|(a, s)| FindingInput { severity: names[*s as usize].into(), confidence: *a as f64 / 100.0, age_days: 30.0 }).collect();
            let higher_severity = (lower_severity + severity_delta).min(4);
            let mut lower = findings.clone();
            lower.push(FindingInput { severity: names[lower_severity as usize].into(), confidence, age_days: age });
            let mut higher = findings;
            higher.push(FindingInput { severity: names[higher_severity as usize].into(), confidence, age_days: age });
            let input = |findings| ModuleInput { module: "Code Assessment".into(), checks_completed: 10, checks_total: 10, findings };
            let lower_score = score(input(lower)).score.unwrap();
            let higher_score = score(input(higher)).score.unwrap();
            prop_assert!(higher_score <= lower_score);
        }
    }
}
