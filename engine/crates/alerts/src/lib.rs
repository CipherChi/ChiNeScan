use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Signal {
    pub key: String,
    pub kind: String,
    pub summary: String,
    pub module: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AlertRuleMatch {
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub module: String,
}

pub fn evaluate(signals: Vec<Signal>) -> Vec<AlertRuleMatch> {
    let mut matches = Vec::new();
    for signal in signals {
        let rule = match signal.kind.as_str() {
            "critical_finding" => {
                Some(("new_critical_finding", "New critical finding", "critical"))
            }
            "malware_hit" => Some(("malware_triage_hit", "Malware triage hit", "high")),
            "scan_failure" => Some(("scan_failure", "Assessment failed", "high")),
            "authorization_block" => Some((
                "authorization_guard_block",
                "Authorization guard blocked action",
                "medium",
            )),
            "repeated_auth_failure" => Some((
                "repeated_auth_failures",
                "Repeated authentication failures",
                "high",
            )),
            _ => None,
        };
        if let Some((rule_id, title, severity)) = rule {
            matches.push(AlertRuleMatch {
                fingerprint: format!("{rule_id}:{}", signal.key),
                rule_id: rule_id.into(),
                title: title.into(),
                severity: severity.into(),
                description: signal.summary.chars().take(500).collect(),
                module: signal.module,
            });
        }
    }
    matches.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    matches.dedup_by(|a, b| a.fingerprint == b.fingerprint);
    matches
}

pub fn evaluate_json(request: &str) -> Result<String, serde_json::Error> {
    let signals: Vec<Signal> = serde_json::from_str(request)?;
    serde_json::to_string(&evaluate(signals))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn rule_matches_are_deduplicated_by_deterministic_fingerprint() {
        let signals = vec![
            Signal {
                key: "f1".into(),
                kind: "critical_finding".into(),
                summary: "critical finding".into(),
                module: "Code Assessment".into()
            };
            2
        ];
        let alerts = evaluate(signals);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "new_critical_finding");
    }

    proptest! {
        #[test]
        fn duplicate_signal_keys_never_create_duplicate_alerts(keys in prop::collection::vec("[a-z0-9]{1,16}", 0..100)) {
            let expected = keys.iter().collect::<std::collections::HashSet<_>>().len();
            let signals = keys.into_iter().map(|key| Signal {
                key,
                kind: "critical_finding".into(),
                summary: "local finding".into(),
                module: "Code Assessment".into(),
            }).collect();
            prop_assert_eq!(evaluate(signals).len(), expected);
        }
    }
}
