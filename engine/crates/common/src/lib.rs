#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Evidence {
    pub message: String,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub normalized: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    #[serde(default)]
    pub title: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub epss: Option<f64>,
    #[serde(default)]
    pub kev: Option<bool>,
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanMetadata {
    pub scan_id: String,
    #[serde(default)]
    pub tool_version: String,
    #[serde(default)]
    pub rule_version: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub methodology: String,
    #[serde(default)]
    pub not_assessed: Vec<String>,
}
