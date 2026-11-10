#![forbid(unsafe_code)]

use chinescan_common::{Finding, ScanMetadata, Severity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum ReporterError {
    InvalidRequest,
    UnsupportedFormat,
    InvalidCvssVector,
    Serialization,
}

impl std::fmt::Display for ReporterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidRequest => "invalid report request",
            Self::UnsupportedFormat => "unsupported report format",
            Self::InvalidCvssVector => "invalid CVSS vector",
            Self::Serialization => "serialization failed",
        };
        f.write_str(message)
    }
}
impl std::error::Error for ReporterError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReportRequest {
    pub format: String,
    pub metadata: ScanMetadata,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub previous_findings: Vec<Finding>,
    /// CWE labels supplied from an operator-imported local catalog.
    #[serde(default)]
    pub cwe_map: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReportResponse {
    pub content: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct ReportBody<'a> {
    schema: &'static str,
    executive_summary: String,
    metadata: &'a ScanMetadata,
    findings: Vec<ReportFinding>,
    diff: Diff,
    manifest: Manifest,
}
#[derive(Clone, Debug, Serialize)]
struct ReportFinding {
    #[serde(flatten)]
    finding: Finding,
    fingerprint: String,
    state: String,
    cwe_names: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize)]
struct Diff {
    new: Vec<String>,
    persisting: Vec<String>,
    fixed: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
struct Manifest {
    algorithm: &'static str,
    sha256: String,
}

pub fn render_json(request: &ReportRequest) -> Result<ReportResponse, ReporterError> {
    validate_request(request)?;
    let current = report_findings(
        &request.findings,
        &request.previous_findings,
        &request.cwe_map,
    );
    let diff = diff_findings(&request.findings, &request.previous_findings);
    let unsigned = ReportBody {
        schema: "chinescan.report/1",
        executive_summary: format!(
            "{} findings in scan {}.",
            current.len(),
            request.metadata.scan_id
        ),
        metadata: &request.metadata,
        findings: current,
        diff,
        manifest: Manifest {
            algorithm: "SHA-256",
            sha256: String::new(),
        },
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(|_| ReporterError::Serialization)?;
    let digest = hex(&Sha256::digest(canonical));
    let body = ReportBody {
        manifest: Manifest {
            algorithm: "SHA-256",
            sha256: digest.clone(),
        },
        ..unsigned
    };
    let content = serde_json::to_string_pretty(&body).map_err(|_| ReporterError::Serialization)?;
    Ok(ReportResponse {
        content,
        sha256: digest,
    })
}

pub fn render(request: &ReportRequest) -> Result<ReportResponse, ReporterError> {
    validate_request(request)?;
    if request.format == "sarif" {
        return render_sarif(request);
    }
    if request.format == "json" {
        return render_json(request);
    }
    let findings = report_findings(
        &request.findings,
        &request.previous_findings,
        &request.cwe_map,
    );
    let diff = diff_findings(&request.findings, &request.previous_findings);
    let body = serde_json::to_value(ReportBody {
        schema: "chinescan.report/1",
        executive_summary: format!(
            "{} findings in scan {}.",
            findings.len(),
            request.metadata.scan_id
        ),
        metadata: &request.metadata,
        findings,
        diff,
        manifest: Manifest {
            algorithm: "SHA-256",
            sha256: String::new(),
        },
    })
    .map_err(|_| ReporterError::Serialization)?;
    let digest = hex(&Sha256::digest(
        serde_json::to_vec(&body).map_err(|_| ReporterError::Serialization)?,
    ));
    let mut content = match request.format.as_str() {
        "csv" => csv(request, &digest),
        "markdown" => markdown(request),
        "html" => html_report(request),
        _ => return Err(ReporterError::UnsupportedFormat),
    };
    match request.format.as_str() {
        "csv" => {}
        "markdown" => content.push_str(&format!("\n<!-- SHA-256 manifest: {digest} -->\n")),
        "html" => {
            content = content.replace(
                "</head>",
                &format!("<meta name=\"report-sha256\" content=\"{digest}\"></head>"),
            )
        }
        _ => {}
    }
    Ok(ReportResponse {
        content,
        sha256: digest,
    })
}

fn validate_request(request: &ReportRequest) -> Result<(), ReporterError> {
    if request.metadata.scan_id.len() > 256
        || request.findings.len() > 10_000
        || request.previous_findings.len() > 10_000
        || request.cwe_map.len() > 10_000
    {
        return Err(ReporterError::InvalidRequest);
    }
    if !["json", "csv", "markdown", "html", "sarif"].contains(&request.format.as_str()) {
        return Err(ReporterError::UnsupportedFormat);
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value
        .replace('\\', "/")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}
fn fingerprint(finding: &Finding) -> String {
    let location = normalized(finding.location.as_deref().unwrap_or(""));
    let evidence = finding
        .evidence
        .iter()
        .map(|item| normalized(item.normalized.as_deref().unwrap_or(&item.message)))
        .collect::<Vec<_>>()
        .join("\n");
    let input = format!(
        "{}\0{}\0{}",
        finding.rule_id.trim().to_lowercase(),
        location,
        evidence
    );
    hex(&Sha256::digest(input.as_bytes()))
}
fn report_findings(
    current: &[Finding],
    previous: &[Finding],
    cwe_map: &BTreeMap<String, String>,
) -> Vec<ReportFinding> {
    let old: std::collections::BTreeSet<_> = previous.iter().map(fingerprint).collect();
    current
        .iter()
        .cloned()
        .map(|mut finding| {
            if let Some(vector) = finding.cvss_vector.as_deref() {
                finding.cvss_score = cvss_v31(vector).ok();
            }
            let fp = fingerprint(&finding);
            let state = if old.contains(&fp) {
                "persisting"
            } else {
                "new"
            }
            .to_owned();
            ReportFinding {
                cwe_names: finding
                    .cwe_ids
                    .iter()
                    .filter_map(|id| cwe_map.get(id).map(|name| (id.clone(), name.clone())))
                    .collect(),
                finding,
                fingerprint: fp,
                state,
            }
        })
        .collect()
}
fn diff_findings(current: &[Finding], previous: &[Finding]) -> Diff {
    let now: BTreeMap<_, _> = current.iter().map(|f| (fingerprint(f), ())).collect();
    let old: BTreeMap<_, _> = previous.iter().map(|f| (fingerprint(f), ())).collect();
    Diff {
        new: now
            .keys()
            .filter(|key| !old.contains_key(*key))
            .cloned()
            .collect(),
        persisting: now
            .keys()
            .filter(|key| old.contains_key(*key))
            .cloned()
            .collect(),
        fixed: old
            .keys()
            .filter(|key| !now.contains_key(*key))
            .cloned()
            .collect(),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn csv_cell(value: &str) -> String {
    let safe = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!(
        "\"{}\"",
        safe.replace('"', "\"\"").replace(['\r', '\n'], " ")
    )
}
fn csv(request: &ReportRequest, manifest: &str) -> String {
    let mut out = String::from(
        "rule_id,severity,location,evidence,remediation,fingerprint,manifest_sha256\r\n",
    );
    for item in report_findings(
        &request.findings,
        &request.previous_findings,
        &request.cwe_map,
    ) {
        let evidence = item
            .finding
            .evidence
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let cells = [
            item.finding.rule_id,
            format!("{:?}", item.finding.severity).to_lowercase(),
            item.finding.location.unwrap_or_default(),
            evidence,
            item.finding.remediation.unwrap_or_default(),
            item.fingerprint,
            manifest.to_owned(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|s| csv_cell(s))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}
fn markdown(request: &ReportRequest) -> String {
    let mut out = format!("# Security report: {}\n\n## Executive summary\n\n{} findings.\n\n## Scope and methodology\n\n{}\n\n{}\n\n## What was not assessed\n\n", request.metadata.scan_id, request.findings.len(), md(&request.metadata.scope), md(&request.metadata.methodology));
    for item in &request.metadata.not_assessed {
        out.push_str(&format!("- {}\n", md(item)));
    }
    out.push_str("\n## Findings\n\n");
    for item in report_findings(
        &request.findings,
        &request.previous_findings,
        &request.cwe_map,
    ) {
        out.push_str(&format!("### {}\n\n- Severity: {:?}\n- Rule: `{}`\n- Location: `{}`\n- Evidence: {}\n- Remediation: {}\n- Fingerprint: `{}` ({})\n\n", md(&item.finding.title), item.finding.severity, md(&item.finding.rule_id), md(item.finding.location.as_deref().unwrap_or("unspecified")), md(&item.finding.evidence.iter().map(|e| e.message.as_str()).collect::<Vec<_>>().join("; ")), md(item.finding.remediation.as_deref().unwrap_or("Not supplied")), item.fingerprint, item.state));
    }
    out
}
fn md(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace('`', "\\`")
}
fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn html_report(request: &ReportRequest) -> String {
    let mut out = format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'\"><title>{}</title></head><body><h1>{}</h1><h2>Executive summary</h2><p>{} findings</p><h2>Scope and methodology</h2><p>{}</p><p>{}</p><h2>What was not assessed</h2><ul>", html_escape(&request.metadata.scan_id), html_escape(&request.metadata.scan_id), request.findings.len(), html_escape(&request.metadata.scope), html_escape(&request.metadata.methodology));
    for item in &request.metadata.not_assessed {
        out.push_str(&format!("<li>{}</li>", html_escape(item)));
    }
    out.push_str("</ul><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Rule</th><th>Location</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>");
    for item in &request.findings {
        let ev = item
            .evidence
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        out.push_str(&format!(
            "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            item.severity,
            html_escape(&item.title),
            html_escape(&item.rule_id),
            html_escape(item.location.as_deref().unwrap_or("")),
            html_escape(&ev),
            html_escape(item.remediation.as_deref().unwrap_or(""))
        ));
    }
    out.push_str("</tbody></table></body></html>");
    out
}
fn level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
fn render_sarif(request: &ReportRequest) -> Result<ReportResponse, ReporterError> {
    let results: Vec<_> = request.findings.iter().map(|f| serde_json::json!({
        "ruleId": f.rule_id, "level": level(&f.severity),
        "message": {"text": format!("{}: {}", f.title, f.evidence.iter().map(|e| e.message.as_str()).collect::<Vec<_>>().join("; "))},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.location.as_deref().unwrap_or("unspecified")}}}],
        "partialFingerprints": {"chinescan/v1": fingerprint(f)},
        "properties": {"severity": format!("{:?}", f.severity).to_lowercase(), "remediation": f.remediation, "cweIds": f.cwe_ids}
    })).collect();
    let rules: BTreeMap<_, _> = request
        .findings
        .iter()
        .map(|f| {
            (
                f.rule_id.clone(),
                serde_json::json!({"id": f.rule_id, "shortDescription": {"text": f.title}}),
            )
        })
        .collect();
    let sarif = serde_json::json!({ "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ChiNeScan", "version": request.metadata.tool_version, "rules": rules.values().collect::<Vec<_>>()}}, "results": results, "properties": {"scanId": request.metadata.scan_id, "scope": request.metadata.scope, "methodology": request.metadata.methodology, "notAssessed": request.metadata.not_assessed}}] });
    let content = serde_json::to_string_pretty(&sarif).map_err(|_| ReporterError::Serialization)?;
    Ok(ReportResponse {
        sha256: hex(&Sha256::digest(content.as_bytes())),
        content,
    })
}

pub fn cvss_v31(vector: &str) -> Result<f64, ReporterError> {
    let parts: Vec<_> = vector
        .strip_prefix("CVSS:3.1/")
        .ok_or(ReporterError::InvalidCvssVector)?
        .split('/')
        .collect();
    let mut m = BTreeMap::new();
    for part in parts {
        let (k, v) = part
            .split_once(':')
            .ok_or(ReporterError::InvalidCvssVector)?;
        m.insert(k, v);
    }
    let get = |key: &str| m.get(key).copied().ok_or(ReporterError::InvalidCvssVector);
    let av = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return Err(ReporterError::InvalidCvssVector),
    };
    let ac = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return Err(ReporterError::InvalidCvssVector),
    };
    let scope = get("S")?;
    if !["U", "C"].contains(&scope) {
        return Err(ReporterError::InvalidCvssVector);
    }
    let pr = match (get("PR")?, scope) {
        ("N", _) => 0.85,
        ("L", "U") => 0.62,
        ("H", "U") => 0.27,
        ("L", "C") => 0.68,
        ("H", "C") => 0.5,
        _ => return Err(ReporterError::InvalidCvssVector),
    };
    let ui = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return Err(ReporterError::InvalidCvssVector),
    };
    let impact_metric = |key: &str| -> Result<f64, ReporterError> {
        Ok(match get(key)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return Err(ReporterError::InvalidCvssVector),
        })
    };
    let c = impact_metric("C")?;
    let i = impact_metric("I")?;
    let a = impact_metric("A")?;
    let impact = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    if impact == 0.0 {
        return Ok(0.0);
    }
    let impact_sub = if scope == "U" {
        6.42 * impact
    } else {
        7.52 * (impact - 0.029) - 3.25 * (impact - 0.02).powf(15.0)
    };
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope == "U" {
        (impact_sub + exploitability).min(10.0)
    } else {
        (1.08 * (impact_sub + exploitability)).min(10.0)
    };
    Ok(round_up(base))
}
fn round_up(value: f64) -> f64 {
    ((value * 10.0).ceil() / 10.0).min(10.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chinescan_common::{Evidence, Severity};
    use proptest::prelude::*;
    fn f(rule: &str, loc: &str, ev: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            title: "test".into(),
            severity: Severity::High,
            confidence: 0.9,
            location: Some(loc.into()),
            evidence: vec![Evidence {
                message: ev.into(),
                location: None,
                normalized: None,
            }],
            remediation: Some("fix".into()),
            cwe_ids: vec![],
            cvss_vector: None,
            cvss_score: None,
            epss: None,
            kev: None,
            fingerprint: None,
        }
    }
    #[test]
    fn cvss_first_reference_vectors() {
        assert_eq!(
            cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap(),
            9.8
        );
        assert_eq!(
            cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").unwrap(),
            7.5
        );
    }
    #[test]
    fn csv_formula_cells_are_prefixed() {
        let mut r = request("csv");
        r.findings[0].rule_id = "=cmd()".into();
        assert!(render(&r).unwrap().content.contains("'=cmd()"));
    }
    #[test]
    fn html_escapes_hostile_strings_and_has_strict_csp() {
        let mut r = request("html");
        r.findings[0].title = "<script>alert(1)</script>".into();
        r.metadata.not_assessed = vec!["<img src=x>".into()];
        let s = render(&r).unwrap().content;
        assert!(!s.contains("<script>"));
        assert!(s.contains("&lt;script&gt;"));
        assert!(s.contains("default-src 'none'"));
        assert!(!s.contains("<script"));
    }
    #[test]
    fn sarif_core_shape_is_21() {
        let r = request("sarif");
        let v: serde_json::Value = serde_json::from_str(&render(&r).unwrap().content).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["runs"][0]["results"][0]["partialFingerprints"].is_object());
        assert!(v["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0"));
    }
    fn request(format: &str) -> ReportRequest {
        ReportRequest {
            format: format.into(),
            metadata: ScanMetadata {
                scan_id: "s1".into(),
                tool_version: "0.1".into(),
                rule_version: "1".into(),
                scope: "local".into(),
                methodology: "static".into(),
                not_assessed: vec!["complete language coverage".into()],
            },
            findings: vec![f("R1", "src/a.rs:5", "issue")],
            previous_findings: vec![],
            cwe_map: BTreeMap::new(),
        }
    }
    proptest! { #[test] fn fingerprint_diff_is_deterministic(path in ".{0,40}", ev in ".{0,40}") { let a=f("R",&path,&ev); let b=f("R",&path,&ev); prop_assert_eq!(fingerprint(&a),fingerprint(&b)); prop_assert_eq!(diff_findings(std::slice::from_ref(&a),&[b]).persisting.len(),1); } }
}
