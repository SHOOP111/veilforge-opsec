use crate::{
    detectors::catalog,
    model::{FindingState, Report, Severity},
};
use anyhow::Result;
use serde_json::{json, Value};

pub fn render(report: &Report) -> Result<String> {
    let rules: Vec<Value> = catalog()
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.id,
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.recommendation},
                "defaultConfiguration": {"level": level(r.severity)},
                "properties": {"tags": ["security", "privacy", "opsec"], "precision": "medium"}
            })
        })
        .collect();
    let results: Vec<Value> = report.findings.iter().map(|finding| {
        let mut value = json!({
            "ruleId": finding.rule_id,
            "level": level(finding.severity),
            "message": {"text": format!("{}. {}", finding.title, finding.recommendation)},
            "partialFingerprints": {"veilforge/v1": finding.id},
            "properties": {
                "severity": finding.severity, "confidence": finding.confidence,
                "fileId": finding.file_id, "occurrences": finding.occurrences,
                "evidence": finding.evidence
            }
        });
        if finding.state == FindingState::Suppressed {
            value["suppressions"] = json!([{"kind": "external", "status": "accepted", "justification": "Unexpired reviewed policy suppression"}]);
        }
        if let Some(change) = finding.change {
            value["baselineState"] = json!(match change {
                crate::model::Change::New => "new", crate::model::Change::Unchanged => "unchanged"
            });
        }
        if let Some(path) = &finding.path {
            let mut physical = json!({"artifactLocation": {"uri": uri(path), "uriBaseId": "%SRCROOT%"}});
            if let Some(location) = &finding.location {
                physical["region"] = json!({"startLine": location.line, "startColumn": location.column});
            }
            value["locations"] = json!([{"physicalLocation": physical}]);
        }
        value
    }).collect();
    let notifications: Vec<Value> = report
        .coverage
        .iter()
        .map(|issue| {
            json!({
                "descriptor": {"id": issue.code}, "level": "warning",
                "message": {"text": format!("{} ({} entries)", issue.message, issue.count)}
            })
        })
        .collect();
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VeilForge", "version": report.tool_version,
                "informationUri": "https://github.com/SHOOP111/veilforge-opsec", "rules": rules}},
            "columnKind": "unicodeCodePoints",
            "results": results,
            "invocations": [{"executionSuccessful": report.coverage.is_empty(), "toolExecutionNotifications": notifications}],
            "properties": {"pathsRevealed": report.paths_revealed, "rootId": report.root_id, "score": report.score}
        }]
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

fn uri(path: &str) -> String {
    let mut output = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}
