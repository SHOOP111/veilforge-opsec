pub mod html;
pub mod sarif;

use crate::model::Report;
use anyhow::{bail, Context, Result};
use std::{io::Write, path::Path};

pub fn json(report: &Report) -> Result<String> {
    serde_json::to_string_pretty(report).context("cannot encode JSON report")
}

pub fn write_new(path: &Path, content: &str) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok() { bail!("report destination already exists; refusing to overwrite"); }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).context("cannot create report in destination directory")?;
    temporary.write_all(content.as_bytes()).context("cannot write report")?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all().context("cannot flush report")?;
    temporary.persist_noclobber(path).map_err(|_| anyhow::anyhow!("cannot publish report; destination must not exist"))?;
    Ok(())
}

pub fn terminal(report: &Report) -> String {
    let mut output = format!(
        "VeilForge {} | OFFLINE DEFENSIVE AUDIT\n\nObserved hygiene: {}/100 — {}\n{} active · {} suppressed · {} exposure chains\n{} files read · {} bytes · {} coverage issue groups\n",
        report.tool_version, report.score.value, report.score.label,
        report.score.active_findings, report.score.suppressed_findings, report.chains.len(),
        report.stats.files_scanned, report.stats.bytes_read, report.coverage.len(),
    );
    for finding in report.findings.iter().filter(|f| f.state == crate::model::FindingState::Active).take(40) {
        output.push_str(&format!("\n[{:8}] {} — {}\n  file {} · finding {}\n  {}\n",
            finding.severity, finding.rule_id, finding.title,
            finding.file_id.as_deref().map(short_id).unwrap_or("host"),
            short_id(&finding.id), finding.recommendation));
    }
    if report.score.active_findings > 40 { output.push_str("\nMore findings available in machine-readable reports.\n"); }
    if let Some(baseline) = &report.baseline {
        output.push_str(&format!("\nBaseline: {} new · {} unchanged · {} resolved\n", baseline.new, baseline.unchanged, baseline.resolved_ids.len()));
    }
    for issue in &report.coverage {
        output.push_str(&format!("\nCoverage [{}] ×{}: {}\n", issue.code, issue.count, issue.message));
    }
    output.push_str("\nThis heuristic score is not a security guarantee. No remote credentials were validated.\n");
    output
}

pub fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}
