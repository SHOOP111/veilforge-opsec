use crate::{
    model::{BaselineSummary, Change, FindingState, Report, SCHEMA_VERSION},
    policy::valid_id,
};
use anyhow::{bail, Context, Result};
use std::{collections::BTreeSet, io::Read, path::Path};

pub fn load(path: &Path) -> Result<Report> {
    let file = std::fs::File::open(path).context("cannot open baseline report")?;
    let mut bytes = Vec::new();
    file.take(32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        bail!("baseline exceeds 32 MiB limit");
    }
    let report: Report = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid report JSON or unsupported schema"))?;
    validate(&report)?;
    Ok(report)
}

pub fn validate(report: &Report) -> Result<()> {
    if report.schema_version != SCHEMA_VERSION {
        bail!("unsupported report schema version");
    }
    if !valid_id(&report.root_id) || !valid_id(&report.key_id) || !valid_id(&report.policy_digest) {
        bail!("invalid report identity fields");
    }
    if report.findings.len() > 200_000
        || report.chains.len() > 200_000
        || report.coverage.len() > 128
    {
        bail!("report exceeds entry limits");
    }
    let mut unique = BTreeSet::new();
    for finding in &report.findings {
        if !valid_id(&finding.id)
            || !unique.insert(&finding.id)
            || finding.file_id.as_ref().is_some_and(|id| !valid_id(id))
            || finding.entity_id.as_ref().is_some_and(|id| !valid_id(id))
            || !crate::detectors::catalog()
                .iter()
                .any(|r| r.id == finding.rule_id)
        {
            bail!("invalid or duplicate report finding identity");
        }
    }
    Ok(())
}

pub fn compare(before: &Report, after: &Report) -> Result<BaselineSummary> {
    validate(before)?;
    validate(after)?;
    if before.key_id != after.key_id {
        bail!("baseline key mismatch: reuse the same --key file");
    }
    if before.root_id != after.root_id {
        bail!("baseline root mismatch: scan the same canonical directory");
    }
    if before.policy_digest != after.policy_digest {
        bail!("baseline policy mismatch: comparison requires identical policy");
    }
    if !before.coverage.is_empty() {
        bail!("baseline has incomplete coverage; use a complete baseline");
    }
    let old: BTreeSet<&str> = before
        .findings
        .iter()
        .filter(|f| f.state == FindingState::Active)
        .map(|f| f.id.as_str())
        .collect();
    let current: BTreeSet<&str> = after
        .findings
        .iter()
        .filter(|f| f.state == FindingState::Active)
        .map(|f| f.id.as_str())
        .collect();
    // Incomplete coverage must never turn a missed finding into a claimed resolution.
    let resolved_ids = if after.coverage.is_empty() {
        old.difference(&current)
            .map(|id| (*id).to_owned())
            .collect()
    } else {
        Vec::new()
    };
    Ok(BaselineSummary {
        new: current.difference(&old).count() as u64,
        unchanged: current.intersection(&old).count() as u64,
        resolved_ids,
    })
}

pub fn apply(before: &Report, after: &mut Report) -> Result<()> {
    let summary = compare(before, after)?;
    let old: BTreeSet<&str> = before
        .findings
        .iter()
        .filter(|f| f.state == FindingState::Active)
        .map(|f| f.id.as_str())
        .collect();
    for finding in &mut after.findings {
        if finding.state == FindingState::Active {
            finding.change = Some(if old.contains(finding.id.as_str()) {
                Change::Unchanged
            } else {
                Change::New
            });
        }
    }
    after.baseline = Some(summary);
    Ok(())
}
