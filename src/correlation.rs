use crate::{
    key::SecretKey,
    model::{Category, ExposureChain, Finding, FindingState, Severity},
};
use std::collections::{BTreeMap, BTreeSet};

pub fn build(findings: &[Finding], key: &SecretKey) -> Vec<ExposureChain> {
    let active: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.state == FindingState::Active)
        .collect();
    let mut chains = Vec::new();
    let mut by_entity: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in &active {
        if let Some(entity) = finding.entity_id.as_deref() {
            by_entity.entry(entity).or_default().push(finding);
        }
        if let Some(file) = finding.file_id.as_deref() {
            by_file.entry(file).or_default().push(finding);
        }
    }
    for group in by_entity.values() {
        let files: BTreeSet<_> = group.iter().filter_map(|f| f.file_id.as_deref()).collect();
        if files.len() >= 2 {
            chains.push(chain(key, "credential-reuse", "Credential replicated across artifacts", Severity::High, group,
                "The same keyed credential fingerprint appears in multiple files. Copies increase accidental publication exposure; this does not prove compromise.",
                "Rotate real credentials and remove every copy, including generated assets and history."));
        }
    }
    for group in by_file.values() {
        let credential = group.iter().any(|f| f.category == Category::Credential);
        let environment = group.iter().any(|f| f.rule_id == "config.env-file");
        let tls = group.iter().any(|f| f.rule_id == "config.tls-bypass");
        let bind = group.iter().any(|f| f.rule_id == "config.public-bind");
        let debug = group.iter().any(|f| f.rule_id == "config.debug");
        if credential && environment {
            chains.push(chain(key, "release-secret", "Credential-bearing environment artifact", Severity::High, group,
                "A likely credential and an environment-file indicator share one artifact. This is a release hygiene risk, not evidence that the file was published.",
                "Exclude the artifact from distribution and rotate any credential that has already been shared."));
        }
        if credential && tls {
            chains.push(chain(key, "credential-tls", "Credential alongside weakened transport checks", Severity::Critical, group,
                "Credential material and a TLS-verification bypass occur in the same configuration. Runtime use has not been observed.",
                "Restore certificate verification and review credential handling before deployment."));
        }
        if bind && debug {
            chains.push(chain(key, "debug-listener", "Debug configuration with a wildcard listener", Severity::High, group,
                "Debug and wildcard binding indicators coexist. If applied at runtime, diagnostics could become externally reachable.",
                "Disable debug output and bind management interfaces to a restricted address."));
        }
    }
    let rdp = active.iter().find(|f| f.rule_id == "host.rdp");
    let firewall = active.iter().find(|f| f.rule_id == "host.firewall");
    if let (Some(rdp), Some(firewall)) = (rdp, firewall) {
        chains.push(chain(key, "rdp-firewall", "RDP enabled with a disabled firewall profile", Severity::High, &[rdp, firewall],
            "Remote Desktop is enabled and at least one firewall profile is disabled. Reachability depends on routing and the active profile; no network probing was performed.",
            "Enable firewall protection and restrict Remote Desktop to authenticated management access."));
    }
    chains.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    chains
}

fn chain(
    key: &SecretKey,
    kind: &str,
    title: &str,
    severity: Severity,
    findings: &[&Finding],
    explanation: &str,
    recommendation: &str,
) -> ExposureChain {
    let ids: BTreeSet<String> = findings.iter().map(|f| f.id.clone()).collect();
    let finding_ids: Vec<String> = ids.into_iter().collect();
    let joined = finding_ids.join(":");
    ExposureChain {
        id: key.fingerprint("chain", &[kind.as_bytes(), joined.as_bytes()]),
        title: title.into(),
        severity,
        finding_ids,
        explanation: explanation.into(),
        recommendation: recommendation.into(),
    }
}
