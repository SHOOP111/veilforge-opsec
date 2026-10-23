use super::Surface;
use crate::model::{Finding, Location};
use anyhow::{Context, Result};
use regex::Regex;
use zeroize::Zeroizing;
use std::collections::BTreeMap;

struct Pattern {
    rule: &'static str,
    regex: Regex,
    capture: usize,
    evidence: &'static str,
    entropy: bool,
}

pub struct TextDetector {
    patterns: Vec<Pattern>,
    tls: Regex,
    bind: Regex,
    debug: Regex,
}

pub struct TextResult {
    pub findings: Vec<Finding>,
    pub capped: bool,
}

impl TextDetector {
    pub fn new() -> Result<Self> {
        let specifications = [
            ("secret.private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", 0, "private-key header present", false),
            ("secret.github", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b", 0, "GitHub token format", false),
            ("secret.aws-id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0, "AWS access-key ID format", false),
            ("secret.slack", r"\bxox[baprs]-[A-Za-z0-9-]{20,200}\b", 0, "Slack token format", false),
            ("secret.jwt", r"\b(eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,2048})\b", 1, "three-part JWT format; not validated online", false),
            ("secret.url-password", r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s/:@]{1,128}:([^\s/@]{4,256})@", 1, "password-bearing URL; address omitted", false),
            ("secret.assignment", r#"(?im)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd)\s*[:=]\s*["']?([A-Za-z0-9_+/.=\-]{20,256})"#, 1, "credential context with high character entropy", true),
        ];
        let mut patterns = Vec::new();
        for (rule, source, capture, evidence, entropy) in specifications {
            patterns.push(Pattern {
                rule,
                regex: Regex::new(source).context("invalid built-in credential detector")?,
                capture,
                evidence,
                entropy,
            });
        }
        Ok(Self {
            patterns,
            tls: Regex::new(r#"(?i)(?:verify(?:_ssl)?|ssl_verify|tls_verify|rejectUnauthorized|CURLOPT_SSL_VERIFYPEER)\s*[:=,]\s*(?:false|0|off)\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b"#)?,
            bind: Regex::new(r#"(?i)(?:bind|listen|host|address)\s*[:=]\s*["']?(?:0\.0\.0\.0|\[?::\]?)"#)?,
            debug: Regex::new(r#"(?i)\b(?:debug|debug_mode|flask_debug)\s*[:=]\s*["']?(?:true|1|on)\b"#)?,
        })
    }

    pub fn scan(&self, text: &str, relative: &str, surface: &Surface<'_>) -> TextResult {
        const MATCH_LIMIT: usize = 256;
        let mut found: BTreeMap<String, Finding> = BTreeMap::new();
        let mut examined = 0usize;
        let mut capped = false;
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(text.match_indices('\n').map(|(index, _)| index + 1))
            .collect();
        'patterns: for pattern in &self.patterns {
            for captures in pattern.regex.captures_iter(text) {
                examined += 1;
                if examined > MATCH_LIMIT {
                    capped = true;
                    break 'patterns;
                }
                let Some(value) = captures.get(pattern.capture) else { continue };
                if placeholder(value.as_str()) || (pattern.entropy && entropy(value.as_str()) < 3.5) {
                    continue;
                }
                let finding = surface.finding(
                    pattern.rule,
                    value.as_str().as_bytes(),
                    Some(position(text, &line_starts, value.start())),
                    &[pattern.evidence],
                    pattern.rule != "secret.private-key",
                );
                insert(&mut found, finding);
            }
        }
        let filename = relative.rsplit('/').next().unwrap_or(relative);
        if filename == ".env" || (filename.starts_with(".env.") && !filename.ends_with("example") && !filename.ends_with("sample") && !filename.ends_with("template")) {
            insert(&mut found, surface.finding("config.env-file", b"env", None, &["environment file by filename"], false));
        }
        if relative.ends_with(".git/config") && text.contains("[remote ") {
            insert(&mut found, surface.finding("config.git-remote", b"remote", None, &["remote stanza; URL not retained"], false));
        }
        let extension = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let is_config = filename.starts_with(".env") || matches!(extension.as_str(), "toml" | "yaml" | "yml" | "ini" | "conf" | "config" | "json" | "properties" | "env");
        if is_config {
            for (rule, regex, evidence) in [
                ("config.tls-bypass", &self.tls, "TLS verification disable flag"),
                ("config.public-bind", &self.bind, "wildcard listener address"),
                ("config.debug", &self.debug, "debug enable flag"),
            ] {
                if let Some(value) = regex.find(text) {
                    insert(&mut found, surface.finding(rule, rule.as_bytes(), Some(position(text, &line_starts, value.start())), &[evidence], false));
                }
            }
        }
        TextResult { findings: found.into_values().collect(), capped }
    }
}

fn insert(found: &mut BTreeMap<String, Finding>, finding: Finding) {
    if let Some(existing) = found.get_mut(&finding.id) {
        existing.occurrences = existing.occurrences.saturating_add(1);
    } else {
        found.insert(finding.id.clone(), finding);
    }
}

fn position(text: &str, starts: &[usize], offset: usize) -> Location {
    let index = starts.partition_point(|start| *start <= offset).saturating_sub(1);
    let start = starts.get(index).copied().unwrap_or(0);
    Location {
        line: (index + 1).min(u32::MAX as usize) as u32,
        column: (text[start..offset].chars().count() + 1).min(u32::MAX as usize) as u32,
    }
}

pub fn entropy(value: &str) -> f64 {
    if value.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for byte in value.bytes() { counts[byte as usize] += 1; }
    let length = value.len() as f64;
    counts.iter().filter(|n| **n > 0).map(|n| {
        let probability = *n as f64 / length;
        -probability * probability.log2()
    }).sum()
}

fn placeholder(value: &str) -> bool {
    let lower = Zeroizing::new(value.to_ascii_lowercase());
    lower.contains("example") || lower.contains("placeholder") || lower.contains("changeme")
        || lower.contains("your_token") || lower.contains("your_password")
        || value.starts_with("${") || value.bytes().all(|b| b == b'x' || b == b'X')
}
