use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, str::FromStr};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 3,
            Self::Medium => 8,
            Self::High => 20,
            Self::Critical => 40,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err("expected info, low, medium, high, or critical".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Credential,
    Metadata,
    Configuration,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingState {
    Active,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    New,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub file_id: Option<String>,
    pub path: Option<String>,
    pub location: Option<Location>,
    pub evidence: Vec<String>,
    pub entity_id: Option<String>,
    pub recommendation: String,
    pub occurrences: u32,
    pub state: FindingState,
    pub change: Option<Change>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureChain {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub finding_ids: Vec<String>,
    pub explanation: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanStats {
    pub files_seen: u64,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub excluded_entries: u64,
    pub bytes_read: u64,
    pub metadata_documents: u64,
    pub binary_files: u64,
    pub host_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageIssue {
    pub code: String,
    pub message: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineSummary {
    pub new: u64,
    pub unchanged: u64,
    pub resolved_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Score {
    pub value: u32,
    pub risk_points: u32,
    pub active_findings: u64,
    pub suppressed_findings: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema_version: u32,
    pub tool_version: String,
    pub created_at: String,
    pub root_id: String,
    pub key_id: String,
    pub policy_digest: String,
    pub paths_revealed: bool,
    pub stats: ScanStats,
    pub coverage: Vec<CoverageIssue>,
    pub findings: Vec<Finding>,
    pub chains: Vec<ExposureChain>,
    pub score: Score,
    pub baseline: Option<BaselineSummary>,
}

impl Report {
    pub fn refresh_score(&mut self) {
        let mut surfaces = BTreeSet::new();
        let mut points = 0u32;
        let mut active = 0u64;
        let mut suppressed = 0u64;
        for finding in &self.findings {
            if finding.state == FindingState::Suppressed {
                suppressed += 1;
                continue;
            }
            active += 1;
            // Repeated occurrences do not inflate a surface's risk contribution.
            if surfaces.insert((&finding.rule_id, &finding.file_id)) {
                points = points.saturating_add(finding.severity.weight());
            }
        }
        let value = 100 - points.min(100);
        let label = if !self.coverage.is_empty() {
            "Incomplete coverage"
        } else if value >= 85 {
            "Low observed exposure"
        } else if value >= 50 {
            "Needs attention"
        } else {
            "High observed exposure"
        };
        self.score = Score {
            value,
            risk_points: points,
            active_findings: active,
            suppressed_findings: suppressed,
            label: label.into(),
        };
    }

    pub fn exit_code(&self, threshold: Severity) -> i32 {
        if !self.coverage.is_empty() {
            3
        } else if self
            .findings
            .iter()
            .any(|f| f.state == FindingState::Active && f.severity >= threshold)
        {
            2
        } else {
            0
        }
    }
}
