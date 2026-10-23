use crate::model::{Finding, FindingState, Severity};
use anyhow::{bail, Context, Result};
use chrono::NaiveDate;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub fail_on: Severity,
    pub exclude: Vec<String>,
    pub suppress: Vec<Suppression>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub rule_id: String,
    pub file_id: Option<String>,
    pub expires: NaiveDate,
    pub reason: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            fail_on: Severity::High,
            exclude: Vec::new(),
            suppress: Vec::new(),
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).context("cannot open policy")?;
        let mut bytes = Vec::new();
        file.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 256 * 1024 {
            bail!("policy exceeds 256 KiB limit");
        }
        let text = std::str::from_utf8(&bytes).context("policy must be UTF-8")?;
        // Parser details may echo policy text; keep CLI errors content-free.
        let policy: Self =
            toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid policy TOML"))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported policy version");
        }
        if self.exclude.len() > 256 || self.suppress.len() > 1024 {
            bail!("policy has too many entries");
        }
        let known = crate::detectors::catalog();
        for suppression in &self.suppress {
            if !known.iter().any(|rule| rule.id == suppression.rule_id) {
                bail!("policy references an unknown rule ID");
            }
            if !(8..=240).contains(&suppression.reason.len()) {
                bail!("suppression reasons must be 8..240 bytes");
            }
            if suppression.file_id.as_ref().is_some_and(|id| !valid_id(id)) {
                bail!("suppression file_id must be a 64-character lowercase hex pseudonym");
            }
        }
        self.exclusions()?;
        Ok(())
    }

    pub fn exclusions(&self) -> Result<GlobSet> {
        let mut builder = GlobSetBuilder::new();
        for pattern in &self.exclude {
            if pattern.len() > 512 {
                bail!("exclusion pattern exceeds 512 bytes");
            }
            let glob = Glob::new(pattern).map_err(|_| anyhow::anyhow!("invalid exclusion glob"))?;
            builder.add(glob);
        }
        builder.build().context("cannot compile exclusion patterns")
    }

    pub fn apply(&self, findings: &mut [Finding], today: NaiveDate) {
        for finding in findings {
            if self.suppress.iter().any(|entry| {
                entry.expires >= today
                    && entry.rule_id == finding.rule_id
                    && entry
                        .file_id
                        .as_ref()
                        .is_none_or(|id| finding.file_id.as_ref() == Some(id))
            }) {
                finding.state = FindingState::Suppressed;
            }
        }
    }

    pub fn expired_count(&self, today: NaiveDate) -> usize {
        self.suppress.iter().filter(|s| s.expires < today).count()
    }

    pub fn digest(&self) -> Result<String> {
        Ok(blake3::hash(&serde_json::to_vec(self)?)
            .to_hex()
            .to_string())
    }
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
