use crate::{
    key::SecretKey,
    model::{Category, Confidence, Finding, FindingState, Location, Severity},
};

pub mod metadata;
pub mod text;

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: &'static str,
    pub recommendation: &'static str,
}

macro_rules! rule {
    ($id:literal, $category:ident, $severity:ident, $confidence:ident, $title:literal, $fix:literal) => {
        Rule {
            id: $id,
            category: Category::$category,
            severity: Severity::$severity,
            confidence: Confidence::$confidence,
            title: $title,
            recommendation: $fix,
        }
    };
}

pub const RULES: &[Rule] = &[
    rule!("secret.private-key", Credential, Critical, High, "Private key material",
        "Revoke or replace the key. Remove it from shared artifacts and version history; deletion alone does not revoke it."),
    rule!("secret.github", Credential, Critical, High, "GitHub token-shaped value",
        "Verify and revoke the token in GitHub, rotate dependent credentials, and use a secret manager."),
    rule!("secret.aws-id", Credential, High, Medium, "AWS access-key identifier",
        "Review the key in IAM, rotate if exposed, and prefer short-lived role credentials. An identifier alone is not a secret access key."),
    rule!("secret.slack", Credential, High, High, "Slack token-shaped value",
        "Revoke the exposed token and review the app's scopes and access logs."),
    rule!("secret.jwt", Credential, High, Medium, "JWT-shaped bearer token",
        "Determine whether this is an active credential. Revoke its session and reduce token lifetime if exposed."),
    rule!("secret.url-password", Credential, High, High, "Password embedded in a connection URL",
        "Rotate the password if exposed. Move authentication out of URLs and into a secret manager."),
    rule!("secret.assignment", Credential, High, Medium, "High-entropy credential assignment",
        "Verify this heuristic finding. Rotate real credentials and keep them out of distributable files."),
    rule!("config.env-file", Configuration, Medium, High, "Environment configuration in scan scope",
        "Do not distribute real .env files. Use a template without values and an explicit release allowlist."),
    rule!("config.git-remote", Configuration, Low, High, "Git remote configuration present",
        "Exclude .git from releases. Remotes may reveal private project names, usernames, or internal infrastructure."),
    rule!("config.tls-bypass", Configuration, High, Medium, "TLS verification appears disabled",
        "Enable certificate verification and install an appropriate trust chain instead of bypassing TLS checks."),
    rule!("config.public-bind", Configuration, Medium, Medium, "Wildcard listener configuration",
        "Bind management services to loopback or restrict access with authentication and firewall policy."),
    rule!("config.debug", Configuration, Medium, Medium, "Debug mode enabled in configuration",
        "Disable debug mode in deployment configuration and verify that stack traces do not reach users."),
    rule!("metadata.identity", Metadata, Medium, High, "Document identity or device metadata",
        "Sanitize metadata in a copy before publishing, then rescan. Review author, editor, device, and timestamp fields."),
    rule!("metadata.gps", Metadata, High, High, "EXIF geolocation metadata",
        "Strip location metadata from a publication copy and verify that no embedded thumbnail retains it."),
    rule!("metadata.active-content", Metadata, High, Medium, "Document active content indicator",
        "Review macros, JavaScript, launch actions, and external relationships before distributing this document."),
    rule!("host.firewall", Host, High, High, "A Windows firewall profile is disabled",
        "Enable all appropriate firewall profiles and review scoped inbound rules with your administrator."),
    rule!("host.defender", Host, High, High, "Microsoft Defender protection is disabled",
        "Confirm another managed antivirus provides protection; otherwise enable Defender real-time protection."),
    rule!("host.rdp", Host, Medium, High, "Remote Desktop connections are enabled",
        "Disable RDP when unnecessary; otherwise require NLA, restrict network access, and apply MFA at the gateway."),
    rule!("host.rdp-nla", Host, High, High, "Remote Desktop does not require NLA",
        "Require Network Level Authentication and restrict RDP to trusted management networks."),
];

pub fn catalog() -> &'static [Rule] {
    RULES
}

pub struct Surface<'a> {
    pub key: &'a SecretKey,
    pub file_id: &'a str,
    pub path: Option<&'a str>,
}

impl Surface<'_> {
    pub fn finding(
        &self,
        rule_id: &str,
        token: &[u8],
        location: Option<Location>,
        evidence: &[&str],
        credential: bool,
    ) -> Finding {
        // Only internal, catalogued rule IDs may call this function.
        let rule = RULES.iter().find(|rule| rule.id == rule_id);
        let (category, severity, confidence, title, recommendation) = match rule {
            Some(rule) => (
                rule.category,
                rule.severity,
                rule.confidence,
                rule.title,
                rule.recommendation,
            ),
            None => (
                Category::Configuration,
                Severity::Info,
                Confidence::Low,
                "Unknown internal rule",
                "Report this internal error to the maintainers.",
            ),
        };
        Finding {
            id: self.key.fingerprint(
                "finding",
                &[rule_id.as_bytes(), self.file_id.as_bytes(), token],
            ),
            rule_id: rule_id.into(),
            category,
            severity,
            confidence,
            title: title.into(),
            file_id: Some(self.file_id.into()),
            path: self.path.map(str::to_owned),
            location,
            evidence: evidence.iter().map(|s| (*s).to_owned()).collect(),
            entity_id: credential.then(|| self.key.fingerprint("credential", &[token])),
            recommendation: recommendation.into(),
            occurrences: 1,
            state: FindingState::Active,
            change: None,
        }
    }
}
