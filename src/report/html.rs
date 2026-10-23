use crate::{
    model::{FindingState, Report},
    report::short_id,
};

pub fn escape(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c if c.is_control() && c != '\n' && c != '\t' => "&#xfffd;".into(),
            c => c.to_string(),
        })
        .collect()
}

pub fn render(report: &Report) -> String {
    let mut html = String::from(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>VeilForge · Exposure atlas</title>
<style>
:root{color-scheme:dark;--ink:#d6e6eb;--muted:#96acb5;--panel:#13232c;--edge:#2d4854;--mint:#74eed4;--red:#ff8d8d}
*{box-sizing:border-box}body{margin:0;background:#09131b;color:var(--ink);font:16px/1.65 system-ui,sans-serif}main{max-width:1150px;margin:auto;padding:40px 24px}header{border-top:4px solid var(--mint);padding-top:22px}h1{font-size:clamp(36px,6vw,64px);letter-spacing:-2px;margin:10px 0}h2{margin-top:38px}p{max-width:85ch}.eyebrow,code{font:13px/1.6 ui-monospace,monospace}.eyebrow{color:var(--mint);letter-spacing:3px}.muted{color:var(--muted)}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:28px 0}.metric,article,details{background:var(--panel);border:1px solid var(--edge);border-radius:12px;padding:20px}.number{font-size:36px;font-weight:700;color:var(--mint)}article{margin:14px 0;border-left:4px solid var(--mint)}.badge{display:inline-block;border:1px solid var(--edge);padding:2px 10px;border-radius:20px;text-transform:uppercase;font-size:12px}.high,.critical{color:var(--red)}details{margin:12px 0}summary{cursor:pointer;font-weight:600}code{overflow-wrap:anywhere}dl{display:grid;grid-template-columns:minmax(80px,140px) 1fr;gap:8px}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}li{margin:10px 0}footer{border-top:1px solid var(--edge);margin-top:40px;padding-top:20px;color:var(--muted)}@media print{body{background:white;color:black}.metric,article,details{background:white}details{break-inside:avoid}.muted,dt,footer{color:#444}}
</style></head><body><main><header><div class="eyebrow">OFFLINE / DEFENSIVE / REDACTED</div><h1>VeilForge</h1><p class="muted">Exposure atlas · Local artifact hygiene, without uploading your files or validating secrets online.</p></header>"#,
    );
    html.push_str(&format!(r#"<section class="metrics" aria-label="Summary"><div class="metric"><div class="number">{}/100</div>{}</div><div class="metric"><div class="number">{}</div>Active findings</div><div class="metric"><div class="number">{}</div>Exposure chains</div><div class="metric"><div class="number">{}</div>Files read</div></section>"#,
        report.score.value, escape(&report.score.label), report.score.active_findings, report.chains.len(), report.stats.files_scanned));
    html.push_str(&format!(
        "<p class=\"muted\">Created {} · v{} · Root pseudonym <code>{}</code>. Paths {}.</p>",
        escape(&report.created_at),
        escape(&report.tool_version),
        escape(short_id(&report.root_id)),
        if report.paths_revealed {
            "explicitly revealed"
        } else {
            "hidden"
        }
    ));
    if !report.coverage.is_empty() {
        html.push_str("<h2>Coverage boundaries</h2><p>Do not interpret an incomplete scan as a clean bill of health.</p><ul>");
        for issue in &report.coverage {
            html.push_str(&format!(
                "<li><code>{}</code> ×{} — {}</li>",
                escape(&issue.code),
                issue.count,
                escape(&issue.message)
            ));
        }
        html.push_str("</ul>");
    }
    if let Some(baseline) = &report.baseline {
        html.push_str(&format!("<h2>Baseline delta</h2><p>{} new · {} unchanged · {} resolved. Resolution is only reported with complete coverage.</p>", baseline.new, baseline.unchanged, baseline.resolved_ids.len()));
    }
    html.push_str("<h2>Exposure chains</h2><p class=\"muted\">Co-occurrence hypotheses, not proof of exploitation. Suppressed findings do not create chains.</p>");
    for chain in &report.chains {
        html.push_str(&format!("<article><span class=\"badge {}\">{}</span><h3>{}</h3><p>{}</p><p><strong>Action:</strong> {}</p><p class=\"muted\">Finding pseudonyms: <code>{}</code></p></article>",
            chain.severity, chain.severity, escape(&chain.title), escape(&chain.explanation), escape(&chain.recommendation),
            escape(&chain.finding_ids.iter().map(|id| short_id(id)).collect::<Vec<_>>().join(" · "))));
    }
    html.push_str("<h2>Finding ledger</h2>");
    for finding in &report.findings {
        let path = finding
            .path
            .as_deref()
            .or(finding.file_id.as_deref())
            .unwrap_or("host");
        let location = finding
            .location
            .as_ref()
            .map(|l| format!("{}:{}", l.line, l.column))
            .unwrap_or_else(|| "metadata / posture".into());
        html.push_str(&format!("<details><summary><span class=\"badge {}\">{}</span> {}{}</summary><dl><dt>Rule</dt><dd><code>{}</code></dd><dt>Artifact</dt><dd><code>{}</code></dd><dt>Location</dt><dd>{}</dd><dt>Confidence</dt><dd>{:?}</dd><dt>Occurrences</dt><dd>{}</dd><dt>Evidence</dt><dd>{}</dd><dt>Action</dt><dd>{}</dd><dt>Finding ID</dt><dd><code>{}</code></dd></dl></details>",
            finding.severity, finding.severity, escape(&finding.title),
            if finding.state == FindingState::Suppressed { " · suppressed" } else { "" },
            escape(&finding.rule_id), escape(path), escape(&location), finding.confidence, finding.occurrences,
            escape(&finding.evidence.join("; ")), escape(&finding.recommendation), escape(&finding.id)));
    }
    html.push_str("<footer>No scripts, external assets, telemetry, or active document content. Credential evidence contains only detector labels and keyed fingerprints. Reports still reveal posture and should be treated as sensitive. A score is a prioritization aid, not certification.</footer></main></body></html>");
    html
}
