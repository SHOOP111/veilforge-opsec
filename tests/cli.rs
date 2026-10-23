use anyhow::{Context, Result};
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn cli_produces_reports_and_expected_exit_codes() -> Result<()> {
    let root = tempdir()?;
    let outputs = tempdir()?;
    let binary = env!("CARGO_BIN_EXE_veilforge");
    let clean = Command::new(binary).arg("scan").arg(root.path()).output()?;
    assert_eq!(clean.status.code(), Some(0));
    fs::write(root.path().join("service.toml"), "verify_ssl=false\n")?;
    let json = outputs.path().join("report.json");
    let sarif = outputs.path().join("report.sarif");
    let html = outputs.path().join("report.html");
    let audit = Command::new(binary)
        .arg("scan")
        .arg(root.path())
        .arg("--json")
        .arg(&json)
        .arg("--sarif")
        .arg(&sarif)
        .arg("--html")
        .arg(&html)
        .output()?;
    assert_eq!(audit.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&json)?)?;
    assert_eq!(report["findings"][0]["rule_id"], "config.tls-bypass");
    assert!(report["findings"][0]["path"].is_null());
    assert!(fs::read_to_string(html)?.contains("VeilForge"));
    let sarif: serde_json::Value = serde_json::from_slice(&fs::read(sarif)?)?;
    assert_eq!(sarif["version"], "2.1.0");
    let repeat = Command::new(binary)
        .arg("scan")
        .arg(root.path())
        .arg("--json")
        .arg(&json)
        .output()?;
    assert_eq!(repeat.status.code(), Some(1));
    fs::write(root.path().join("opaque.bin"), [0, 1, 0])?;
    let incomplete = Command::new(binary).arg("scan").arg(root.path()).output()?;
    assert_eq!(incomplete.status.code(), Some(3));
    let stderr = String::from_utf8(incomplete.stderr).context("stderr is not UTF-8")?;
    assert!(!stderr.contains("opaque.bin"));
    Ok(())
}
