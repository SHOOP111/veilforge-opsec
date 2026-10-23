use anyhow::{Context, Result};
use chrono::NaiveDate;
use std::{fs, io::Write, path::Path};
use tempfile::tempdir;
use veilforge::{
    baseline,
    detectors::{
        metadata::MetadataDetector,
        text::{entropy, TextDetector},
        Surface,
    },
    key::SecretKey,
    model::{Change, FindingState, Severity},
    policy::{Policy, Suppression},
    report,
    scan::{scan, ScanOptions},
};

fn fake_token() -> String {
    // Synthetic, non-working credential shape assembled in memory, never a real token.
    format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
}

#[test]
fn secrets_are_redacted_in_every_output_and_ids_are_stable() -> Result<()> {
    let root = tempdir()?;
    let token = fake_token();
    fs::write(
        root.path().join("credentials.env"),
        format!("auth_token={token}\n"),
    )?;
    let key = SecretKey::from_bytes([7; 32]);
    let options = ScanOptions::new(root.path());
    let first = scan(&options, &Policy::default(), &key)?;
    let second = scan(&options, &Policy::default(), &key)?;
    assert!(!first.findings.is_empty());
    assert_eq!(
        first.findings.iter().map(|f| &f.id).collect::<Vec<_>>(),
        second.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert!(first.findings.iter().all(|f| f.path.is_none()));
    for output in [
        report::json(&first)?,
        report::sarif::render(&first)?,
        report::html::render(&first),
        report::terminal(&first),
    ] {
        assert!(!output.contains(&token));
        assert!(!output.contains("credentials.env"));
        assert!(!output.contains(&root.path().to_string_lossy().to_string()));
    }
    assert_eq!(first.exit_code(Severity::High), 2);
    Ok(())
}

#[test]
fn key_domains_are_separated_and_keys_are_not_overwritten() -> Result<()> {
    let key = SecretKey::from_bytes([1; 32]);
    assert_ne!(
        key.fingerprint("file", &[b"a"]),
        key.fingerprint("credential", &[b"a"])
    );
    assert_ne!(
        key.fingerprint("file", &[b"a", b"bc"]),
        key.fingerprint("file", &[b"ab", b"c"])
    );
    assert_ne!(key.id(), SecretKey::from_bytes([2; 32]).id());
    let directory = tempdir()?;
    let path = directory.path().join("test.vfkey");
    SecretKey::create(&path)?;
    let before = fs::read(&path)?;
    assert_eq!(before.len(), 32);
    assert!(SecretKey::create(&path).is_err());
    assert_eq!(before, fs::read(&path)?);
    assert_eq!(SecretKey::load(&path)?.id(), SecretKey::load(&path)?.id());
    Ok(())
}

#[test]
fn utf16_and_unicode_locations_work_on_windows_artifacts() -> Result<()> {
    let root = tempdir()?;
    let source = format!("# λ\r\nauth_token={}\r\n", fake_token());
    let mut bytes = vec![0xff, 0xfe];
    for unit in source.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(root.path().join("service.env"), bytes)?;
    let key = SecretKey::from_bytes([3; 32]);
    let result = scan(&ScanOptions::new(root.path()), &Policy::default(), &key)?;
    let finding = result
        .findings
        .iter()
        .find(|f| f.rule_id == "secret.github")
        .context("missing token detection")?;
    assert_eq!(finding.location.as_ref().map(|l| l.line), Some(2));
    assert_eq!(finding.location.as_ref().map(|l| l.column), Some(12));
    assert!(result.coverage.is_empty());
    Ok(())
}

#[test]
fn baselines_do_not_claim_resolution_with_missing_coverage() -> Result<()> {
    let root = tempdir()?;
    let key = SecretKey::from_bytes([4; 32]);
    let path = root.path().join("settings.toml");
    fs::write(&path, format!("api_key = \"{}\"\n", fake_token()))?;
    let options = ScanOptions::new(root.path());
    let before = scan(&options, &Policy::default(), &key)?;
    let mut after = scan(&options, &Policy::default(), &key)?;
    baseline::apply(&before, &mut after)?;
    assert!(after
        .findings
        .iter()
        .all(|f| f.change == Some(Change::Unchanged)));
    fs::write(&path, "harmless = true\n")?;
    let fixed = scan(&options, &Policy::default(), &key)?;
    assert_eq!(
        baseline::compare(&before, &fixed)?.resolved_ids.len(),
        before.findings.len()
    );
    fs::write(root.path().join("unknown.bin"), [0, 1, 2, 0])?;
    let incomplete = scan(&options, &Policy::default(), &key)?;
    assert!(baseline::compare(&before, &incomplete)?
        .resolved_ids
        .is_empty());
    assert_eq!(incomplete.exit_code(Severity::Critical), 3);
    assert!(baseline::compare(&incomplete, &fixed).is_err());
    let other = scan(
        &options,
        &Policy::default(),
        &SecretKey::from_bytes([5; 32]),
    )?;
    assert!(baseline::compare(&before, &other).is_err());
    Ok(())
}

#[test]
fn suppressions_expire_and_do_not_create_exposure_chains() -> Result<()> {
    let key = SecretKey::from_bytes([6; 32]);
    let file_id = key.fingerprint("file", &[b".env"]);
    let surface = Surface {
        key: &key,
        file_id: &file_id,
        path: None,
    };
    let mut findings = TextDetector::new()?
        .scan(&format!("auth_token={}\n", fake_token()), ".env", &surface)
        .findings;
    let today = NaiveDate::from_ymd_opt(2030, 1, 1).context("invalid test date")?;
    let mut policy = Policy::default();
    for rule_id in ["secret.github", "secret.assignment"] {
        policy.suppress.push(Suppression {
            rule_id: rule_id.into(),
            file_id: Some(file_id.clone()),
            expires: today,
            reason: "Reviewed synthetic fixture".into(),
        });
    }
    policy.validate()?;
    policy.apply(&mut findings, today);
    assert!(findings
        .iter()
        .filter(|f| f.rule_id.starts_with("secret."))
        .all(|f| f.state == FindingState::Suppressed));
    assert!(veilforge::correlation::build(&findings, &key).is_empty());
    assert_eq!(
        policy.expired_count(today.succ_opt().context("invalid date increment")?),
        2
    );
    let mut invalid = policy;
    invalid.suppress[0].rule_id = "does.not.exist".into();
    assert!(invalid.validate().is_err());
    Ok(())
}

#[test]
fn repeated_credentials_and_unsafe_config_form_exposure_chains() -> Result<()> {
    let root = tempdir()?;
    let text = format!(
        "auth_token={}\nverify_ssl=false\ndebug=true\nhost=0.0.0.0\n",
        fake_token()
    );
    fs::write(root.path().join(".env"), &text)?;
    fs::write(root.path().join("service.toml"), &text)?;
    let report = scan(
        &ScanOptions::new(root.path()),
        &Policy::default(),
        &SecretKey::from_bytes([8; 32]),
    )?;
    assert!(report
        .chains
        .iter()
        .any(|c| c.title == "Credential replicated across artifacts"));
    assert!(report
        .chains
        .iter()
        .any(|c| c.title == "Credential alongside weakened transport checks"));
    assert!(report
        .chains
        .iter()
        .any(|c| c.title == "Debug configuration with a wildcard listener"));
    Ok(())
}

#[test]
fn oversized_files_and_match_storms_produce_coverage_gaps() -> Result<()> {
    let root = tempdir()?;
    fs::write(root.path().join("large.txt"), vec![b'a'; 2048])?;
    let mut options = ScanOptions::new(root.path());
    options.max_file_bytes = 1024;
    let key = SecretKey::from_bytes([9; 32]);
    let result = scan(&options, &Policy::default(), &key)?;
    assert_eq!(result.stats.bytes_read, 0);
    assert!(result.coverage.iter().any(|i| i.code == "file-size-limit"));
    fs::remove_file(root.path().join("large.txt"))?;
    fs::write(
        root.path().join("storm.txt"),
        format!("{}\n", fake_token()).repeat(300),
    )?;
    let result = scan(&ScanOptions::new(root.path()), &Policy::default(), &key)?;
    assert!(result.coverage.iter().any(|i| i.code == "match-limit"));
    assert_eq!(result.exit_code(Severity::Critical), 3);
    Ok(())
}

#[test]
fn exclusions_are_explicit_and_outputs_are_not_clobbered() -> Result<()> {
    let root = tempdir()?;
    fs::create_dir(root.path().join("target"))?;
    fs::write(root.path().join("target").join("hidden.txt"), fake_token())?;
    fs::write(root.path().join("visible.txt"), "nothing sensitive")?;
    let result = scan(
        &ScanOptions::new(root.path()),
        &Policy::default(),
        &SecretKey::from_bytes([10; 32]),
    )?;
    assert!(result.findings.is_empty());
    assert_eq!(result.stats.files_scanned, 1);
    assert_eq!(result.stats.excluded_entries, 1);
    let path = root.path().join("out.json");
    report::write_new(&path, "original")?;
    assert!(report::write_new(&path, "overwritten").is_err());
    assert_eq!(fs::read_to_string(path)?, "original\n");
    Ok(())
}

#[test]
fn metadata_is_bounded_redacted_and_never_extracted() -> Result<()> {
    let key = SecretKey::from_bytes([11; 32]);
    let file_id = key.fingerprint("file", &[b"doc.docx"]);
    let surface = Surface {
        key: &key,
        file_id: &file_id,
        path: None,
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        writer.start_file(
            "docProps/core.xml",
            zip::write::SimpleFileOptions::default(),
        )?;
        writer.write_all(b"<dc:creator>Private Example Identity</dc:creator>")?;
        writer.start_file(
            "word/vbaProject.bin",
            zip::write::SimpleFileOptions::default(),
        )?;
        writer.write_all(b"not executable; synthetic")?;
        writer.start_file(
            "../../never-extract.txt",
            zip::write::SimpleFileOptions::default(),
        )?;
        writer.write_all(b"not extracted")?;
        writer.finish()?;
    }
    let result = MetadataDetector::new()?.scan(cursor.get_ref(), "docx", &surface);
    assert!(result.recognized);
    assert!(result
        .findings
        .iter()
        .any(|f| f.rule_id == "metadata.identity"));
    assert!(result
        .findings
        .iter()
        .any(|f| f.rule_id == "metadata.active-content"));
    assert!(!serde_json::to_string(&result.findings)?.contains("Private Example Identity"));
    let malformed = MetadataDetector::new()?.scan(b"PK\x03\x04garbage", "docx", &surface);
    assert!(malformed.incomplete);
    Ok(())
}

#[test]
fn exif_gps_and_malformed_media_are_handled_without_values() -> Result<()> {
    let key = SecretKey::from_bytes([12; 32]);
    let id = key.fingerprint("file", &[b"photo.jpg"]);
    let surface = Surface {
        key: &key,
        file_id: &id,
        path: None,
    };
    let mut tiff = b"II\x2a\0\x08\0\0\0\x01\0".to_vec();
    tiff.extend_from_slice(&[0x25, 0x88, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    tiff.extend_from_slice(&[0, 0, 0, 0]);
    let mut payload = b"Exif\0\0".to_vec();
    payload.extend_from_slice(&tiff);
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1];
    jpeg.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    jpeg.extend_from_slice(&payload);
    jpeg.extend_from_slice(&[0xff, 0xd9]);
    let detector = MetadataDetector::new()?;
    let result = detector.scan(&jpeg, "jpg", &surface);
    assert!(result.findings.iter().any(|f| f.rule_id == "metadata.gps"));
    for length in 0..jpeg.len() {
        let _ = detector.scan(&jpeg[..length], "jpg", &surface);
    }
    for length in 0..512 {
        let bytes: Vec<u8> = (0..length)
            .map(|index| (index * 73 + length * 19) as u8)
            .collect();
        let _ = detector.scan(&bytes, "docx", &surface);
    }
    Ok(())
}

#[test]
fn html_escapes_untrusted_paths_and_sarif_percent_encodes_them() -> Result<()> {
    assert_eq!(
        report::html::escape("<script>&\"'"),
        "&lt;script&gt;&amp;&quot;&#39;"
    );
    let root = tempdir()?;
    fs::write(
        root.path().join("settings.toml"),
        format!("api_key='{}'", fake_token()),
    )?;
    let mut result = scan(
        &ScanOptions::new(root.path()),
        &Policy::default(),
        &SecretKey::from_bytes([13; 32]),
    )?;
    for finding in &mut result.findings {
        finding.path = Some("<img src=x onerror=alert(1)>#.toml".into());
    }
    let html = report::html::render(&result);
    assert!(!html.contains("<img"));
    assert!(!html.contains("<script"));
    assert!(html.contains("default-src 'none'"));
    let sarif = report::sarif::render(&result)?;
    let document: serde_json::Value = serde_json::from_str(&sarif)?;
    assert_eq!(document["version"], "2.1.0");
    let uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .context("missing SARIF URI")?;
    assert!(uri.starts_with("%3Cimg%20"));
    assert!(uri.contains("%23"));
    Ok(())
}

#[test]
fn low_entropy_and_placeholder_values_are_not_secrets() -> Result<()> {
    assert_eq!(entropy("aaaaaaaa"), 0.0);
    assert!(entropy("aB3dE5gH7jK9mN1pQ2sT4vW6yZ8") > 3.5);
    let key = SecretKey::from_bytes([14; 32]);
    let id = key.fingerprint("file", &[b"test"]);
    let surface = Surface {
        key: &key,
        file_id: &id,
        path: None,
    };
    let result = TextDetector::new()?.scan(
        "api_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\npassword=example_value_is_not_a_real_secret",
        "sample.toml",
        &surface,
    );
    assert!(result.findings.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_followed_and_symlink_roots_are_refused() -> Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempdir()?;
    let outside = tempdir()?;
    fs::write(outside.path().join("secret.txt"), fake_token())?;
    symlink(outside.path(), root.path().join("linked"))?;
    let key = SecretKey::from_bytes([15; 32]);
    let result = scan(&ScanOptions::new(root.path()), &Policy::default(), &key)?;
    assert!(result.findings.is_empty());
    assert!(result.coverage.iter().any(|i| i.code == "link-skipped"));
    assert!(scan(
        &ScanOptions::new(root.path().join("linked")),
        &Policy::default(),
        &key
    )
    .is_err());
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_junctions_are_not_followed() -> Result<()> {
    let root = tempdir()?;
    let outside = tempdir()?;
    fs::write(outside.path().join("secret.txt"), fake_token())?;
    let linked = root.path().join("junction");
    let status = std::process::Command::new(veilforge::windows::system_executable("cmd.exe")?)
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&linked)
        .arg(outside.path())
        .output()?;
    assert!(
        status.status.success(),
        "cannot create synthetic CI junction"
    );
    let result = scan(
        &ScanOptions::new(root.path()),
        &Policy::default(),
        &SecretKey::from_bytes([16; 32]),
    )?;
    fs::remove_dir(&linked)?;
    assert!(result.findings.is_empty());
    assert!(result.coverage.iter().any(|i| i.code == "link-skipped"));
    Ok(())
}

#[test]
fn policy_parser_rejects_unknown_fields_and_invalid_globs() -> Result<()> {
    let root = tempdir()?;
    let path = root.path().join("policy.toml");
    fs::write(
        &path,
        "version = 1\nfail_on = 'high'\nunknown_option = true",
    )?;
    assert!(Policy::load(&path).is_err());
    fs::write(&path, "version = 1\nexclude = ['[']")?;
    assert!(Policy::load(&path).is_err());
    fs::write(&path, include_str!("../docs/policy.example.toml"))?;
    assert!(Policy::load(&path).is_ok());
    Ok(())
}

#[test]
fn file_and_total_budget_limits_are_enforced() -> Result<()> {
    let root = tempdir()?;
    for name in ["a.txt", "b.txt", "c.txt"] {
        fs::write(root.path().join(name), vec![b'a'; 700])?;
    }
    let key = SecretKey::from_bytes([17; 32]);
    let mut options = ScanOptions::new(root.path());
    options.max_total_bytes = 1024;
    let result = scan(&options, &Policy::default(), &key)?;
    assert!(result.stats.bytes_read <= 1024);
    assert!(result.coverage.iter().any(|i| i.code == "total-byte-limit"));
    options.max_total_bytes = 10_000;
    options.max_files = 1;
    let result = scan(&options, &Policy::default(), &key)?;
    assert_eq!(result.stats.files_scanned, 1);
    assert!(result.coverage.iter().any(|i| i.code == "file-count-limit"));
    Ok(())
}

#[test]
fn reserved_key_and_baseline_paths_are_not_scanned() -> Result<()> {
    let root = tempdir()?;
    let path = root.path().join("key.vfkey");
    fs::write(&path, fake_token())?;
    let mut options = ScanOptions::new(root.path());
    options.reserved_paths.push(path);
    let result = scan(
        &options,
        &Policy::default(),
        &SecretKey::from_bytes([18; 32]),
    )?;
    assert_eq!(result.stats.files_scanned, 0);
    assert!(result.findings.is_empty());
    Ok(())
}

#[test]
fn report_ids_do_not_depend_on_line_numbers() -> Result<()> {
    let root = tempdir()?;
    let path = root.path().join("config.toml");
    fs::write(&path, format!("api_key={}\n", fake_token()))?;
    let key = SecretKey::from_bytes([19; 32]);
    let options = ScanOptions::new(root.path());
    let first = scan(&options, &Policy::default(), &key)?;
    fs::write(
        &path,
        format!("# new harmless line\napi_key={}\n", fake_token()),
    )?;
    let second = scan(&options, &Policy::default(), &key)?;
    assert_eq!(
        first.findings.iter().map(|f| &f.id).collect::<Vec<_>>(),
        second.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn scan_limits_are_validated_before_reading() -> Result<()> {
    let root = tempdir()?;
    let key = SecretKey::from_bytes([20; 32]);
    let mut options = ScanOptions::new(root.path());
    options.threads = 0;
    assert!(scan(&options, &Policy::default(), &key).is_err());
    assert_eq!(
        veilforge::scan::normalized_path(Path::new("one").join("two").as_path()),
        "one/two"
    );
    Ok(())
}
