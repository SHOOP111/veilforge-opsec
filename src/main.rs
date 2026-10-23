use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::{collections::BTreeSet, path::PathBuf};
use veilforge::{
    baseline, detectors,
    key::SecretKey,
    model::Severity,
    policy::Policy,
    report,
    scan::{self, ScanOptions},
};

#[derive(Parser)]
#[command(
    name = "veilforge",
    version,
    about = "Offline, privacy-preserving defensive OPSEC auditor",
    long_about = "VeilForge audits a directory you own or are authorized to inspect. No network access, secret validation, cleanup, or evasion. Hidden paths and ephemeral keyed fingerprints are the default."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Audit local artifacts; optional read-only Windows posture snapshot.
    Scan(ScanArgs),
    /// Create a persistent 32-byte fingerprint key; never overwrites.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a strict policy template; never overwrites.
    InitPolicy {
        #[arg(long)]
        out: PathBuf,
    },
    /// Show the detector catalog (no scan).
    Rules,
    /// Compare two JSON reports from the same key, root, and policy.
    Compare {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
    },
    /// Explain a built-in detector and its remediation.
    Explain { rule_id: String },
}

#[derive(Args)]
struct ScanArgs {
    /// Authorized directory to inspect. Symlink/reparse-point roots are refused.
    root: PathBuf,
    /// Persistent key for stable pseudonyms. Default: ephemeral key.
    #[arg(long)]
    key: Option<PathBuf>,
    /// Strict versioned TOML policy.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Previous complete JSON report; requires --key.
    #[arg(long, requires = "key")]
    baseline: Option<PathBuf>,
    /// Opt in to relative paths in output files. Matched values remain hidden.
    #[arg(long)]
    reveal_paths: bool,
    /// Run fixed, read-only Windows firewall, Defender, RDP, and NLA checks.
    #[arg(long)]
    host: bool,
    /// JSON destination (must not already exist).
    #[arg(long)]
    json: Option<PathBuf>,
    /// SARIF 2.1.0 destination (must not already exist).
    #[arg(long)]
    sarif: Option<PathBuf>,
    /// Self-contained, script-free HTML destination (must not already exist).
    #[arg(long)]
    html: Option<PathBuf>,
    /// Active-finding exit threshold; overrides policy. Coverage gaps always exit 3.
    #[arg(long)]
    fail_on: Option<Severity>,
    #[arg(long, default_value_t = scan::DEFAULT_MAX_FILE_BYTES)]
    max_file_bytes: u64,
    #[arg(long, default_value_t = scan::DEFAULT_MAX_TOTAL_BYTES)]
    max_total_bytes: u64,
    #[arg(long, default_value_t = scan::DEFAULT_MAX_FILES)]
    max_files: usize,
    #[arg(long, default_value_t = 64)]
    max_depth: usize,
    #[arg(long, default_value_t = 4)]
    threads: usize,
}

fn main() -> std::process::ExitCode {
    match run(Cli::parse()) {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("VeilForge error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Keygen { out } => {
            SecretKey::create(&out)?;
            println!(
                "Fingerprint key created. Keep it private, outside scan roots and version control."
            );
            Ok(0)
        }
        Command::InitPolicy { out } => {
            report::write_new(&out, include_str!("../docs/policy.example.toml"))?;
            println!(
                "Policy template created. Review exclusions and use time-limited suppressions."
            );
            Ok(0)
        }
        Command::Rules => {
            for rule in detectors::catalog() {
                println!("{:28} {:8} {}", rule.id, rule.severity, rule.title);
            }
            Ok(0)
        }
        Command::Explain { rule_id } => {
            let rule = detectors::catalog()
                .iter()
                .find(|r| r.id == rule_id)
                .context("unknown rule ID; run `veilforge rules`")?;
            println!(
                "{} [{}]\n{}\n\n{}",
                rule.id, rule.severity, rule.title, rule.recommendation
            );
            Ok(0)
        }
        Command::Compare { before, after } => {
            let old = baseline::load(&before)?;
            let current = baseline::load(&after)?;
            let summary = baseline::compare(&old, &current)?;
            println!(
                "{} new · {} unchanged · {} resolved",
                summary.new,
                summary.unchanged,
                summary.resolved_ids.len()
            );
            if !current.coverage.is_empty() {
                println!("Current scan is incomplete; no findings are claimed resolved.");
                return Ok(3);
            }
            Ok(if summary.new > 0 { 2 } else { 0 })
        }
    }
}

fn run_scan(args: ScanArgs) -> Result<i32> {
    let mut destinations = BTreeSet::new();
    for path in [&args.json, &args.sarif, &args.html].into_iter().flatten() {
        if std::fs::symlink_metadata(path).is_ok() {
            bail!("output destination exists; use a new filename");
        }
        let filename = path
            .file_name()
            .context("output destination requires a filename")?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let canonical = parent
            .canonicalize()
            .context("output parent directory must exist")?
            .join(filename);
        // Case-fold conservatively on Windows to reject ambiguous destination aliases.
        #[cfg(windows)]
        let identity = canonical.to_string_lossy().to_lowercase();
        #[cfg(not(windows))]
        let identity = canonical;
        if !destinations.insert(identity) {
            bail!("output destinations must be distinct");
        }
    }
    let policy = match &args.policy {
        Some(path) => Policy::load(path)?,
        None => Policy::default(),
    };
    let key = match &args.key {
        Some(path) => SecretKey::load(path)?,
        None => {
            eprintln!("Privacy: ephemeral key; report IDs cannot be compared across runs. Use `keygen` and --key for baselines.");
            SecretKey::ephemeral()
        }
    };
    let old = args
        .baseline
        .as_ref()
        .map(|p| baseline::load(p))
        .transpose()?;
    let mut options = ScanOptions::new(args.root);
    options.max_file_bytes = args.max_file_bytes;
    options.max_total_bytes = args.max_total_bytes;
    options.max_files = args.max_files;
    options.max_depth = args.max_depth;
    options.threads = args.threads;
    options.reveal_paths = args.reveal_paths;
    options.include_host = args.host;
    options.reserved_paths = [
        &args.key,
        &args.policy,
        &args.baseline,
        &args.json,
        &args.sarif,
        &args.html,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    let mut result = scan::scan(&options, &policy, &key)?;
    if let Some(before) = &old {
        baseline::apply(before, &mut result)?;
    }
    if let Some(path) = &args.json {
        report::write_new(path, &report::json(&result)?)?;
    }
    if let Some(path) = &args.sarif {
        report::write_new(path, &report::sarif::render(&result)?)?;
    }
    if let Some(path) = &args.html {
        report::write_new(path, &report::html::render(&result))?;
    }
    print!("{}", report::terminal(&result));
    Ok(result.exit_code(args.fail_on.unwrap_or(policy.fail_on)))
}
