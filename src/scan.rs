use crate::{
    correlation,
    detectors::{metadata::MetadataDetector, text::TextDetector, Surface},
    key::{nofollow, SecretKey},
    model::{CoverageIssue, Finding, Report, ScanStats, Score, SCHEMA_VERSION},
    policy::Policy,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use rayon::prelude::*;
use std::{collections::BTreeMap, fs::OpenOptions, io::Read, path::{Path, PathBuf}};
use walkdir::{DirEntry, WalkDir};
use zeroize::Zeroizing;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_FILES: usize = 20_000;

pub struct ScanOptions {
    pub root: PathBuf,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub max_depth: usize,
    pub threads: usize,
    pub reveal_paths: bool,
    pub include_host: bool,
    pub reserved_paths: Vec<PathBuf>,
}

impl ScanOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_files: DEFAULT_MAX_FILES,
            max_depth: 64,
            threads: 4,
            reveal_paths: false,
            include_host: false,
            reserved_paths: Vec::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        if !(1..=16).contains(&self.threads)
            || !(1..=200_000).contains(&self.max_files)
            || !(1..=128).contains(&self.max_depth)
            || !(1024..=64 * 1024 * 1024).contains(&self.max_file_bytes)
            || !(1024..=4 * 1024 * 1024 * 1024).contains(&self.max_total_bytes)
        {
            bail!("invalid limits: threads 1..16, files 1..200000, depth 1..128, file bytes 1 KiB..64 MiB, total bytes 1 KiB..4 GiB");
        }
        Ok(())
    }
}

struct Candidate {
    path: PathBuf,
    relative: String,
    file_id: String,
    length: u64,
}

#[derive(Default)]
struct FileResult {
    findings: Vec<Finding>,
    bytes: u64,
    scanned: bool,
    binary: bool,
    metadata: bool,
    issues: Vec<&'static str>,
}

pub fn scan(options: &ScanOptions, policy: &Policy, key: &SecretKey) -> Result<Report> {
    options.validate()?;
    policy.validate()?;
    let root_meta = std::fs::symlink_metadata(&options.root).context("cannot inspect scan root")?;
    if !root_meta.is_dir() || unsafe_entry(&root_meta) {
        bail!("scan root must be a directory, not a symlink or reparse point");
    }
    let root = options.root.canonicalize().context("cannot resolve scan root")?;
    let root_id = key.fingerprint("root", &[root.as_os_str().as_encoded_bytes()]);
    let exclusions = policy.exclusions()?;
    let reserved: Vec<PathBuf> = options.reserved_paths.iter().filter_map(|p| p.canonicalize().ok()).collect();
    let mut stats = ScanStats { host_requested: options.include_host, ..Default::default() };
    let mut issues = BTreeMap::new();
    let mut candidates = Vec::new();
    let mut scheduled_bytes = 0u64;
    let mut walker = WalkDir::new(&root).follow_links(false).sort_by_file_name().into_iter();
    while let Some(entry) = walker.next() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => { issue(&mut issues, "traversal-error"); continue; }
        };
        if entry.depth() == 0 { continue; }
        let relative_path = match entry.path().strip_prefix(&root) {
            Ok(path) => path,
            Err(_) => { issue(&mut issues, "outside-root"); continue; }
        };
        let relative = normalized_path(relative_path);
        if default_excluded(&entry) || exclusions.is_match(&relative) || reserved.iter().any(|p| p == entry.path()) {
            stats.excluded_entries += 1;
            if entry.file_type().is_dir() { walker.skip_current_dir(); }
            continue;
        }
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => { issue(&mut issues, "metadata-error"); continue; }
        };
        if unsafe_entry(&metadata) {
            stats.files_skipped += 1;
            issue(&mut issues, "link-skipped");
            if entry.file_type().is_dir() { walker.skip_current_dir(); }
            continue;
        }
        if metadata.is_dir() {
            if entry.depth() >= options.max_depth {
                issue(&mut issues, "depth-limit");
                walker.skip_current_dir();
            }
            continue;
        }
        if !metadata.is_file() {
            issue(&mut issues, "special-file-skipped");
            continue;
        }
        stats.files_seen += 1;
        if candidates.len() >= options.max_files {
            issue(&mut issues, "file-count-limit");
            stats.files_skipped += 1;
            break;
        }
        let length = metadata.len();
        if length > options.max_file_bytes {
            stats.files_skipped += 1;
            issue(&mut issues, "file-size-limit");
            continue;
        }
        if scheduled_bytes.saturating_add(length) > options.max_total_bytes {
            stats.files_skipped += 1;
            issue(&mut issues, "total-byte-limit");
            continue;
        }
        scheduled_bytes += length;
        candidates.push(Candidate {
            path: entry.path().to_owned(),
            file_id: key.fingerprint("file", &[relative_path.as_os_str().as_encoded_bytes()]),
            relative,
            length,
        });
    }
    let text_detector = TextDetector::new()?;
    let metadata_detector = MetadataDetector::new()?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(options.threads).build()
        .context("cannot initialize bounded worker pool")?;
    let results: Vec<FileResult> = pool.install(|| candidates.par_iter().map(|candidate| {
        inspect(candidate, &root, options, key, &text_detector, &metadata_detector)
    }).collect());
    let mut findings = Vec::new();
    for result in results {
        stats.bytes_read += result.bytes;
        if result.scanned { stats.files_scanned += 1; } else { stats.files_skipped += 1; }
        if result.binary { stats.binary_files += 1; }
        if result.metadata { stats.metadata_documents += 1; }
        for code in result.issues { issue(&mut issues, code); }
        findings.extend(result.findings);
    }
    if options.include_host {
        let host = crate::windows::audit(key);
        findings.extend(host.findings);
        for code in host.issues { issue(&mut issues, code); }
    }
    let today = Utc::now().date_naive();
    policy.apply(&mut findings, today);
    let expired = policy.expired_count(today);
    if expired > 0 { issues.insert("expired-suppression", expired as u64); }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule_id.cmp(&b.rule_id)).then(a.id.cmp(&b.id)));
    let chains = correlation::build(&findings, key);
    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        tool_version: crate::VERSION.into(),
        created_at: Utc::now().to_rfc3339(),
        root_id,
        key_id: key.id(),
        policy_digest: policy.digest()?,
        paths_revealed: options.reveal_paths,
        stats,
        coverage: issues.into_iter().map(|(code, count)| CoverageIssue {
            code: code.into(), message: coverage_message(code).into(), count,
        }).collect(),
        findings,
        chains,
        score: Score { value: 0, risk_points: 0, active_findings: 0, suppressed_findings: 0, label: String::new() },
        baseline: None,
    };
    report.refresh_score();
    Ok(report)
}

fn inspect(candidate: &Candidate, root: &Path, options: &ScanOptions, key: &SecretKey, text: &TextDetector, metadata: &MetadataDetector) -> FileResult {
    let mut result = FileResult::default();
    let bytes = match read_bounded(candidate, root) {
        Ok(bytes) => bytes,
        Err(code) => { result.issues.push(code); return result; }
    };
    result.bytes = bytes.len() as u64;
    result.scanned = true;
    let surface = Surface {
        key, file_id: &candidate.file_id,
        path: options.reveal_paths.then_some(candidate.relative.as_str()),
    };
    let extension = candidate.path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let meta = metadata.scan(&bytes, &extension, &surface);
    result.metadata = meta.recognized;
    result.findings.extend(meta.findings);
    if meta.incomplete { result.issues.push("document-partial"); }
    if meta.recognized { result.binary = true; return result; }
    if let Some(decoded) = decode_text(&bytes) {
        let found = text.scan(&decoded, &candidate.relative, &surface);
        result.findings.extend(found.findings);
        if found.capped { result.issues.push("match-limit"); }
    } else {
        result.binary = true;
        result.issues.push("binary-uninspected");
    }
    result
}

fn read_bounded(candidate: &Candidate, root: &Path) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
    let resolved = candidate.path.canonicalize().map_err(|_| "open-error")?;
    if !resolved.starts_with(root) || resolved != candidate.path { return Err("path-changed"); }
    let before = std::fs::symlink_metadata(&candidate.path).map_err(|_| "open-error")?;
    if !before.is_file() || unsafe_entry(&before) || before.len() != candidate.length { return Err("path-changed"); }
    let mut options = OpenOptions::new();
    options.read(true);
    nofollow(&mut options);
    let mut file = options.open(&candidate.path).map_err(|_| "open-error")?;
    let opened = file.metadata().map_err(|_| "open-error")?;
    if !opened.is_file() || unsafe_entry(&opened) || opened.len() != candidate.length || !same_file(&before, &opened) {
        return Err("path-changed");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(candidate.length.min(64 * 1024) as usize));
    Read::by_ref(&mut file).take(candidate.length).read_to_end(&mut bytes).map_err(|_| "read-error")?;
    let after = file.metadata().map_err(|_| "read-error")?;
    if bytes.len() as u64 != candidate.length || after.len() != opened.len() || after.modified().ok() != opened.modified().ok() {
        return Err("file-changed");
    }
    Ok(bytes)
}

fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.created().ok() == b.created().ok() && a.modified().ok() == b.modified().ok()
    }
}

pub(crate) fn unsafe_entry(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() { return true; }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    { false }
}

fn default_excluded(entry: &DirEntry) -> bool {
    entry.file_type().is_dir() && entry.file_name().to_str().is_some_and(|name| matches!(name,
        "target" | "node_modules" | ".veilforge" | ".venv" | "venv" | "__pycache__"))
}

pub fn normalized_path(path: &Path) -> String {
    path.components().map(|c| c.as_os_str().to_string_lossy().chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect::<String>())
        .collect::<Vec<_>>().join("/")
}

fn decode_text(bytes: &[u8]) -> Option<Zeroizing<String>> {
    if bytes.starts_with(b"\xff\xfe") || bytes.starts_with(b"\xfe\xff") {
        if bytes.len() % 2 != 0 { return None; }
        let little = bytes.starts_with(b"\xff\xfe");
        let units = Zeroizing::new(bytes[2..].chunks_exact(2).map(|b| if little {
            u16::from_le_bytes([b[0], b[1]])
        } else { u16::from_be_bytes([b[0], b[1]]) }).collect::<Vec<_>>());
        return String::from_utf16(&units).ok().map(Zeroizing::new);
    }
    if bytes.contains(&0) { return None; }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    std::str::from_utf8(bytes).ok().map(|s| Zeroizing::new(s.to_owned()))
}

fn issue(issues: &mut BTreeMap<&'static str, u64>, code: &'static str) {
    *issues.entry(code).or_default() += 1;
}

fn coverage_message(code: &str) -> &'static str {
    match code {
        "link-skipped" => "Symlinks or Windows reparse points were skipped, never followed.",
        "file-count-limit" => "The file-count limit stopped traversal; remaining files were not scanned.",
        "file-size-limit" => "Files exceeded the per-file limit and were not read.",
        "total-byte-limit" => "The total read budget prevented scanning additional files.",
        "depth-limit" => "Directories beyond the depth limit were not traversed.",
        "document-partial" => "Document metadata inspection was partial or a document was malformed/unsupported.",
        "binary-uninspected" => "Unrecognized binary or legacy-encoded files were not inspected for credentials.",
        "match-limit" => "A file exceeded the credential-match limit; further matches were not examined.",
        "expired-suppression" => "Expired policy suppressions were ignored; renew only after review.",
        "host-unsupported" => "Host posture checks are only supported on Windows.",
        "host-incomplete" => "One or more Windows posture checks were unavailable or failed.",
        _ => "Some files could not be inspected safely or changed during inspection.",
    }
}
