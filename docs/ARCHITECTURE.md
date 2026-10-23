# Architecture

## Execution pipeline

```text
CLI / strict TOML policy / optional 32-byte key
          │
          ▼
canonical root + exclusions + reserved key/policy/baseline paths
          │
          ▼
no-follow traversal → count/depth/file/total budgets → candidate manifest
          │
          ▼
bounded Rayon pool → no-follow open + metadata checks → bounded read
          │
          ├── UTF-8 / BOM UTF-16 → regex + entropy + configuration indicators
          └── document magic / extension → bounded EXIF / Office / PDF inspectors
          │
          ▼
redacted findings + explicit coverage counters
          │
          ├── optional fixed Windows read-only posture probe
          ▼
time-scoped policy suppressions → active-only exposure correlations
          │
          ▼
score + optional same-root/key/policy baseline delta
          │
          ▼
terminal / JSON / SARIF / script-free escaped HTML
```

## Modules

| Path | Responsibility |
|---|---|
| `src/main.rs` | CLI, output preflight, persistent/ephemeral key selection, exit behavior |
| `src/key.rs` | Random key creation, platform key-file protections, framed keyed fingerprints |
| `src/scan.rs` | Scope enforcement, safe-open best-effort checks, worker and byte limits, text decoding, coverage |
| `src/detectors/mod.rs` | Static rule catalog and content-free finding construction |
| `src/detectors/text.rs` | Known credential shapes, context/entropy heuristic, unsafe configuration |
| `src/detectors/metadata.rs` | Bounded, non-executing JPEG/Office/PDF inspection |
| `src/windows.rs` | Opt-in, fixed PowerShell snapshot with timeout; trusted-system-path helper |
| `src/policy.rs` | Strict TOML, known rules, bounded globs, reviewed expiring suppressions |
| `src/correlation.rs` | Keyed credential reuse and co-occurrence hypotheses |
| `src/baseline.rs` | Bounded JSON loading, schema/identity validation, safe resolution logic |
| `src/report/` | Redacted output encoders and no-clobber report publication |
| `tests/` | Focused security invariants and end-to-end exit/output contracts |

## Identity design

Each fingerprint uses a keyed BLAKE3 hasher, a versioned namespace, a length-framed domain, and length-framed components. Length framing prevents ambiguous concatenations. No unkeyed hash of a credential is persisted. A fixed key creates stable correlation within an audit program; an ephemeral key intentionally prevents cross-run matching.

- **Root ID:** canonical OS-native absolute path, hidden behind keyed hashing.
- **File ID:** root-relative OS-native path bytes; different path encodings/platforms are not promised identical IDs.
- **Finding ID:** rule ID + file ID + matched value or a constant metadata/config marker. No line number, so inserting a harmless line does not reset a finding.
- **Entity ID:** matched credential only, allowing reuse detection across files/rules. Private-key headers do not receive entity IDs because equal headers do not imply equal keys.
- **Chain ID:** chain kind + sorted unique finding IDs.

The raw matched value is only handed to the keyed hasher. Evidence strings come from the static catalog/detector code, not the input. Line/column positions describe a value's start, never a code snippet. Multiple occurrences of the same rule/value/file are aggregated.

## Reporting and scores

JSON schema version is explicit; unknown fields and unknown rule IDs are rejected on baseline import. Reports are data, not digitally authenticated records. Baseline trust is the user's responsibility. Key/root/policy mismatches fail closed. Old incomplete reports are not accepted as baselines; incomplete current reports can report new/unchanged but never resolved findings.

Score weights: info `0`, low `3`, medium `8`, high `20`, critical `40`, deduplicated per rule and surface; displayed value is `100 - min(points, 100)`. It is intentionally transparent. Chain severity is explanatory and is not added to points, avoiding double counting. The score label explicitly changes to incomplete when coverage is missing.

SARIF has no physical locations unless paths are explicitly revealed. This preserves privacy but limits IDE/code-scanning navigation. Revealed locations use percent-encoded relative URIs and Unicode-code-point columns. JSON always retains pseudonyms. HTML escapes all strings and embeds no executable code. Reports are published with a synced temporary file and no-clobber persist; output files are not group-wide private by guarantee on Windows (see threat model).

## Document boundaries

Office processing never extracts members and reads only a fixed metadata/relationship allowlist, with size limits before and during decompression. Macros are detected by member names and never opened. Ordinary external hyperlinks can produce an active-content indicator: this is not a malware verdict. XML is searched lexically; entities/DTDs are not resolved. Relationships beyond the allowlist make coverage partial.

JPEG processes marker lengths and bounded TIFF directory offsets. GPS pointers alone create a location finding; coordinates and device values are not stored. The reader is not a comprehensive image sanitization validator. PDF is a lexical indicator reader and always partial. Unsupported media types are visibly partial rather than silently green.

## CI philosophy

No local compile or test operations are necessary. GitHub runner workflows own formatting, lockfile generation, important invariant tests, static checks, dependency policy, and release builds. Source maintenance is manually dispatched and commits only `Cargo.lock`, `src/`, and `tests/`; a CI dispatch after maintenance validates the resulting commit. Release tests occur only on deliberate release dispatch, not on every source change.
