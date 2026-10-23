# Threat model and limitations

## Intended use

An authorized operator wants to review a directory before publication, identify accidental credential/configuration/metadata exposure, and optionally review basic Windows defensive posture. VeilForge reduces accidental disclosure in its own report formats while keeping limitations visible.

## In scope

- Accidental credential-shaped strings in supported text files.
- Obvious publication identity/geolocation metadata and active-content indicators.
- Selected unsafe deployment configuration indicators.
- Unsafe symlinks/reparse points, file changes, unsupported encoding, and resource caps.
- Avoiding raw secret/snippet output, remote validation, document execution, or report scripts.
- Same-audit credential replication and baseline comparison without plaintext persistence.

## Not in scope

- Exploitation, stealth, evasion, anti-forensics, browser credential stores, account takeover, network scanning, or automated remediation.
- Proving absence of secrets, proving an input is not malicious, or validating token privileges/expiry.
- Full PDF/image/Office parsing, hidden steganography, archive recursion, Git history unpacking, encrypted documents, alternate data streams, or comprehensive PII recognition.
- A hostile local administrator, kernel malware, compromised dependencies, or attackers mutating the filesystem while scans run.
- Making report files safe to publish publicly. Reports reveal detector results, posture, timing, file relationships, counts, and pseudonymous identity.

## Residual risks

### Filesystem races and hard links

VeilForge refuses link/reparse roots, does not follow traversal links, checks canonical containment and file metadata, uses final-component no-follow open flags, and checks opened-file metadata/length/modification time. These are best-effort checks, **not a sandbox**. Concurrent parent-directory replacements can still race with path-based opens. Hard links are regular files and can reference content shared with another path. On Windows, creation/modified-time/size comparison is not a cryptographic file-identity proof. Run on a trusted, quiescent directory or snapshot, with the minimum necessary account privileges.

The per-directory sort used for reproducible scheduling allocates directory entries; an adversarial enormous single directory can consume memory before file limits apply. Total byte budgets count scheduled file bytes, not decompressor CPU, Unicode expansion, or all report object allocations. Bounded documents/workers and match limits mitigate, but do not eliminate, resource exhaustion. There is no full-scan wall-clock timeout. Use an external job/container/time limit for untrusted input.

### Secret memory

Read buffers, decoded text buffers, temporary lowercase/PDF text copies, and the fingerprint key are zeroized on normal drop where practical. OS file caches, allocator copies, regex internals, swap, crash dumps, process snapshots, aborted processes, and kernel memory are not controlled. `panic=abort` does not run destructors. Zeroization is defense in depth, not a no-residue guarantee.

### Fingerprint key confidentiality

A stolen persistent key allows dictionary attacks against report fingerprints for guessed values/paths and creates cross-run linkability. Do not check keys into Git, put them inside scan roots, or send them with reports. The `.gitignore` excludes common key/report names but cannot prevent every accidental commit. Ephemeral keys are the safer default for one-off reports, but cannot support baselines.

On Windows, key generation disables ACL inheritance on the newly created empty file and grants the current SID access before writing. The inherited file owner, administrators, and backup privileges can still access or replace files. Loaded keys reject reparse points but do **not** fully audit existing Windows ACLs; inspect ACLs yourself. SystemRoot is used to locate Windows system executables; a hostile process environment is not defended against. `whoami` and `icacls` are used only for requested key creation. They are not used by ordinary artifact scans.

### Reports and terminal privacy

Raw matched credentials and neighboring text are not included. Default relative paths are hidden; absolute roots are only keyed IDs. File-ID relationships, rule IDs, line/column numbers, scores, creation time, and occurrence counts remain visible. `--reveal-paths` intentionally exposes names; filenames themselves may contain secrets. Terminal output does not reveal paths even with this flag. CLI parser/system errors may identify explicitly supplied arguments or OS error context; do not pass secrets as arguments.

Report creation uses a temporary file and refuses overwrite. UNIX temporary report files are owner-only; Windows report files inherit directory security and are **not guaranteed private**. Use a private output directory. Different output files are not a multi-file transaction: an I/O failure can leave earlier complete reports in place. Never assume reports are signed or tamper-proof.

### Heuristics and unsupported content

Known-token patterns can match fake fixtures. Generic credential assignments require context and entropy, but passwords with low entropy, transformed values, split literals, and unrecognized patterns can be missed. Placeholder filtering can miss real credentials containing placeholder-like substrings. Private-key detection recognizes headers, not key validity or complete key content.

Config detectors do not interpret a language, deployment environment, or comments. A flagged setting may be inactive. Conversely quoted keys, alternate syntax, nested formats, and interpolated values may be missed. Repeated copies and co-occurrences are exposure hypotheses, not observed exploitation.

JPEG EXIF inspection checks a limited set of top-level and linked directory tags, not every MakerNote, nested thumbnail, or EXIF subdirectory field. XMP segments cause partial coverage. PDF inspection cannot reliably read encrypted/compressed metadata and is always partial. Office inspection is lexical, fixed-member, and does not follow XML entities. Legacy Office/media formats are partial. Some formats not recognized by extension or magic can be treated as unsupported binary. Treat every metadata result as an aid to review—not certification that sanitization succeeded.

### Windows posture

`--host` invokes a fixed PowerShell script without a profile, user interpolation, elevation, network commands, or writes. It queries firewall profiles, Defender status, and RDP registry settings, discarding stderr and emitting booleans only. Third-party antivirus can make a Defender warning expected. Missing cmdlets, privileges, endpoint policies, and PowerShell restrictions cause incomplete coverage. PowerShell command/module loading still relies on a trustworthy Windows installation/environment. The 15-second timeout kills the direct child, not an arbitrary malicious descendant tree. No network reachability or effective domain/GPO analysis is performed.

### Policy and baselines

Exclusions deliberately reduce scope and are counted as pruned entries, not coverage errors. A score applies only to non-excluded supported scope. Suppressions need review; a global suppression can hide many findings. Expired entries are ignored and cause an incomplete-policy warning. JSON baselines are schema/identity-validated but not signed; maliciously edited reports can affect comparisons. Keep keys, policies, and baselines under your own access controls.

### Supply chain and CI

Public repository content must never contain user scan data or real credentials. GitHub runner tests use only temporary synthetic inputs. Actions are pinned and lockfiles are committed, but compiler/crate/runner compromise remains possible. Dependency advisories are checked separately and can fail when upstream crates acquire new advisories. Checksums detect accidental corruption, not malicious replacement by a repository attacker. Releases are not code-signed Windows executables and may trigger SmartScreen.

## Responsible operating procedure

1. Use a trusted directory/snapshot and an unprivileged account.
2. Scan the actual release artifact, not an entire disk or another person's files.
3. Keep reports and keys outside the scan scope in private directories.
4. Investigate coverage issues before using a report as a baseline.
5. Review findings; rotate/revoke real exposed credentials at their issuer.
6. Sanitize publication copies using trusted format-specific tools and rescan.
7. Never equate a score of 100 with anonymity, invisibility, or complete safety.
