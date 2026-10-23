# VeilForge

**Offline exposure intelligence for files you are about to share.**

[![CI](https://github.com/SHOOP111/veilforge-opsec/actions/workflows/ci.yml/badge.svg)](https://github.com/SHOOP111/veilforge-opsec/actions/workflows/ci.yml)

VeilForge is a Windows-first Rust defensive OPSEC auditor. It finds likely credentials, publication metadata, risky configuration, and combinations that deserve attention—without sending files anywhere, opening documents in applications, or checking tokens against a remote service.

> Defensive auditing, not invisibility. No anti-forensics, log removal, credential extraction from browsers, exploitation, persistence, or evasion. Use only on files and systems you own or are authorized to inspect.

## What makes it different

- **Keyed identity plane:** BLAKE3 keyed, domain-separated pseudonyms for roots, artifacts, credentials, findings, and exposure chains. No raw matched values or surrounding lines in reports. Paths are hidden by default.
- **Exposure atlas:** combines repeated credential copies, credential-bearing environment files, weakened TLS with credentials, debug wildcard listeners, and RDP/firewall posture. Every chain is explicitly a hypothesis, not an observed attack.
- **Coverage honesty:** oversized files, traversal failures, changing files, links, unrecognized binaries, incomplete documents, and capped matches are reported. An incomplete scan returns `3`, even when no finding crosses the threshold.
- **Stable baselines:** findings survive line-number changes. Comparisons require the same key, canonical root, and policy. Incomplete scans never claim missing findings are resolved.
- **Publication metadata:** bounded JPEG EXIF pointer/tag inspection, Office core properties, macros and selected external relationships, and lexical PDF metadata/action indicators. ZIP members are never extracted.
- **Windows posture, explicitly opt-in:** fixed read-only checks for firewall profiles, Defender, RDP, and Network Level Authentication. No elevation or automatic changes.
- **Reviewable policy:** strict TOML, scoped file-ID suppressions with mandatory rationale and UTC expiry, explicit glob exclusions, and an auditable policy digest.
- **Three report planes:** versioned JSON, SARIF 2.1.0, and a self-contained HTML exposure atlas with CSP, no scripts, no fonts/CDNs, no active links or remote assets.
- **Bounded execution:** parallel workers, file/total byte budgets, file count/depth limits, match caps, symlink/reparse-point rejection, and source-buffer zeroization on normal drop.

## Windows quick start

Download a Windows release ZIP from [Releases](https://github.com/SHOOP111/veilforge-opsec/releases), when one is available. Release binaries are built only on GitHub runners. CI status is not a release signature; independently verify provenance before use.

The commands below are **usage examples**. They are not automatically run by repository creation or workflows on your PC.

```powershell
# Inspect a publication directory; nothing is changed in that directory.
.\veilforge.exe scan "C:\Work\publication" `
  --json "C:\Audit\report-001.json" `
  --html "C:\Audit\report-001.html"

# Stable identities for repeat audits; keep the key OUTSIDE the scan directory.
.\veilforge.exe keygen --out "C:\Audit\identity.vfkey"
.\veilforge.exe scan "C:\Work\publication" `
  --key "C:\Audit\identity.vfkey" --json "C:\Audit\baseline.json"

# Subsequent scan; use the same canonical directory and policy.
.\veilforge.exe scan "C:\Work\publication" `
  --key "C:\Audit\identity.vfkey" --baseline "C:\Audit\baseline.json" `
  --json "C:\Audit\report-002.json" --html "C:\Audit\report-002.html"

# Host posture is never collected unless you explicitly request it.
.\veilforge.exe scan "C:\Work\publication" --host

# Paths can identify people/projects. Reveal them only when you need locations.
.\veilforge.exe scan "C:\Work\publication" --reveal-paths `
  --sarif "C:\Audit\report-003.sarif"

.\veilforge.exe init-policy --out "C:\Audit\policy.toml"
.\veilforge.exe rules
.\veilforge.exe explain secret.private-key
.\veilforge.exe compare --before "C:\Audit\baseline.json" --after "C:\Audit\report-002.json"
```

Create the output parent directory yourself. Output files and keys are **never overwritten**. The fingerprint key is 32 raw random bytes—not a password or hex string. Windows key creation removes inherited ACLs and grants the current user access before writing the key; UNIX keys use mode `0600` and reject permissive loaded keys. See [security limitations](docs/THREAT_MODEL.md) for ACL and administrator caveats.

Linux uses the same CLI, without `.exe`. Host posture is Windows-only; `--host` elsewhere yields incomplete coverage.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete observed coverage within explicit scope; no active finding at/above threshold |
| `1` | Command, policy, output, key, or baseline error |
| `2` | Complete scan with active findings at/above `--fail-on` (default `high`), or new findings in `compare` |
| `3` | Incomplete coverage or expired suppressions; no clean verdict |

Finding exit codes evaluate individual rules, not chain severity. The score is a deliberately simple, capped rule/surface prioritization measure—not a compromise probability or certification. Suppressed findings remain in the ledger and do not contribute to the score or chains.

### Resource controls

Defaults: 4 workers, 4 MiB/file, 256 MiB total scheduled reads, 20,000 files, depth 64, and 256 credential candidates per file. CLI limits are validated; maximum file size is 64 MiB and maximum total scheduled reads is 4 GiB. Office inspection has separate 4,096 member / 256 KiB member / 1 MiB aggregate metadata budgets. Host PowerShell is bounded to 15 seconds and 8 KiB output.

Built-in excluded directories: `target`, `node_modules`, `.veilforge`, `.venv`, `venv`, `__pycache__`. **`.git` is not excluded**: its config can contain credentials or identifying remotes. Add explicit exclusions when the scan is limited to a release artifact. `excluded_entries` counts pruned entries, not every descendant. Hidden descendants are outside the declared scan scope.

UTF-8 (including BOM) and BOM-marked UTF-16LE/BE text are supported. Legacy code pages are not silently decoded. Unrecognized binaries and unsupported document types create coverage gaps. PDF inspection is always marked partial because compressed/encrypted objects are not parsed.

## CI only—no local build or test required

All development validation in this repository runs in [GitHub Actions](https://github.com/SHOOP111/veilforge-opsec/actions):

- **Remote source maintenance** (`workflow_dispatch`): generate `Cargo.lock` and format Rust on an Ubuntu runner, then commit only those changes. Run this first on a new repository or when intentionally refreshing the lockfile.
- **CI**: one critical invariant/CLI test suite and Clippy pass on Windows and Linux; formatting on Linux; separate dependency advisory/license/source policy. No benchmarks, stress farms, or redundant build-only jobs.
- **Release binaries** (manual, existing `vX.Y.Z` tag): test the tagged source, build optimized Windows/Linux binaries, package licenses, and publish SHA-256 checksums after both platforms pass.
- **Dependabot**: monthly grouped dependency/action updates, rather than noisy daily rebuilds.

Actions use GitHub-hosted runners, not self-hosted runners. No workflow accesses this machine or scans user files. Release and source-maintenance jobs require explicit dispatch. Code checkout has read-only permissions except the narrow maintenance and release-publish jobs. External Actions are pinned to commit SHAs.

To trigger CI remotely with GitHub CLI:

```text
gh workflow run ci.yml --repo SHOOP111/veilforge-opsec
gh run list --repo SHOOP111/veilforge-opsec
```

## Documentation

- [Architecture and data flow](docs/ARCHITECTURE.md)
- [Threat model and limitations](docs/THREAT_MODEL.md)
- [Policy template](docs/policy.example.toml)
- [Security reporting](SECURITY.md)
- [Contributing without local tests](CONTRIBUTING.md)

## License

Dual-licensed under MIT or Apache-2.0, at your option. Third-party dependencies retain their respective licenses.
