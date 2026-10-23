# Contributing

## Remote-only validation

Do not compile or test on the project owner's PC. Use GitHub-hosted Actions runners. Editing, source review, Git operations, and workflow dispatch are sufficient locally.

1. Make small, reviewable source edits. Never add real scan data or credentials.
2. Push a feature branch or open a PR. Existing lockfiles are required for `--locked` CI.
3. Let CI run the important invariant/CLI suite and Clippy on Windows/Linux.
4. For changes that need formatting or an intentional dependency-lock refresh, the owner can manually dispatch **Remote source maintenance** on `main`. Fork contributors can use their own GitHub runner workflow to format the branch. The maintenance bot's push does not automatically trigger CI; manually dispatch **CI** afterward.
5. Investigate remote logs. Do not start redundant local builds, repeated benchmark jobs, or whole-system scans.

## Detector standards

- Catalog every rule with severity, confidence, fixed evidence labels, and concrete remediation.
- No matched input or surrounding snippets in findings, errors, or logs.
- No online token validation, DNS lookup, scanning external machines, browser credential extraction, cleanup, or anti-forensics.
- Validate all lengths/offsets and declare incomplete coverage rather than swallowing limitations.
- Keep tests synthetic and focused on important properties: redaction, path containment/no-follow behavior, resource limits, policy expiry, baseline identity, malformed document handling, report escaping, and CLI exit codes.
- Keep Windows portability explicit. Gate OS APIs with `cfg`; do not depend on a UNIX shell for runtime functionality.
- Preserve versioned identity framing and explain migrations before changing IDs/schema.

## Public source hygiene

Only source, docs, and synthetic tests belong in the repository. Inspect `git diff --cached` before pushing. Never add `target`, user keys, actual report output, local configuration, filesystem listings, auth tokens, or absolute user paths.
