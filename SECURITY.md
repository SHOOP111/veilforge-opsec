# Security policy

VeilForge is a defensive local audit tool, not a guarantee of anonymity or complete safety. Review [the threat model](docs/THREAT_MODEL.md) before use.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository when available, or privately contact the maintainer through the repository's GitHub profile. Do not put real secrets, scan reports, key files, identifying paths, or exploit-bearing personal documents into a public issue.

Provide a minimal **synthetic** reproduction, affected version/commit, platform, expected security property, and impact. File traversal escapes, secret leakage in output, unbounded parser behavior, unsafe active content, and report injection are especially important.

The initial supported development line is `0.1.x`. There is no SLA, independent audit, Windows signing certificate, or guarantee of bug-free operation. Credential exposures should also be handled directly with the credential issuer; deleting a file or report is not revocation.
