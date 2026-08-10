# Security policy

Please report security issues by emailing security@fastauth.dev. We will respond within 72 hours and aim to ship a fix within 14 days for high-severity issues.

We do not accept security disclosures via public GitHub issues.

## Supported versions

Before 1.0, only the latest published minor release receives security fixes.
Users should upgrade to the latest release before reporting a vulnerability.

| Version | Supported |
|---------|-----------|
| 0.14.x  | yes       |
| < 0.14  | no        |

## Security maturity

FastAuth is beta software. It uses automated dependency, static-analysis, type,
and test gates, but it has not completed an independent external security audit.
Evaluate it against your own threat model before using it for sensitive or
regulated workloads.

## Reporting guidance

Include the affected version, a minimal reproduction, impact, and any suggested
mitigation. Do not include real credentials, tokens, or personal data. We will
coordinate acknowledgement, remediation, and disclosure timing with reporters.
