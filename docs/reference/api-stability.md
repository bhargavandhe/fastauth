# API stability

The stability policy applies starting with fastauth 0.14.0. Stable contracts
include documented exports and signatures, HTTP methods and schemas, documented
storage/plugin protocols, configuration fields, and CLI commands.

A public removal requires a changelog entry, migration instructions, a
`FastAuthDeprecationWarning` where possible, and at least one subsequent minor
release before removal. Urgent pre-1.0 security fixes may bypass the window
only when preserving behavior would leave users at risk.

The repository-root
[`API_STABILITY.md`](https://github.com/bhargavandhe/fastauth/blob/main/API_STABILITY.md)
is the authoritative policy.
