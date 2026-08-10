# API stability policy

This policy applies starting with fastauth 0.14.0. Earlier development releases
were intentionally breaking and are not covered retroactively.

## Stable public surface

The supported public contract consists of:

- names exported from documented modules and their documented signatures;
- HTTP methods, paths, request and response schemas, and error codes;
- storage and plugin protocols documented as extension contracts;
- documented configuration fields and CLI commands.

Implementation modules, undocumented attributes, generated OpenAPI ordering,
and database implementation details are not stable contracts.

## Deprecation process

A public removal requires all of the following:

1. a changelog entry and migration instructions;
2. a runtime `FastAuthDeprecationWarning` where technically possible;
3. at least one subsequent minor release before removal;
4. no silent semantic reuse of the old name.

Pre-1.0 releases may still contain breaking changes. An urgent security fix may
bypass the normal window when preserving the old behavior would leave users at
risk; the release notes must identify that exception explicitly.

Use `fastauth.deprecations.warn_deprecated()` for runtime warnings so messages
consistently name the replacement and planned removal release.
