# Contributing to authkit

## Project-wide rules (non-negotiable)

1. **No leading-underscore names.** Anywhere. Not on modules, classes, functions, methods, attributes, parameters, or local variables. Use `authkit.__all__` and packaging for export control. The rule is enforced by `tests/unit/test_no_private_names.py`.
2. **Async only.** Public APIs are `async def`. No sync wrappers.
3. **Pydantic v2 everywhere — including data containers.** Every domain model, every request/response payload, every config, every value object MUST be a `pydantic.BaseModel`. `NamedTuple`, `@dataclass`, `TypedDict`, and ad-hoc classes are not allowed for data. `dict` and `list` are allowed as fields **inside** a `BaseModel` but are not allowed as the public type of a value object. The framework does not depend on `pydantic-settings` and does not read process-level configuration; config sourcing is the consumer's responsibility.
4. **No plain dicts returned by any function.** Public functions, methods, async functions, and FastAPI handlers MUST declare a `BaseModel` return type (or `None`, `Response`, a `Sequence[BaseModel]`, etc.) and MUST return an instance of that model. The four documented carve-outs below are the only exceptions; each requires a docstring stating which rule it falls under and why.
5. **No ObjectIds stored as raw strings.** When an adapter backs onto MongoDB, every primary key (`_id`) and every foreign-key field MUST be a real `bson.ObjectId` in BSON. Domain models (`authkit.domain.models`) keep these as `str` for storage agnosticism and stable wire format; the adapter does the `str` ⇄ `ObjectId` conversion at its boundary. Content-derived fields (token hashes, JOSE `kid`, rate-limit composite keys, email addresses, usernames) remain strings — they are not Mongo references. See `authkit/adapters/beanie.py` for the canonical implementation and the foreign-key map at the top of that module.
6. **Pyright strict.** Every PR must pass `uv run pyright`.
7. **TDD.** Write the failing test first. Run it. Watch it fail. Then write the minimum code to make it pass.
8. **Conventional commits.** `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.

## Documented carve-outs from rule 4 (no plain dicts returned)

The following four functions return `dict` and are the ONLY allowed exceptions. Each carries an inline docstring repeating this rationale; new exceptions require updating this list AND the docstring at the call site.

1. **`authkit.runtime.api.AuthApi.generate_openapi_schema`** and **`authkit.plugins.openapi.OpenApiPlugin.render_schema`** — OpenAPI 3.1 documents are an external specification (OpenAPI Initiative) with thousands of optional fields; no static Pydantic model captures every valid document, and FastAPI's own `get_openapi` returns `dict[str, Any]`.
2. **`authkit.security.jwt.JwksRegistry.decrypt_private_jwk`** — the decrypted private JWK is fed directly into `joserfc.jwk.import_key`, which takes `dict[str, Any]` because JWK members are algorithm-dependent per RFC 7517 + RFC 7518 (OKP/EC/RSA each have their own field set). The outer JWKS envelope (`as_jwks_json`) IS a Pydantic `JwksDocument`; only the per-key dict remains as-is.
3. **`authkit.plugins.jwt.default_payload_builder`** — JWT payloads are deliberately open-ended per RFC 7519 §4. Each application defines its own custom claims on top of the registered ones; the builder's return type stays `dict[str, Any]` so users can extend it.
4. **`authkit.plugins.test_utils.TestHelpers.get_auth_headers`** — HTTP headers are dict-typed by RFC 9110 §5 and every HTTP client library accepts them as `dict[str, str]`. Wrapping in a Pydantic `RootModel` would add friction with zero gain.

If you encounter a fifth case, propose it in a PR description with: (a) the external specification that forces the open shape, (b) the alternative Pydantic typing you considered, and (c) why it fails. Adding to this list is not a casual decision.

## Session transports

Every endpoint that consumes a session accepts the token via either:
- the signed cookie named `authkit.session_token` (default), or
- the `Authorization: Bearer <token>` header.

Bearer-only requests bypass CSRF (there is no cookie ambient authority to abuse).
Both transports flow through the same `SessionStrategy.read(token)` call.
