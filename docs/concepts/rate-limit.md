# Rate limiting

`RateLimiter` enforces a sliding-window quota per `(path, ip_bucket)` pair.
The storage backend is pluggable: `MemoryRateLimitStorage` (default, fine for
single-process deployments) and `DatabaseRateLimitStorage` (multi-process,
backed by the `rate_limits` collection). Selection is config-driven:

```python
from fastauth import FastAuthOptions
from fastauth.domain.enums import RateLimitStorageKind
from fastauth.options import RateLimitOptions
from datetime import timedelta

options = FastAuthOptions(
    # ...
    rate_limit=RateLimitOptions(
        storage=RateLimitStorageKind.DATABASE,
        window=timedelta(seconds=60),
        max_requests=100,
    ),
)
```

Stricter defaults apply to the high-value sign-in and password-reset endpoints
via `DEFAULT_STRICT_RULES` (e.g. `/sign-in/email` → 3 requests per 10 s).
Plugins can declare their own rules with `Plugin.rate_limit_rules()`.

IPv6 addresses are collapsed to their `/64` network prefix before bucketing
(configurable via `AdvancedOptions.ipv6_subnet`); IPv4-mapped IPv6 addresses
(`::ffff:a.b.c.d`) are stored as the underlying IPv4. When a request exceeds
its quota the limiter raises `RateLimitError`, which the FastAPI integration
turns into a `429` response with an `X-Retry-After` header.
