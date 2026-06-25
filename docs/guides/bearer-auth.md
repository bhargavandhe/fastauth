# Bearer authentication

Every authkit endpoint accepts either a signed session cookie or a
`Authorization: Bearer <token>` header. The token format is identical in both
cases — the cookie path simply wraps the plain token in an
`itsdangerous` envelope for tamper resistance.

## Using Bearer with `httpx`

```python
sign_up = await client.post(
    "/auth/sign-up/email",
    json={"email": "alice@example.com", "password": "correct-horse-staple"},
)
token = sign_up.cookies["authkit.session_token"]
plain = auth.context.signed_cookie.unpack(token)  # strip the signed envelope

headers = {"authorization": f"Bearer {plain}"}
session = await client.get("/auth/get-session", headers=headers)
assert session.status_code == 200
```

## Native mobile / non-browser clients

Pure Bearer requests are exempt from CSRF protection — the middleware skips
the check when no session cookie is present. This keeps native apps and
server-to-server callers simple while still protecting browser sessions.

## With JWTs from `JwtPlugin`

When `JwtPlugin` is installed, `POST /auth/token` returns a freshly-signed
JWT carrying the same user claims. Verify it locally using the JWKS document
at `GET /auth/jwks` — no round-trip to authkit is required.

```python
import httpx
from joserfc import jwt, jwk

jwks = (await client.get("/auth/jwks")).json()
key = jwk.KeySet.import_key_set(jwks).keys[0]
token = (await client.post("/auth/token", headers=headers)).json()["token"]
claims = jwt.decode(token, key)
print(claims.claims["sub"])
```
