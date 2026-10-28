# Review guide - where each requirement lives

A one-page map for the defence: every item of the assignment, the file and the
line to open, and what to say about it.

Open the folder in VS Code and use `Ctrl+P` to jump to the files below.

## Security requirements

| Requirement | Where | What to point at |
| --- | --- | --- |
| Passwords are hashed, never stored | `app/security.py:23` | `hash_password()` uses `bcrypt.hashpw` with a per-password salt; cost factor 12 from `app/config.py:27` |
| Password check is constant-time | `app/auth.py:96` | a dummy bcrypt check runs even when the user does not exist, so the response time does not reveal whether an account exists |
| JWT is signed with HS256 only | `app/security.py:66` | `jwt.encode(..., algorithm="HS256")` - the algorithm is fixed, never taken from the token |
| JWT verification pins the algorithm | `app/security.py:78` | `algorithms=["HS256"]` blocks algorithm-confusion (`alg: none`) attacks; issuer and expiry are checked too (`:70`) |
| Protected endpoints require a bearer token | `app/auth.py:20` | `token_required` decorator, used on every `/api/*` view |
| SQL can never be built from user input | `app/api.py:39` | `db.execute("... WHERE title LIKE ? ...", (pattern,))` - placeholders, values passed separately |
| LIKE wildcards are escaped | `app/api.py:17` | `_like_pattern()` so a `%` from the client cannot widen the query |
| Output is escaped | `app/security.py:84` | `escape_deep()` (MarkupSafe) for everything returned as JSON |
| Input is validated and length-capped | `app/security.py:100` | `clean_text()` strips control characters and enforces a maximum length |
| Security headers on every response | `app/__init__.py:42` | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (`:43`), `Content-Security-Policy` (`:46`) |
| Errors do not leak internals | `app/errors.py` | one JSON error shape, no stack traces returned |
| Secrets come from the environment | `app/config.py` | `SECRET_KEY` required in production, random only in development |

## The three required endpoints

| Endpoint | Where |
| --- | --- |
| `POST /auth/login` | `app/auth.py:77` - returns the JWT, sets no cookie |
| `GET /api/data` (protected) | `app/api.py:30` - search with `?q=`, parameterised |
| `GET/POST /api/notes` (protected) | `app/api.py:91` (create), `:136` (read one) |

## Tests and CI

| Item | Where | Result |
| --- | --- | --- |
| Test suite | `tests/test_auth.py`, `tests/test_api.py`, `tests/test_security.py` | 25 tests |
| Run locally | `python -m pytest -q` | `25 passed` |
| SAST gate | `.github/workflows/ci.yml` (job `SAST (bandit)`) | `bandit -r app -ll` - no issues |
| Dependency audit | same file (job `SCA (pip-audit)`) | no known vulnerabilities |
| Pipeline | GitHub Actions, 3 jobs | green run, 3 artifacts |

## What to say in one sentence each

1. *Passwords*: bcrypt with cost 12 and a per-password salt; verification is
   constant-time and does not reveal whether the account exists.
2. *Tokens*: HS256 only, pinned on verification, short lifetime, `iss` checked.
3. *Database*: every query uses placeholders; the LIKE pattern is escaped so the
   client cannot change the shape of the query.
4. *Output*: all values pass through `escape_deep()` before they are returned.
5. *Transport layer*: CSP, nosniff and frame-deny headers are set centrally for
   every response.
6. *Proof*: 25 tests, bandit clean, pip-audit clean, three green CI jobs.
