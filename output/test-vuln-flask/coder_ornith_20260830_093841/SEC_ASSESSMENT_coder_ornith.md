# Security Assessment — 2026-08-30 — coder_ornith

## Graphify context

graphify-out contains `graph.json` and `manifest.json`; `GRAPH_REPORT.md` is absent. The `graphify` CLI is installed and functional (reads from `graph.json`), so Steps 3b/4b/6 graph queries are available. No `GRAPH_REPORT.md` corpus summary to consult.

## Scanned files

- app.py
- db_seed.py
- forms/__init__.py
- forms/account_form.py
- forms/image_form.py
- forms/login_form.py
- forms/note_form.py
- forms/registration_form.py
- models/__init__.py
- models/base_model.py
- models/note.py
- models/registration_code.py
- models/user.py
- routes/__init__.py
- routes/account.py
- routes/home.py
- routes/login.py
- routes/notes.py
- routes/registration_codes.py
- routes/signup.py
- utils/__init__.py
- utils/notes.py
- utils/profile_image.py
- .opencode/plugins/graphify.js

## Semgrep baseline

Tool used: `semgrep_semgrep_scan` (no `security_check` MCP present). Filtered to ERROR/WARNING, excluding non-source. Paths resolved to full repo paths.

| file:line | rule-name | severity |
|---|---|---|
| routes/account.py:33 | avoid-sqlalchemy-text | ERROR |
| routes/account.py:105 | insecure-deserialization | ERROR |
| routes/account.py:105 | secure-set-cookie | WARNING |
| routes/account.py:105 | avoid-pickle | WARNING |
| routes/account.py:118 | avoid-pickle | WARNING |
| routes/account.py:128 | avoid-pickle | WARNING |
| app.py:31 | render-template-string | WARNING |
| utils/profile_image.py:7 | dynamic-urllib-use-detected | WARNING |
| .opencode/plugins/graphify.js:18 | path-join-resolve-traversal | WARNING |

## Secret scan baseline

LeakFerret (`scan_repository`) not in tool list — skipped.

## Attack surface

### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | HTTP GET | routes/home.py:8 | Yes | Home dashboard (`/`) |
| 2 | HTTP GET | routes/home.py:14 | Yes | Home (`/home`) |
| 3 | HTTP GET | routes/signup.py:28 | No | Public signup page (`/signup`) |
| 4 | HTTP POST | routes/signup.py:33 | No | Public user registration (`/signup`) |
| 5 | HTTP GET | routes/login.py:17 | No | Login page (`/login`) |
| 6 | HTTP POST | routes/login.py:22 | No | Credential authentication (`/login`) |
| 7 | HTTP GET | routes/login.py:43 | Yes | Logout (`/logout`) |
| 8 | HTTP GET | routes/login.py:50 | Yes | Session check (`/is_logged_in`) |
| 9 | HTTP GET | routes/account.py:18 | Yes | Profile view (`/account`) |
| 10 | HTTP GET | routes/account.py:24 | Yes | User search (`/search`) |
| 11 | HTTP GET | routes/account.py:41 | Yes | User notes (`/accounts/<id>/notes`) |
| 12 | HTTP POST | routes/account.py:51 | Yes | Profile image upload (`/account/image`) |
| 13 | HTTP POST | routes/account.py:68 | Yes | Profile update (`/account`) |
| 14 | HTTP POST | routes/account.py:98 | Yes | Dark-mode toggle (`/darkmode`) |
| 15 | HTTP GET | routes/notes.py:10 | Yes | Notes list (`/notes`) |
| 16 | HTTP POST | routes/notes.py:16 | Yes | Create note (`/notes`) |
| 17 | HTTP POST | routes/notes.py:39 | Yes | Delete note (`/notes/<id>/delete`) |
| 18 | HTTP GET | routes/registration_codes.py:12 | Yes (admin) | List registration codes |
| 19 | HTTP POST | routes/registration_codes.py:26 | Yes (admin) | Create registration code |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | Authentication | routes/login.py:22 | Credentials -> session cookie |
| 2 | Pre-request gate | routes/account.py:112 (before_request) | Session/cookie -> access decision |
| 3 | Admin authorization | routes/registration_codes.py:15,29 | current_user.is_admin |
| 4 | Session persistence / serialization | routes/account.py:105,118,128 | User state (pickle) |
| 5 | Output rendering | app.py:31 (render_template_string) | Template + context |
| 6 | External resource fetch | utils/profile_image.py:7 | User-supplied URL (urllib) |
| 7 | Database query construction | routes/account.py:33 (sqlalchemy.text) | User input -> SQL |

## Attack paths

Directed `graphify path` (10 queries, all entry points -> pickle/text/urllib/SSTI sinks) returned **no directed path**. Undirected search instead revealed the import chain: `signup.py --imports_from--> app.py --imports_from--> account.py --contains--> account()`. The graph is import-edge based and does not model the WSGI/HTTP dispatch that actually routes requests into handlers, so directed data-flow paths could not be established via the tool. No multi-file attack path skeleton available for Step 6.

## Dead code candidates

`graphify explain` (5 queries). Incoming-edge analysis:
- `utils/profile_image.py` — 1 incoming edge (`account.py` imports it at L15). Reachable; not dead.
- `app.py` — central hub, 6 route files import it. Not dead.
- `db_seed.py` — 1 incoming edge (`app.py` imports it at L7). Reachable; not dead.
- `routes/account.py` — degree 16, imports app/note/profile_image. Not dead.
- `routes/notes.py` — **zero incoming import edges** (only imports `app.py`; all 9 edges outgoing). Candidate. (Consistent with a route module loaded by the WSGI server rather than imported by another module — to be verified by call-site grep in Step 6.)

## Findings

### routes/account.py:118 — Pickle deserialization RCE via `preferences` cookie (before_request)
**CWE:** CWE-502
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     routes/account.py:114 — `preferences = request.cookies.get('preferences')` (attacker-controlled cookie)
Transform:  routes/account.py:118 — `loads(b64decode(preferences))` — `pickle.loads` on decoded cookie value
Sink:       routes/account.py:118 — pickle deserialization → arbitrary code execution

```python
preferences = request.cookies.get('preferences')
if preferences is None:
    preferences = default_preferences
else:
    preferences = loads(b64decode(preferences))
```

**Exploit:** 1. Attacker sends any request with a `preferences` cookie whose value is a base64-encoded pickle payload -> 2. `before_request` (runs before every route, ahead of `@login_required`) calls `pickle.loads` on it -> 3. malicious pickle executes arbitrary code (RCE).
**Mitigations:** None. Cookie is base64-encoded, not signed or encrypted; no integrity check.
**Fix:** Replace pickle with JSON for the preferences cookie; never unpickle attacker-controlled data.

### app.py:31 — Server-side template injection in 404 handler
**CWE:** CWE-94
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     app.py:32 — `request.path` (attacker-controlled URL path)
Transform:  app.py:31-32 — `f"{error}. Requested URL was {request.path}"` passed to `render_template_string`
Sink:       app.py:31 — `render_template_string` evaluates Jinja2 syntax present in `request.path`

```python
detailed_message = render_template_string(
    f"{error}. Requested URL was {request.path}"
)
```

**Exploit:** 1. Attacker requests a non-existent URL containing Jinja2 syntax, e.g. `GET /{{7*7}}` -> 2. triggers the 404 handler, `request.path` injected into `render_template_string` -> 3. template evaluated → info disclosure / RCE via Jinja2 sandbox escape.
**Mitigations:** None. Dynamic, untrusted input passed to `render_template_string`.
**Fix:** Render a static template and pass `request.path` as a parameter; never pass `request.path` into `render_template_string`.

### routes/signup.py:17 — SQL injection on public registration (unauthenticated)
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     routes/signup.py:45 — `code = form.registration_code.data` (unauthenticated user input)
Transform:  routes/signup.py:46 — `validate_token(code, session)`
Sink:       routes/signup.py:17 — `text(f"...WHERE code = '{code}'")` f-string interpolation into raw SQL

```python
result = session.execute(
    text(f"""
        SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}'
    """)).first()
```

**Exploit:** 1. Unauthenticated user POSTs `/signup` with a crafted `registration_code` -> 2. value interpolated into raw SQL via `text()` -> 3. injection enables UNION/error-based extraction of registration codes / other tables. (`except OperationalError` swallows some errors but not all injection vectors.)
**Mitigations:** None. `text()` bypasses parameterization.
**Fix:** Parameterize the lookup: `session.execute(text("SELECT id, code FROM registration_codes WHERE code = :c"), {"c": code})`.

### routes/account.py:33 — SQL injection in search filter
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     routes/account.py:27 — `search_param = request.args.get('search', '')`
Transform:  routes/account.py:33 — `f"text like '%{search_param}%'?"` interpolated into `sqlalchemy.text()`
Sink:       routes/account.py:33 — `text()` passes raw SQL to DB, bypassing parameter binding

```python
personal_notes = session.query(Note).filter(
    Note.user_id == current_user.id,
    text(f"text like '%{search_param}%'")).all()
```

**Exploit:** 1. Authenticated user sends `GET /search?search=' OR '1'='1` -> 2. value interpolated into raw SQL via `text()` -> 3. WHERE clause manipulated → UNION-based extraction / boolean-based blind SQLi.
**Mitigations:** None. `text()` bypasses parameterization.
**Fix:** Use ORM column operators (`Note.notes.like(f'%{search_param}%')`) or a bound parameter; never build SQL with an f-string.

### utils/profile_image.py:7 — SSRF via user-supplied image URL
**CWE:** CWE-918
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     routes/account.py:60 — `form.url.data` (user-submitted image URL from `/account/image` POST)
Transform:  routes/account.py:60-61 — `get_base64_image_blob(form.url.data).encode()`
Transform:  utils/profile_image.py:12 — `get_base64_image_blob(url)` -> `download(url)`
Sink:       utils/profile_image.py:7 — `urlopen(url)` fetches attacker-controlled URL; response reflected as base64

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

**Exploit:** 1. Authenticated user POSTs `/account/image` with `url=http://169.254.169.254/latest/meta-data/` -> 2. `get_base64_image_blob` -> `download` -> `urlopen` fetches the internal endpoint -> 3. response base64-encoded and returned in the profile image, exfiltrating internal data.
**Mitigations:** `ImageForm.url` is a wtforms `URLField` (format-only validation; does not block internal hosts or non-https schemes).
**Fix:** Allow-list schemes (https only) and block private/loopback/link-local/metadata ranges before `urlopen`; validate the resolved hostname.

### app.py:11 — Hardcoded session secret key
**CWE:** CWE-259
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     app.py:11 — `app.secret_key = "super secret key"` (static, committed to source)
Sink:       app.py:11 — Flask signs session cookies with this key

```python
app.secret_key = "super secret key"
```

**Exploit:** 1. If source is accessible (e.g. public repo), attacker reads the hardcoded key -> 2. forges valid session cookies -> 3. account takeover for any user.
**Mitigations:** None. Key is hardcoded and predictable.
**Fix:** Load `secret_key` from an environment variable / secrets manager and rotate the current key.

### routes/account.py:105 — Insecure cookie flags (missing Secure/HttpOnly/SameSite)
**CWE:** CWE-OTHER (cookie attributes Secure/HttpOnly/SameSite absent)
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood LOW = LOW (ACTIVE)

**Data flow:**
Source:     routes/account.py:105 — `response.set_cookie('preferences', ...)` without flags
Sink:       routes/account.py:105 — cookie set without Secure, HttpOnly, or SameSite

```python
response.set_cookie('preferences', b64encode(dumps(preferences)).decode())
```

**Exploit:** 1. Cookie transmitted over HTTP (no Secure) or readable by JS (no HttpOnly) or sent cross-site (no SameSite) -> 2. the preferences cookie (a base64 pickle blob) is exposed/stolen -> 3. aids the pickle-based attack and preference theft.
**Mitigations:** None.
**Fix:** `set_cookie(..., secure=True, httponly=True, samesite='Lax')`.

## Dead code findings
None. (`routes/notes.py` showed zero incoming import edges in the graphify import graph — an artifact of route modules importing `app.py` and being loaded by the WSGI server rather than imported by another module — so it is an entry point, not dead code.)

## Test-only findings
None.

## Dependency findings

Source: `osv-scanner_scan_vulnerable_dependencies` on project root. 5 vulnerabilities across 3 packages in `requirements.txt`. All are Flask-stack packages loaded at runtime → ACTIVE.

### click@8.1.7 — Command injection (PYSEC-2026-2132)
**CVE:** no CVE — advisory only (PYSEC-2026-2132)
**CWE:** CWE-78
**Reachability:** ACTIVE — transitive dependency of Flask, loaded/executed at runtime
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** PROBABLE — package is loaded, but the specific vulnerable code path (shell/completion parsing) is not confirmed exercised in a WSGI deployment
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)
**Vulnerable path:** `flask` imports `click` (CLI parser) -> click <=8.3.2 shell-splitting -> command injection
**Fixed in:** 8.3.3
**Fix:** upgrade

### flask@3.1.1 — Web framework vulnerability (PYSEC-2026-2151)
**CVE:** no CVE — advisory only (PYSEC-2026-2151)
**CWE:** CWE-OTHER (advisory description truncated by scanner)
**Reachability:** ACTIVE — directly imported (e.g. app.py:6, all route modules)
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** PROBABLE
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)
**Vulnerable path:** Flask is the core web framework; vulnerable code executes on every request
**Fixed in:** 3.1.3
**Fix:** upgrade

### werkzeug@3.1.5 — WSGI library vulnerability (PYSEC-2026-2320)
**CVE:** no CVE — advisory only (PYSEC-2026-2320)
**CWE:** CWE-OTHER (advisory description truncated by scanner)
**Reachability:** ACTIVE — transitive dependency of Flask, loaded/executed at runtime
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** PROBABLE
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)
**Vulnerable path:** Werkzeug powers Flask request/response handling -> executes on every request
**Fixed in:** 3.1.6
**Fix:** upgrade

## Findings summary

### First-party code
Total findings: 7 (Active: 7, Conditional: 0, Dead: 0, Test-only: 0)

| Severity | Count | Confirmed | Probable | Possible |
|----------|-------|-----------|----------|----------|
| CRITICAL | 2     | 2         | 0        | 0        |
| HIGH     | 3     | 3         | 0        | 0        |
| MEDIUM   | 1     | 1         | 0        | 0        |
| LOW      | 1     | 1         | 0        | 0        |

### Dependencies
Total findings: 3 (Active: 3, Dead: 0)

| Package | Version | CVE | Severity | Called? |
|---------|---------|-----|----------|---------|
| click   | 8.1.7   | PYSEC-2026-2132 | HIGH    | Yes |
| flask   | 3.1.1   | PYSEC-2026-2151 | MEDIUM  | Yes |
| werkzeug| 3.1.5   | PYSEC-2026-2320 | MEDIUM  | Yes |

### All findings

| File/Package | Finding | CWE | Reachability | Impact | Likelihood | Severity | Confidence |
|--------------|---------|-----|--------------|--------|------------|----------|------------|
| routes/account.py:118 | Pickle RCE via cookie | CWE-502 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| app.py:31 | SSTI in 404 handler | CWE-94 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| routes/signup.py:17 | SQLi on registration | CWE-89 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| routes/account.py:33 | SQLi in search | CWE-89 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| utils/profile_image.py:7 | SSRF via image URL | CWE-918 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| click@8.1.7 | Command injection | CWE-78 | ACTIVE | HIGH | MEDIUM | HIGH | PROBABLE |
| app.py:11 | Hardcoded secret key | CWE-259 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| flask@3.1.1 | Framework vuln | CWE-OTHER | ACTIVE | MODERATE | MEDIUM | MEDIUM | PROBABLE |
| werkzeug@3.1.5 | WSGI vuln | CWE-OTHER | ACTIVE | MODERATE | MEDIUM | MEDIUM | PROBABLE |
| routes/account.py:105 | Insecure cookie flags | CWE-OTHER | ACTIVE | LOW | LOW | LOW | CONFIRMED |





### Notes
- Only unauthenticated entry points are the public registration flow (`/signup` GET+POST) and the login flow (`/login` GET+POST). All other routes carry `@login_required`.
- `pickle` is imported at routes/account.py:1 and used at lines 105/118/128 for serializing user/session data — a code-execution-prone sink.
- `sqlalchemy.text()` at routes/account.py:33 bypasses parameter binding; reachable SQL-injection sink if user input reaches it.
- `urllib` at utils/profile_image.py:7 supports `file://` schemes — SSRF/local-file-read sink.
- `render_template_string()` at app.py:31 builds templates from strings — SSTI sink.
- `before_request` at routes/account.py:112 is the single auth gate executed before every route handler.



