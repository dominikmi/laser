# Security Assessment — 2026-08-30 — coder_ornith

graphify-out not available (GRAPH_REPORT.md missing; only graph.json present)

## Semgrep baseline

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

## Attack surface

### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | HTTP GET | routes/home.py:8 | No | Public home index `/` |
| 2 | HTTP GET | routes/home.py:14 | No | Public home `/home` |
| 3 | HTTP GET/POST | routes/login.py:17,22 | No (login endpoint) | Username/password authentication |
| 4 | HTTP GET | routes/login.py:50 | No | Session liveness check `/is_logged_in` |
| 5 | HTTP GET/POST | routes/signup.py:28,33 | No | Account registration |
| 6 | HTTP GET | routes/account.py:18 | Yes (before_request) | Profile view `/account` |
| 7 | HTTP GET | routes/account.py:24 | Yes (before_request) | User search, `search` arg -> SQL |
| 8 | HTTP GET | routes/account.py:41 | No | Public shared notes `/accounts/<id>/notes` |
| 9 | HTTP POST | routes/account.py:51 | Yes | Profile image upload `/account/image` |
| 10 | HTTP POST | routes/account.py:68 | Yes | Account update `/account` |
| 11 | HTTP POST | routes/account.py:98 | Yes | Darkmode toggle `/darkmode` (cookie write) |
| 12 | HTTP GET | routes/notes.py:10 | Yes | Notes list `/notes` |
| 13 | HTTP POST | routes/notes.py:16 | Yes | Create note `/notes` |
| 14 | HTTP POST | routes/notes.py:39 | Yes | Delete note `/notes/<id>/delete` |
| 15 | HTTP GET/POST | routes/registration_codes.py:12,26 | Yes | Registration code management |
| 16 | CLI | db_seed.py | n/a | DB seed script |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | Authentication | routes/login.py:22, app.py:24 | Session credentials |
| 2 | Session/cookie persistence | routes/account.py:112,123 | preferences cookie (pickle) |
| 3 | Input->DB query | routes/account.py:27,33 | search query param |
| 4 | File upload handling | utils/profile_image.py:7 | uploaded image URL/path |
| 5 | Template rendering | app.py:31 | error/request.path |

### Notes
- Flask app; session auth via Flask-Login (`@login_manager.user_loader`, before_request guard).
- Public entry points: home, login, signup, is_logged_in, shared notes, registration codes.
- Authenticated entry points: account, search, image upload, note CRUD, darkmode, registration codes.
- `search` param is interpolated into a SQLAlchemy `text()` string (route/account.py:33) — SQL injection sink.
- `preferences` cookie is read and unpickled (account.py:114-128) — deserialization sink.
- Insecure `set_cookie` in account.py:105 — cookie security.
- Template built via f-string in app.py:31 — SSTI sink.
- `urllib` with dynamic value in profile_image.py:7 — SSRF/file-read sink.

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

## Findings

### app.py:31-32 — Server-Side Template Injection in 404 handler
**CWE:** CWE-94
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     app.py:32 — `request.path` (attacker-controlled HTTP request path)
Transform:  app.py:31 — f-string interpolates `request.path` into a Jinja2 template string
Sink:       app.py:31 — `render_template_string(...)` compiles and renders attacker-controlled template
Trigger:    app.py:29-30 — `@app.errorhandler(404)` → `page_not_found(error)` fires on any unmatched route

```python
@app.errorhandler(404)
def page_not_found(error):
    detailed_message = render_template_string(
        f"{error}. Requested URL was {request.path}"
    )
```

**Exploit:** 1. Attacker GETs `http://host/{{7*7}}` (no route matches) -> 2. Flask 404 handler renders `request.path` through `render_template_string` -> 3. Jinja2 evaluates `{{7*7}}` (or `{{config}}`/RCE payloads) -> arbitrary code execution / config disclosure.
**Mitigations:** None. `render_template_string` is imported (app.py:6) and used with unsanitized request data.
**Fix:** Build the message with plain string concatenation (no template rendering): `detailed_message = f"{error}. Requested URL was {request.path}"` and pass it as data to `render_template`.

### routes/account.py:112-118 — Unauthenticated pickle deserialization (RCE) via before_request
**CWE:** CWE-502
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     account.py:114 — `request.cookies.get('preferences')` (attacker-controlled cookie on every request)
Transform:  account.py:118 — `loads(b64decode(preferences))` calls `pickle.loads` on attacker input
Sink:       account.py:118 — `from pickle import loads` (account.py:1) deserializes arbitrary object
Trigger:    account.py:112 — `@app.before_request` runs for every request before auth is checked

```python
@app.before_request
def before_request():
    preferences = request.cookies.get('preferences')
    if preferences is None:
        preferences = default_preferences
    else:
        preferences = loads(b64decode(preferences))
```

**Exploit:** 1. Attacker crafts a base64-encoded pickle payload (e.g. `os.system('id')`) and sets it as the `preferences` cookie -> 2. Sends any HTTP request; `@app.before_request` unpickles it before `@login_required` runs -> 3. Arbitrary command execution on the server. Unauthenticated and reachable on every route.
**Mitigations:** None. `pickle.loads` runs on a client-controlled cookie value.
**Fix:** Do not use pickle for cookie data. Serialize the preferences dict as JSON (`json.dumps`/`json.loads`) or sign the cookie with Flask's secret via `secure_cookie`; validate structure before use.

### routes/account.py:27-33 — SQL injection in /search
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     account.py:27 — `search_param = request.args.get('search', '')` (untrusted query param)
Transform:  account.py:33 — f-string injects `search_param` into a raw SQL fragment
Sink:       account.py:33 — `text(f"text like '%{search_param}%'")` passes SQL to the DB unchanged

```python
    search_param = request.args.get('search', '')
    with Session() as session:
        session.query(Note)
        personal_notes = session.query(Note).filter(
            Note.user_id == current_user.id,
            text(f"text like '%{search_param}%'")).all()
```

**Exploit:** 1. Attacker GETs `/search?search=%25%27%20UNION%20SELECT%20password,2,3%20FROM%20users--` -> 2. Value is interpolated into `text()` and appended to the WHERE clause -> 3. UNION-based extraction of other tables' data (credentials/PII) or query manipulation.
**Mitigations:** None. `sqlalchemy.text()` bypasses parameterization (semgrep: avoid-sqlalchemy-text).
**Fix:** Use parameterized filters: `.filter(Note.user_id == current_user.id, Note.text.ilike(f'%{search_param}%'))` instead of `text()`.

### utils/profile_image.py:6-8 — SSRF / arbitrary file read via urlopen (called from routes/account.py:60)
**CWE:** CWE-918
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     account.py:60-61 — `get_base64_image_blob(form.url.data)` (attacker-supplied image URL from ImageForm)
Transform:  profile_image.py:11-12 — `get_base64_image_blob(url)` → `download(url)`
Sink:       profile_image.py:7 — `urlopen(url)` fetches the URL; `file://` scheme reads local files

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

**Exploit:** 1. Authenticated user POSTs `/account/image` with `url=file:///etc/passwd` -> 2. `urlopen` reads the local file on the server -> 3. Content is base64-encoded and stored as the user's profile image, exfiltrating server files.
**Mitigations:** None. No URL scheme/allowlist validation before `urlopen`.
**Fix:** Validate the URL scheme (allowlist http/https only), enforce an allowlist of hosts, and/or run the fetch in a sandbox with no local filesystem access.

### app.py:11 — Hardcoded Flask session secret key
**CWE:** CWE-259
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     app.py:11 — literal string assigned to `app.secret_key`
Transform:  Flask uses `secret_key` to sign session cookies (Werkzeug)
Sink:       app.py:11 — weak, committed secret enables session-cookie forgery

```python
app.secret_key = "super secret key"
```

**Exploit:** 1. Attacker obtains the source (or guesses the trivial value) -> 2. Forges a signed session cookie with `is_authenticated=True` for any user -> 3. Unauthorized authenticated access (auth bypass).
**Mitigations:** None. Secret is hardcoded and weak.
**Fix:** Load the key from an environment variable or secret manager: `app.secret_key = os.environ["FLASK_SECRET_KEY"]`; rotate the current key.

### routes (POST endpoints) — Missing CSRF protection on state-changing requests
**CWE:** CWE-352
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     Forms use plain `wtforms.Form` (no CSRF): forms/account_form.py:1, forms/login_form.py:1
Transform:  State-changing POST routes render/accept no `csrf_token` and validate no token: /account (account.py:68), /darkmode (account.py:98), /notes (notes.py:16), /notes/<id>/delete (notes.py:39), /account/image (account.py:51)
Sink:       Any of the above POST endpoints execute state changes from an unverified cross-site request

```python
from wtforms import Form, PasswordField, EmailField, BooleanField


class AccountForm(Form):
    email = EmailField('Email Address')
```

**Exploit:** 1. Attacker hosts a page that auto-POSTs to `http://host/account` (or /notes/<id>/delete) with the victim's authenticated cookie -> 2. Browser sends the cross-site request (cookies included) -> 3. Account fields / notes changed without the victim's intent.
**Mitigations:** None. No CSRF token anywhere in the forms or routes.
**Fix:** Use `Flask-WTF`'s `CSRFProtectedForm` (or equivalent) so every form embeds and validates a `csrf_token`; enforce `SameSite=Strict/Lax` on cookies as defense-in-depth.

### routes/notes.py:43-48 — Insecure Direct Object Reference (IDOR) on note deletion
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     notes.py:39-41 — `/notes/<int:note_id>/delete` POST, `note_id` from the URL path
Transform:  notes.py:44 — `session.get(Note, note_id)` fetches the note by primary key
Sink:       notes.py:48 — `session.delete(note)` deletes any note regardless of ownership

```python
    with Session() as session:
        note = session.get(Note, note_id)
        if note is None:
            flash('Note not found', 'warning')
        else:
            session.delete(note)
            session.commit()
```

**Exploit:** 1. Authenticated attacker learns another user's note_id -> 2. POSTs `/notes/<victim_note_id>/delete` -> 3. The note is deleted even though it belongs to a different user (no ownership check).
**Mitigations:** None. Deletion is by primary key with no `user_id` ownership check.
**Fix:** Scope the delete to the current user: `note = session.get(Note, note_id); if note and note.user_id != current_user.id: abort(403)` before deleting.

### routes/account.py:105,127 — Insecure cookie configuration (missing Secure/HttpOnly/SameSite)
**CWE:** CWE-OTHER (insecure cookie configuration: missing Secure, HttpOnly, and SameSite attributes)
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood LOW = LOW (ACTIVE)

**Data flow:**
Source:     account.py:105 — `response.set_cookie('preferences', ...)` in `/darkmode`
Transform:  account.py:127 — `response.set_cookie('preferences', ...)` in `@app.after_request`
Sink:       account.py:105,127 — cookies set without `secure`, `httponly`, or `samesite` attributes

```python
    response.set_cookie('preferences', b64encode(dumps(preferences)).decode())
```

**Exploit:** 1. Cookie transmitted over plaintext HTTP or exposed to script access (no HttpOnly) -> 2. Stealable via MITM or XSS -> 3. `preferences` cookie value (base64 pickle) can be read/misused; also no SameSite increases CSRF exposure.
**Mitigations:** None. `set_cookie` calls omit security attributes.
**Fix:** Set `response.set_cookie('preferences', value, secure=True, httponly=True, samesite='Lax')`.

## Dead code findings
None

## Test-only findings
None

## Dependency findings

### click@8.1.7 — Command injection in click.edit()
**CVE:** CVE-2026-7246
**CWE:** CWE-78
**Reachability:** DEAD — not imported in app code; `click.edit()` is a CLI-prompt helper not reached during HTTP request handling (transitive dep of flask)
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood LOW = LOW (DEAD, capped from MEDIUM)

**Vulnerable path:** transitive dependency of flask; `click.edit()` (interactive editor) is only invoked by CLI commands, not in the request path. Not called in codebase.
**Fixed in:** 8.3.3
**Fix:** Upgrade: `click>=8.3.3`.

### flask@3.1.1 — Cache containing sensitive information (missing Vary: Cookie)
**CVE:** CVE-2026-27205
**CWE:** CWE-200
**Reachability:** ACTIVE — flask imported throughout (e.g. app.py:6, routes/*.py); session accessed via flask_login (routes/login.py:53-55)
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood LOW = LOW (ACTIVE)

**Vulnerable path:** flask request handling accesses the session; certain access forms omit `Vary: Cookie`, letting caches store per-user responses. Requires a caching proxy that does not ignore cookie responses.
**Fixed in:** 3.1.3
**Fix:** Upgrade: `flask>=3.1.3`.

### werkzeug@3.1.5 — Infinite file read via safe_join Windows device names
**CVE:** CVE-2026-27199
**CWE:** CWE-400
**Reachability:** DEAD — `safe_join`/`send_from_directory` not called in codebase (transitive dep of flask); Windows-only
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood LOW = LOW (DEAD, capped from MEDIUM)

**Vulnerable path:** `werkzeug.security.safe_join` (used by `send_from_directory`) accepts Windows device names like `example/NUL`, causing an indefinite read hang. Not called in codebase.
**Fixed in:** 3.1.6
**Fix:** Upgrade: `werkzeug>=3.1.6`.

## Findings summary

### First-party code
Total findings: 8 (Active: 8, Conditional: 0, Dead: 0, Test-only: 0)

| Severity | Count | Confirmed | Probable | Possible |
|----------|-------|-----------|----------|----------|
| CRITICAL | 1     | 1         | 0        | 0 |
| HIGH     | 4     | 4         | 0        | 0 |
| MEDIUM   | 2     | 2         | 0        | 0 |
| LOW      | 1     | 1         | 0        | 0 |

### Dependencies
Total findings: 3 (Active: 1, Dead: 2)

| Package | Version | CVE | Severity | Called? |
|---------|---------|-----|----------|---------|
| click | 8.1.7 | CVE-2026-7246 | LOW | No (DEAD) |
| flask | 3.1.1 | CVE-2026-27205 | LOW | Yes (ACTIVE) |
| werkzeug | 3.1.5 | CVE-2026-27199 | LOW | No (DEAD) |

### All findings

| File/Package | Finding | CWE | Reachability | Impact | Likelihood | Severity | Confidence |
|--------------|---------|-----|--------------|--------|------------|----------|------------|
| app.py | SSTI in 404 handler | CWE-94 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| routes/account.py | pickle RCE via before_request | CWE-502 | ACTIVE | CRITICAL | MEDIUM | HIGH | CONFIRMED |
| routes/account.py | SQLi in /search | CWE-89 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| utils/profile_image.py | SSRF/file:// via urlopen | CWE-918 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| app.py | Hardcoded session secret | CWE-259 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| routes | Missing CSRF protection | CWE-352 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| routes/notes.py | IDOR on note deletion | CWE-284 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| routes/account.py | Insecure cookie config | CWE-OTHER | ACTIVE | LOW | LOW | LOW | CONFIRMED |

