# Security Assessment — 2026-08-30 — Ornith_1_5_35B_A3B_MLX_4bit

graphify-out not available (no `GRAPH_REPORT.md`; only `graph.json`, `manifest.json`, `cache/`, `.graphify_analysis.json`, `.graphify_root` present). Attack-path and dead-code analysis (Step 4b) skipped.

## Attack surface

### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | HTTP GET | routes/signup.py:28 | No (public) | Signup form |
| 2 | HTTP POST | routes/signup.py:33 | No (public) | Registration submit → inserts code via `text(f"...")` (L16) |
| 3 | HTTP GET | routes/login.py:17 | No (public) | Login form |
| 4 | HTTP POST | routes/login.py:22 | No (public) | Credential verification |
| 5 | HTTP GET | routes/account.py:18 | Yes (login_required) | Account dashboard |
| 6 | HTTP GET | routes/account.py:24 | Yes | Search → `text(f"...{search_param}...")` (L33) |
| 7 | HTTP POST | routes/account.py:51 | Yes | Profile image upload (urllib, profile_image.py:7) |
| 8 | HTTP POST | routes/account.py:68 | No (unauthenticated) | Account update → `is_admin` mass-assignment |
| 9 | HTTP POST | routes/account.py:98 | No (unauthenticated) | Dark mode toggle → stores preferences cookie (L105) |
| 10 | HTTP GET | routes/registration_codes.py:12 | Yes + is_admin | List registration codes |
| 11 | HTTP POST | routes/registration_codes.py:26 | Yes + is_admin | Create code → `RegistrationCode(str(uuid4()))` (ORM, L34; no raw SQL) |
| 12 | HTTP GET | routes/home.py:8 | Yes | Home index |
| 13 | HTTP GET | routes/notes.py:10 | Yes | List notes |
| 14 | HTTP POST | routes/notes.py:16 | Yes | Add note |
| 15 | HTTP POST | routes/notes.py:39 | Yes | Delete note |
| 16 | HTTP GET | routes/login.py:50 | Yes | is_logged_in check |
| 17 | HTTP GET | app.py:30 | No (404 handler) | page_not_found → `render_template_string` (SSTI) |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | Authentication (Flask-Login) | app.py:15-24; `@login_required` on select routes (account dashboard, search, image, home, notes, is_logged_in); `POST /account` (L68) and `POST /darkmode` (L98) are **unauthenticated** | session / user credentials |
| 2 | Authorization (admin gate) | routes/registration_codes.py:15,29 | `current_user.is_admin` |
| 3 | Cookie / session persistence | routes/account.py:105,113-128 | darkmode preferences cookie (pickle) |
| 4 | Form validation | forms/* (ImageForm, AccountForm, LoginForm, NoteForm, RegistrationForm) | user-supplied fields |
| 5 | DB session boundary | models/*; `session.merge()` | serialized ORM objects |

## Scanned files

Application source (23 files; `graphify-out/` and `.security-output/` excluded per spec; `.opencode/plugins/graphify.js` excluded as opencode plugin code, not app under review):

| File | Role |
|------|------|
| app.py | Flask app factory, login_manager, error handlers |
| db_seed.py | DB seeding script |
| forms/__init__.py | — |
| forms/account_form.py | AccountForm |
| forms/image_form.py | ImageForm |
| forms/login_form.py | LoginForm |
| forms/note_form.py | NoteForm |
| forms/registration_form.py | RegistrationForm |
| models/__init__.py | — |
| models/base_model.py | Base model |
| models/note.py | Note model |
| models/registration_code.py | RegistrationCode model |
| models/user.py | User model |
| routes/__init__.py | route init |
| routes/account.py | account/search/image/update/darkmode routes |
| routes/home.py | home/index routes |
| routes/login.py | login/logout/is_logged_in routes |
| routes/notes.py | notes CRUD routes |
| routes/registration_codes.py | admin registration-code routes |
| routes/signup.py | public signup routes |
| utils/__init__.py | — |
| utils/notes.py | note helpers |
| utils/profile_image.py | profile image / urllib |

## Findings

### routes/account.py:118 — Unsafe Deserialization (pickle.loads) in before_request
**CWE:** CWE-502
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE, no change)

**Data flow:**
Source:     routes/account.py:114 — `request.cookies.get('preferences')` (attacker-controlled cookie, read inside `@app.before_request`)
Sink:       routes/account.py:118 — `loads(b64decode(preferences))` (`pickle.loads` on decoded cookie)

```python
@app.before_request
def before_request():
    preferences = request.cookies.get('preferences')
    if preferences is None:
        preferences = default_preferences
    else:
        preferences = loads(b64decode(preferences))
```

**Exploit:** 1. Attacker sends any request (including public `/login`, `/signup`) with cookie `preferences=<base64 pickle payload>` 2. `before_request` runs before `@login_required` and calls `pickle.loads` 3. Arbitrary code execution (RCE).
**Mitigations:** None.
**Fix:** Do not use pickle; store preferences as JSON (`json.loads`).

### routes/account.py:33 — SQL Injection via SQLAlchemy text() f-string
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE, no change)

**Data flow:**
Source:     routes/account.py:27 — `request.args.get('search', '')` (untrusted query parameter)
Sink:       routes/account.py:33 — `text(f"text like '%{search_param}%'")` (f-string bypasses parameter binding)

```python
search_param = request.args.get('search', '')
...
personal_notes = session.query(Note).filter(
    Note.user_id == current_user.id,
    text(f"text like '%{search_param}%'')).all()
```

**Exploit:** 1. Authenticated user visits `/search?search=' UNION SELECT credentials--` 2. `search_param` is interpolated into `sqlalchemy.text()` 3. Arbitrary SQL executes against the database.
**Mitigations:** None (`text()` bypasses parameterization).
**Fix:** Use column operators, e.g. `Note.title.like(f"%{search_param}%")`.

### routes/account.py:105 — Insecure cookie configuration
**CWE:** CWE-OTHER (insecure cookie — missing `Secure`/`HttpOnly`/`SameSite` flags)
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood MEDIUM = LOW (ACTIVE, no change)

**Data flow:**
Sink:       routes/account.py:105 — `response.set_cookie('preferences', b64encode(dumps(preferences)).decode())` (also L127 in `after_request`)

```python
response.set_cookie('preferences', b64encode(dumps(preferences)).decode())
```

**Exploit:** Session cookie not marked `Secure`/`HttpOnly`/`SameSite` → susceptible to network sniffing (missing `Secure`) or XSS exfiltration (missing `HttpOnly`); both are multi-step/precondition-dependent exploits.
**Mitigations:** None.
**Fix:** Set `secure=True, httponly=True, samesite='Lax'`.

### app.py:31 — Server-Side Template Injection (render_template_string)
**CWE:** CWE-94
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE, no change)

**Data flow:**
Source:     app.py:32 — `request.path` (attacker-controlled URL path, present on any unmatched route that triggers the 404 handler)
Sink:       app.py:31-33 — `render_template_string(f"{error}. Requested URL was {request.path}")` (f-string rendered as a Jinja2 template)

```python
@app.errorhandler(404)
def page_not_found(error):
    detailed_message = render_template_string(
        f"{error}. Requested URL was {request.path}"
    )
```

**Exploit:** 1. Attacker requests an unmatched route containing Jinja2 syntax, e.g. `/{{(7*7).__class__}}` 2. Flask routes it to the 404 handler 3. `render_template_string` renders the injected expression → template injection → potential RCE.
**Mitigations:** None.
**Fix:** Never pass user-controlled data to `render_template_string`; use `render_template` with predefined templates and autoescaping.

### utils/profile_image.py:7 — SSRF / arbitrary file read via urllib
**CWE:** CWE-918
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE, no change)

**Data flow:**
Source:     routes/account.py:60 — `get_base64_image_blob(form.url.data)` (ImageForm `url` field, POST /account/image)
Transform:  utils/profile_image.py:12 — `download(url)`
Sink:       utils/profile_image.py:7 — `urlopen(url)` (`file://` → arbitrary local file read; SSRF to internal services)

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

**Exploit:** 1. Authenticated user POSTs `/account/image` with `url=file:///etc/passwd` (or an internal endpoint) 2. `get_base64_image_blob` → `download` → `urlopen` fetches the target 3. Local file read or SSRF into internal network.
**Mitigations:** None (no URL scheme/IP validation).
**Fix:** Whitelist `https://`; reject `file://`, `ftp://`, and private/internal IPs.

### routes/account.py:76 — Unauthenticated admin privilege escalation (mass assignment)
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE, no change)

**Data flow:**
Source:     routes/account.py:70 — `form = AccountForm(request.form)`; form.data includes `is_admin` (BooleanField) and `email`
Transform:  routes/account.py:76-81 — comprehension excludes only `key != 'password'`; `is_admin` is NOT excluded → `current_user.__dict__.update(filtered_values)`
Sink:       routes/account.py:81,91,92 — `current_user.__dict__.update(...)` sets `is_admin=True`; `session.merge(current_user)`; `session.commit()` persists admin flag

```python
filtered_values = {
    key: value
    for key, value in form.data.items()
    if value is not None and key != 'password'
}
current_user.__dict__.update(filtered_values)
...
session.merge(current_user)
session.commit()
```

**Exploit:** 1. Attacker POSTs `/account` (no `@login_required` on this route) with `is_admin=True` (and target `email`) 2. `update_account` builds `filtered_values` excluding only `password`, so `is_admin` is mass-assigned to the user object 3. `session.commit()` persists `is_admin=True` → full admin privilege escalation (or creation of an admin account when unauthenticated).
**Mitigations:** None (only `password` is excluded from mass assignment; `is_admin` is not).
**Fix:** Whitelist allowed fields (e.g., only `email`); never mass-assign `is_admin`; add `@login_required`.

### routes/notes.py:44 — Insecure Direct Object Reference (IDOR) on note deletion
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE, no change)

**Data flow:**
Source:     routes/notes.py:41 — `note_id` from route `/notes/<int:note_id>/delete` (attacker-controlled integer)
Sink:       routes/notes.py:44,48 — `session.get(Note, note_id)` then `session.delete(note)` — no check that `note.user_id == current_user.id`

```python
def delete_note(note_id: int):
    with Session() as session:
        note = session.get(Note, note_id)
        if note is None:
            flash('Note not found', 'warning')
        else:
            session.delete(note)
            session.commit()
```

**Exploit:** 1. Authenticated user POSTs `/notes/<other_user_note_id>/delete` 2. `delete_note` fetches the note by ID and deletes it without verifying ownership 3. Cross-user deletion of notes (IDOR).
**Mitigations:** None (no ownership check; only `@login_required`).
**Fix:** Add `if note.user_id != current_user.id: flash('Not authorized'); return` before `session.delete`.

### db_seed.py:18 — Pre-seeded admin account with hardcoded weak credentials
**CWE:** CWE-259
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = MEDIUM (ACTIVE, no change)

**Data flow:**
Source:     app.py:7,21 — `from db_seed import setup_db` ... `setup_db()` (called at app startup)
Transform:  db_seed.py:18-19 — creates `admin = User('admin@evfa.com', hashpw(b'admin', gensalt()).decode(), True)` (plaintext `'admin'` in source; `is_admin=True`)
Sink:       routes/login.py:22 — public `/login` (POST) authenticates against the pre-seeded admin account

```python
admin = User('admin@evfa.com',
             hashpw(b'admin', gensalt()).decode(), True)
```

**Exploit:** 1. App boots, calls `setup_db()` (app.py:21), creating admin@evfa.com with password `'admin'` (disclosed in db_seed.py:18) 2. Attacker logs in via public `/login` with admin@evfa.com / admin 3. Full admin access.
**Mitigations:** None (weak password `'admin'` is disclosed in source; only bcrypt-hashed at seed time).
**Fix:** Do not hardcode seed admin credentials; generate a strong random password at seed time and surface it securely, or require admin creation via a setup wizard.

### routes/signup.py:15 — SQL Injection (unauthenticated via public signup)
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood HIGH = HIGH (ACTIVE, no change)

**Data flow:**
Source:     routes/signup.py:45 — `code = form.registration_code.data` (attacker-controlled, public POST /signup)
Transform:  routes/signup.py:46 — `validate_token(code, session)`
Sink:       routes/signup.py:16-18 — `text(f"""SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}' """)` (sink is the interpolated `{code}`; table name is server-defined)

```python
def validate_token(code: str, session: Session) -> Union[str, None]:
    try:
        result = session.execute(
            text(f"""
                SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}'
            """)).first()
```

**Exploit:** 1. Attacker POSTs public `/signup` with registration_code = `' UNION SELECT id, code FROM registration_code--` 2. `do_signup` (unauthenticated) calls `validate_token`, interpolating `code` into `text()` 3. Data exfiltration of all registration codes / user data; potential stacked-query abuse.
**Mitigations:** None (`text()` f-string bypasses parameterization; `OperationalError` is swallowed).
**Fix:** Parameterize: `text("SELECT id, code FROM registration_code WHERE code = :code")` with `parameters={"code": code}`.

### app.py:11 — Hardcoded application secret key
**CWE:** CWE-259
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE, no change)

**Data flow:**
Sink:       app.py:11 — `app.secret_key = "super secret key"` (hardcoded, predictable Flask session secret)

```python
app.secret_key = "super secret key"
```

**Exploit:** 1. Attacker reads the source (or guesses the predictable key) 2. Forges signed session/cookies 3. Session forgery / hijack.
**Mitigations:** None.
**Fix:** Load `SECRET_KEY` from an environment variable or secret manager; use a high-entropy random value.

## Dead code findings

None. No first-party dead code (all 6 route modules are imported via `routes/__init__.py:4-10` and registered at `app.py:20`). The dependency `click@8.1.7`'s vulnerable function (`click.edit()`) is not called in this app (served via uwsgi, `uwsgi.ini:2`) — see `## Disputed findings`.

## Test-only findings

None. No test files exist in the application source (only `.opencode/node_modules` plugin dependencies).

## Dependency findings

Source: `/Users/mikey/HomeWorks/OpenCode-tests/test-vuln-flask/requirements.txt` (scanned via `osv-scanner` MCP `scan_vulnerable_dependencies`; 5 packages affected — 0 Critical, 1 High, 4 Medium, from 1 ecosystem; 5 can be fixed. The "5" counts flask+werkzeug twice across the `lockfile` and `unknown` ecosystems → 3 unique vulnerabilities).

### flask@3.1.1 — missing Vary: Cookie header (Use of Cache Containing Sensitive Information)
**CVE:** CVE-2026-27205 (PYSEC-2026-2151, GHSA-68rp-wp8r-4726)
**CWE:** CWE-200
**Reachability:** ACTIVE — flask imported at app.py:6; flask-login 0.6.3 accesses `in session` on every request (flask_login/utils.py:215-227, login_manager.py:450-476)
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE, no change)

**Vulnerable path:** requirements.txt → `flask@3.1.1` → response emitted without `Vary: Cookie` header.
**Fixed in:** 3.1.3
**Fix:** Upgrade flask to ≥3.1.3.

**Exploit:** Behind a caching proxy that doesn't ignore cookie-bearing responses, a response containing a logged-in user's session keys may be cached and served to other users → sensitive info exposure.

### werkzeug@3.1.5 — safe_join Windows device name → read hang (DoS)
**CVE:** CVE-2026-27199 (PYSEC-2026-2320, GHSA-29vq-49wr-vm6x)
**CWE:** CWE-400
**Reachability:** ACTIVE — werkzeug is Flask's WSGI runtime; imported at app.py:6, called on every request
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE, no change)

**Vulnerable path:** requirements.txt → `werkzeug@3.1.5` → `safe_join()` with a Windows device name (e.g., `example/NUL`) → `send_from_directory` opens the file but reading hangs.
**Fixed in:** 3.1.6
**Fix:** Upgrade werkzeug to ≥3.1.6.

**Exploit:** On a Windows server, an attacker requests a path ending in a special device name (e.g., `example/NUL`) → read hangs indefinitely → DoS.

> Note: `click@8.1.7` (CVE-2026-7246) is disputed and its vulnerable function (`click.edit()`, used only by the Flask CLI) is not called in this app (served via uwsgi, `uwsgi.ini:2`), so it is excluded from the active dependency count and documented under `## Disputed findings`.

## Findings summary

### First-party code
Total findings: 10 (Active: 10, Conditional: 0, Dead: 0, Test-only: 0)

| Severity | Count | Confirmed | Probable | Possible |
|----------|-------|-----------|----------|----------|
| CRITICAL | 3 | 3 | 0 | 0 |
| HIGH | 3 | 3 | 0 | 0 |
| MEDIUM | 3 | 3 | 0 | 0 |
| LOW | 1 | 1 | 0 | 0 |

### Dependencies
Total findings: 3 (Active: 2, Dead: 1)

| Package | Version | CVE | Severity | Called? |
|---------|---------|-----|----------|---------|
| flask | 3.1.1 | CVE-2026-27205 | MEDIUM | Yes (app.py:6; flask-login session access) |
| werkzeug | 3.1.5 | CVE-2026-27199 | MEDIUM | Yes (WSGI runtime, app.py:6) |
| click | 8.1.7 | CVE-2026-7246 [DISPUTED] | LOW (capped) | No — click.edit() not called (uwsgi); DEAD |

### All findings

| ID | Finding | CWE | Reachability | Impact | Likelihood | Severity | Confidence |
|----|---------|-----|--------------|--------|------------|----------|------------|
| V-001 | app.py:31 SSTI | CWE-94 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| V-002 | account.py:118 pickle | CWE-502 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| V-003 | account.py:76 admin escalation | CWE-284 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| V-004 | account.py:33 SQLi | CWE-89 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| V-005 | signup.py:15 SQLi | CWE-89 | ACTIVE | HIGH | HIGH | HIGH | CONFIRMED |
| V-006 | profile_image.py:7 SSRF | CWE-918 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| V-007 | click@8.1.7 | CWE-78 | DEAD | MODERATE | LOW | LOW (capped) | POSSIBLE |
| V-008 | db_seed.py:18 hardcoded creds | CWE-259 | ACTIVE | HIGH | MEDIUM | MEDIUM | CONFIRMED |
| V-009 | notes.py:44 IDOR | CWE-284 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| V-010 | app.py:11 hardcoded secret | CWE-259 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| V-011 | flask@3.1.1 | CWE-200 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| V-012 | werkzeug@3.1.5 | CWE-400 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| V-013 | account.py:105 cookie | CWE-OTHER | ACTIVE | LOW | MEDIUM | LOW | CONFIRMED |

## Disputed findings

### click@8.1.7 — [DISPUTED] command injection in click.edit()
**CVE:** CVE-2026-7246 (PYSEC-2026-2132, GHSA-47fr-3ffg-hgmw) — **isDisputed: true**
**CWE:** CWE-78 (OSV record maps it to CWE-77; reported here as CWE-78, Command Injection, per the allowed list)
**Reachability:** DEAD — `click.edit()` is not called anywhere in this app; served via uwsgi (`uwsgi.ini:2`), the Flask CLI is never invoked (no `__main__`).
**Impact:** MODERATE
**Likelihood:** LOW
**Confidence:** POSSIBLE
**Severity:** Impact MODERATE x Likelihood LOW = LOW (DEAD, capped from HIGH — `click.edit()` not called; CVE disputed by Pallets)

**Vulnerable path:** requirements.txt → `click@8.1.7` → `click.edit()` (Flask CLI editor, used by `flask run`/help). Not reached at runtime (uwsgi).
**Dispute:** OSV summary — "This CVE record was assigned not following CNA/CVE rules and is not considered a valid vulnerability by the Pallets Click project." CVSS `AV:L/AC:H/PR:H/UI:R` (local, high-privilege, user-interation).
**Fixed in:** 8.3.3
**Recommendation:** Upgrade click to ≥8.3.3 as defense-in-depth; not counted as an active finding.

## Validation

Reviewed by `@critic` (adversarial) and `@verifier` (fact-checker) subagents against `security-review-ref.md`.

- **Reachability:** All 10 first-party findings are ACTIVE with source-to-sink call chains verified against actual code (before_request hook runs on every request; GET /search; POST /darkmode; 404 handler; POST /account/image; POST /account; POST delete; app.py:21 at boot; public /signup). Authentication is correctly treated as a Likelihood factor (MEDIUM), not a Reachability factor (so none are CONDITIONAL).
- **file:line:** Every cited hop verified against source (app.py:31/32/11/7/21/29; account.py:118,33,70,76-81,105; signup.py:16-18,45-46; profile_image.py:7,12; notes.py:44; db_seed.py:18-19; login.py:22; app.py:6).
- **CWE:** All within the allowed list; cookie finding reclassified to CWE-OTHER (CWE-614 was not in the list).
- **Format:** All findings use the spec format (all required fields; Severity computation includes the reachability adjustment slot). Dependency findings use the spec dependency template.
- **Dependency scan:** 3 unique vulnerabilities (5 affected rows — flask+werkzeug double-counted across lockfile/unknown ecosystems), matching a live osv-scanner scan.
- **Disputed:** click@8.1.7 (CVE-2026-7246) reclassified DEAD (`click.edit()` not called; app served via uwsgi) and documented under `## Disputed findings` (OSV `isDisputed: true`).
- **Tables:** Internal consistency verified — 13 total findings (10 first-party + 3 dependency); severity and reachability distributions agree with the detailed findings.
