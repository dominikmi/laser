# Security Assessment — 2026-08-30 — coder_ornith

## Graph corpus

- graphify-out/GRAPH_REPORT.md: NOT AVAILABLE (file missing; only graph.json, manifest.json, cache present)
- graphify-out/graph.json: present

## Attack surface

### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | HTTP GET | routes/home.py:8 | No | Root `/` landing page |
| 2 | HTTP GET | routes/home.py:14 | Yes (`@login_required`) | `/home` dashboard |
| 3 | HTTP GET/POST | routes/login.py:18 | No | `/login` credential form |
| 4 | HTTP GET | routes/login.py:44 | Yes | `/logout` |
| 5 | HTTP GET | routes/login.py:50 | No | `/is_logged_in` status check |
| 6 | HTTP GET | routes/account.py:18 | Yes | `/account` profile view |
| 7 | HTTP GET | routes/account.py:24 | Yes | `/search` note search (request.args) |
| 8 | HTTP POST | routes/account.py:51 | Yes | `/account/image` profile image upload |
| 9 | HTTP POST | routes/account.py:68 | Yes | `/account` profile update (request.form) |
| 10 | HTTP POST | routes/account.py:98 | Yes | `/darkmode` cookie set (request.cookies) |
| 11 | HTTP GET/POST | routes/notes.py:10 | Yes | `/notes` list/create |
| 12 | HTTP POST | routes/notes.py:39 | Yes | `/notes/<id>/delete` |
| 13 | HTTP GET/POST | routes/registration_codes.py:12 | Yes (admin) | `/registration-codes` |
| 14 | HTTP GET/POST | routes/signup.py:28 | No | `/signup` registration (validate_token raw SQL) |
| 15 | CLI | db_seed.py:1 | No | DB seed script |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | Unauthenticated HTTP -> auth (flask_login) | routes/login.py:18 | credentials |
| 2 | User cookie -> deserialization | routes/account.py:118 | serialized preferences |
| 3 | Registration code param -> raw SQL | routes/signup.py:17 | user-provided code |
| 4 | Session secret key (hardcoded) | app.py:11 | session signing key |

### Notes
- Flask app entry: `app.py:10` (`Flask(__name__)`), secret key hardcoded at `app.py:11`.
- Public (unauthenticated) entry points: `/`, `/login`, `/is_logged_in`, `/signup`.
- Auth: `flask_login` `login_required` guards most routes; `/registration-codes` also checks `current_user.is_admin`.
- User input sinks observed: `request.args` (search), `request.form` (forms), `request.cookies` (preferences, image), raw SQL via `session.execute` in signup.
- Passwords hashed with bcrypt (`hashpw`/`checkpw`); stored in `models/user.py:17`.

## Attack paths

- `/` (routes/home.py:home) -> app.py -> routes/signup.py (signup) -> validate_token raw SQL [4 hops]
- `/login` (routes/login.py:login) -> models/user.py (User) [3 hops]
- `/search` (routes/account.py:search) -> routes/account.py (account) -> before/after_request deserialization [2 hops]

## Dead code candidates

- None identified — db_seed.py, routes/registration_codes.py, utils/notes.py, routes/notes.py, app.page_not_found() all reachable via imports from app.py; no zero-indegree entry-point-disconnected files found.

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

### app.py:31-32 — Server-Side Template Injection (404 handler)
**CWE:** CWE-94
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [CRITICAL] x Likelihood [HIGH] = CRITICAL (ACTIVE, no adjustment)

**Data flow:**
Source:     app.py:32 — `request.path` (attacker-controlled URL path) enters the 404 handler
Transform:  app.py:31-32 — f-string interpolates `request.path` into a template string
Sink:       app.py:31-32 — `render_template_string(...)` compiles/renders attacker-injected Jinja2

```python
@app.errorhandler(404)
def page_not_found(error):
    detailed_message = render_template_string(
        f"{error}. Requested URL was {request.path}"
    )
    return render_template("404.html", detailed_message=detailed_message)
```

**Exploit:** 1. Attacker requests a non-existent path containing Jinja2 syntax, e.g. GET `/%7B%7B7*7%7D%7D` (decodes to `{{7*7}}`) -> 2. Flask 404s -> page_not_found() interpolates request.path into the f-string -> render_template_string compiles it as a Jinja2 template -> 3. Template executes `{{7*7}}` (and can escape the sandbox for RCE).
**Mitigations:** None. `render_template_string` with user input is inherently vulnerable; the f-string does no escaping.
**Fix:** Do not pass user-controlled data to `render_template_string`. Build the message with string concatenation/`str.format` and pass it as a template *variable* via `render_template("404.html", detailed_message=...)` so it is autoescaped.

### routes/account.py:112-118 — Insecure Pickle Deserialization (cookie)
**CWE:** CWE-502
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [CRITICAL] x Likelihood [HIGH] = CRITICAL (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:114 — `request.cookies.get('preferences')` (attacker-controlled cookie, any request)
Transform:  routes/account.py:118 — `b64decode(preferences)` decodes the cookie
Sink:       routes/account.py:118 — `loads(...)` = `pickle.loads` (imported routes/account.py:1) deserializes attacker data

```python
@app.before_request
def before_request():
    preferences = request.cookies.get('preferences')
    if preferences is None:
        preferences = default_preferences
    else:
        preferences = loads(b64decode(preferences))

    g.preferences = preferences
```

**Exploit:** 1. Attacker crafts a base64-encoded pickle payload as the `preferences` cookie -> 2. Sends it to any route (before_request runs before @login_required) -> pickle.loads instantiates attacker-chosen classes -> 3. Remote code execution (e.g. `os.system` via a deserialized object).
**Mitigations:** None. The app writes its own cookies via `pickle.dumps` (routes/account.py:105,128), but any user can forge a cookie; no signature or format validation.
**Fix:** Replace pickle with a safe serializer (e.g. `json`) for the cookie, or sign the cookie with `secret_key`/itsdangerous and validate before decoding.

### routes/signup.py:15-18 — SQL Injection in registration code lookup
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, partial mitigation lowers likelihood one level)

**Data flow:**
Source:     routes/signup.py:45 — `code = form.registration_code.data` (attacker-controlled)
Transform:  routes/signup.py:46 — `validate_token(code, session)` called
Sink:       routes/signup.py:15-18 — f-string interpolates `code` into SQL passed to `session.execute(text(...))`

```python
def validate_token(code: str, session: Session) -> Union[str, None]:
    try:
        result = session.execute(
            text(f"""
                SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}'
            """)).first()
```

**Exploit:** 1. Attacker submits a signup with a malicious `registration_code`, e.g. `' OR '1'='1` -> 2. Interpolated into the WHERE clause at signup.py:17 -> 3. SQLi allows returning an arbitrary code id (UNION-based extraction of other rows/users is also possible).
**Mitigations:** Partial — signup.py:52 re-fetches the token and checks `token.code != code`, which blocks simple auth-bypass, but UNION-based data extraction still works. Partial mitigation lowers likelihood one level.
**Fix:** Parameterize the query: `text("SELECT id, code FROM registration_code WHERE code = :code")` with `{"code": code}`; never interpolate user input into SQL.

### routes/account.py:31-33 — SQL Injection in note search
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:27 — `search_param = request.args.get('search', '')` (attacker-controlled query param)
Transform:  routes/account.py:31-33 — f-string injects `search_param` into `text(...)` filter
Sink:       routes/account.py:33 — executed against the notes table

```python
personal_notes = session.query(Note).filter(
    Note.user_id == current_user.id,
    text(f"text like '%{search_param}%'")).all()
```

**Exploit:** 1. Authenticated user requests `/search?search=' UNION SELECT password FROM users--` -> 2. Interpolated into the SQL text() at account.py:33 -> 3. Data exfiltration or boolean-based blind extraction from the notes query context.
**Mitigations:** None. The parameter is interpolated raw into a `text()` construct.
**Fix:** Use bound parameters, e.g. `text("... text like :q")` with `{"q": f"%{search_param}%"}`, or escape/validate input.

### utils/profile_image.py:6-8 — Server-Side Request Forgery (image URL)
**CWE:** CWE-918
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:60-61 — `form.url.data` (attacker-controlled) passed to `get_base64_image_blob`
Transform:  utils/profile_image.py:12 — `download(url)` called
Sink:       utils/profile_image.py:7 — `urlopen(url)` fetches attacker-chosen URL

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

**Exploit:** 1. Authenticated user POSTs `/account/image` with `url=http://169.254.169.254/latest/meta-data/` (or `file:///etc/passwd`) -> 2. add_image() calls get_base64_image_blob -> download -> urlopen at profile_image.py:7 -> 3. SSRF to cloud metadata/internal services, exposing credentials or internal resources.
**Mitigations:** None. No URL scheme/allowlist/hostname validation before `urlopen`.
**Fix:** Validate the URL against an allowlist of schemes (https/http only) and hostnames, block private/loopback/metadata IP ranges, and avoid fetching arbitrary URLs.

### app.py:11 — Hardcoded Flask session secret key
**CWE:** CWE-259
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [HIGH] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     app.py:11 — literal string assigned to `app.secret_key`
Sink:       app.py:11 — used to sign all session cookies at runtime

```python
app = Flask(__name__)
app.secret_key = "super secret key"
```

**Exploit:** 1. Source (committed to the public git repo) reveals the session signing key -> 2. Attacker forges valid session cookies (`session` cookie) for any user -> 3. Account takeover / session hijack.
**Mitigations:** None. The key is hardcoded in source control.
**Fix:** Load `secret_key` from an environment variable or secret manager (e.g. `os.environ["FLASK_SECRET_KEY"]`); rotate the exposed key.

### routes/account.py:68-81 — Mass-Assignment privilege escalation
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:70 — `form = AccountForm(request.form)` exposes `is_admin` (forms/account_form.py:8)
Transform:  routes/account.py:76-80 — `filtered_values` includes every field except `password`
Sink:       routes/account.py:81 — `current_user.__dict__.update(filtered_values)` persists `is_admin`

```python
filtered_values = {
    key: value
    for key, value in form.data.items()
    if value is not None and key != 'password'
}
current_user.__dict__.update(filtered_values)
```

**Exploit:** 1. Authenticated normal user POSTs `/account` with `is_admin=true` in the form body -> 2. AccountForm exposes the `is_admin` BooleanField; filtered_values keeps it (only `password` is excluded) -> 3. `current_user.__dict__.update` sets `is_admin=True`, merged and committed -> privilege escalation to admin.
**Mitigations:** None. Mass assignment onto `current_user.__dict__` with no field allowlist.
**Fix:** Update only allowed fields explicitly (e.g. `email`); never bulk-assign `form.data` onto a model/user object. Also add `@login_required` to `update_account` (currently missing).

### db_seed.py:17-19 — Hardcoded default credentials
**CWE:** CWE-259
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     db_seed.py:17-19 — plaintext passwords `b'user'` / `b'admin'` passed to `hashpw`
Sink:       db_seed.py:17-19 — seeded `User` rows including an `is_admin=True` admin (`admin@evfa.com`/`admin`)

```python
user = User('user@evfa.com', hashpw(b'user', gensalt()).decode())
admin = User('admin@evfa.com',
             hashpw(b'admin', gensalt()).decode(), True)
```

**Exploit:** 1. Source reveals the seeded admin password `admin` (and a static registration code at db_seed.py:9) -> 2. Attacker logs in as `admin@evfa.com` -> 3. Admin access to `/registration-codes` and admin-only features.
**Mitigations:** None. Default credentials are hardcoded and shipped with the app.
**Fix:** Do not seed default admin credentials; require admin creation at deploy time via a prompt/env var with a strong random password.

### routes/notes.py:39-51 — Insecure Direct Object Reference (note deletion)
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [MODERATE] x Likelihood [MEDIUM] = MEDIUM (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/notes.py:39 — `note_id` from the URL path
Sink:       routes/notes.py:44-48 — `session.get(Note, note_id)` then `session.delete(note)` with no ownership check

```python
@app.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id: int):
    with Session() as session:
        note = session.get(Note, note_id)
        if note is None:
            flash('Note not found', 'warning')
        else:
            session.delete(note)
```

**Exploit:** 1. Authenticated user (or a CSRF victim) POSTs to `/notes/<any_id>/delete` -> 2. delete_note fetches the note by id without checking `note.user_id == current_user.id` -> 3. Deletes another user's notes (cross-user destruction).
**Mitigations:** None. No ownership/authorization check on the deleted object.
**Fix:** Assert `note.user_id == current_user.id` before deleting; scope the query to the current user.

### routes/notes.py:16-51 — Missing CSRF protection on state-changing POSTs
**CWE:** CWE-352
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [MODERATE] x Likelihood [MEDIUM] = MEDIUM (ACTIVE, no adjustment)

**Data flow:**
Source:     Attacker-controlled page forces a victim's browser to POST to app endpoints
Sink:       routes/notes.py:48 (`delete_note`), routes/notes.py:32 (`add_note`), routes/account.py:91 (`update_account`)

```python
@app.route('/notes', methods=['POST'])
@login_required
def add_note():
    ...
    session.add(note)
    session.commit()
```

**Exploit:** 1. Attacker hosts a page that auto-POSTs to `/notes/<id>/delete` (or `/notes`, `/account`) while the victim is authenticated -> 2. Endpoints use plain `wtforms.Form` (not `FlaskForm`), so no CSRF token is required (Flask-WTF installed but never wired via `CSRFProtect`) -> 3. Unauthorized note deletion/creation/account changes.
**Mitigations:** None. No CSRF token middleware; forms are unauthenticated `wtforms.Form`.
**Fix:** Use `Flask-WTF`'s `FlaskForm`/`CSRFProtect(app)` on all state-changing POST routes, or implement synchronous CSRF tokens manually.

## Dependency findings

### click@8.1.7 — Command Injection (PYSEC-2026-2132)
**CVE:** PYSEC-2026-2132
**CWE:** CWE-78
**Reachability:** ACTIVE — transitively imported via Flask (Flask depends on click); present in the runtime dependency graph
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** PROBABLE
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Vulnerable path:** click is a transitive dependency of Flask; its CLI/option-parsing code is only exercised when the app is launched through the Flask CLI (`flask run`/`flask` group), not under the uwsgi WSGI deployment. Not imported directly in application code.
**Fixed in:** 8.3.3
**Fix:** Upgrade click to >= 8.3.3 (or pin a non-vulnerable version).

### werkzeug@3.1.5 — Vulnerability (PYSEC-2026-2320, CVSS 6.3)
**CVE:** PYSEC-2026-2320
**CWE:** CWE-OTHER (see advisory)
**Reachability:** ACTIVE — Werkzeug is the WSGI layer Flask serves all requests through; present in the runtime dependency graph
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** PROBABLE
**Severity:** Impact [MODERATE] x Likelihood [MEDIUM] = MEDIUM (ACTIVE, no adjustment)

**Vulnerable path:** Werkzeug handles request/response parsing for every request served by the Flask app (transitively imported, no direct application import).
**Fixed in:** 3.1.6
**Fix:** Upgrade werkzeug to >= 3.1.6.

### flask@3.1.1 — Vulnerability (PYSEC-2026-2151, CVSS 4.3)
**CVE:** PYSEC-2026-2151
**CWE:** CWE-OTHER (see advisory)
**Reachability:** ACTIVE — core framework; imported directly in app.py:6 and every route module
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** PROBABLE
**Severity:** Impact [MODERATE] x Likelihood [MEDIUM] = MEDIUM (ACTIVE, no adjustment)

**Vulnerable path:** Flask is imported directly (app.py:6) and used to serve all requests.
**Fixed in:** 3.1.3
**Fix:** Upgrade flask to >= 3.1.3.

## Findings summary

### First-party code
Total findings: 10 (Active: 10, Conditional: 0, Dead: 0, Test-only: 0)

| Severity | Count | Confirmed | Probable | Possible |
|----------|-------|-----------|----------|----------|
| CRITICAL | 2     | 2         | 0        | 0        |
| HIGH     | 6     | 6         | 0        | 0        |
| MEDIUM   | 2     | 2         | 0        | 0        |
| LOW      | 0     | 0         | 0        | 0        |

### Dependencies
Total findings: 3 (Active: 3, Dead: 0)

| Package | Version | CVE | Severity | Called? |
|---------|---------|-----|----------|---------|
| click | 8.1.7 | PYSEC-2026-2132 | HIGH | yes (transitive via Flask) |
| werkzeug | 3.1.5 | PYSEC-2026-2320 | MEDIUM | yes (transitive, WSGI layer) |
| flask | 3.1.1 | PYSEC-2026-2151 | MEDIUM | yes (direct import) |

### All findings

| File/Package | Finding | CWE | Reachability | Impact | Likelihood | Severity | Confidence |
|--------------|---------|-----|--------------|--------|------------|----------|------------|
| app.py:31-32 | SSTI in 404 handler | CWE-94 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| routes/account.py:118 | Pickle deserialization (cookie) | CWE-502 | ACTIVE | CRITICAL | HIGH | CRITICAL | CONFIRMED |
| routes/signup.py:17 | SQLi in code lookup | CWE-89 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| routes/account.py:33 | SQLi in note search | CWE-89 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| utils/profile_image.py:7 | SSRF via image URL | CWE-918 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| app.py:11 | Hardcoded secret key | CWE-259 | ACTIVE | HIGH | HIGH | HIGH | CONFIRMED |
| routes/account.py:81 | Mass-assignment privilege escalation | CWE-284 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| db_seed.py:17 | Hardcoded default credentials | CWE-259 | ACTIVE | HIGH | MEDIUM | HIGH | CONFIRMED |
| routes/notes.py:44 | IDOR note deletion | CWE-284 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| routes/notes.py:16 | Missing CSRF protection | CWE-352 | ACTIVE | MODERATE | MEDIUM | MEDIUM | CONFIRMED |
| click@8.1.7 | Command Injection | CWE-78 | ACTIVE | HIGH | MEDIUM | HIGH | PROBABLE |
| werkzeug@3.1.5 | WSGI vuln | CWE-OTHER | ACTIVE | MODERATE | MEDIUM | MEDIUM | PROBABLE |
| flask@3.1.1 | Flask vuln | CWE-OTHER | ACTIVE | MODERATE | MEDIUM | MEDIUM | PROBABLE |
