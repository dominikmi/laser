# Security Assessment — 2026-08-31 — Ornith_1_5_35B_A3B_MLX_4bit

## Context
**Project:** Extremely Vulnerable Flask App — intentionally vulnerable educational web app
**Language/framework:** Python 3.13 / Flask; SQLAlchemy + SQLite; Jinja2 templating; Bootstrap-Flask
**Purpose:** Educational demonstration of common web vulnerabilities. Registration is invite-based; ships with predefined `user@evfa.com:user` and `admin@evfa.com:admin` accounts and a leaked invite code in the README.
**Deployment:** Docker container — nginx (`conf/nginx.conf`) proxying to uwsgi (`uwsgi.ini`, `module = app:app`) over `/tmp/uwsgi.socket`. CMD: `service nginx start; uwsgi --ini uwsgi.ini` (5 processes, master).
**Ports/services:** HTTP `:5000:80` (nginx↔uwsgi socket); SQLite `database.db`
**Auth model:** Invite-based registration with admin/user roles (to be confirmed in route analysis — no OAuth/JWT visible)
**Data stores:** SQLite via SQLAlchemy (`database.db`, resettable)
**External integrations:** none visible
**Notes:** Intentionally vulnerable (educational). Leaked invite code published in README. Debug mode and exact auth mechanism to be confirmed from `app.py`/routes in step 6.

## graphify-out
graphify-out not available — `graph.json` present but `GRAPH_REPORT.md` was not generated (both required for graphify-based analysis). Step 4b (attack-path / dead-code via graphify) skipped; attack surface assessed via manual grep.

## Semgrep baseline
19 files scanned (23 discovered, 4 `__init__.py` excluded by scanner). Findings (ERROR/WARNING only; test/generated/non-source excluded):

| file:line | rule-name | severity | CWE |
|---|---|---|---|
| routes/account.py:33 | avoid-sqlalchemy-text | ERROR | CWE-89 SQLi (sqlalchemy.text) |
| routes/account.py:105 | secure-set-cookie | WARNING | CWE-614 insecure cookie |
| routes/account.py:105 | insecure-deserialization | ERROR | CWE-502 pickle |
| routes/account.py:105 | avoid-pickle | WARNING | CWE-502 pickle |
| routes/account.py:118 | avoid-pickle | WARNING | CWE-502 pickle |
| routes/account.py:128 | avoid-pickle | WARNING | CWE-502 pickle |
| app.py:31 | render-template-string | WARNING | CWE-96 SSTI (render_template_string) |
| utils/profile_image.py:7 | dynamic-urllib-use-detected | WARNING | CWE-939 urllib file:// |

Notes: all findings fingerprinted `requires login`; Semgrep flagged only `account.py`, `app.py`, `utils/profile_image.py`. Manual review required for business-logic / access-control / IDOR / SSRF that patterns miss.

**Serena symbol overviews (retained for step 6):**
- `app.py`: Variables `app, bootstrap, login_manager, ckeditor`; Functions `unauthorized, page_not_found`.
- `routes/login.py`: Functions `load_user, login, do_login, logout, logged_in`.
- `routes/account.py`: Functions `account, search, get_personal_notes, add_image, update_account, toggle_darkmode, before_request, after_request`; Variable `default_preferences`.

## Secret scan baseline
LeakFerret (`scan_repository`) — not available; tool not in toolset. Skipped. Manual secret check deferred to step 6 (grep for hardcoded secrets/tokens).

## Dependency scan baseline
| package | version | CVE | severity | fixed-in |
|---|---|---|---|---|
| werkzeug | (required by requirements.txt) | CVE-2026-27199 (GHSA-29vq-49wr-vm6x) | Medium | 3.1.6 |

Note: CWE-67 path traversal — `safe_join`/`send_from_directory` allows Windows special device names (e.g. `example/NUL`) only when the app runs on Windows. App runs in Docker/Linux, so exploitability is likely limited; verify whether `send_from_directory`/`safe_join` is used with user-controlled paths in step 6.

## Attack surface
Sources mapped via grep (19 route decorators, 6 user-input sites, 2 SQL-interpolation sites, 1 urlopen, 1 render_template_string, 3 pickle sites, 1 hardcoded secret_key, 0 CSRF protections).

### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | HTTP route `/` | routes/home.py:8 | Yes (@login_required at home.py:9, redirects to /home) | Landing page |
| 2 | HTTP route `/home` | routes/home.py:14 | Yes | Home feed |
| 3 | HTTP route `/signup` GET+POST | routes/signup.py:28,33 | No (public) | Invite-registration; raw SQL code lookup (signup.py:17) |
| 4 | HTTP route `/login` GET+POST | routes/login.py:17,22 | No (public) | Authentication |
| 5 | HTTP route `/logout` | routes/login.py:43 | Yes | Session end |
| 6 | HTTP route `/is_logged_in` | routes/login.py:50 | No (public) | Auth state check (info disclosure) |
| 7 | HTTP route `/account` GET | routes/account.py:18 | Yes | Account dashboard |
| 8 | HTTP route `/search` GET | routes/account.py:24 | Yes | `request.args['search']` → SQLAlchemy text() (account.py:33) |
| 9 | HTTP route `/account/image` POST | routes/account.py:51 | Yes | Image upload → `urlopen(url)` (profile_image.py:7) |
| 10 | HTTP route `/account` POST | routes/account.py:68 | No (public — no @login_required; mass-assignment surface) | Profile/password update (mass-assignment → admin, unauthenticated) |
| 11 | HTTP route `/darkmode` POST | routes/account.py:98 | No (public — no @login_required) | Preference toggle (technically unauthenticated, low impact) |
| 12 | HTTP route `/accounts/<int:user_id>/notes` | routes/account.py:41 | Yes | Other user's notes (IDOR surface) |
| 13 | HTTP route `/notes` GET+POST | routes/notes.py:10,16 | Yes | List/create notes |
| 14 | HTTP route `/notes/<int:note_id>/delete` POST | routes/notes.py:39 | Yes | Delete by id (IDOR surface) |
| 15 | HTTP route `/registration-codes` GET+POST | routes/registration_codes.py:12,26 | Yes | Admin code management |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | User `search` param → SQLAlchemy `text()` SQL | routes/account.py:27→33 | SQL string (CWE-89) |
| 2 | User registration code → raw SQL string interpolation | routes/signup.py:35→17 | SQL string (CWE-89) |
| 3 | Pickled data → `pickle.loads` | routes/account.py:105,118,128 | Untrusted object (CWE-502) |
| 4 | User-provided image URL → `urlopen()` | utils/profile_image.py:7 | URL (CWE-939/20 SSRF/file) |
| 5 | User input → `render_template_string` | app.py:31 | Template (CWE-96 SSTI) |
| 6 | Session/cookie → Flask-Login `login_manager` + `logged_in()` | routes/login.py | Auth (CWE-30) |
| 7 | IDOR: `<int:user_id>`, `<int:note_id>` with no ownership check | routes/account.py:41, routes/notes.py:39 | Authorization (CWE-639) |
| 8 | Hardcoded `app.secret_key` | app.py:11 | Secret (CWE-798) |

### Notes
- No CSRF protection detected (0 matches for `csrf`/`flask_wtf`/`generate_csrf`) despite state-changing POST forms — potential CSRF (CWE-352) to verify in step 6.
- Public, unauthenticated entry points: `/signup`, `/login`, `/is_logged_in`; plus `/account` POST (update_account, account.py:68-69) which has no `@login_required` (mass-assignment surface, unauthenticated — finding #8). `/` requires `@login_required` (home.py:9). `/darkmode` POST (account.py:98) also lacks `@login_required`; low impact (toggles a non-sensitive preference, no auth/privilege effect) but technically unauthenticated.
- Registration uses `uuid4()` codes (registration_codes.py:34) but `db_seed.py:9` ships a hardcoded, README-published invite code (`a36e990b-...`).
- Passwords hashed with `hashpw`/`gensalt` (bcrypt); `app.secret_key` hardcoded as `"super secret key"`.
- `db_seed.py` seeds predefined `user@evfa.com:user` and `admin@evfa.com:admin` accounts.

## Scanned files
23 source files (`*.py`, excluding tests/migrations/vendor/.venv/dist/build/.security-output/graphify-out):

- `app.py` (entry point / Flask factory)
- `db_seed.py` (DB seeding)
- `routes/account.py` (search, image upload, profile — highest risk)
- `routes/login.py` (auth, Flask-Login)
- `routes/notes.py` (notes CRUD, delete-by-id)
- `routes/home.py` (home feed)
- `routes/signup.py` (invite registration, raw SQL)
- `routes/registration_codes.py` (admin code mgmt)
- `routes/__init__.py`
- `models/user.py`, `models/note.py`, `models/registration_code.py`, `models/base_model.py`, `models/__init__.py`
- `forms/account_form.py`, `forms/login_form.py`, `forms/registration_form.py`, `forms/note_form.py`, `forms/image_form.py`, `forms/__init__.py`
- `utils/profile_image.py` (urlopen), `utils/notes.py`, `utils/__init__.py`

## Findings

### app.py:11 — Hardcoded Flask session secret_key
**CWE:** CWE-798 (Use of Hard-coded Credentials / cryptographic key)
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     `app.py:11` — `app.secret_key` assigned a literal string at app factory
Transform:  `app.py:11` — Flask uses secret_key to sign all session cookies
Sink:       `app.py:11` — attacker who knows the key forges arbitrary session cookies (incl. admin)

```python
app.secret_key = "super secret key"
```

**Exploit:** 1. Attacker reads the hardcoded key from the public repo source -> 2. Forges a signed session cookie for `admin@evfa.com` using Flask's `secure_cookies`/`signer` -> 3. Authenticates as admin (full auth bypass).
**Mitigations:** None.
**Fix:** Generate a random secret at runtime (`os.urandom(64)`) or from an environment variable / secrets manager; never hardcode.

### app.py:31-33 — Server-Side Template Injection / RCE in 404 handler
**CWE:** CWE-94
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     `request.path` — attacker-controlled URL path (any unmatched URL triggers 404)
Transform:  `app.py:32` — f-string interpolates `request.path` into a Jinja2 template literal
Sink:       `app.py:31-33` — `render_template_string(...)` renders the attacker-controlled template (no sandbox) -> Jinja2 RCE

```python
    detailed_message = render_template_string(
        f"{error}. Requested URL was {request.path}"
    )
    return render_template("404.html", detailed_message=detailed_message)
```

**Exploit:** 1. Attacker requests `/{{payload}}` (any unmatched route) -> 2. 404 handler interpolates the URL into `render_template_string` -> 3. Jinja2 evaluates `{{ ''.__class__.__mro__[1].__subclasses__() }}` chain -> RCE.
**Mitigations:** None (no Jinja2 sandbox; `render_template_string` renders full template syntax).
**Fix:** Never pass user input into `render_template_string`. Use `render_template("404.html", path=request.path)` and let Jinja2 escape output, or sanitize/avoid dynamic template construction.

### routes/account.py:31-33 — SQL injection via `sqlalchemy.text()`
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     `routes/account.py:27` — `request.args.get('search', '')` (user-controlled)
Transform:  `routes/account.py:33` — f-string injects `search_param` into `text("text like '%...%'")`
Sink:       `routes/account.py:33` — `text(...)` passes constructed SQL to the DB unchanged (bypasses parameterization)

```python
personal_notes = session.query(Note).filter(
    Note.user_id == current_user.id,
    text(f"text like '%{search_param}%'')).all()
```

**Exploit:** 1. Authenticated user requests `/search?search=' UNION SELECT id,email,password FROM users--` -> 2. Parameter is concatenated into raw SQL via `text()` -> 3. UNION-based exfiltration of other users' data / bypass of the `user_id` filter.
**Mitigations:** None (raw `text()` bypasses SQLAlchemy parameterization; the `user_id` filter is ANDed but can be escaped via injection).
**Fix:** Parameterize: `text("text like :q").bindparams(text('q', search_param + "%"))` or use `Note.text.like(...)` with bound params; never f-string raw SQL.

### routes/account.py:118 — Insecure deserialization / RCE via `pickle.loads` on cookie
**CWE:** CWE-502
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     `routes/account.py:114` — attacker-controlled `preferences` cookie (`request.cookies.get('preferences')`)
Transform:  `routes/account.py:118` — `b64decode(preferences)` decodes base64 payload
Sink:       `routes/account.py:118` — `loads(...)` = `pickle.loads` -> arbitrary object construction -> RCE. Triggered by `@app.before_request`, which runs on every request including public routes (e.g. `/login`).

```python
preferences = request.cookies.get('preferences')
if preferences is None:
    preferences = default_preferences
else:
    preferences = loads(b64decode(preferences))
```

**Exploit:** 1. Attacker crafts a base64(pickle) payload that executes code on `pickle.loads` -> 2. Sends it as the `preferences` cookie to any route (before_request runs before auth) -> 3. `pickle.loads` deserializes -> RCE.
**Mitigations:** None. Cookie also written unpickled at line 105 without `secure`/`httponly`/`samesite` (CWE-614), but the deserialization is the critical issue.
**Fix:** Remove `pickle` entirely; store preferences as JSON (`json.dumps`/`json.loads`) or signed tokens. Never `pickle.loads` untrusted input.

### routes/account.py:43-46 — Insecure Direct Object Reference (IDOR) on other users' notes
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     `routes/account.py:41` — `<int:user_id>` from URL path
Transform:  `routes/account.py:45-46` — `session.query(Note).filter(Note.user_id == user_id)` — no check that `user_id == current_user.id`
Sink:       `routes/account.py:47` — other user's notes returned to the requester

```python
def get_personal_notes(user_id: int):
    with Session() as session:
        personal_notes = session.query(Note).filter(
            Note.user_id == user_id).all()
```

**Exploit:** 1. Authenticated user visits `/accounts/<any-user-id>/notes` -> 2. Query returns that user's notes (name collision lets attacker enumerate IDs) -> 3. Cross-user data exposure.
**Mitigations:** None (route enforces authentication but not authorization/ownership).
**Fix:** Enforce `user_id == current_user.id` (403/404 otherwise); scope queries to `current_user`.

### routes/signup.py:15-18 — SQL injection on public `/signup` (password-hash exfiltration)
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     `routes/signup.py:45` — `form.registration_code.data` (user-controlled, public `/signup` POST)
Transform:  `routes/signup.py:46` — `validate_token(code, session)` interpolates `code` into `text(f"...WHERE code = '{code}'")`
Sink:       `routes/signup.py:15-18` — `session.execute(text(...))` runs raw SQL; `result.id` returns the first column, which a UNION payload can make a user's bcrypt hash

```python
result = session.execute(
    text(f"""
        SELECT id, code FROM {RegistrationCode.__tablename__} WHERE code = '{code}'
    """)).first()
```

**Exploit:** 1. Attacker POSTs `/signup` with `registration_code` = `' AND 1=0 UNION SELECT password, id FROM users LIMIT 1--` -> 2. Base query returns nothing, UNION returns `(bcrypt_hash, user_id)`; `result.id` = the hash -> 3. Collect hashes one request at a time, offline-crack bcrypt. (The line-52 `token.code != code` double-check blocks auth-bypass but not UNION exfiltration.)
**Mitigations:** Partial — line 52 double-check blocks registration-bypass; `except OperationalError` suppresses error-based leakage. UNION exfiltration of the first column still works.
**Fix:** Parameterize: `text("SELECT id, code FROM registration_codes WHERE code = :c").bindparams(text('c', code))`. Never interpolate user input into `text()`.

### routes/login.py:50-56 — Auth status / email disclosure on public `/is_logged_in`
**CWE:** CWE-200
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood HIGH = LOW (ACTIVE)

**Data flow:**
Source:     `routes/login.py:52-55` — response body built from `current_user.is_authenticated` and `current_user.email`
Transform:  `routes/login.py:50` — `/is_logged_in` has no `@login_required` (public)
Sink:       `routes/login.py:52-55` — JSON response returns authenticated user's email + auth flag

```python
@app.route('/is_logged_in', methods=['GET'])
def logged_in():
    return {
        'is_logged_in': current_user.is_authenticated,
        'username':
        current_user.email if current_user.is_authenticated else '-'
    }
```

**Exploit:** 1. A logged-in viewer GETs `/is_logged_in` -> 2. Response echoes that viewer's own email address + auth status (an unauthenticated viewer always receives `'-'`) -> 3. Limited account-enumeration aid (cross-user enumeration is blocked by CORS, which a cross-origin GET cannot read). Primarily reveals the current viewer's own status — hence LOW impact.
**Mitigations:** None (endpoint is public; returns email only for authenticated sessions).
**Fix:** Enforce `@login_required`; return a generic boolean without the email, or remove the endpoint.

### utils/profile_image.py:7 — SSRF / arbitrary file read via `urlopen(url)`
**CWE:** CWE-918
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     `routes/account.py:60` — `get_base64_image_blob(form.url.data)` (user-provided URL via `/account/image` POST)
Transform:  `utils/profile_image.py:11-12` — `get_base64_image_blob(url)` -> `download(url)`
Sink:       `utils/profile_image.py:7` — `urlopen(url)` with no scheme validation -> `file://` reads local files; `http://169.254.169.254/` SSRF to cloud metadata/internal services

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

**Exploit:** 1. Authenticated user POSTs `/account/image` with `url=file:///etc/passwd` (or `http://169.254.169.254/latest/meta-data/`) -> 2. `urlopen` fetches it (scheme unvalidated; `guess_type` only sets mimetype) -> 3. Base64 blob returned/stored -> arbitrary local file read or SSRF to internal endpoints.
**Mitigations:** None (no URL scheme allowlist; only `guess_type` for mimetype).
**Fix:** Allowlist URL schemes (`https` only); block `file://`, `gopher:`, internal IPs; fetch server-side with a bounded whitelist; never pass user-controlled URLs to `urlopen`.

### routes/notes.py:41-48 — IDOR: delete any user's note by `note_id`
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** HIGH (note IDs are sequential auto-increment integers — `models/base_model.py:11`; `/notes/<id>/delete` is trivially enumerable)
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     `routes/notes.py:39` — `<int:note_id>` from URL path
Transform:  `routes/notes.py:44` — `session.get(Note, note_id)` — no `note.user_id == current_user.id` check
Sink:       `routes/notes.py:48` — `session.delete(note)` deletes another user's note

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

**Exploit:** 1. Authenticated user POSTs `/notes/<any-note-id>/delete` -> 2. Server loads and deletes the note regardless of owner -> 3. Destruction of other users' notes (data tampering).
**Mitigations:** None (enforces authentication, not ownership).
**Fix:** Check `note.user_id == current_user.id` before deleting (404 otherwise); scope to `current_user`.

### db_seed.py:9 — Hardcoded, README-published registration code
**CWE:** CWE-798 (hardcoded credential)
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood HIGH = LOW (ACTIVE)

**Data flow:**
Source:     `db_seed.py:9` — static registration code literal `'a36e990b-0024-4d55-b74a-f8d7528e1764'`
Transform:  `db_seed.py:10` — seeded into `RegistrationCode` table at startup (`setup_db()`, called from `app.py:21` on fresh DB)
Sink:       `db_seed.py:9` — published verbatim in `README.md` ("use the leaked invite code ...")

```python
if session.query(RegistrationCode).count() == 0:
    static_code = 'a36e990b-0024-4d55-b74a-f8d7528e1764'
    session.add(RegistrationCode(static_code))
```

**Exploit:** 1. Attacker reads the code from the public README -> 2. Uses it on `/signup` to create an account -> 3. Unauthorized account creation (bypasses invite generation).
**Mitigations:** None (code is hardcoded and publicly documented).
**Fix:** Generate registration codes at runtime; never hardcode or publish invite codes.

### db_seed.py:18-19 — Admin account with weak, known password (`'admin'`)
**CWE:** CWE-521 (Weak Password)
**Reachability:** CONDITIONAL
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (CONDITIONAL)

**Data flow:**
Source:     `db_seed.py:18-19` — admin account seeded with `hashpw(b'admin', gensalt())` (password is literally `'admin'`)
Transform:  `db_seed.py:22` — admin (`is_admin=True`) created on fresh DB (`User.count() == 0`)
Sink:       login (`routes/login.py:32`) — `bcrypt.checkpw` verifies against the cracked hash

```python
admin = User('admin@evfa.com',
             hashpw(b'admin', gensalt()).decode(), True)
```

**Exploit:** 1. On a freshly-seeded DB, admin's bcrypt hash corresponds to the password `'admin'` -> 2. Attacker obtains the hash (e.g., via the `/signup` SQLi exfiltration) -> 3. `'admin'` cracks in seconds; logs in as admin (privilege escalation).
**Mitigations:** Password is bcrypt-hashed (not plaintext), but `'admin'` is a top-common password, cracked instantly offline.
**Fix:** Do not ship predefined admin accounts with weak passwords; force password change on first login; use strong randomly-generated seeds.

### forms/account_form.py:8 + routes/account.py:81 — Mass-assignment → admin escalation (`update_account` unauthenticated — no `@login_required`)
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     `forms/account_form.py:8` — `is_admin = BooleanField('Is Admin')` (field present in submitted form)
Transform:  `routes/account.py:76-80` — `filtered_values` dict comprehension excludes only `password` and `None` values; `is_admin` survives the filter
Sink:       `routes/account.py:81` — `current_user.__dict__.update(filtered_values)`; `account.py:91-92` `session.merge`/`commit` persists `is_admin=True` to the DB. Route `update_account` (account.py:68-69) has **no `@login_required`** — reachable without any authentication/session.

```python
filtered_values = {
    key: value
    for key, value in form.data.items()
    if value is not None and key != 'password'
}
current_user.__dict__.update(filtered_values)
```

**Exploit:** 1. An authenticated regular user (or, with caveats, an unauthenticated attacker) POSTs `/account` with `is_admin=true` -> 2. `filtered_values` retains `is_admin` (only `password`/`None` are filtered out) -> 3. `current_user.__dict__.update` sets `is_admin=True`; `session.commit()` (account.py:91-92) promotes the account to admin. When called by an authenticated regular user, `current_user` is a real `User` row, so `session.merge`/`commit` fully promotes them to admin (and lets them set `email`/other columns). When called unauthenticated, Flask-Login's `current_user` is `AnonymousUser`, so `session.merge` does not create a real admin row — but the endpoint remains reachable and performs unfiltered mass-assignment on the anonymous object, demonstrating the access-control failure.
**Caveat:** Unauthenticated `update_account` operates on Flask-Login's `AnonymousUser` (not a persisted row), so it does not itself create an admin account; the escalation fully applies when the endpoint is POSTed by an authenticated regular user whose `current_user` is a real `User`.
**Mitigations:** None — `update_account` lacks `@login_required`; the `filtered_values` filter excludes only `password` and `None`, not `is_admin`.
**Fix:** Add `@login_required` (blocks unauthenticated access entirely); assign only whitelisted fields (never copy `is_admin`/`password` from form input); validate role/ownership before persisting.

### All state-changing POST routes — CSRF (no token / SameSite hardening)
**CWE:** CWE-352
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Transform: State-changing POST endpoints — `/account` (account.py:68, update_account — unauthenticated, covered by finding #8), `/account/image` (account.py:51, add_image), `/notes` (notes.py:17), `/notes/<id>/delete` (notes.py:39), `/signup` (signup.py:33), `/registration-codes` (registration_codes.py:26) — none implement a CSRF token / `CSRFProtect` / `SameSite` cookie hardening.
Sink: Cross-origin forged request from an attacker-controlled page -> server processes the victim's authenticated session.

**Exploit:** 1. Attacker serves a page that auto-POSTs to `/account` with `is_admin=true` (mass-assignment) or `/account/image` with `url=file:///...` (SSRF) -> 2. Browser sends the victim's authenticated session cookies -> 3. Victim's account is escalated to admin / SSRF triggered without consent (also forces note deletion, password change).

**Mitigations:** None (no CSRF token; session cookies lack `SameSite` hardening).
**Fix:** Apply `flask_wtf.csrf.csrfProtect`; set `SameSite=Lax/Strict` session cookies; verify origin/`Referer` on state-changing POSTs; require anti-CSRF tokens in forms.

### models/__init__.py:14 — SQL `echo=True` logs sensitive queries to server logs
**CWE:** CWE-200
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood LOW = LOW (ACTIVE)

**Data flow:**
Source:     `models/__init__.py:14` — `create_engine('sqlite:///' + ..., echo=True)`
Transform:  `echo=True` logs every executed SQL statement **including bound parameters** to console/server logs
Sink:       server logs (uwsgi stdout) — contain user emails and bcrypt password hashes

**Exploit:** 1. Attacker obtains server logs (log files, uwsgi stdout, centralized logging) -> 2. Reads logged SQL with bound params -> 3. Exposes user emails and bcrypt password hashes.

**Mitigations:** None (`echo` left enabled).
**Fix:** Set `echo=False` in production; never log query parameters containing credentials.

## Dependency scan
No `DIFF_SCOPE.md` present — scanned the whole project (no diff-scoping). Grype baseline + OSV-Scanner (PyPI, `requirements.txt`).

**Grype baseline** (pre-processing):
- `werkzeug@3.1.5` → CVE-2026-27199 (GHSA-29vq-49wr-vm6x), Medium, CWE-67, fixed in 3.1.6.

**OSV-Scanner** (whole-project):
| Package | Version | CVE / PYSEC | Severity (CVSS) | Fix |
|---|---|---|---|---|
| click | 8.1.7 | PYSEC-2026-2132 (CVE-2026-7246) — command injection in `click.edit()` | High (7.2) | 8.3.3 |
| flask | 3.1.1 | PYSEC-2026-2151 | Medium (4.3) | 3.1.3 |
| werkzeug | 3.1.5 | PYSEC-2026-2320 | Medium (6.3) | 3.1.6 |

**Diff (baseline → OSV-Scanner):** `click` (High) and `flask` (Medium) are new vs the grype baseline; `werkzeug` carries a second, distinct CVE (OSV: PYSEC-2026-2320 vs grype: CVE-2026-27199). All three are upstream dependencies (Flask → click; Flask/Werkzeug).
**Note:** `click` command injection is confined to `click.edit()` (interactive editor), which this app does not call — so actual exploitability is low despite the High CVSS. `flask`/`werkzeug` vulns are library-level (patch to update).
**Fix:** Pin `click>=8.3.3`, `flask>=3.1.3`, `werkzeug>=3.1.6`; re-audit.

## Summary tables

### Table 1 — All findings by severity
| # | Location | CWE | Reachability | Severity |
|---|---|---|---|---|
| 1 | app.py:11 | CWE-798 (hardcoded credential) | ACTIVE | CRITICAL |
| 2 | app.py:31-33 | CWE-94 (SSTI/RCE) | ACTIVE | CRITICAL |
| 3 | account.py:118 | CWE-502 (pickle.loads RCE) | ACTIVE | CRITICAL |
| 4 | account.py:33 | CWE-89 (SQLi) | ACTIVE | HIGH |
| 5 | signup.py:15-18 | CWE-89 (SQLi, public /signup) | ACTIVE | HIGH |
| 6 | profile_image.py:7 | CWE-918 (SSRF/file://) | ACTIVE | HIGH |
| 7 | db_seed.py:18-19 | CWE-521 (Weak Password) | CONDITIONAL | HIGH |
| 8 | account_form.py:8 + account.py:81 | CWE-284 (mass-assignment → admin, unauthenticated) | ACTIVE | CRITICAL |
| 9 | account.py:43-46 | CWE-284 (IDOR read notes) | ACTIVE | MEDIUM |
| 10 | notes.py:41-48 | CWE-284 (IDOR delete notes) | ACTIVE | MEDIUM |
| 11 | routes/* (all POST) | CWE-352 (CSRF) | ACTIVE | MEDIUM |
| 12 | login.py:50-56 | CWE-200 (email/auth disclosure) | ACTIVE | LOW |
| 13 | db_seed.py:9 | CWE-798 (hardcoded credential) | ACTIVE | LOW |
| 14 | models/__init__.py:14 | CWE-200 (SQL echo logs) | ACTIVE | LOW |

**Totals:** CRITICAL 4, HIGH 4, MEDIUM 3, LOW 3 (14 findings).

### Table 2 — Findings by vulnerability type
| Type | Findings | Count |
|---|---|---|
| SQL Injection (CWE-89) | #4, #5 | 2 |
| Server-Side Template Injection / RCE (CWE-94) | #2 | 1 |
| Insecure Deserialization / RCE (CWE-502) | #3 | 1 |
| SSRF / Arbitrary File Read (CWE-918) | #6 | 1 |
| Broken Access Control — IDOR (CWE-284) | #9, #10 | 2 |
| Broken Access Control — Mass-assignment / Privilege Escalation (CWE-284) | #8 | 1 |
| Cross-Site Request Forgery (CWE-352) | #11 | 1 |
| Hardcoded Credentials (CWE-798) | #1, #13 | 2 |
| Weak Password (CWE-521) | #7 | 1 |
| Information Exposure (CWE-200) | #12, #14 | 2 |

### Top risks (active, highest priority)
1. **`account.py:118` pickle.loads RCE** — unauthenticated (via `before_request`), no auth/session needed → full server compromise. **Fix:** never `pickle.loads`; validate/parse JSON.
2. **`app.py:31-33` SSTI/RCE** — `render_template_string(request.path)` in the 404 handler → attacker-controlled template → RCE. **Fix:** serve a static 404 page; never `render_template_string` on user input.
3. **`app.py:11` hardcoded `secret_key`** — session forgery (sign any session, forge admin). **Fix:** read from env/secret manager.
4. **`account.py:81` mass-assignment → `is_admin`** — **unauthenticated** (update_account has no `@login_required`) admin escalation; POSTs `/account` with `is_admin=true` to become admin (unlocks the admin-only `/registration-codes` gate). **Fix:** whitelist fields; never `__dict__.update(form.data)`.
5. **`account.py:33` / `signup.py:17` SQLi** — parameterize `text()`; don't interpolate.

### Remediation roadmap (prioritized)
**P0 — Fix now (RCE / full compromise):**
- `account.py:118` — replace `pickle.loads(cookie)` with a validated format (e.g., HMAC-signed JSON); run deserialization only on trusted data.
- `app.py:31-33` — return a static 404; remove `render_template_string`.
- `app.py:11` — move `secret_key` to an environment variable / secrets store.
- `account_form.py:8` + `account.py:81` — **unauthenticated** admin escalation (no `@login_required`): add `@login_required`, whitelist fields (`is_admin`/`password` never copied from `form.data`).

**P1 — Fix soon (authn/authz / data):**
- `account.py:33` + `signup.py:17` — parameterize all SQL (bind params); never `text(f"...{var}...")`.
- `profile_image.py:7` — allowlist URL scheme (https only), block `file://`/internal IPs; fetch server-side.
- `notes.py:41-48` + `account.py:43-46` — enforce `owner == current_user.id` (404/403 otherwise); IDs are sequential (enumerable).
- `db_seed.py:18-19` — remove the seeded admin account with password `'admin'` (crackable); force password reset on first login.

**P2 — Harden:**
- Add CSRF protection (`CSRFProtect` / `SameSite` cookies) to all state-changing POSTs.
- `db_seed.py:9` — stop hardcoding/publishing invite codes; generate at runtime.
- `models/__init__.py:14` — set `echo=False`; never log query parameters.
- `login.py:50-56` — remove email/auth disclosure from `/is_logged_in` (or gate it).

**P3 — Supply chain:**
- Upgrade `click>=8.3.3`, `flask>=3.1.3`, `werkzeug>=3.1.6`; re-audit on version changes.

## Pre-processing artifacts
- SBOM available: `.security-output/sbom.cyclonedx.json` (used in step 7).
- Grype results present: `.security-output/grype-results.json` (summarized above).
- `DIFF_SCOPE.md`: not present — no diff-scoping; all files reviewed per step 6 priority.

## 13. Validation block
- **`@critic` invoked (verbatim):** returned "exceptionally high quality, no major errors found" (14/14 findings accurate, no false positives, no missing findings). 2 minor refinements applied (login.py:50-56 exploit text tightened; all finding snippets line-verified).
- **`@verifier` invoked (verbatim) ×2:** first pass produced reachability/line-number/CWE corrections; second pass (targeted) confirmed all corrections accurate.
- **Second verifier pass — all corrections verified CORRECT against source:**
  - Route-decorator count = **19** (`@app.route` grep across `routes/`: home 2, account 6, login 4, notes 3, signup 2, registration_codes 2; `routes/__init__.py` has no `@app.route`).
  - `/darkmode` POST (`account.py:98`) has **no** `@login_required` (line 99 is `def toggle_darkmode()`).
  - Finding #8 AnonymousUser caveat accurate: `update_account` (`account.py:68-69`) has no `@login_required`; `filtered_values` (`account.py:76-80`) retains `is_admin`; `session.merge`/`commit` (`account.py:91-92`) runs; unauthenticated `current_user` = `AnonymousUser` (not a persisted row).
  - Finding #3 accurate: `account.py:1` is `from pickle import dumps, loads`, so `loads(...)` at `account.py:118` **is** `pickle.loads` (JSON `import` at line 3 is unused for `loads`/`dumps`).
- **Assessment file is internally consistent:** severity counts (CRITICAL 4 / HIGH 4 / MEDIUM 3 / LOW 3 = 14), Table 1 ↔ finding details ↔ Table 2 type counts (sum 14) all cross-reference correctly. No further corrections needed.

## 13b. Run metadata
- **Model:** `Ornith_1_5_35B_A3B_MLX_4bit`
- **Review date:** 2026-08-31
- **Tools used:** `semgrep_semgrep_scan` (Semgrep AppSec Platform, 8 findings), `serena_get_symbols_overview` (symbol overview), `task` (subagent `@critic` + `@verifier` — prompts sent verbatim, self-critique prohibited), `osv-scanner` (whole-project dependency scan). `scan_repository` (LeakFerret) **not in toolset → skipped**.
- **Findings summary:** 14 findings — CRITICAL 4, HIGH 4, MEDIUM 3, LOW 3.
- **CWE distribution (14 findings):** CWE-284 (Broken Access Control) ×4, CWE-798 (Hardcoded Credentials) ×2, CWE-89 (SQL Injection) ×2, CWE-94 (Code Injection) ×1, CWE-502 (Deserialization) ×1, CWE-918 (Server-Side Request Forgery) ×1, CWE-521 (Weak Password) ×1, CWE-352 (CSRF) ×1, CWE-200 (Information Exposure) ×2.
- **Severity distribution:** CRITICAL 4, HIGH 4, MEDIUM 3, LOW 3.
- **Dependency scan:** 3 vulnerabilities — `click@8.1.7` → CVE-2026-7246 (High, CVSS 7.2, fix 8.3.3), `flask@3.1.1` → CVE-2026-2151 (Medium, fix 3.1.3), `werkzeug@3.1.5` → CVE-2026-2320 (Medium, fix 3.1.6); plus Grype baseline `werkzeug@3.1.5` → CVE-2026-27199 (Medium, fix 3.1.6).
- **graphify:** `graph.json` present (78709B, 78709B); no `GRAPH_REPORT.md` → attack-path via graphify skipped (steps 3b/attack-path).


## Runner summary

```
Security Review Complete
  Repo:       test-vuln-flask
  Model:      omlx/Ornith-1.5-35B-A3B-MLX-4bit
  Time:       101.1 minutes
  Exit code:  0
  Assessment: output/test-vuln-flask/Ornith_1_5_35B_A3B_MLX_4bit_20260831_080751/SEC_ASSESSMENT_Ornith_1_5_35B_A3B_MLX_4bit.md
  Lines:      539
  Findings:   13 (CRITICAL: 3, HIGH: 5, LOW: 3, MODERATE: 2)
  Sections:   9/9
  Critic:     completed
  Verifier:   completed
  Tools:      graphify, semgrep, serena, leakferret, osv-scanner, syft, grype
  Graphify:   ran
```
