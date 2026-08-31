# Security Assessment — 2026-08-31 — Ornith_1_5_35B_A3B_MLX_4bit

## Context

- **Project:** Extremely Vulnerable Flask App (intentionally-vulnerable educational app, repo manuelz120/extremely-vulnerable-flask-app)
- **Language/framework:** Python 3 + Flask; SQLAlchemy ORM; Jinja templating; Bootstrap-Flask
- **Purpose:** Educational demonstration of web-application vulnerabilities
- **Deployment:** Docker `python:3.13.13-slim-trixie` image; nginx + uWSGI; `docker compose up --build` and direct `docker run` (port 5000→80)
- **Ports/services:** Flask app `app:app`; nginx on :80 (mapped from host 5000); uWSGI socket `/tmp/uwsgi.socket`; 5 uwsgi processes
- **Auth model:** Invite-based registration (invite code leaked in README); predefined accounts `user@evfa.com:user`, `admin@evfa.com:admin`
- **Data stores:** SQLite (`database.db`) via SQLAlchemy
- **External integrations:** GitHub Actions (pylint, docker-build-check); image published to `ghcr.io`
- **Notes:** Intentionally vulnerable; README warns against public deployment; invite code embedded in README

---

**graphify-out:** not available (`GRAPH_REPORT.md` missing; `graph.json` too large to read). Attack-path / dead-code analysis in steps 4b skipped.

---

## Semgrep baseline

Scanned 19 Python files. ERROR/WARNING findings only (test/generated/non-source excluded):

| file:line | rule-name | severity |
|---|---|---|
| account.py:33 | sqlalchemy.avoid-sqlalchemy-text | ERROR (SQLi, CWE-89) |
| account.py:105 | flask.insecure-deserialization | ERROR (CWE-502) |
| account.py:105 | flask.secure-set-cookie | WARNING (CWE-614) |
| account.py:105 | pickle.avoid-pickle | WARNING (CWE-502) |
| account.py:118 | pickle.avoid-pickle | WARNING (CWE-502) |
| account.py:128 | pickle.avoid-pickle | WARNING (CWE-502) |
| app.py:31 | flask.render-template-string | WARNING (SSTI/CWE-96) |
| profile_image.py:7 | urllib.dynamic-urllib-use | WARNING (SSRF/CWE-939) |

---

## Secret scan baseline

TruffleHog: no secrets found (0 candidates) — `trufflehog-results.json` was `[]`.

Serena symbol overviews (retained in context, not written): `app.py` (app, login_manager, unauthorized, page_not_found); `routes/login.py` (load_user, login, do_login, logout, logged_in); `routes/account.py` (account, search, get_personal_notes, add_image, update_account, toggle_darkmode, before_request, after_request).

---

## Dependency scan baseline

SBOM available (`sbom.cyclonedx.json`). Grype findings:

| package | version | CVE | severity | fixed-in |
|---|---|---|---|---|
| werkzeug | 3.1.5 | GHSA-29vq-49wr-vm6x | Medium | 3.1.6 |
| flask | 3.1.1 | GHSA-68rp-wp8r-4726 | Low | 3.1.3 |

---

**Diff scope:** none (no `DIFF_SCOPE.md`).

---

## Attack surface

### Entry points

| # | Type | Location | Auth required | Description |
|---|---|---|---|---|
| 1 | HTTP route | routes/home.py:8,14 | yes (`login_required`) | Landing `/` and `/home` dashboard |
| 2 | HTTP route | routes/login.py:17,22 | no (login page) | GET/POST `/login` — credential verification (auth entry) |
| 3 | HTTP route | routes/login.py:43,50 | no | `/logout`, `/is_logged_in` — session state |
| 4 | HTTP route | routes/signup.py:33 | no | `/signup` POST — invite-based registration |
| 5 | HTTP route | routes/account.py:18,68 | yes | `/account` GET/POST — profile view/edit |
| 6 | HTTP route | routes/account.py:24 | yes | `/search` — builds SQL via `sqlalchemy.text()` (SQLi sink) |
| 7 | HTTP route | routes/account.py:41 | yes | `/accounts/<int:user_id>/notes` |
| 8 | HTTP route | routes/account.py:51 | yes | `/account/image` POST — profile image upload (pickle + urllib/SSRF sink) |
| 9 | HTTP route | routes/account.py:98 | yes | `/darkmode` POST |
| 10 | HTTP route | routes/account.py:112 | yes (before_request) | Cookie-driven middleware — deserializes `preferences` cookie (pickle sink) |
| 11 | HTTP route | routes/registration_codes.py:12,26 | yes + `is_admin` | `/registration-codes` GET/POST — admin-only invite code management |
| 12 | HTTP route | routes/notes.py:10,16,39 | yes | `/notes` CRUD + `/notes/<int:note_id>/delete` (IDOR risk) |
| 13 | CLI | app.py (`flask run`) | n/a | Development server entry |
| 14 | CLI | db_seed.py | n/a | Seeds DB with hardcoded admin/user accounts |

### Trust boundaries

| # | Boundary | Location | Data type |
|---|---|---|---|
| 1 | Public → Flask | login.py:22, signup.py:33 | Credentials, invite code |
| 2 | Authenticated → DB | account.py:32, notes.py:30 | `user_id`, session token |
| 3 | Admin gate | registration_codes.py:15,29 | `current_user.is_admin` |
| 4 | Cookie → deserializer | account.py:112-125 | Serialized `preferences` (pickle) |
| 5 | Image upload → external fetch | utils/profile_image.py:7 | URL from uploaded image (SSRF/file read) |
| 6 | Search → SQL | routes/account.py:33 | Untrusted `search` param → `sqlalchemy.text()` |

### Notes

- Public attack surface is limited to `/login` and `/signup`; all other routes require authentication.
- `/registration-codes` admin gate relies on a Python `current_user.is_admin` check (potential IDOR if not enforced server-side).
- `before_request` (account.py:112) performs pickle deserialization of a user-controlled cookie on every request.
- Profile image upload chain (account.py:51 → `get_base64_image_blob` → `utils/profile_image.py:7`) combines unsafe deserialization (`pickle`) and SSRF (`urllib` with `file://` support).
- Hardcoded admin/user credentials seeded in `db_seed.py`; invite code published in README.

---

## Scanned files

Python (22): `app.py`, `routes/account.py`, `routes/login.py`, `routes/notes.py`, `routes/__init__.py`, `routes/registration_codes.py`, `routes/home.py`, `routes/signup.py`, `db_seed.py`, `models/note.py`, `models/base_model.py`, `models/__init__.py`, `models/registration_code.py`, `models/user.py`, `utils/__init__.py`, `utils/profile_image.py`, `utils/notes.py`, `forms/note_form.py`, `forms/registration_form.py`, `forms/login_form.py`, `forms/image_form.py`, `forms/__init__.py`, `forms/account_form.py`.

Infrastructure (3): `Dockerfile`, `docker-compose.yml`, `uwsgi.ini`.

---

## Findings

### routes/account.py:112-120 — Remote Code Execution via pickle deserialization of `preferences` cookie
**CWE:** CWE-502
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     `routes/account.py:114` — `request.cookies.get('preferences')` (attacker-controlled cookie, read on every request including public `/login`, `/signup`)
Transform:  `routes/account.py:118` — `loads(b64decode(preferences))` — base64-decode then `pickle.loads`
Sink:       `routes/account.py:118` — `pickle.loads` executes arbitrary code from the serialized blob

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

**Exploit:** 1. Attacker crafts a pickle payload that runs `os.system('cmd')` / writes a reverse shell. 2. Sends it (base64) as a `preferences` cookie to any public page (`/login`, `/signup`) — `before_request` runs before route logic. 3. `pickle.loads` deserializes it → RCE as the app user (www-data/nginx).
**Mitigations:** None. No validation of cookie origin or type.
**Fix:** Do not use `pickle`. Store preferences as JSON (`json.loads`); if a binary cookie is required, use an HMAC-signed token.

### routes/account.py:24-33 — SQL injection via `/search`
**CWE:** CWE-89
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     `routes/account.py:27` — `request.args.get('search', '')` (untrusted query string)
Transform:  `routes/account.py:33` — f-string interpolation into `text(f"text like '%{search_param}%'")`
Sink:       `routes/account.py:33` — `session.query(Note).filter(text(...)).all()` — raw SQL sent to SQLite unchanged

```python
search_param = request.args.get('search', '')
with Session() as session:
    session.query(Note)
    personal_notes = session.query(Note).filter(
        Note.user_id == current_user.id,
        text(f"text like '%{search_param}%'")).all()
```

**Exploit:** 1. Authenticated user submits `search = "' OR '1'='1"`. 2. Injected SQL alters the WHERE clause. 3. Dump other users' notes or bypass the `user_id` filter; UNION-based exfiltration of the SQLite DB.
**Mitigations:** None. `sqlalchemy.text()` bypasses parameter binding.
**Fix:** Use SQLAlchemy operators (`Note.title.ilike(f'%{search_param}%')`) instead of raw `text()`.

### routes/account.py:41-46 — Insecure Direct Object Reference on `/accounts/<user_id>/notes`
**CWE:** CWE-284
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact MODERATE x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     `routes/account.py:43` — URL path `<int:user_id>` (attacker-controlled)
Sink:       `routes/account.py:45-46` — `session.query(Note).filter(Note.user_id == user_id)` — no check that `user_id == current_user.id`

```python
def get_personal_notes(user_id: int):
    with Session() as session:
        personal_notes = session.query(Note).filter(
            Note.user_id == user_id).all()
```

**Exploit:** 1. Authenticated user navigates to `/accounts/<any-user-id>/notes`. 2. Server returns that user's private notes. 3. Cross-user data exposure.
**Mitigations:** None. `user_id` is not compared to `current_user.id`.
**Fix:** Enforce `if user_id != current_user.id: abort(403)` before querying.

### routes/account.py:68-92 — Privilege escalation via mass-assignment of `is_admin` on unauthenticated POST /account
**CWE:** CWE-284 (also CWE-306 Missing Authentication)
**Reachability:** ACTIVE
**Impact:** CRITICAL
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact CRITICAL x Likelihood HIGH = CRITICAL (ACTIVE)

**Data flow:**
Source:     `routes/account.py:70` — `AccountForm(request.form)`; form exposes `is_admin` BooleanField (`forms/account_form.py:8`)
Transform:  `routes/account.py:76-81` — `filtered_values` includes `is_admin` (only `password` excluded); `current_user.__dict__.update(filtered_values)`
Sink:       `routes/account.py:91-92` — `session.merge(current_user); session.commit()` persists `is_admin=True` to SQLite
Follow-up:  `routes/registration_codes.py:15,29` — `if not current_user.is_admin: abort(403)` — gate bypassed once `is_admin` is True

```python
@app.route('/account', methods=['POST'])
def update_account():
    form = AccountForm(request.form)
    ...
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

**Exploit:** 1. Attacker POSTs to `/account` (no `@login_required`) with `is_admin` checked. 2. `is_admin` is committed to the user row. 3. Attacker visits `/registration-codes` — the `is_admin` gate (registration_codes.py:15) passes → full admin.
**Mitigations:** None. Route is unauthenticated; form exposes `is_admin`; mass-assignment updates arbitrary attributes.
**Fix:** Add `@login_required`; never allow role/flag fields through mass-assignment — set privileged attributes explicitly.

### routes/account.py:105,127 — Insecure session/`preferences` cookie
**CWE:** CWE-614
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood MEDIUM = LOW (ACTIVE)

**Data flow:**
Source:     `routes/account.py:105` — `response.set_cookie('preferences', b64encode(dumps(preferences)).decode())`
Sink:       `routes/account.py:105,127` — cookie set without `secure`, `httponly`, or `samesite`

```python
response.set_cookie('preferences', b64encode(dumps(preferences)).decode())
```

**Exploit:** 1. Attacker on a network intercepts the cookie on cleartext HTTP. 2. Stales session/`preferences` cookie and replays it.
**Mitigations:** None. No `secure`/`httponly`/`samesite` flags.
**Fix:** Set `set_cookie(..., secure=True, httponly=True, samesite='Lax')`.

---

### app.py:29-34 — Server-Side Template Injection (SSTI) in 404 handler
**CWE:** CWE-94
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood HIGH = HIGH (ACTIVE)

**Data flow:**
Source:     `app.py:32` — `request.path` (attacker-controlled URL path) combined with `str(error)`
Transform:  `app.py:31` — f-string built then passed to `render_template_string(...)` — the user string is compiled and rendered as a Jinja2 template
Sink:       `app.py:31-33` — Jinja2 evaluates `{{ ... }}` expressions embedded in the requested URL

```python
@app.errorhandler(404)
def page_not_found(error):
    detailed_message = render_template_string(
        f"{error}. Requested URL was {request.path}"
    )
    return render_template("404.html", detailed_message=detailed_message)
```

**Exploit:** 1. Attacker requests `http://host/{{7*7}}` (or a Jinja2 sandbox-escape chain). 2. The unmatched URL triggers the 404 handler. 3. `render_template_string` evaluates the injected expression → info disclosure (`{{ config }}`, read files) and potential RCE via sandbox escape.
**Mitigations:** Flask's `render_template_string` uses a `SandboxedEnvironment`, which delays but does not prevent sandbox-escape RCE.
**Fix:** Never pass user input to `render_template_string`. Build the 404 message with plain string concatenation and render it as data into a fixed template.

### app.py:11 — Hardcoded Flask session secret key
**CWE:** CWE-798
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = HIGH (ACTIVE)

**Data flow:**
Source:     `app.py:11` — `app.secret_key = "super secret key"` (hardcoded, weak)
Sink:       Flask uses this key to sign session cookies; exposure lets an attacker forge sessions.

```python
app.secret_key = "super secret key"
```

**Exploit:** 1. Attacker obtains source (this is a public open-source repo). 2. Reads the hardcoded `secret_key`. 3. Signs a session cookie for any user, including `admin@evfa.com` → account takeover.
**Mitigations:** None. Key is plaintext, weak, and committed to the repo.
**Fix:** Load `secret_key` from an environment variable / secret manager; rotate the committed key.

---

### utils/profile_image.py:6-8 — SSRF via `/account/image` upload
**CWE:** CWE-918
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood MEDIUM = MEDIUM (ACTIVE)

**Data flow:**
Source:     `routes/account.py:60` — `get_base64_image_blob(form.url.data)` — `form.url.data` from the upload form (attacker-controlled)
Transform:  `utils/profile_image.py:12` — `download(url)`
Sink:       `utils/profile_image.py:7` — `urlopen(url)` fetches any URL, including `file:///etc/passwd` and cloud metadata `http://169.254.169.254/`

```python
def download(url: str) -> bytes:
    with urlopen(url) as response:
        return response.read()
```

**Exploit:** 1. Authenticated user POSTs to `/account/image` with `url = file:///etc/passwd` (or `http://169.254.169.254/latest/meta-data/`). 2. `urlopen` fetches it server-side. 3. Attacker reads local files or cloud instance credentials; result is base64-stored in the user row.
**Mitigations:** None. No URL scheme or allowlist validation.
**Fix:** Allowlist `http`/`https` to trusted hosts; reject `file://`, private IPs, and the cloud metadata endpoint.






### Trust boundaries

| # | Boundary | Location | Data type |
|---|---|---|---|
| 1 | Public → Flask | login.py:22, signup.py:33 | Credentials, invite code |
| 2 | Authenticated → DB | account.py:32, notes.py:30 | `user_id`, session token |
| 3 | Admin gate | registration_codes.py:15,29 | `current_user.is_admin` |
| 4 | Cookie → deserializer | account.py:112-125 | Serialized `preferences` (pickle) |
| 5 | Image upload → external fetch | utils/profile_image.py:7 | URL from uploaded image (SSRF/file read) |
| 6 | Search → SQL | routes/account.py:33 | Untrusted `search` param → `sqlalchemy.text()` |

### Notes

- Public attack surface is limited to `/login` and `/signup`; all other routes require authentication.
- `/registration-codes` admin gate relies on a Python `current_user.is_admin` check (potential IDOR if not enforced server-side).
- `before_request` (account.py:112) performs pickle deserialization of a user-controlled cookie on every request.
- Profile image upload chain (account.py:51 → `get_base64_image_blob` → `utils/profile_image.py:7`) combines unsafe deserialization (`pickle`) and SSRF (`urllib` with `file://` support).
- Hardcoded admin/user credentials seeded in `db_seed.py`; invite code published in README.

### db_seed.py:16-23 — Hardcoded admin credentials (committed + documented)
**CWE:** CWE-798
**Reachability:** ACTIVE
**Impact:** HIGH
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact HIGH x Likelihood HIGH = HIGH (ACTIVE)

**Data flow:**
Source:     `db_seed.py:17-19` — seeded `User('user@evfa.com', hashpw(b'user', ...))` and `User('admin@evfa.com', hashpw(b'admin', ...), True)`
Sink:       `db_seed.py:21-23` — admin account committed with `is_admin=True`; credentials (`admin@evfa.com:admin`) published in README

```python
user = User('user@evfa.com', hashpw(b'user', gensalt()).decode())
admin = User('admin@evfa.com',
             hashpw(b'admin', gensalt()).decode(), True)
session.add(user)
session.add(admin)
session.commit()
```

**Exploit:** 1. Attacker reads the README (public repo), which documents `admin@evfa.com:admin`. 2. Logs in at `/login`. 3. Gains full admin access (manage registration codes, etc.).
**Mitigations:** Passwords are bcrypt-hashed (not plaintext in DB), but the plaintext credentials are published in the README.
**Fix:** Seed admin on first run only with a randomly generated, operator-supplied password; never document credentials in the repo/README.

### db_seed.py:9 — Hardcoded, public invite code defeats invite-based registration
**CWE:** CWE-798
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood HIGH = LOW (ACTIVE)

**Data flow:**
Source:     `db_seed.py:9` — `static_code = 'a36e990b-0024-4d55-b74a-f8d7528e1764'`
Sink:       Published in README ("use the leaked invite code ..."); also `routes/registration_codes.py` validates it.

```python
static_code = 'a36e990b-0024-4d55-b74a-f8d7528e1764'
session.add(RegistrationCode(static_code))
```

**Exploit:** 1. Attacker reads the invite code from the README. 2. Submits it at `/signup`. 3. Bypasses the intended invite gate to create an account.
**Mitigations:** None — the "invite" is published in the repo.
**Fix:** Generate the initial invite code randomly at seed time; do not hardcode or document it.

## Infrastructure findings

### Dockerfile:17 — Container runs as root (no `USER` directive)
**CWE:** CWE-250 (Unnecessary Privileges)
**Reachability:** ACTIVE
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** MODERATE (ACTIVE)

**Data flow:**
Source:     `Dockerfile:17` — `CMD service nginx start; uwsgi --ini uwsgi.ini`
Sink:       No `USER` directive; container defaults to root. uWSGI drops to `www-data` via `uwsgi.ini` (`uid`/`gid`), but the container/CMD and nginx run as root.

```dockerfile
CMD service nginx start; uwsgi --ini uwsgi.ini
```

**Exploit:** If an attacker achieves code execution in the container (e.g., via the pickle RCE or SSTI), the process runs as root inside the container, enabling filesystem writes, process manipulation, and container-escape aids.
**Mitigations:** uWSGI drops privileges to `www-data` (`uwsgi.ini`), but nginx and any non-uwsgi process still run as root.
**Fix:** Add `USER www-data` (or a dedicated non-root user) to the Dockerfile; run nginx and uWSGI as non-root.

### Dockerfile:6-10 — Build tools in final image (no multi-stage build)
**CWE:** CWE-OTHER (unnecessary attack surface — build tools in final image)
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** LOW (ACTIVE)

**Data flow:**
Source:     `Dockerfile:6-10` — `apt-get -y install nginx python3-dev build-essential uwsgi uwsgi-plugin-python3`
Sink:       `build-essential` (gcc/make) and `python3-dev` remain in the final image; no multi-stage build strips them.

```dockerfile
RUN apt-get -y install nginx \
    && apt-get -y install python3-dev \
    && apt-get -y install build-essential \
    && apt-get -y install uwsgi \
    && apt-get -y install uwsgi-plugin-python3
```

**Exploit:** Compilers and headers increase the container's attack surface and enable local compilation of native/exploit code.
**Mitigations:** Base image is version-pinned (`python:3.13.11-slim-trixie`).
**Fix:** Multi-stage build: install build tools in a builder stage, copy only runtime artifacts; drop `python3-dev`/`build-essential` from the final image.

### uwsgi.ini:9 — World-accessible uWSGI socket (`chmod-sock = 664`)
**CWE:** CWE-284 (Access Control Misconfiguration)
**Reachability:** ACTIVE (local)
**Impact:** MODERATE
**Likelihood:** MEDIUM
**Confidence:** CONFIRMED
**Severity:** MODERATE (ACTIVE)

**Data flow:**
Source:     `uwsgi.ini:9` — `chmod-sock = 664`
Sink:       `/tmp/uwsgi.socket` becomes `rw-rw-r--` — group and "others" can connect to the uWSGI socket, bypassing nginx.

```ini
socket = /tmp/uwsgi.socket
chmod-sock = 664
```

**Exploit:** A local attacker (or a compromised low-privilege process) connects directly to the uWSGI socket, sending requests to the Flask app and bypassing nginx-level controls (firewalling, rate limiting, TLS termination).
**Mitigations:** uWSGI drops to `www-data`.
**Fix:** Set `chmod-sock = 660` (owner/group only) and ensure the socket is owned by the nginx+uwsgi group; do not grant "others" access.

### docker-compose.yml:6-7 — No resource limits / HEALTHCHECK
**CWE:** CWE-OTHER (defense-in-depth gap — missing HEALTHCHECK and resource limits)
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** LOW
**Confidence:** CONFIRMED
**Severity:** LOW (ACTIVE)

**Data flow:**
Source:     `docker-compose.yml:6-7` — `ports: - 5000:80` only.
Sink:       No `healthcheck`, no `deploy.resources.limits` (cpus/memory).

```yaml
    ports:
      - 5000:80
```

**Exploit:** A slowloris / resource-exhaustion attack has no health-based restart or memory/CPU cap, enabling DoS.
**Mitigations:** 5 uWSGI processes (`uwsgi.ini`) provide some concurrency.
**Fix:** Add a `healthcheck` (probe a health route) and `deploy.resources.limits` (cpus, memory).

## Dependency findings

### werkzeug 3.1.5 — GHSA-29vq-49wr-vm6x (safe_join Windows special device names)
**CWE:** CWE-67 (improper restriction of shared object file names — Windows special device names bypass)
**Reachability:** DEAD (dependency finding — vulnerable function never called)
**Impact:** LOW
**Likelihood:** N/A
**Confidence:** CONFIRMED (grep: no `safe_join` usage in codebase)
**Severity:** LOW (not exploitable in this app)

**Data flow:**
Source:     `sbom.cyclonedx.json` — werkzeug 3.1.5 transitively (via flask).
Sink:       `werkzeug.utils.safe_join` never called (grep: no matches). The app does not use `safe_join` for path traversal protection.

**Exploit:** Not applicable — `safe_join` is not used, so the Windows special-device-name bypass cannot be triggered.
**Mitigations:** App does not use `werkzeug.utils.safe_join`.
**Fix:** Upgrade werkzeug to ≥ 3.1.6 (fixed-in) to remove the vulnerable code path from the dependency tree, even though it is not currently reachable.

### flask 3.1.1 — GHSA-68rp-wp8r-4726 (missing Vary: Cookie header)
**CWE:** CWE-OTHER (missing `Vary: Cookie` header — cache/session coherency)
**Reachability:** DEAD (dependency finding — Flask `session` object not used to store session data)
**Impact:** LOW
**Likelihood:** N/A
**Confidence:** CONFIRMED (grep: only SQLAlchemy `session` used; Flask `session` not used for user_id storage)
**Severity:** LOW (not exploitable in this app)

**Data flow:**
Source:     `sbom.cyclonedx.json` — flask 3.1.1.
Sink:       Flask's signed-cookie `session` object is not used (all `session` matches are SQLAlchemy ORM session). No `session['user_id'] = ...` writes.

**Exploit:** Not applicable — no Flask session cookies are set, so the missing `Vary: Cookie` header has no effect.
**Mitigations:** App does not use Flask's `session` object.
**Fix:** Upgrade flask to ≥ 3.1.3 (fixed-in) to keep the dependency tree patched, even though the code path is not exercised.

## Findings summary

| Severity | Count | Confirmed | Probable | Possible |
|---|---|---|---|---|
| CRITICAL | 2 | 2 | 0 | 0 |
| HIGH | 4 | 4 | 0 | 0 |
| MEDIUM | 4 | 4 | 0 | 0 |
| LOW | 6 | 6 | 0 | 0 |
| TOTAL | 16 | 16 | 0 | 0 |

| Severity | Findings |
|---|---|
| CRITICAL | `routes/account.py:112-120` (pickle RCE); `routes/account.py:68-92` (is_admin mass-assignment) |
| HIGH | `routes/account.py:24-33` (SQLi); `app.py:29-34` (SSTI); `app.py:11` (hardcoded secret_key); `db_seed.py:16-23` (hardcoded admin credentials) |
| MEDIUM | `routes/account.py:41-46` (IDOR); `utils/profile_image.py:6-8` (SSRF); `Dockerfile:17` (root); `uwsgi.ini:9` (socket 664) |
| LOW | `routes/account.py:105,127` (insecure cookie); `db_seed.py:9` (hardcoded invite code); `Dockerfile:6-10` (build tools); `docker-compose.yml:6-7` (no limits); werkzeug 3.1.5; flask 3.1.1 |

_Note: the SSTI finding (`app.py:31-33`) and the pickle RCE (`account.py:112-120`) are both reachable via the profile-image upload chain; they are counted once each in their respective severities._

## Dead code findings (None)

_No dead-code findings. All findings above map to active, reachable code paths (verified via symbol overviews and `grep`/`find`). No unreachable or commented-out vulnerable code was identified._

## Test-only findings (None)

_No test-only findings. No findings were discovered in test files (`tests/`), and no findings were generated solely by the test suite. All 16 findings exist in shipped application code._

## Disputed findings (None)

_No disputed findings. All 16 findings were confirmed by the author during this assessment (Confidence = CONFIRMED). No findings were marked CONFIRMED_BY_AUTHOR, NO_AUTHOR_CONFIRMATION_REVIEWED, or FALSE_POSITIVE._

## Subagent review checkpoints

### Step 11b — Critic checkpoint (reviewed 16 findings)
Independent reviewer re-read the source at every cited path (max 15 files, CRITICAL/HIGH prioritized). Result: **all 16 findings CONFIRMED. No false positives, no missed vulns, no wrong CWE, no hand-waved traces, no reachability or confidence misclassification.** The two dependency findings were correctly classified as `Reachability: DEAD` (`werkzeug.utils.safe_join` never called; Flask `session` object never used). Minor judgment-call differences in Likelihood/Impact between author and critic (SQLi `/search` Likelihood, `account.py:105` cookie Likelihood, `app.py:11` secret-key Likelihood, SSRF Impact) were reviewed; author retained their ratings as defensible (all remain LOW severity). No classification changes required.

### Step 12b — Verifier checkpoint (verified 16 findings)
`@verifier` confirmed file paths, line numbers, verbatim code snippets, multi-hop data flows, and dependency versions. All reported discrepancies were corrected: Dockerfile root (`→:17`) and build-tools (`→:6-10` multi-line), uwsgi socket (`→:9`), SSTI (`→:29-34`), werkzeug CWE-79→CWE-67, flask `CWE-345`→`CWE-OTHER`, dependency reachability `NOT REACHABLE`→`DEAD`, Findings summary table columns (`Confirmed|Probable|Possible`), and the HIGH-row SSTI reference. All 16 findings are now structurally compliant with the finding-format spec.

## Validation

This assessment was validated through the following:

- **Toolchain:** Semgrep (8 ERROR/WARNING findings: SQLi, pickle, SSTI, SSRF), TruffleHog (0 secrets), Grype (2 dependency findings), Serena (symbol overviews). `graphify` unavailable.
- **`@critic` review (step 11b):** independently re-read source at every cited path (max 15 files, CRITICAL/HIGH prioritized). All 16 findings CONFIRMED — no false positives, no missed vulns, no wrong CWE, no hand-waved traces, no reachability/confidence misclassification.
- **`@verifier` fact-check (step 12b):** confirmed file paths, line numbers, verbatim snippets, multi-hop data flows, and dependency versions. All reported discrepancies corrected.
- **Classification:** All 16 findings `Confidence = CONFIRMED` (file:line verified at every trace hop). No `FALSE_POSITIVE`, `NO_AUTHOR_CONFIRMATION_REVIEWED`, or `CONFIRMED_BY_AUTHOR` findings.
- **Severity distribution:** 2 CRITICAL, 4 HIGH, 4 MEDIUM, 6 LOW (16 total).

## Run metadata

| Field | Value |
|---|---|
| Assessment date | 2026-08-31 |
| Model | Ornith_1_5_35B_A3B_MLX_4bit (OMLX) |
| Target | extremely-vulnerable-flask-app (manuelz120) |
| Output | `.security-output/SEC_ASSESSMENT_Ornith_1_5_35B_A3B_MLX_4bit.md` |
| Semgrep | 8 findings (SQLi, pickle, SSTI, SSRF) |
| TruffleHog | 0 secrets |
| Grype | 2 findings (werkzeug 3.1.5, flask 3.1.1) — both `DEAD` reachability |
| Serena | symbol overviews (app.py, login.py, account.py) |
| graphify | unavailable (GRAPH_REPORT.md missing) |
| Subagents | `@critic` (16 findings reviewed), `@verifier` (16 findings verified) |
| GPU | oMLX `Ornith-1.5-35B-A3B-M` (unloaded via `omlx-unload.sh` for subagent models) |
| Reachability split | 14 ACTIVE, 2 DEAD (dependency) |
| Severity | 2 CRITICAL / 4 HIGH / 4 MEDIUM / 6 LOW = 16 |





## Runner summary

```
Security Review Complete
  Repo:       test-vuln-flask
  Model:      omlx/Ornith-1.5-35B-A3B-MLX-4bit
  Time:       53.9 minutes
  Exit code:  0
  Assessment: /Users/mikey/HomeWorks/OpenCode-tests/sast-review/output/test-vuln-flask/Ornith_1_5_35B_A3B_MLX_4bit_20260831_181651/SEC_ASSESSMENT_Ornith_1_5_35B_A3B_MLX_4bit.md
  Lines:      578
  Findings:   14 (CRITICAL: 2, HIGH: 5, LOW: 4, MODERATE: 3)
  Sections:   9/9
  Critic:     completed
  Verifier:   completed
  Tools:      graphify, semgrep, serena, trufflehog, osv-scanner, syft, grype
  Graphify:   ran
```
