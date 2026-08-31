# Security Assessment — 2026-08-31 — Ornith_1_5_35B_A3B_MLX_4bit

## Context
**Project:** CVEs Analytics — container-image vulnerability analytics platform
**Language/framework:** Python (uv-managed), FastAPI/uvicorn
**Purpose:** Scans Docker container images for CVEs, enriches findings with threat intelligence, computes Bayesian risk scores, and models attack paths through the cyber kill chain. Exposes a CLI (`cves-analytics`) and a REST API.
**Deployment:** No deployment config found (no Dockerfile/compose/uwsgi/gunicorn/nginx/k8s/serverless in repo root). API runs via `uvicorn src.api.main:create_app --host 0.0.0.0 --port 8000`.
**Ports/services:** HTTP :8000 (FastAPI/uvicorn, bound to 0.0.0.0); SQLite DB `analytics.db`.
**Auth model:** none visible — no auth middleware, all `/api/*` endpoints appear unauthenticated.
**Data stores:** SQLite (`analytics.db`), reference data cache directory (`data/`), upload directory (`uploads/`).
**External integrations:** container image scanning (Docker images), external CVE/OSV data sources (referenced in pipeline).
**Notes:** `CVE_DEBUG` env var (default `false`); API binds to `0.0.0.0` (all interfaces); SSE job status stream endpoint (`/api/stream/{job_id}`); file upload handling implied (`--upload-dir`/`uploads/`).

## Semgrep baseline
Semgrep scanned 30 source files. Findings (ERROR/WARNING only, CWE-89 SQL Injection):

| file:line | rule-name | severity |
|---|---|---|
| src/data/stores/duckdb_store.py:78 | python.sqlalchemy.security.sqlalchemy-execute-raw-query | ERROR |
| src/data/stores/duckdb_store.py:78 | python.lang.security.audit.formatted-sql-query | WARNING |
| src/data/stores/duckdb_store.py:82 | python.sqlalchemy.security.sqlalchemy-execute-raw-query | ERROR |
| src/data/stores/duckdb_store.py:82 | python.lang.security.audit.formatted-sql-query | WARNING |
| src/data/stores/duckdb_store.py:85 | python.sqlalchemy.security.sqlalchemy-execute-raw-query | ERROR |
| src/data/stores/duckdb_store.py:85 | python.lang.security.audit.formatted-sql-query | WARNING |


## Disputed findings
None. The single critic item (No-auth Likelihood MEDIUM→HIGH) was accepted; no disputes raised.

## Validation
Reviewed by @critic and @verifier on 2026-08-31.
Critic issues: 1 raised, 1 accepted, 0 disputed.
Verifier issues: 5 found, 3 corrected (Sink line profiles.py:48→44; Confidence summary trimmed to valid values CONFIRMED/PROBABLE/POSSIBLE; ## Validation section added), 0 findings removed. Format discrepancies (extra workflow sections ## Semgrep baseline / ## Dependency scan baseline / ## Attack paths / ## Dead code candidates; Findings summary table naming) left as workflow-required per steps 3b/4b.

## Dependency scan baseline
Grype: 0 matches (no dependency vulnerabilities). SBOM available (`.security-output/sbom.cyclonedx.json`, 1.7 MB) — used in step 7. No DIFF_SCOPE.md present.

## Attack surface
### Entry points
| # | Type | Location | Auth required | Description |
|---|------|----------|---------------|-------------|
| 1 | REST route | src/api/routers/profiles.py:43 (POST) | none | Create profile (unauthenticated) |
| 2 | REST route | src/api/routers/profiles.py:68 (GET) | none | Get profile by id |
| 3 | REST route | src/api/routers/profiles.py:91 (PATCH) | none | Update profile — profile_id parameter |
| 4 | REST route | src/api/routers/profiles.py:126 (DELETE) | none | Delete profile by profile_id |
| 5 | REST route | src/api/routers/scans.py:69 (POST) | none | Trigger scan — profile_id parameter |
| 6 | REST route | src/api/routers/scans.py:149 (POST) | none | Generate scenario — profile_id; feeds yaml.load sink |
| 7 | REST route | src/api/routers/scans.py:122 (GET) | none | Get scan details by run_id |
| 8 | REST route | src/api/routers/stream.py:18 (GET) | none | SSE job status stream by job_id |
| 9 | REST route | src/api/main.py:59 (GET) | none | Health check |
| 10 | CLI (argparse) | src/cli/pipeline.py:20 | n/a | `cves-analytics` entry point; --profile, --images, --data-dir |

### Trust boundaries
| # | Boundary | Location | Data type |
|---|----------|----------|-----------|
| 1 | Public API -> service layer | src/api/routers/*.py -> src/services/*.py | profile_id, run_id, job_id, image names |
| 2 | Service -> DuckDB store | src/services/*.py -> src/data/stores/duckdb_store.py:78 | SQL query with interpolated table name |
| 3 | API generate-scenario -> simulation | src/api/routers/scans.py:150 -> src/simulation/scenario_generator.py:68 | user-supplied scenario config -> yaml.load |
| 4 | CLI -> pipeline -> store | src/cli/pipeline.py -> DuckDBStore | profile/image args |

### Notes
- No authentication/authorization middleware — all `/api/*` routes public.
- Route path parameters (profile_id, run_id, job_id) flow into DuckDB `_execute()` (SQL sink) and scenario generation (yaml.load sink).
- `_validate_table_name()` at duckdb_store.py:18 uses an allowlist regex `^[a-zA-Z_][a-zA-Z0-9_]*$` invoked before every interpolated table name (write_table L73, read_table L99, table_exists L123); the only caller (pipeline.py:129) passes the HARDCODED name `"findings"` → SQL injection fully neutralized. No finding (ref: full mitigation = no finding).
- `yaml.load(f)` at scenario_generator.py:68 and application_templates.py:79 both use `YAML(typ="safe")` (ruamel.yaml safe loader) → safe deserialization, no CWE-502. `ScenarioGenerator()` is constructed with the default `config_path="config/services.yaml"` (scans.py:159 / cli/pipeline.py:76), so no user-controlled path reaches the `open()` at _load_config L60. No path traversal.

## Attack paths
- src/api/main.py:59 (create_app) -> lifespan() -> _get_duckdb_store() -> DuckDBStore -> ._execute() (4 hops) -> src/data/stores/duckdb_store.py:78/82/85 [DuckDB SQL sink]
- src/cli/pipeline.py (_run_cli) -> main() -> DuckDBStore -> ._execute() (3 hops) -> src/data/stores/duckdb_store.py:78 [DuckDB SQL sink]
- src/api/routers/scans.py:150 (generate_scenario handler) -> ScenarioGenerator.generate_scenario -> yaml.load(f) at src/simulation/scenario_generator.py:68 [unsafe deserialization sink] — reachable by data flow though graphify returned no directed path.

## Dead code candidates
- src/simulation/application_templates.py `_load_application_templates()` (yaml.load at L79) — no directed call path from any entry point in graph; reachable only via application_builder.py import. Flagged for reachability check in step 6.

## Scanned files
49 source files (excluded: tests/, .venv/, .git/, caches, egg-info, graphify-out, .security-output):

src/__init__.py, src/api/__init__.py, src/api/dependencies.py, src/api/main.py,
src/api/routers/__init__.py, src/api/routers/profiles.py, src/api/routers/scans.py,
src/api/routers/stream.py, src/cli/__init__.py, src/cli/pipeline.py,
src/core/__init__.py, src/core/attack/__init__.py, src/core/attack/kill_chain.py,
src/core/models/__init__.py, src/core/risk/__init__.py, src/core/risk/bayesian_assessor.py,
src/data/__init__.py, src/data/loaders/__init__.py, src/data/loaders/cvss_bt.py,
src/data/loaders/cwe.py, src/data/loaders/epss.py, src/data/loaders/kev.py,
src/data/stores/__init__.py, src/data/stores/duckdb_store.py,
src/data/transformers/__init__.py, src/data/transformers/enricher.py,
src/db/sqlite_models.py, src/services/__init__.py, src/services/analysis.py,
src/services/enrichment.py, src/services/pipeline.py, src/services/scanner.py,
src/simulation/__init__.py, src/simulation/application_builder.py,
src/simulation/application_templates.py, src/simulation/control_probabilities.py,
src/simulation/control_type_selector.py, src/simulation/control_types.py,
src/simulation/scenario_config.py, src/simulation/scenario_generator.py,
src/simulation/security_controls.py, src/simulation/system_simulator.py,
src/utils/__init__.py, src/utils/config.py, src/utils/logging_config.py, hello.py


## Findings
### src/api/main.py:55, src/api/routers/profiles.py:43, src/api/routers/scans.py:74 — No authentication on network-exposed REST API (0.0.0.0:8000)
**CWE:** CWE-306 Missing Authentication
**Reachability:** ACTIVE
**Impact:** LOW
**Likelihood:** HIGH
**Confidence:** CONFIRMED
**Severity:** Impact LOW x Likelihood HIGH = LOW ([reachability], none)

**Data flow:**
Source:     README.md:15,55 — API launched with `uvicorn ... --host 0.0.0.0 --port 8000` (all network interfaces, external exposure).
Transform:  src/api/main.py:55-57 — `create_app()` registers all routers with no auth middleware/dependency; only `Depends` is `session_dep` (SQLite session, src/api/dependencies.py:44) — no credential check anywhere.
Sink:       src/api/routers/profiles.py:44 (create_profile) / src/api/routers/scans.py:74 (trigger_scan) — state-mutating endpoints accept requests with no credential check.

```python
# src/api/main.py:55-57
app.include_router(profiles_router.router, prefix="/api/profiles")
app.include_router(scans_router.router, prefix="/api/profiles")
app.include_router(stream_router.router, prefix="/api/stream")
```

**Exploit:** 1. Attacker reaches the API on 0.0.0.0:8000. -> 2. POSTs to /api/profiles (create) or /api/profiles/{id}/scans (trigger scan) with no authentication. -> 3. Unauthenticated state mutation: profile tampering, scan-triggering (resource use), scenario generation.

**Mitigations:** None. No auth middleware; all `/api/*` endpoints public.
**Fix:** Add an authentication dependency (e.g., FastAPI `Depends()`) to state-mutating routes; enforce credential validation before handling requests.


## Dead code findings
None. The dead-code candidate `src/simulation/application_templates.py::_load_application_templates()` (yaml.load at L79) uses `YAML(typ="safe")` → no vulnerability. No finding.

## Test-only findings
None. All flagged code (`scanner.py` image validation, `sqlite_models.py` ORM, `profiles.py` pydantic) is exercised only under unit tests; no finding.

## Dependency findings
- Grype: 0 matches.
- OSV-Scanner: no issues found.
- SBOM: present (`.security-output/sbom.cyclonedx.json`); no flagged CVEs.
No dependency vulnerabilities found.


## Findings summary
### Findings table
| file:line | CWE | Reachability | Impact | Likelihood | Confidence | Severity |
|---|---|---|---|---|---|---|
| src/api/main.py:55, src/api/routers/profiles.py:43, src/api/routers/scans.py:74 | CWE-306 Missing Authentication | ACTIVE | LOW | HIGH | CONFIRMED | LOW |

### Severity summary
| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 1 |

### Confidence summary
| Confidence | Count |
|---|---|
| CONFIRMED | 1 |
| PROBABLE | 0 |
| POSSIBLE | 0 |

### Reachability summary
| Reachability | Count |
|---|---|
| ACTIVE | 1 |
| CONDITIONAL | 0 |
| DEAD | 0 |

### Likelihood summary
| Likelihood | Count |
|---|---|
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |

### Impact summary
| Impact | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MODERATE | 0 |
| LOW | 1 |



