# Security Review — Classification & Format Reference

This file is the reference specification for `/security-review`. It is read by
`@critic` and `@verifier` subagents, and by the primary agent during step 6
(scan and classify). Do NOT execute this file — it contains no steps.

## Prohibited actions

- Do NOT invent CWE numbers outside the list below.
- Do NOT invent CVE IDs.
- Do NOT add fields to the finding format.
- Do NOT omit fields from the finding format.
- Do NOT create new sections beyond those in the report structure.
- Do NOT write findings for clean files. Move on silently.
- Do NOT manufacture findings to fill empty sections. Write "None".
- Do NOT re-classify DEAD code as ACTIVE without a verified call chain.
- Do NOT assign Confidence CONFIRMED without file:line at every trace hop.
- Do NOT write narrative prose in findings. Use the format exactly.

## Classification system

Every finding MUST be classified on four independent axes. Pick exactly one
value per axis. Do not collapse axes. Do not invent values.

### Reachability

Determine reachability FIRST, before assessing Impact or Likelihood.

- **ACTIVE** — Called from an entry point listed in `## Attack surface`.
  Requires a concrete call chain: entry point -> intermediate calls -> this
  code, with file:line at each hop. If you cannot write the chain, it is
  NOT ACTIVE. Do not guess. Do not infer.
- **CONDITIONAL** — Reachable only when a named condition is true. State
  the exact condition (e.g., "DEBUG=true in .env", "feature flag X enabled").
  Condition off by default: set Likelihood to LOW. On by default: no effect.
- **DEAD** — No call path from any entry point. Orphaned functions,
  unreferenced modules, commented-out code. Verify: grep for the function
  name across the codebase. Zero call sites outside its own file = DEAD.
  Report under `## Dead code findings`. Do not re-classify as ACTIVE later
  unless the critic provides a verified call chain.
- **TEST-ONLY** — Called only from test files (`test_*`, `*_test`, `/tests/`).
  Report under `## Test-only findings`. Severity capped at LOW unless the
  test server is exposed to a network. Do not treat as ACTIVE.

### Impact (damage if exploited)

- **CRITICAL** — Full system compromise: RCE, complete auth bypass, full
  database dump, persistent backdoor, cryptographic key extraction.
- **HIGH** — Significant damage: privilege escalation, bulk data exposure
  (PII, credentials, financial), persistent injection (stored XSS), secret
  exposure, arbitrary file read/write.
- **MODERATE** — Contained damage: single-user data exposure, session hijack,
  partial access control bypass, CSRF on state-changing actions.
- **LOW** — Minimal damage: version/path info disclosure, verbose error
  messages, denial of service, defense-in-depth gaps, missing security headers.

### Likelihood (feasibility of exploitation)

- **HIGH** — All of: unauthenticated, publicly reachable, no special
  conditions, well-known exploit pattern, single-step attack.
- **MEDIUM** — Any one of: requires authentication, requires one specific
  precondition, requires a 2-step attack chain.
- **LOW** — Two or more of: requires privileged/admin access, requires
  specific configuration, requires 3+ step chain, race condition, or social
  engineering.

### Confidence (certainty this is real)

- **CONFIRMED** — Full source-to-sink trace verified by reading actual code.
  Every hop cites a real file:line that was read.
- **PROBABLE** — Trace mostly verified but one hop is inferred. State which
  hop is inferred.
- **POSSIBLE** — Vulnerable pattern detected but data flow from untrusted
  source to sink is not confirmed. Input might be hardcoded, sanitized
  upstream, or unreachable.

### Severity (derived — do NOT assign directly)

Look up Impact x Likelihood in this matrix:

|                     | Likelihood HIGH | Likelihood MEDIUM | Likelihood LOW |
|---------------------|-----------------|-------------------|----------------|
| **Impact CRITICAL** | CRITICAL        | HIGH              | MEDIUM         |
| **Impact HIGH**     | HIGH            | HIGH              | MEDIUM         |
| **Impact MODERATE** | MEDIUM          | MEDIUM            | LOW            |
| **Impact LOW**      | LOW             | LOW               | LOW            |

Reachability adjustments (applied after matrix lookup):
- **ACTIVE**: no change.
- **CONDITIONAL**: no change, but condition MUST be reflected in Likelihood.
- **DEAD**: cap at MEDIUM. Note "(capped from [original] — dead code)".
- **TEST-ONLY**: cap at LOW. Note "(capped from [original] — test-only)".

Show the computation in every finding:
`Severity: Impact [X] x Likelihood [Y] = [Z] ([reachability], [adjustment])`

## Rules for classification

These rules are hard constraints. Do not override them with reasoning.

- No trace = not CONFIRMED. If you cannot write source -> sink with file:line
  at every hop, set Confidence to POSSIBLE. No exceptions.
- Dead code: report it, classify as DEAD, cap severity at MEDIUM. Do NOT
  skip dead code. Do NOT inflate dead code to ACTIVE.
- Full mitigation = no finding. If a mitigation fully neutralizes the
  vulnerability, do NOT report it. Do NOT report it as "mitigated" either.
  Partial mitigation (e.g., blocklist not allowlist): report it, lower
  Likelihood by one level.
- Clean files: move on silently. Do NOT write "no findings" entries. Do NOT
  mention clean files anywhere in the assessment.
- Clean codebase: write `## Findings\nNo vulnerabilities found.` Do NOT
  lower standards to fill the section. An empty findings section with "No
  vulnerabilities found" is a valid review outcome.

## CWE list (use ONLY these)

CWE-22 Path Traversal | CWE-78 Command Injection | CWE-79 XSS | CWE-89 SQLi |
CWE-94 Code Injection | CWE-200 Info Exposure | CWE-250 Unnecessary Privileges |
CWE-284 Access Control | CWE-306 Missing Auth | CWE-327 Broken Crypto |
CWE-352 CSRF | CWE-400 Resource Exhaustion | CWE-502 Unsafe Deserialization |
CWE-611 XXE | CWE-614 Sensitive Cookie Without Secure |
CWE-798 Hardcoded Credentials | CWE-918 SSRF | CWE-OTHER (describe)

CWE-798 covers both hardcoded passwords (formerly CWE-259) and other
credentials (API keys, tokens, secrets). Use CWE-798 for all cases.

No invented CVE IDs. No CWE numbers outside this list.

## Container security checklist

Apply this checklist instead of the source-code CWE list when reviewing
Dockerfiles, docker-compose files, and similar infrastructure-as-code.

- Running as root? Missing `USER` directive or explicit `USER root`.
- Unpinned base image? Using `:latest` or no tag instead of a digest
  or version-pinned tag.
- Secrets in build? `ARG`/`ENV` used for passwords, tokens, or keys
  (they persist in image layers). `COPY` of `.env`, credentials, or
  private keys into the image.
- Unnecessary attack surface? Installing dev tools, debug packages,
  or full package managers in the final stage. Missing multi-stage
  build when build tools are present.
- Dangerous instructions? `--privileged`, `--cap-add`, `SYS_ADMIN`,
  `--security-opt=no-new-privileges:false`, `--pid=host`,
  `--network=host` in compose. `EXPOSE` of unnecessary ports.
- Health/resource gaps? Missing `HEALTHCHECK`. No resource limits in
  compose (`mem_limit`, `cpus`).
- Writable filesystem? Missing `read_only: true` when feasible.

Classify using the same four-axis system. Reachability for container
findings is ACTIVE if the Dockerfile is in the build path.

## Finding format — first-party code

```markdown
### [FILE]:[LINES] — [TITLE]
**CWE:** CWE-XXX
**Reachability:** [exactly one of: ACTIVE | CONDITIONAL | DEAD | TEST-ONLY]
**Impact:** [exactly one of: CRITICAL | HIGH | MODERATE | LOW]
**Likelihood:** [exactly one of: HIGH | MEDIUM | LOW]
**Confidence:** [exactly one of: CONFIRMED | PROBABLE | POSSIBLE]
**Severity:** Impact [X] x Likelihood [Y] = [Z] ([reachability], [adjustment])

**Data flow:**
Source:     [file:line — what untrusted data enters here]
Transform:  [file:line — function/method, what it does to the data]
Transform:  [file:line — next hop, if any]
Sink:       [file:line — where the data causes harm]

\`\`\`python
<exact code at the sink, max 20 lines, copied verbatim from the file>
\`\`\`

**Exploit:** 1. [concrete attacker action] -> 2. [how input reaches sink] -> 3. [resulting harm]
**Mitigations:** [existing controls and whether sufficient, or "None"]
**Fix:** [specific code change recommendation]
```

Use this format exactly. Do not omit fields. Do not add fields.

## Finding format — container/infrastructure findings

Use this format for Dockerfiles, docker-compose files, and similar
infrastructure-as-code files where data-flow tracing does not apply.

```markdown
### [FILE]:[LINES] — [TITLE]
**CWE:** CWE-XXX
**Reachability:** ACTIVE (built and deployed) | CONDITIONAL (state condition) | DEAD
**Impact:** [exactly one of: CRITICAL | HIGH | MODERATE | LOW]
**Likelihood:** [exactly one of: HIGH | MEDIUM | LOW]
**Confidence:** [exactly one of: CONFIRMED | PROBABLE | POSSIBLE]
**Severity:** Impact [X] x Likelihood [Y] = [Z] ([reachability], [adjustment])

\`\`\`dockerfile
<exact lines from the file, max 10 lines, copied verbatim>
\`\`\`

**Risk:** [what an attacker gains from this misconfiguration]
**Fix:** [specific change — e.g. "Add USER nonroot", "Pin base image to digest"]
```

Use this format exactly. Do not omit fields. Do not add fields.

## Finding format — dependency findings

```markdown
### [PACKAGE]@[VERSION] — [TITLE]
**CVE:** [CVE-XXXX-XXXXX or "no CVE — advisory only"]
**CWE:** CWE-XXX
**Reachability:** [ACTIVE — vulnerable function called at file:line | DEAD — not imported/called]
**Impact:** [exactly one of: CRITICAL | HIGH | MODERATE | LOW]
**Likelihood:** [exactly one of: HIGH | MEDIUM | LOW]
**Confidence:** [exactly one of: CONFIRMED | PROBABLE | POSSIBLE]
**Severity:** Impact [X] x Likelihood [Y] = [Z] ([reachability], [adjustment])

**Vulnerable path:** [import chain -> function at file:line, or "not called in codebase"]
**Fixed in:** [version, or "no fix available"]
**Fix:** [upgrade | pin | remove | workaround]
```

Use this format exactly. Do not omit fields. Do not add fields.

## Report structure

The assessment file MUST contain these sections in this order. Write empty
sections (with "None" or "No findings") rather than omitting them.

1. `# Security Assessment — [date] — [model]`
2. `## Context` (project, framework, deployment, ports, auth, data stores)
3. `## Attack surface` (entry points + trust boundaries tables)
4. `## Scanned files` (file list)
4. `## Findings` (ACTIVE and CONDITIONAL, ordered by severity descending)
5. `## Dead code findings` (DEAD, severity capped at MEDIUM)
6. `## Test-only findings` (TEST-ONLY, severity capped at LOW)
7. `## Dependency findings` (third-party/supply-chain)
8. `## Findings summary` (tables below)
9. `## Disputed findings` (after critic review; "None" if no disputes)
10. `## Validation` (after subagent review)
11. `## Run metadata` (model, date, finding counts, critic/verifier status)

## Findings summary tables

### First-party code
Total findings: X (Active: X, Conditional: X, Dead: X, Test-only: X)

| Severity | Count | Confirmed | Probable | Possible |
|----------|-------|-----------|----------|----------|
| CRITICAL | X     | X         | X        | X        |
| HIGH     | X     | X         | X        | X        |
| MEDIUM   | X     | X         | X        | X        |
| LOW      | X     | X         | X        | X        |

### Dependencies
Total findings: X (Active: X, Dead: X)

| Package | Version | CVE | Severity | Called? |
|---------|---------|-----|----------|---------|

### All findings

| File/Package | Finding | CWE | Reachability | Impact | Likelihood | Severity | Confidence |
|--------------|---------|-----|--------------|--------|------------|----------|------------|
