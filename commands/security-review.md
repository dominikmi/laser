---
description: Run a security assessment. Usage: /security-review <model-name>
---

You are a security engineer performing a structured review. Model name: **$1**

## Constraints

- Execute steps 1-14 in order. Do NOT reorder, skip, or insert steps.
- Do NOT perform any action not explicitly listed in a step. If a step does
  not mention it, do not do it.
- All output goes to the assessment file via edit/write tool. Do NOT write
  analysis, reasoning, summaries, or commentary to chat. Chat is silent
  until step 14.
- Do NOT tell the user "done" before step 14.
- On error: write one line to the assessment file noting what failed. Retry
  once. Then proceed to the next step. Do NOT diagnose the error.
- Steps 11-12b are the subagent delegation chain. You MUST complete all
  four steps (11 → 11b → 12 → 12b) before writing `## Validation` in
  step 13. Do NOT skip 11b or 12b. Do NOT combine them with other steps.
- You MUST NOT self-critique or self-verify. Do NOT substitute your own
  review. Do NOT "sanity check" findings before delegating. Do NOT
  re-review after delegation. A `## Validation` section that does not
  reference @critic and @verifier output is a FAILURE.
- Invoke `@critic` **exactly once** (step 11), then process its response
  (step 11b), then invoke `@verifier` **exactly once** (step 12), then
  process its response (step 12b). Two subagent calls total.
- Send subagent prompts **exactly as written**. Do NOT rephrase, extend, or
  add context to them. Copy-paste only.
- After each subagent returns: you MUST process its response in the
  immediately following step (11b or 12b). Do NOT proceed to the next
  subagent or to step 13 until you have edited the assessment file with
  the results. Every accepted item = one edit. Every dispute = one append.
- If a subagent returns zero items: write "0 issues raised" in the
  checkpoint line. If a subagent fails or returns no response: write
  `FAILED — [reason]` in the checkpoint line. Then proceed. Do NOT
  attempt the subagent's job yourself.
- Do NOT read files speculatively. Read a file only when a step explicitly
  requires it. Do NOT re-read source files you have already read. Exception:
  re-reading the assessment file is allowed when a step requires it (e.g.
  steps 8, 9, 13).
- Context budget: every file read, tool output, and assessment edit consumes
  context permanently. Rules:
  - Do NOT write raw tool output to the assessment — write summary tables.
  - Write each finding to the assessment immediately after reading its file.
  - Do NOT batch-read files. Read one, process it, write findings, move on.
  - If step 5 lists more than $FILE_CAP source files: scan the first $FILE_CAP
    (prioritized per step 6 ordering). Write "Note: X files not scanned due
    to context limits" in the assessment. Do NOT attempt to scan all files.

## Reference file

Classification definitions, finding formats, severity matrix, and report
structure are in `.opencode/commands/security-review-ref.md`. Read that file
once at step 6. Do NOT read it earlier. Do NOT re-read it.

## Steps

**Step 1.** Run: `mkdir -p .security-output`

Nothing else.

**Step 2.** Write header to `.security-output/SEC_ASSESSMENT_$1.md`:
`# Security Assessment — $(date +%Y-%m-%d) — $1`

Nothing else.

**Step 2b.** Build a `## Context` section.

1. Read `README.md` first 120 lines (skip if absent).
2. `ls` repo root. Read up to 3 deploy config files (first 40 lines each;
   prefer Dockerfile and compose files). Deploy configs: Dockerfile,
   docker-compose.yml, compose.yaml, uwsgi.ini, gunicorn.conf.py,
   nginx.conf, Procfile, k8s/, serverless.yml, fly.toml, app.yaml, etc.
3. Write `## Context` with one `**Key:** value` line per field: Project,
   Language/framework, Purpose, Deployment, Ports/services, Auth model,
   Data stores, External integrations, Notes.

Max 5 tool calls. Do NOT read source files.

**Step 3.** Check if `graphify-out/GRAPH_REPORT.md` and `graphify-out/graph.json`
exist (`ls graphify-out/`).

If both exist: read only the first 80 lines of `GRAPH_REPORT.md`
(`head -80 graphify-out/GRAPH_REPORT.md`). This covers the corpus summary and
community structure. Do NOT read the full file — it can exceed 10k tokens.
Do NOT read `graph.json` (too large). Do NOT summarize in chat.

For details beyond the first 80 lines, use the graphify CLI:
- `graphify path "A" "B"` — shortest path between two nodes
- `graphify explain "X"` — a node and its immediate neighbors

If graphify-out is missing: write "graphify-out not available" in the
assessment. Do NOT attempt to generate or build the graph.

**Step 3b.** Tool-assisted baseline scans. For each tool below: if the MCP tool
appears in your tool list, make the specified call. If it does not appear,
skip it. Do NOT check versions, run help commands, or verify installations.

- **Semgrep** — first, glob for source files at the project root (e.g.
  `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`, `**/*.rb` — pick
  the languages present). Then one call: `semgrep_scan` with `code_files`
  set to an array of `{"path": "/absolute/path/to/file"}` objects for the
  source files found. Max 50 files — if more exist, select entry-point,
  route, and Dockerfile/compose files first. Do NOT pass directory paths —
  only individual files.
  Do NOT write the raw output to the assessment — it can be 100k+ tokens.
  Instead, write a compact summary table to `## Semgrep baseline` with max
  30 rows: `| file:line | rule-name | severity |`
  Filter: keep only ERROR and WARNING severity. Exclude findings in test
  files, generated files, and non-source files (.md, .yml, .json). You have
  the full results in your tool-call context for cross-reference in step 6.
- **TruffleHog** — read `.security-output/trufflehog-results.json` (pre-generated
  by the runner). Write a compact summary to `## Secret scan baseline` with max
  20 rows: `| file:line | detector | redacted-value | verified |`
  Use the `Redacted` field from each JSON object — do NOT manually redact.
  If the file is missing or empty, write
  "TruffleHog: no secrets found (0 candidates)".
- **Serena** — max 3 calls total in this step: `get_symbols_overview` on up
  to 3 entry-point files. Do NOT write Serena output to the assessment.
  Retain in your context for use in step 6.

If semgrep finds zero results or semgrep is unavailable: write
"Semgrep: no findings (0 results)" to `## Semgrep baseline`. The review
proceeds — use graphify paths, grype results, and manual analysis in step 6.

Max tool calls this step: 7 total. If a tool call fails, skip it.

**Step 3c.** Check for pre-processing artifacts. The runner may have generated
these files before the review started. Check with `ls .security-output/`:

- **SBOM** — if `.security-output/sbom.cyclonedx.json` exists: note "SBOM
  available" in the assessment. Do NOT read the full SBOM — it can be huge.
  It will be used in step 7.
- **Grype results** — if `.security-output/grype-summary.json` exists: read
  it (pre-summarized by the runner). If only `.security-output/grype-results.json`
  exists: read the first 200 lines (`head -200 .security-output/grype-results.json`).
  Write a compact summary to `## Dependency scan baseline` with max 20 rows:
  `| package | version | CVE | severity | fixed-in |`
  These pre-scanned dependency vulnerabilities guide steps 6 and 7.
- **Diff scope** — if `.security-output/DIFF_SCOPE.md` exists: read it.
  This narrows the review to changed files and their callers. In steps 5-6,
  prioritize files listed in the diff scope. Still scan other files if
  context allows, but diff-scope files come first.

If none of these exist: proceed. They are optional.

**If both semgrep (step 3b) and grype (this step) produced zero findings** —
or neither tool was available — write to the assessment:
"No automated scanner findings. Full manual review required."

Max tool calls this step: 3 (1 ls + up to 2 reads).

**Step 4.** Map the attack surface. Write `## Attack surface` with three
subsections: `### Entry points` table (`# | Type | Location | Auth required
| Description`), `### Trust boundaries` table (`# | Boundary | Location |
Data type`), `### Notes` (observations).

Sources: graphify community/god-node lists (if read in step 3), plus grep
for route decorators, CLI parsers, `input()`, deserialization, socket
listeners, env var reads in security decisions.

Max 30 rows. Library with no entry points: write "Library — findings
assessed as CONDITIONAL." Do NOT read source files.

**Step 4b.** Attack-path and dead-code analysis. Skip entirely if graphify-out
is missing.

Attack paths — pick the top 3 entry points by exposure (unauthenticated and
public first). For each, run `graphify path` against at most 3 sink files
likely to contain dangerous operations. **Max 10 `graphify path` queries total.**
If a path is found: write it to `## Attack paths` as a one-line entry:
`entry_file -> hop1 -> hop2 -> sink_file (N hops)`. Stop after writing.

Dead code — run `graphify explain` on files that appear in no attack path.
**Max 5 `graphify explain` queries.** If a file has zero incoming edges from
entry-point-connected files: write it to `## Dead code candidates` as a
one-line entry. Stop after writing.

Do NOT read any source files in this step. Do NOT analyze or reason about
results. Write the lists and move on. Step 6 verifies.

**Step 5.** List source files. Run a single find/glob command. Exclude:
`/tests/`, `/test/`, `test_*.py`, `*_test.py`, `conftest.py`, `/migrations/`,
`/generated/`, `/vendor/`, `/third_party/`, `/node_modules/`, `/.venv/`,
`/dist/`, `/build/`, `.security-output/`, `graphify-out/`.

Also include infrastructure files at any depth: `Dockerfile*`,
`docker-compose*.yml`, `compose*.yaml`, `*.Dockerfile`. These are
security-critical and must appear in the file list even though they are
not traditional source code.

Write the list to `## Scanned files`. Nothing else.

**Step 6.** Read `.opencode/commands/security-review-ref.md` once.

Scanners are a starting point, not a verdict. Semgrep uses pattern rules —
it misses business logic flaws, access control gaps, IDOR, SSRF, and
multi-file data flow issues. A clean semgrep scan does NOT mean a clean
codebase. You MUST manually review every file against the full CWE list
regardless of scanner results.

Scan files from step 5 in this priority order:
1. Files in diff scope from step 3c (if `DIFF_SCOPE.md` was present).
2. Files on attack paths from step 4b (if any).
3. Files with semgrep findings from step 3b (if any).
4. Files that import packages flagged by grype from step 3c (if any).
5. Entry-point files (routes, handlers, CLI parsers, main modules).
6. Files with high graphify connectivity (many incoming/outgoing edges) —
   these are integration points where data converges.
7. Infrastructure files (`Dockerfile*`, `docker-compose*.yml`, `compose*.yaml`)
   — these define the runtime security posture of the deployed application.
8. Seed, fixture, and example files (`db_seed*`, `seed*`, `fixtures/*`,
   `.env.example`, `**/initial_data*`) — common sources of hardcoded
   credentials and leaked secrets.
9. Files containing security-sensitive operations. Grep for these patterns
   before reading: `password|secret|token|auth|session|crypt|deserializ|
   pickle|yaml\.load|exec|eval|subprocess|os\.system|render|sql|query`.
10. Remaining files.

Process files one at a time. For each file: read it, find issues, write
findings to the assessment, then move to the next file. Do NOT batch-read
multiple files. Do NOT hold file contents for later — write findings
immediately so the file content can leave context. You MAY batch up to
3 findings from the same file into a single edit call.

For each file:
1. Read the file.
2. Check against the FULL CWE list in the ref file. Do NOT invent CWE
   categories. Do NOT limit your review to scanner-flagged patterns.
   Look for: SQL injection, XSS, path traversal, command injection,
   SSRF, IDOR, insecure deserialization, hardcoded secrets, missing
   auth checks, race conditions, business logic flaws, and unsafe
   data flow across files.
3. If semgrep flagged this file (check your step 3b summary table):
   verify the finding's reachability and classify it. Write a single
   finding that cites both the semgrep rule and your manual verification.
   Do NOT write separate semgrep and manual findings for the same code
   location. Also look for issues semgrep missed in the same file.
4. If grype flagged a package this file imports (check step 3c baseline):
   verify whether the vulnerable function is called and classify.
5. Classify each finding on all four axes per the ref file.
6. Write the finding to the assessment file immediately (using the format
   from the ref file). For multi-file data flow traces:
   - Use the attack path from step 4b as the skeleton (if one exists).
   - If Serena MCP is available: one `find_referencing_symbols` call per
     finding to verify the sink is called. Max 1 Serena call per finding.
   - If graphify is available and trace spans 3+ files: one `graphify path`
     call to confirm connectivity. No path = DEAD or CONDITIONAL.
7. For dead-code candidates from step 4b: grep for call sites. Zero call
   sites = DEAD. Do NOT run additional graphify queries.
8. **Dockerfile / docker-compose files**: apply the container security
   checklist from the ref file instead of the CWE source-code checklist.
9. Move to next file. Do NOT write analysis between files.

**Step 7.** Scan dependencies. Use all available sources — they complement
each other.

- **Grype results** (from step 3c): if `## Dependency scan baseline` was
  written, start from those findings. For each: one grep for imports of the
  affected package. Called = ACTIVE. Not called = DEAD. Write to
  `## Dependency findings`.
- **OSV-Scanner** (if MCP available): one call: `scan_vulnerable_dependencies`
  on the project root. Merge with grype results — OSV may find different
  CVEs (different database). For new findings not already in grype baseline:
  one grep for imports. Write to `## Dependency findings`.
- **Neither grype nor osv-scanner:** read the first dependency manifest found
  (check in order: `pyproject.toml`, `requirements.txt`, `package.json`,
  `go.mod`, `Cargo.toml`). For each direct dependency: websearch for CVEs.
  If CVE found: one grep for imports. Write to `## Dependency findings`.

Max 20 import greps total across all sources. Stop.

**Step 8.** Write summary tables (formats in ref file) to assessment file.
Nothing else.

**Step 9.** Read the assessment file. Check these sections exist: Attack
surface, Scanned files, Findings (or "No vulnerabilities found"), Findings
summary. If a section is missing: write it now (empty with "None"). Do NOT
add sections not in this list. Do NOT rewrite existing content.

**Step 10.** Confirm file is saved. Nothing else.

**Step 10b.** Free GPU memory for subagents. Run:
`bash .security-output/omlx-unload.sh 2>/dev/null || true`
This unloads the primary model from GPU so the critic/verifier models can
load. If the script does not exist (non-oMLX primary): this is a no-op.
Do NOT skip this step.

**Step 11.** Read `.security-output/critic-prompt.txt`. Send its full
contents to `@critic` as the message — copy-paste, no modifications.
Wait for the critic to respond. Do NOT proceed to step 11b until the
critic has returned its response.

**Step 11b.** Process critic response. This is a mandatory step — do NOT skip it.

Read the critic's response. Count the items. Then process each item
top-to-bottom in one pass:

- Do NOT re-read source files. Do NOT deliberate. Do NOT weigh options.
- For each item, do exactly ONE of:
  A. **Accept** — edit the assessment file NOW. Use the critic's
     classification verbatim. Do NOT rephrase or improve it.
  B. **Dispute** — append to `## Disputed findings`:
     `Title | Critic says: [X] | I say: [Y] because [file:line evidence]`
- Max 3 disputes. Accept all others.

After processing ALL items, append this checkpoint line to the assessment:

`<!-- critic-checkpoint: ITEMS items, ACCEPTED accepted, DISPUTED disputed -->`

Replace ITEMS/ACCEPTED/DISPUTED with actual counts. If the critic returned
zero items: write `<!-- critic-checkpoint: 0 items, 0 accepted, 0 disputed -->`.
If the critic failed: write `<!-- critic-checkpoint: FAILED — [reason] -->`.

Do NOT proceed to step 12 until the checkpoint line is written.

**Step 12.** Read `.security-output/verifier-prompt.txt`. Send its full
contents to `@verifier` as the message — copy-paste, no modifications.
Wait for the verifier to respond. Do NOT proceed to step 12b until the
verifier has returned its response.

**Step 12b.** Process verifier response. This is a mandatory step — do NOT skip it.

Read the verifier's response. Count the discrepancies. Then process each
item top-to-bottom in one pass:

- Do NOT re-read files. Do NOT deliberate. The verifier reports facts.
- For each discrepancy, do exactly ONE of:
  A. **Path/line wrong** — replace with the verifier's corrected path/line.
  B. **Snippet wrong** — replace with the exact code the verifier reported.
  C. **Trace hop missing** — use the verifier's correction. If verifier says
     "hop does not exist": delete the finding entirely.
  D. **Confidence issue** — downgrade: CONFIRMED->PROBABLE, PROBABLE->POSSIBLE,
     POSSIBLE->delete the finding.
- Zero disputes with the verifier. These are facts, not opinions.

After processing ALL items, append this checkpoint line to the assessment:

`<!-- verifier-checkpoint: ITEMS items, CORRECTED corrected, REMOVED removed -->`

Replace ITEMS/CORRECTED/REMOVED with actual counts. If the verifier returned
zero discrepancies: write `<!-- verifier-checkpoint: 0 items, 0 corrected, 0 removed -->`.
If the verifier failed: write `<!-- verifier-checkpoint: FAILED — [reason] -->`.

Do NOT proceed to step 13 until the checkpoint line is written.

**Step 13.** Read back the two checkpoint lines from the assessment file. Use
their counts to write the `## Validation` section. Append to the assessment:

```
## Validation
Reviewed by @critic and @verifier on $(date +%Y-%m-%d).
Critic issues: [ITEMS from critic-checkpoint] raised, [ACCEPTED] accepted, [DISPUTED] disputed.
Verifier issues: [ITEMS from verifier-checkpoint] found, [CORRECTED] corrected, [REMOVED] findings removed.
```

If a checkpoint says FAILED: write `@critic: FAILED — [reason]` or
`@verifier: FAILED — [reason]` instead of counts.

A `## Validation` section that does not reference @critic and @verifier is
wrong. Do NOT write a self-check. Do NOT list sections. The only content
in this section is the subagent summary above.

Nothing else.

**Step 13b.** Append a run metadata block to the assessment file:

```
## Run metadata
- Model: $1
- Date: $(date +%Y-%m-%d %H:%M)
- Findings: [total] (CRITICAL: X, HIGH: X, MEDIUM: X, LOW: X)
- Sections: [found]/[expected]
- Critic: completed|failed
- Verifier: completed|failed
```

Fill in the actual counts from the assessment. Nothing else.

**Step 14.** Write to chat (this is the ONLY chat output for the entire review):

```
Assessment: .security-output/SEC_ASSESSMENT_$1.md
Findings: X (CRITICAL: X, HIGH: X, MEDIUM: X, LOW: X)
Disputed: X
Critic: completed|failed
Verifier: completed|failed
```

Nothing else. Do NOT paste findings, tables, summaries, or explanations.
