# RESEARCH DOSSIER: Semgrep

> Part of the Lancer ecosystem. A Rust clone of Semgrep — language-agnostic pattern-based static analyzer. Build with Claude Code.
> Upstream: github.com/semgrep/semgrep (OCaml + Python, LGPL-2.1, ~1.x). 30+ languages, 3000+ community rules in the Semgrep Registry, Semgrep AppSec platform (Code/Secrets/Supply Chain). Industry standard for SAST-as-code.

## Feature Parity Mandate

**`lancer-semgrep` MUST ship with 100% feature parity to the upstream `semgrep` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `semgrep --help` (and the long-form man page / docs) must work in `lancer-semgrep --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-semgrep` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-semgrep --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Semgrep (formerly "sgrep" — "semantic grep") is a language-agnostic static analyzer that runs **pattern-based rules** over source code. Two distinct layers stack on top of each other:

1. **Syntactic pattern matching.** Patterns look like real code (`subprocess.call($CMD, shell=True)`, `db.query("SELECT * FROM users WHERE id = " + $X)`) but they abstract over identifier names, literal values, and sub-expressions via **metavariables** (`$X`, `$CMD`, `$F`). Patterns match the source's AST after both pattern and source have been parsed by the same language grammar; metavariables bind to source AST nodes. The `...` (ellipsis) operator matches arbitrary sub-expressions or statement sequences ("deep matching").
2. **Inter-procedural taint tracking.** A `mode: taint` rule declares `pattern-sources`, `pattern-sinks`, `pattern-sanitizers`, and `pattern-propagators`. Semgrep then runs a forward dataflow over the CFG built from the AST, propagating taint state from sources through assignments and function calls until a sink is reached without an intervening sanitizer.

Both layers are driven by YAML rule files. Community rules live in `github.com/semgrep/semgrep-rules` (3000+ rules across OWASP Top 10, CWE, secrets, compliance, ML/AI security, dependency confusion, supply chain). Pro rules ship via the Semgrep AppSec platform (commercial) and add inter-file/inter-procedural taint that the OSS engine lacks.

Supported languages span **30+**: Python, JavaScript, TypeScript (including JSX/TSX), Java, Go, Ruby, C, C++, Rust, Kotlin, Swift, Scala, PHP, C#, Solidity, Bash, Lua, R, Julia, OCaml, Clojure, Hack, Elixir, Dart, Apex (Salesforce), Cairo, Move, Bicep, Terraform/HCL, Dockerfile, YAML, JSON, and pattern-only for Generic. Output formats include text, JSON, SARIF (GitHub code-scanning), GitLab SAST, JUnit XML, and emacs/vim.

## Internal architecture

**Target workspace** (`Cargo.toml`):
```
[workspace]
members = [
  "lancer-semgrep",          # CLI binary
  "semgrep-core",            # rule engine, matcher, taint
  "tree-sitter-langs",       # language grammar bundle
  "semgrep-rules",           # rule loader + registry sync
  "semgrep-taint",           # forward/backward dataflow
  "semgrep-output",          # SARIF / JSON / GitLab / text emit
]
```

- **`lancer-semgrep`** — CLI binary (clap 4.x). Same flag surface as upstream `semgrep` for drop-in compat. Parses args, picks scan/ci/login/playground mode, calls `semgrep-core`.
- **`semgrep-core`** — Orchestration: target enumeration via `walkdir` + gitignore, language detection, parallel rule execution via `rayon`, finding deduplication, baseline diff against a git commit, per-rule cache.
- **`tree-sitter-langs`** — Thin wrapper bundling `tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-typescript`, `tree-sitter-go`, `tree-sitter-rust`, `tree-sitter-java`, `tree-sitter-ruby`, `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-c-sharp`, `tree-sitter-php`, `tree-sitter-kotlin`, `tree-sitter-swift`, `tree-sitter-scala`, `tree-sitter-bash`, `tree-sitter-yaml`, `tree-sitter-dockerfile`, `tree-sitter-hcl`, `tree-sitter-solidity`, etc. Exposes a uniform `Parser` trait wrapping the per-language `tree_sitter::Parser`.
- **`semgrep-rules`** — Rule loader: `serde_yaml` deserialization, schema validation, `--config` resolution (local path, registry slug `p/python`, URL, `auto`), rule cache in `~/.semgrep/cache/`.
- **`semgrep-taint`** — Forward dataflow engine: CFG construction from AST, taint state lattice, sanitizer propagation, source/sink classification, propagator handling.
- **`semgrep-output`** — Formatters: text (terminal-coloured), JSON (Semgrep-native schema), SARIF (`serde_sarif`), GitLab SAST, JUnit XML, GitHub-actions-grouped output.

**Key modules in `semgrep-core/src/`:**

- `parse/`
  - `parser.rs` — Dispatch on detected language → invoke matching tree-sitter parser → produce a tagged AST node tree (`SgNode`).
  - `pattern_parser.rs` — Parse a rule's `pattern:` string using the **same** tree-sitter grammar as targets, with the **metavariable lexer extension** (anything starting with `$` becomes a metavariable token; `...` becomes an ellipsis token).
  - `lang_detect.rs` — File extension → language enum mapping. Falls back to shebang sniffing for scripts.
- `match/`
  - `engine.rs` — Pattern unifier. Walks the source AST, attempts unification against the rule pattern AST, returns a list of `Match { node_range, metavar_bindings }`.
  - `unifier.rs` — Core unification primitive: structural match between pattern AST and source AST modulo metavariables and ellipsis.
  - `ellipsis.rs` — Ellipsis matching across statement sequences, argument lists, expression sub-trees ("deep matching").
  - `metavar.rs` — Metavariable binding store: `$X → SgNode`. Reused across compound rule operators (`pattern-not`, `metavariable-pattern`).
  - `rule_evaluator.rs` — Combine `pattern`, `pattern-not`, `pattern-either`, `pattern-inside`, `pattern-not-inside`, `pattern-regex`, `metavariable-regex`, `metavariable-comparison`, `metavariable-pattern` per Semgrep's boolean semantics.
- `taint/`
  - `cfg.rs` — Build per-function control-flow graph from AST (`petgraph::DiGraph<NodeId, EdgeKind>`).
  - `dataflow.rs` — Forward fixed-point dataflow. Taint state per program point. Lattice: `Untainted ⊑ Tainted(source_label) ⊑ Top`.
  - `sources_sinks.rs` — Pattern-based source/sink/sanitizer/propagator matching reused from `match/engine.rs`.
  - `interproc.rs` — (Pro mode) Inter-procedural taint via function summary tables. OSS mode is intra-procedural.
- `autofix/`
  - `fix.rs` — Apply rule's `fix:` template by substituting metavariable bindings into the template string; produces a unified diff.
  - `fix_regex.rs` — Apply `fix-regex` template (regex-based substitution).
- `cache/`
  - `rule_cache.rs` — Per-rule compiled-pattern cache.
  - `target_cache.rs` — Per-file parsed-AST cache keyed by content hash.
- `baseline/`
  - `git_diff.rs` — Compute file diff vs `--baseline-commit`; only run rules on hunks. `--diff-depth` controls context expansion.
- `output/` — Re-exports `semgrep-output`.

**How a rule executes:**
1. `semgrep-rules` loads YAML, validates schema, compiles each `pattern:` string by feeding it to the same tree-sitter parser used for targets (with metavar extension).
2. `semgrep-core` enumerates targets (respecting `.gitignore`, `.semgrepignore`, `--include`, `--exclude`).
3. For each `(target, rule)` pair where `rule.languages` matches `target.language`, the rule is dispatched to `match/engine.rs` (syntactic) or `semgrep-taint` (taint mode).
4. Findings accumulate per file; deduplication merges findings with identical `(file, range, rule_id)`.
5. Output emitter writes JSON/SARIF/text/etc.

Rule execution is parallelised three ways: `(targets × rules)` via `rayon::par_iter` over the cartesian product, with per-target AST parsing memoised in `target_cache`.

## Granular feature catalog

**Rule format (`rules:` YAML array, each rule has):**
- `id` — unique identifier (`python.lang.security.audit.dangerous-subprocess-use`).
- `pattern` — single pattern.
- `patterns` — list combined with AND (each item is a pattern operator).
- `pattern-either` — list combined with OR.
- `pattern-not` — negation; remove matches contained in this pattern.
- `pattern-inside` — match must be lexically nested inside this pattern.
- `pattern-not-inside` — match must NOT be lexically nested inside this pattern.
- `pattern-regex` — fall back to regex (escape hatch for unparseable input or pre-filter).
- `pattern-not-regex` — negative regex pre-filter.
- `metavariable-regex` — constrain a bound metavariable by regex (`metavariable: $X`, `regex: '^db_'`).
- `metavariable-comparison` — Python-like expression evaluated against metavariable bindings (`comparison: $N > 100`).
- `metavariable-pattern` — re-run a nested pattern over a metavariable's bound node (effectively recursive pattern matching).
- `metavariable-type` — constrain metavariable by inferred type (Pro engine).
- `fix` — replacement template using metavariable substitution.
- `fix-regex` — replacement via regex `regex` / `replacement`.
- `message` — human-readable finding text (supports metavariable interpolation: `Dangerous subprocess call with $CMD`).
- `severity` — `INFO` / `WARNING` / `ERROR`.
- `languages` — list of language identifiers the rule applies to.
- `metadata` — free-form dict for CWE, OWASP, references, technology tags, license, confidence, likelihood, impact.
- `options` — per-rule engine knobs (e.g., `symbolic_propagation: true`).
- `paths` — `include` / `exclude` glob lists scoped to this rule.

**Taint mode rule (`mode: taint`):**
```yaml
- id: tainted-sql-from-request
  mode: taint
  languages: [python]
  pattern-sources:
    - pattern: request.GET.get(...)
    - pattern: request.POST.get(...)
  pattern-sinks:
    - pattern: cursor.execute($SQL, ...)
  pattern-sanitizers:
    - pattern: bleach.clean(...)
    - pattern: escape($X)
  pattern-propagators:
    - pattern: $X = f"... {$Y} ..."
      from: $Y
      to: $X
  message: SQL query built from user input
  severity: ERROR
```

**Join mode (cross-file):**
- `mode: join` — declare named sub-rules over different files, then join findings on shared metavariables (e.g., a route handler in `routes.py` + an SQL query in `db.py` where `$ROUTE` and `$HANDLER` agree).

**CLI surface (`lancer-semgrep <subcommand> [flags]`):**

*Top-level subcommands (Semgrep-compat):*
- `lancer-semgrep scan` (default) — run rules over targets.
- `lancer-semgrep ci` — meta-command for CI: detects PR/branch, runs baseline diff, posts findings.
- `lancer-semgrep login` / `logout` — Semgrep AppSec auth (stubbed; OSS-only mode skips).
- `lancer-semgrep publish` — push private rules to AppSec.
- `lancer-semgrep test` — run rule unit tests against `.yaml` + `.py` test pairs.
- `lancer-semgrep validate` — schema-check rule files.
- `lancer-semgrep shouldafound` — Pro feature stub.
- `lancer-semgrep install-semgrep-pro` — Pro engine installer (no-op in OSS clone).

*Config / rules:*
- `--config <path|slug|url|auto>` — rule source. Slugs like `p/python`, `p/owasp-top-ten`, `p/javascript`, `p/secrets`, `r/python.lang.security.audit.dangerous-subprocess-use`.
- `--config-policy` — Semgrep AppSec policy (Pro).
- `--no-rewrite-rule-ids` — preserve original rule IDs in output.

*Target control:*
- `--lang <name>` — force language (for piped stdin or odd extensions).
- `--include <glob>` — only matching paths.
- `--exclude <glob>` — exclude matching paths.
- `--exclude-rule <id>` — skip this rule.
- `--max-target-bytes <N>` — skip files larger than N bytes (default 1 MB).

*Severity / output filtering:*
- `--severity <INFO|WARNING|ERROR>` — only emit findings at or above this level.
- `--strict` — non-zero exit on parse errors.
- `--quiet`, `--verbose`, `--debug`.
- `--error` — non-zero exit if any findings.

*Output formats:*
- `--json` — Semgrep-native JSON.
- `--sarif` — SARIF 2.1.0.
- `--gitlab-sast` — GitLab SAST report JSON.
- `--gitlab-secrets` — GitLab Secrets report JSON.
- `--junit-xml` — JUnit XML.
- `--emacs` / `--vim` — line-oriented formats for editor integration.
- `--output <file>` — write to file instead of stdout.

*Baseline / diff:*
- `--baseline-commit <SHA>` — only emit findings introduced since this commit.
- `--diff-depth <N>` — how many lines of context around a diff hunk to consider.

*Performance:*
- `--jobs <N>` — parallelism (default = CPU count).
- `--max-memory <MB>` — memory cap per worker.
- `--timeout <sec>` — per-rule timeout.
- `--timeout-threshold <N>` — kill a rule after N file timeouts.
- `--time` — emit per-rule timing.
- `--no-git-ignore` — ignore `.gitignore`.

*Experimental / Pro:*
- `--enable-experimental` — turn on experimental engine features.
- `--pro` — use Pro engine (requires login; OSS clone errors out cleanly).
- `--pro-intrafile` / `--pro-interfile` — Pro analysis depth.
- `--dataflow-traces` — emit full taint trace in findings.

*Telemetry:*
- `--metrics <auto|on|off>` — anonymous usage telemetry (default `auto`).

**Registry slugs (popular ones):**
- `p/default` — high-confidence cross-language baseline.
- `p/owasp-top-ten` — OWASP 2021 mapping.
- `p/cwe-top-25` — CWE Top 25 (2024).
- `p/security-audit` — broad audit pack.
- `p/secrets` — credential scanning (AWS keys, JWT, GitHub tokens, etc.).
- `p/javascript`, `p/python`, `p/golang`, `p/java`, `p/typescript`, `p/ruby`, `p/php`, `p/csharp`, `p/c`, `p/cpp`, `p/rust`, `p/kotlin`, `p/swift`, `p/scala`, `p/solidity`, `p/bash`, `p/dockerfile`, `p/terraform`, `p/kubernetes`.
- `p/react`, `p/django`, `p/flask`, `p/express`, `p/spring`, `p/rails`, `p/nextjs`, `p/nestjs`.
- `p/ai`, `p/ml-security` — model-related rules (prompt injection patterns in Python/JS code).
- `p/supply-chain` — `npm install` / `pip install` typosquatting + dependency confusion patterns.
- `r/<rule-id>` — single rule by ID.

**Supply chain mode (`semgrep ci` with Pro):**
- Scans dependency manifests (`package.json`, `requirements.txt`, `Pipfile.lock`, `pom.xml`, `Gemfile.lock`, `Cargo.lock`, `go.sum`).
- Cross-references known-vulnerable versions (Semgrep AppSec advisory DB).
- Marks vulns as "reachable" or "unreachable" by analysing whether the vulnerable function is called from your code (uses the OSS engine).

**Pro engine differentiators (commercial, not cloned):**
- Inter-file taint (taint flows across function call boundaries across files).
- Inter-procedural function summary cache.
- Constant propagation through Python f-strings and JS template literals.
- Type-aware metavariables (`metavariable-type`).
- "Cross-function reachability" for supply-chain scoring.
- **Redesigned interfile analysis engine (2026 Q1/Q2)** — 20-40% perf gain; taint config computation parallelised over `--jobs`. Replicate the parallel taint-config phase in `semgrep-taint::interproc`.
- `--x-mem-policy=aggressive|balanced` — OCaml GC tuning. Our Rust port maps to a `--mem-policy` knob over `mimalloc`/`jemalloc` allocator selection.

**Newer rule-format features to support (2025–2026):**
- `mode: extract` — sub-language scanning. Extract embedded SQL strings from Python, embedded JS from HTML, embedded shell from Dockerfile `RUN`; re-scan the extracted snippet with rules for the inner language. Requires an `extract:` block declaring the regex/pattern to pull from + the target language.
- `mode: search` — alias for the default pattern-match mode (introduced as explicit mode keyword).
- `mode: secrets` — Semgrep Secrets rule shape (entropy + regex + optional `validators:` that hit live APIs to confirm a credential is real).
- **Taint labels** — sources can declare `label: user-input`, sinks can declare `requires: user-input and not admin-only`, enabling typed taint with boolean expressions (replaces single-label `Tainted(source_label)`).
- **Taint by side-effect** — a sanitizer can be declared `by-side-effect: true`, meaning calling it mutates the argument to untainted (e.g., `validate_in_place(buf)`).
- **`lower()` / `upper()` in `metavariable-comparison`** — case-insensitive string comparisons (Feb 2026).
- **Variadic function support in taint mode** (Apr 2026) — `*args`/`**kwargs` in Python, `...rest` in JS propagate taint correctly through all variadic arguments.
- **Symbolic propagation** (`options.symbolic_propagation: true`) — track value-equivalent expressions: `x = foo(); y = x; sink(y)` resolves `y == foo()`.
- **`r2c-internal-project-depends-on`** — Supply Chain matcher; rule triggers only when the target project depends on a given package + version range.
- **Per-rule `validators:`** (Secrets mode) — declare an HTTP request to make against the candidate secret; if the response matches `valid:` criteria, mark finding as validated (vs unvalidated).

**Languages — extended matrix (the upstream "30+"):**
- **GA (production):** Python, JavaScript, TypeScript (incl. JSX/TSX), Java, Go, Ruby, C, C++, C#, PHP, Rust, Kotlin, Swift.
- **Beta:** Scala (Apr 2026 tree-sitter parser upgrade), Bash, Elixir, Dart, Lua, Solidity, Terraform/HCL, Dockerfile, YAML, JSON, XML, HTML.
- **Experimental:** Apex (Salesforce), Bicep (Azure), Cairo (StarkNet), Move (Sui/Aptos), Clojure, Lisp, Scheme, OCaml, Julia, R, Hack, Jsonnet, **OpenFGA** (Feb 2026 — authorization-language scanning), **PowerShell** (Mar 2026 beta).
- **Generic mode:** `--lang generic` — line-aware regex-style matcher for any text file (ERB, Jinja templates, INI, etc.); no AST, just `pattern-regex`/string matching.

**Semgrep Secrets (commercial product — must support rule-shape parity):**
- 630+ credential type detectors (AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Twilio, OpenAI, Anthropic, HuggingFace, PyPI, npm, Cargo, Docker, Datadog, PagerDuty, Snowflake, MongoDB Atlas, Postgres URI, MySQL URI, Redis URI, JWT, generic high-entropy).
- Entropy heuristic + regex + optional `validators:` block per rule (HTTP call to vendor's verify endpoint).
- `--secrets` flag enables the Secrets ruleset.
- Output schema adds `validation_state: VALID | INVALID | NO_VALIDATOR | VALIDATION_ERROR`.
- Custom secrets supported under multiple active policies (Feb 2026 fix).

**Semgrep Supply Chain (commercial — must support manifest scanning + reachability):**
- 12 languages × 15 package managers: npm (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), pip (`requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`), Maven (`pom.xml`), Gradle (`build.gradle`, `build.gradle.kts`), Cargo (`Cargo.lock`), Composer (`composer.lock`), RubyGems (`Gemfile.lock`), Go modules (`go.mod`, `go.sum`), NuGet (`packages.config`, `*.csproj`), Hex (`mix.lock`), Pub (`pubspec.lock`), SwiftPM (`Package.resolved`).
- **Rust reachability** (Apr 2026) — call-graph + Cargo source scan to mark whether the vuln function is reached.
- **Lockfile-less scanning for Java/Kotlin** (Mar 2026 beta) — synthesises dep graph from `pom.xml`/`build.gradle` directly.
- `SEMGREP_LOCAL_BUILD_ENV` env var (Feb 2026) — JSON object of env vars to pass to package managers during dep resolution.
- SBOM export (CycloneDX, SPDX) with dependency-path information (Apr 2026).
- Auto-generated PRs to upgrade vulnerable deps to safe versions ("Upgrade Guidance").

**MCP server (`semgrep mcp`) — first-class subcommand (must clone):**
- Subcommand `lancer-semgrep mcp` starts an MCP server (stdio or HTTP transport).
- Exposes 8+ tools to MCP clients (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code):
  1. `semgrep_scan` — scan a directory with optional rule config.
  2. `semgrep_scan_with_custom_rule` — scan with a one-shot ad-hoc rule string.
  3. `semgrep_list_rules` — list available rules, optionally filtered by language.
  4. `semgrep_get_supported_languages` — enumerate supported languages.
  5. `semgrep_rule_schema` — return the JSON schema for a rule file (for AI rule generation).
  6. `semgrep_analyze_results` — re-analyse a previously emitted JSON result file.
  7. `semgrep_create_rule` — author a rule (pattern, language, message, severity) and save to a path.
  8. `semgrep_filter_results` — narrow scan results by rule ID, language, severity, path glob, or message substring.
- DNS rebinding protection on the HTTP transport (Feb 2026).
- MCP hooks for Claude Code / Cursor retrieve custom rules from the Semgrep Registry (Feb 2026).
- Bundled with **Hooks + Skills** in the Semgrep Plugin install (Mar 2026) — agentic hooks for Windsurf, Cursor, Claude Code.
- Default config runs Code + Supply Chain + Secrets in one MCP server.
- Clean output prompts AI agent to regenerate code until findings clear.

**Semgrep AppSec platform (commercial cloud — REST-API surface to mirror):**
- `POST /api/v1/findings/upload` — upload CLI scan results.
- `GET /api/v1/projects` — list projects + scan history.
- Policies, Managed Scans (server-side cron), branch-scoped scanning.
- AI Auto-Triage ("Semgrep Multimodal", née "Assistant") — LLM rates findings TP/FP/Severity with 97% agreement claim.
- "AI-powered detection" (Mar 2026) — beta IDOR / broken-authz detector that combines LLM reasoning with Semgrep findings.
- Network Broker (single-pubkey, Feb 2026) — on-prem agent for scanning private repos behind a firewall.
- Semgrep Guardian — PR-merge gate; Supply Chain hook support added Apr 2026.
- "Click to Fix" → renamed **Autofix** (Mar 2026) — AI-generated fix PRs.
- AWS Bedrock BYOK with IAM role-assumption (Apr 2026).
- Jira ticketing integration; findings API includes AI-detected findings.

**CLI flags newly important (2025–2026):**
- `--x-mem-policy <aggressive|balanced>` — OCaml GC mode (Pro). Map to a Rust `mimalloc`/`jemalloc`/`stdalloc` selection at link time + a per-run hint.
- `--secrets` — enable Secrets product.
- `--supply-chain` — enable Supply Chain scanning.
- `--code` — enable Semgrep Code (default if no other product flag set).
- `--oss-only` — disable Pro features even if logged in.
- `--matching-explanations` — emit per-finding match-tree explanation (debugging rules).
- `--text` (default) — explicit name for the default text format.
- `--trace` / `--trace-endpoint <url>` — OpenTelemetry trace export.
- `--rewrite-rule-ids` / `--no-rewrite-rule-ids` — toggle the `path.to.rule.id` → `id` rewrite.
- `--scan-unknown-extensions` — try to scan files whose extension we don't recognise (uses content sniffing).
- `--use-git` / `--no-git` — toggle git-aware target enumeration.
- `--force-color` / `--no-color` — terminal colour override.
- `--show-supported-languages` — print the language matrix and exit.
- `--registry-caching` — cache registry rule packs locally.

## Engineering hard parts

**Tree-sitter parsing across 30+ languages.** Each tree-sitter grammar has its own naming conventions (node kinds, field names). We need a per-language **node-kind canonicaliser** that maps grammar-specific names (`function_definition` in Python vs `function_declaration` in JS vs `method_declaration` in Java) onto a uniform query layer. Roughly 200-300 LOC per language to canonicalise the dozen-ish node kinds Semgrep patterns actually reference.

**Pattern matching DSL semantics.**
- **Ellipsis (`...`) matching.** Inside a function body, `foo(); ...; bar()` matches `foo(); x = 1; y = 2; bar()` (statement-level ellipsis). Inside an argument list, `f($X, ...)` matches `f(a, b, c, d)` (argument-level). Inside an expression, `$X.method(...)` matches `obj.chain.method(a, b)`. Disambiguation depends on the **enclosing AST context**, not the syntactic `...` itself.
- **Deep matching.** A pattern like `subprocess.call(...)` should match `subprocess.call(...)` regardless of how many statements precede it inside an arbitrarily-nested function. The engine walks every AST subtree, attempting unification, and reports all matching subtrees.
- **Polymorphic metavariables.** `$X` can match an identifier, a literal, a function call, even a whole block. The rule writer constrains via `metavariable-regex` / `metavariable-pattern` / `metavariable-type`.
- **Ordered vs unordered.** Statement sequences are ordered (ellipsis matches a contiguous gap); function arguments are ordered; struct fields are unordered (in some languages); dictionary entries are unordered. The matcher carries an "ordered" flag per node kind.

**Taint analysis.**
- Forward dataflow over the per-function CFG built from the AST.
- State at each program point is a map `Var → TaintLabel`.
- Assignments propagate taint from RHS to LHS.
- Function calls (intra-procedural mode) treat the return as the LUB of the arguments' taint, unless a sanitizer pattern matches the call site.
- Sanitizer patterns are matched per-program-point; when matched, the sanitized variable's taint label is cleared at the matching node.
- Propagators encode custom flow rules (e.g., f-string interpolation propagates taint from inputs to output).

**Inter-procedural analysis.** OSS Semgrep is intra-procedural — taint dies at function boundaries. Pro Semgrep computes per-function summaries: "given taint on parameters P, taint flows out via return value R and via mutations to global G". A summary is a graph (input vars → output vars with optional sanitizer guards). Computing summaries requires a call-graph + fixed-point over the workspace; the worst case is the whole codebase. Caching summaries between runs is essential.

**Autofix synthesis.** The rule's `fix:` is a template string with `$X` placeholders. To apply: take the rule's match, substitute metavariable bindings into the template, generate a text replacement. The hard part is **preserving formatting** — the replacement must respect indentation, line endings, and (ideally) the surrounding code's style. Semgrep's OCaml engine does this via source-mapped substitution; in Rust we'd use the byte range of the match and the byte ranges of each metavariable binding.

**Performance.** Multi-million-LOC monorepos (e.g., Chromium) must scan in seconds-to-minutes, not hours. Three levers:
1. **Parallelism.** `rayon::par_iter` over `(targets × rules)`. Cap with `--jobs`.
2. **AST cache.** Parse each target once; reuse the parsed tree-sitter tree across all rules targeting that language.
3. **Pattern pre-filter.** Each compiled pattern includes a set of **required string literals** (`subprocess.call`, `cursor.execute`). The target's source text is searched for these strings (Boyer-Moore via `memchr`) before attempting AST unification. If no required string is present, the rule is skipped for that file.

**Rule cache.** Compiled patterns (parsed AST + required-string set + ellipsis positions) are cached on disk keyed by rule SHA, so successive runs over the same rules pay zero parse cost.

**Baseline diff.** `--baseline-commit SHA1` invokes `git diff SHA1...HEAD --name-only` to get changed files, then `git diff SHA1...HEAD <file>` for hunk ranges. Findings whose ranges don't intersect any added/changed hunk (expanded by `--diff-depth` lines) are suppressed. The intent is "only flag what this PR introduced".

**Tree-sitter grammar quirks.** Each grammar has known edge cases (template literals, JSX, type annotations, macros in Rust, generics) where the tree shape differs from naive expectations. Each language ships with a per-language test suite of patterns that round-trip through the engine.

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| Tree-sitter parsers (core) | `tree-sitter` 0.22 | Runtime |
| Per-language grammars | `tree-sitter-python` 0.21, `tree-sitter-javascript` 0.21, `tree-sitter-typescript`, `tree-sitter-go`, `tree-sitter-rust`, `tree-sitter-java`, `tree-sitter-ruby`, `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-c-sharp`, `tree-sitter-php`, `tree-sitter-bash`, `tree-sitter-yaml`, `tree-sitter-dockerfile`, `tree-sitter-hcl`, `tree-sitter-solidity` (Joran-Dirk Greef's), `tree-sitter-kotlin`, `tree-sitter-swift`, `tree-sitter-scala`, `tree-sitter-lua`, `tree-sitter-r`, `tree-sitter-elixir`, `tree-sitter-clojure`, `tree-sitter-ocaml` | One crate per language |
| Rule YAML loading | `serde_yaml` 0.9 | Rule deserialization |
| YAML schema validation | hand-rolled over serde + `jsonschema` 0.18 | Per-rule schema |
| Metavariable regex | `regex` 1.11 | `metavariable-regex` constraints |
| Generic regex match | `regex` 1.11, `memchr` 2.7 | Pattern pre-filter |
| CFG / dataflow graph | `petgraph` 0.6 | CFG + call graph + taint propagation |
| Parallelism | `rayon` 1.11 | `(targets × rules)` |
| File walking | `walkdir` 2.5 + `ignore` 0.4 | Respects `.gitignore` / `.semgrepignore` |
| Glob matching | `globset` 0.4 | `--include` / `--exclude` |
| SARIF output | `serde_sarif` 0.4 | GitHub code-scanning |
| GitLab SAST | hand-rolled via `serde_json` | Schema documented by GitLab |
| JSON | `serde_json` 1.0 | Semgrep-native + GitLab |
| JUnit XML | `junit-report` 0.8 | CI integration |
| CLI | `clap` 4.4 | Mirror Semgrep flag names |
| Logging | `tracing` 0.1 + `tracing-subscriber` 0.3 | Structured logs |
| HTTP for registry | `reqwest` 0.12 + `rustls` | Pull `p/...` packs from registry |
| Cache | `redb` 2.x | Rule cache + target cache |
| Hashing | `sha2` 0.10, `blake3` 1.5 | Cache keys |
| Git ops | `git2` 0.19 or shell-out `git` | Baseline diff |
| Errors | `eyre` 0.6 | Match Aderyn/Slither |
| Async runtime | `tokio` 1.40 | Registry HTTP + LSP |
| Terminal colour | `owo-colors` 4.x | Text output |
| Diff rendering | `similar` 2.6 | Autofix diff preview |
| Schema for templates | `tinytemplate` 1.2 or hand-rolled | `fix:` substitution |
| Process spawn | `duct` 0.13 | Pro engine subprocess (stub) |

Per-language grammar crates pull in their C grammars and compile via `cc-rs`. Build time is the biggest cost — we add a Cargo feature per language so users can compile only the grammars they need.

## Bug bounty workflows

- **Audit a target's open-source codebase before testing the deployed app.** Before opening Burp on `target.com`, clone their public GitHub repos (org-wide) and run `lancer-semgrep --config p/owasp-top-ten --config p/secrets`. Patterns the engine finds in dev code very often persist into prod. Look for: SSRF (URL constructed from user input), SQLi (string concatenation into queries), authz holes (route handlers without `@requires_auth` decorator), prototype pollution (`Object.assign({}, req.body)`), open redirects (`res.redirect(req.query.url)`), JWT secrets in source, hard-coded API keys.
- **Audit a dependency's source.** When a target ships an unusual OAuth library or in-house crypto helper, fetch its source from npm/PyPI/crates.io and scan with `p/security-audit`. Often the dep itself has known patterns Semgrep recognises.
- **CI integration in personal bug-bounty automation.** Hook `lancer-semgrep ci` into your auto-recon pipeline so when your scanner adds a new target's open-source repo, Semgrep runs and posts findings into your tracker. Combined with subfinder + GitHub recon, this scales reconnaissance dramatically.
- **Post-bug write-up.** After confirming a vuln on one endpoint, write a tiny custom rule (`pattern: db.query("..." + $X)`) and rescan the codebase. Almost always there are 5-15 sibling bugs. Submit them as a batch.
- **Bug-class-of-the-week.** New CVE drops (e.g., `jsonwebtoken` insecure default, `lodash.template` prototype pollution, `pickle.loads` arbitrary code exec)? Write a 10-line Semgrep rule for the pattern, scan every target's vendored deps. New bounties.
- **Diff scans on monitored repos.** Use `--baseline-commit` against yesterday's HEAD on a watchlist of target repos. New commits trigger new scans; new findings surface as alerts.
- **Rule mining from existing audits.** When an audit report mentions a class of bug ("the team's logger leaks user PII to console"), encode it as a Semgrep rule. Apply across the rest of the bug-bounty target list.
- **MCP server in Lancer.** Expose `lancer-semgrep` over MCP so Claude/Cursor can request scans interactively while triaging a target. "Find any SSRFs in the codebase under `services/`."

## 2024–2026 state

- **Semgrep 1.0 (2023):** rename from `sgrep`; stable rule format; Semgrep AppSec rebrand of cloud product (formerly `r2c`).
- **Semgrep 1.30–1.50 (2024):** OCaml engine rewrite of taint mode for inter-file analysis (Pro); experimental Apex (Salesforce), Bicep (Azure), Cairo (StarkNet), Move (Sui/Aptos) support; Solidity coverage hardened; multi-line metavariable propagation in f-strings.
- **Semgrep 1.55–1.80 (mid 2024):** Semgrep Secrets GA (validated secret detection — actually attempts API calls against suspected keys to confirm validity); Semgrep Supply Chain reachability mode generally available; new registry packs for ML/AI security (prompt injection in Python+LangChain code).
- **Semgrep 1.85–1.95 (late 2024):** Improved Java generics handling; better Kotlin/Swift support; experimental Rust macro expansion in patterns; experimental Solidity `unchecked { ... }` block awareness.
- **Semgrep 1.100+ (Q1 2025):** OSS engine taint improvements (sanitizer-by-side-effect); `mode: extract` for sub-language scanning (e.g., SQL strings inside Python — scan the embedded SQL with SQL rules); Semgrep AppSec platform UI overhaul.
- **Semgrep 1.110+ (mid 2025):** **MCP server** stub upstream — third-party `semgrep-mcp` runner emerges; Claude/Cursor can call Semgrep scans as a tool. Custom-rule scaffolding from natural language via Semgrep AppSec.
- **Semgrep 1.120+ (late 2025–2026):** Pro engine reachability for npm/PyPI cross-function call resolution; experimental Carbon / Mojo / Zig grammars; AI-assisted rule generation; `--ai-rank` for severity scoring of findings; AppSec "Genai" features (find LLM prompt injection patterns, find unsafe `langchain.tools` registrations).
- **Community ecosystem:** semgrep-rules repo has 3500+ rules; semgrep-rules-managed (commercial) ships another 2000+; per-language community packs (`p/react-best-practices`, `p/nextjs-strict`) maintained by external contributors; integrations into GitHub Actions, GitLab CI, Bitbucket, CircleCI, Jenkins, Azure DevOps.

### Note — deep-research update 2026-05-30

Upstream at **v1.164.0** (May 27, 2026); 331 total releases since v1.0. Reconciled this plan against current state:

- **MCP server is now first-class.** `semgrep mcp` ships in-tree at `semgrep/mcp` and bundles into the "Semgrep Plugin" for Claude Code / Cursor / Windsurf / VS Code (Code + Supply Chain + Secrets in one MCP). DNS rebinding protection on HTTP transport (Feb 2026). Hooks pull custom rules from Registry. Exposes 8 tools: scan/scan-with-custom-rule/list-rules/get-supported-languages/rule-schema/analyze-results/create-rule/filter-results. `lancer-semgrep mcp` is now a P0 subcommand, not "wire AI augmentation".
- **Interfile engine redesigned (Apr 2026)** — 20–40% perf gain, taint-config phase parallelised over `--jobs`. Mirror this in `semgrep-taint/src/interproc.rs` (parallel config compile via `rayon::par_iter` over rules).
- **Taint mode upgrades:** variadic-function support (Apr 2026), assignment-tracking accuracy (Feb 2026), Scala `for-yield` flow (Feb 2026), Scala lambda + cross-file globals (Mar 2026), SARIF trace fix with correct file URI + sink call trace in `codeFlows` (Apr 2026).
- **New languages since plan v1:** **OpenFGA** (authz language, Feb 2026 experimental), **PowerShell** (Mar 2026 beta), Scala tree-sitter rewrite (Apr 2026). Add to `tree-sitter-langs` matrix.
- **Supply Chain expansion:** Rust reachability GA (Apr 2026), Java/Kotlin lockfile-less scan (Mar 2026 beta), `SEMGREP_LOCAL_BUILD_ENV` (Feb 2026), SBOM dep-path export (Apr 2026), 12 langs × 15 package managers.
- **Secrets:** 630+ credential detectors; validators with 30-second timeout (down from 15 min in Mar 2026); `validation_state` field in output; entropy + regex + live-API verification.
- **AppSec / Multimodal (rebrand of "Assistant", Mar 2026):** AI-powered IDOR/broken-authz detection (Mar 2026 beta), Autofix (renamed from "Click to Fix"), Bedrock BYOK with IAM (Apr 2026), Managed Scans on non-default branches, Semgrep Guardian Supply Chain hooks.
- **New CLI flags to clone:** `--x-mem-policy {aggressive|balanced}`, `--secrets`, `--supply-chain`, `--code`, `--matching-explanations`, `--trace`/`--trace-endpoint`, `--show-supported-languages`, `--scan-unknown-extensions`. CLI retry logic now extends to HTTP 429 + 5xx.
- **Rule format additions:** `mode: extract` (sub-language scanning, e.g., embedded SQL in Python), `mode: secrets` (entropy + `validators:`), explicit `mode: search`, **taint labels** with `requires:` boolean expressions, taint **by-side-effect** sanitizers, `lower()`/`upper()` in `metavariable-comparison`, symbolic propagation.
- **OpenGrep fork** — Semgrep was forked by community as OpenGrep over commercial-license concerns; parity work in `lancer-semgrep` should target both upstreams' OSS rule format (largely identical for now).
- **OSS LOC vs Pro:** Pro-only features (interfile taint, type-aware metavariables, supply-chain reachability, Secrets validators) remain closed-source; our Rust port reimplements them from public docs + observable behaviour.

### Research note — 2026-05-31 (post-1.164 deltas)

Direct walk of `semgrep.dev/docs/release-notes/february-2026` + Apr/May 2026 monthly bulletins. Items missed earlier:

- **JSON rule parsing 5× speedup (Apr 2026).** Hand-written RFC 8259 parser replaces serde-json roundtrip; measured 382 MB rule pack drops from 134s → 28s. Our `serde_json` path won't hit this — must consider `simd-json` (Rust) for the same scale of rule packs, or a custom RFC 8259 parser tuned for Semgrep's rule shape (mostly nested maps + arrays of strings).
- **PHP becomes 11th reachability language (Apr 2026).** Supply Chain `--reachability` now supports PHP. List of reachability-enabled languages: Python, JS, TS, Java, Go, Ruby, C#, Kotlin, Scala, Rust, **PHP**. Add PHP reachability to our supply-chain matrix.
- **Improved field-tracking capacity per object (Feb 2026).** Default object-field tracking limit raised — previously dropped fields after N, now tracks substantially more. Reduces false negatives. Our taint engine must expose `--max-fields-tracked-per-object N` flag for parity.
- **Case-insensitive metavariable-comparison (Feb 2026).** `metavariable-comparison: { comparison: "lower($X) == 'foo'" }` and `upper(...)` now valid functions in the comparison DSL. Our DSL parser must register `lower`/`upper` as built-ins.
- **MCP server `refs` parameter (May 2026).** `semgrep_findings` MCP tool accepts `refs: ["main", "release/1.5"]` to filter findings by branch. Defaults to primary branch when omitted. Our MCP server's `get_findings` tool exposes the same parameter.
- **MCP `autotriage_verdict` optional (May 2026).** Findings without an AI verdict still returned when this filter is omitted. Our MCP must distinguish "filter unset" from "filter = null".
- **MCP OAuth for Streamable HTTP transport (May 2026).** Previously the MCP server's HTTP transport was anonymous on localhost; now OAuth is **required** when using `--transport http`. The stdio transport (used by Claude Desktop) remains anonymous. Our MCP server must enforce the same.
- **MCP DNS-rebinding protection (Feb 2026).** Bind to `127.0.0.1` only by default; reject any `Host:` header that resolves to a non-loopback IP. Our `lancer-semgrep mcp` HTTP transport must enforce both.
- **`--x-mem-policy` Pro-only (Feb 2026).** `aggressive` (default; releases heap aggressively, peak RAM lower) vs `balanced` (compromises peak-RAM for speed; OCaml GC less aggressive). Pro-only upstream — we don't have a Pro/OSS gate, but the flag still applies. Our Rust port maps `aggressive`/`balanced` to `mimalloc` `MIMALLOC_PURGE_DECOMMITS` vs default purge behaviour, or to `jemalloc` `narenas` tuning.
- **`SEMGREP_LOCAL_BUILD_ENV` — JSON, not string (Feb 2026).** The env var is a JSON object string like `'{"PIP_INDEX_URL":"https://internal/...","CARGO_NET_GIT_FETCH_WITH_CLI":"true"}'` — passed wholesale to each invoked package manager (`pip install`, `cargo metadata`, `npm install`). Our Supply-Chain resolver passes this through.
- **CVE link → Advisory page (Feb 2026).** Findings with CVEs now link to Semgrep Advisory pages (with reachability info + remediation), not generic NIST CVE pages. Our finding emitter must construct `https://semgrep.dev/advisories/<id>` URLs when an advisory exists.
- **Custom secrets in multi-policy projects (Feb 2026).** When a project has multiple Secrets policies active, custom-secret patterns can now be attached to any of them (previously only to the default). Our policy resolver must accept the same.
- **Project tags update gating (Feb 2026).** Project tags can no longer be modified via `.semgrepconfig.yml` changes in PR scans — only during full scans. Forces audit trail. Our equivalent: separate read-only vs read-write policy contexts.
- **Network Broker single-pubkey enforcement (Feb 2026).** On-prem Network Broker now refuses to register a second public key (was multiple). Forces operators to rotate via revoke-then-add flow. If we ever ship a network broker companion, mirror.
- **Scala for-yield taint (Feb 2026).** Scala's `for x <- xs yield f(x)` desugaring now models taint flow correctly (previously broke). Implicit block scopes parse fix. Our Scala AST walker must mirror.
- **Taint through nested functions improved (Pro, Feb 2026).** Closure capture now tracks taint through inner functions. Our Pro-equivalent must implement closure-aware taint propagation.

Sources: [Semgrep February 2026 release notes](https://semgrep.dev/docs/release-notes/february-2026), [Semgrep January 2026 release notes](https://semgrep.dev/docs/release-notes/january-2026), [Semgrep releases on GitHub](https://github.com/semgrep/semgrep/releases), [Semgrep MCP](https://semgrep.dev/docs/mcp).

## AI augmentation ideas

- **LLM-generated rules from natural language.** "Find SSRF in this code." Claude reads a few sample files, writes a Semgrep rule (`pattern: requests.get($URL)` with `metavariable-pattern: $URL = request.GET.get(...)`), tests it on the corpus, refines until matches look right. Saved as a custom rule for reuse.
- **Auto-classify findings (TP vs FP).** Each finding plus surrounding context goes to an LLM judge; LLM rates likely real-vuln 0-100 with one-sentence justification. Threshold-suppress in the report.
- **Suggest sanitizer patterns.** Taint mode emitted a finding, but the auditor knows the codebase has an in-house sanitizer (`safe_html(x)`). LLM reads the codebase, identifies sanitizer-shaped functions, proposes adding them to `pattern-sanitizers` of relevant rules.
- **Summarise a finding cluster.** A 200-finding report often has 10-15 root causes. LLM clusters by semantic similarity ("all 47 of these are the same missing-CSRF pattern across forms"), collapsing the report into actionable groups.
- **Per-language rule variants.** Write one canonical rule for Python (`requests.get($URL)` SSRF). LLM produces JS (`axios.get($URL)`), Go (`http.Get($URL)`), Ruby (`Net::HTTP.get(...)`), Java (`HttpClient.send(...)`) variants automatically.
- **Auto-fix synthesis.** Given a finding + AST snippet, LLM proposes a patch as a unified diff. Often correct for mechanical fixes (`shell=True` → `shell=False`, `eval(...)` → `ast.literal_eval(...)`).
- **Rule explanation in plain language.** Generic Semgrep messages are short. LLM rewrites per-finding with actual variable/function names from the codebase ("In `views/user.py`, line 47, `cursor.execute(sql)` builds `sql` from `request.GET['q']` via the string concat on line 45 — SQL injection.").
- **Rule mining from historical audits.** Feed past pentest reports' findings + the matching code; LLM extracts the underlying pattern as a Semgrep rule. Repeat across many reports → ever-growing private rule library.
- **Conversational triage.** Chat pane with the current finding loaded as context. "Is this exploitable given the input is validated upstream in `middleware/auth.py`?" LLM walks the chain.

## Implementation phases (16-week roadmap)

Semgrep's surface is large but the OSS engine is conceptually tight. Allow extra time for the multi-language matrix.

**Week 1 — Workspace bootstrap + tree-sitter base.** Cargo workspace (6 crates as above). Wire `tree-sitter-python` and `tree-sitter-javascript` as the v0 languages. Smoke test: parse a Python file, dump tree-sitter AST.

**Week 2 — Pattern parsing.** Implement metavariable lexer extension (anything starting with `$` in a pattern string becomes a metavar token; `...` becomes an ellipsis token). Parse pattern strings using the same tree-sitter grammar as targets. Round-trip simple patterns (`f($X)`, `import $M`).

**Week 3 — Matcher v0 (Python only).** Implement structural unification. Walk the source AST, attempt to unify each subtree against the pattern AST. Bind metavariables; succeed if unification succeeds. Test against a 10-rule Python pack from semgrep-rules.

**Week 4 — Ellipsis + deep matching.** Statement-level ellipsis (`foo(); ...; bar()`), argument-level ellipsis (`f($X, ...)`), expression-level ellipsis. Deep matching: walk every subtree, not just the top.

**Week 5 — Pattern combinators.** Implement `patterns:`, `pattern-either:`, `pattern-not:`, `pattern-inside:`, `pattern-not-inside:`, `pattern-regex:`, `metavariable-regex:`, `metavariable-comparison:`, `metavariable-pattern:`. Test against the canonical `p/python` pack.

**Week 6 — Add JavaScript + TypeScript.** Per-language node-kind canonicaliser. Run the same matcher with the new grammars. Test against `p/javascript`.

**Week 7 — CFG + intra-procedural taint.** Per-function CFG construction from AST. Forward dataflow with taint lattice. Sources/sinks/sanitizers via pattern matching. Test against a hand-rolled SSRF rule and an SQLi rule on a sample Flask app.

**Week 8 — Autofix.** Apply rule's `fix:` template by substituting metavariable bindings. Generate unified diff via `similar`. CLI flag `--autofix` to write fixes in place.

**Week 9 — Add Go + Ruby + Java.** Per-language canonicalisers; rerun matcher and taint. Test against `p/golang`, `p/ruby`, `p/java`.

**Week 10 — Add C, C++, C#, PHP, Rust, Kotlin, Swift.** Bulk language addition. Most are straightforward once Python+JS+Go work. Solidity grammar pulled in for the `lancer-aderyn` / `lancer-slither` overlap.

**Week 11 — CLI + output formats.** Mirror Semgrep flag surface. SARIF (`serde_sarif`), GitLab SAST (hand-rolled), JUnit XML, text (colourised), JSON. Per-rule timing via `--time`.

**Week 12 — Performance: parallelism + AST cache + pre-filter.** `rayon::par_iter` over `(targets × rules)`. Per-target tree-sitter cache keyed by content hash. Pattern pre-filter using required string literals + `memchr`. Benchmark against upstream on 100k-LOC corpus; aim within 2-3x of OCaml engine.

**Week 13 — Registry + baseline diff.** Pull `p/...` packs from the Semgrep Registry via HTTPS. Per-pack cache. `--baseline-commit` via `git2`. `--diff-depth` context expansion.

**Week 14 — Join mode + supply chain.** `mode: join` cross-file rules. Supply-chain mode: scan `package.json` / `requirements.txt` / `Cargo.lock` etc. against an advisory feed; mark reachable via OSS engine intra-procedural taint.

**Week 15 — Rule cache + test runner.** On-disk rule compilation cache (`redb`). `lancer-semgrep test` rule-test runner (rule.yaml + rule.py with `// ruleid:` and `// ok:` annotations).

**Week 16 — AI augmentation + MCP server + polish.** Wire LLM-generated rules from natural language. Wire `--ai-rank` for severity scoring. MCP server module exposing each rule (or rule pack) as a tool. Performance pass. Drop-in compat smoke test: pipe `lancer-semgrep`'s JSON through `semgrep` itself to verify schema.

---

## GUI (Lancer-standard pattern)

`lancer-semgrep` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-semgrep-cli` companion binary), but the **plain `lancer-semgrep` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-semgrep/`, `%APPDATA%\lancer-semgrep\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-semgrep-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-semgrep.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-semgrep.exe` (double-click opens the GUI window).
- Linux: `build/lancer-semgrep` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-semgrep` (bundled into `lancer-semgrep.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-semgrep/
├── Cargo.toml                  # workspace manifest
├── Cargo.lock                  # committed (binary, not library)
├── crates/
│   ├── lancer-semgrep/         # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── semgrep-core/           # rule engine, matcher, taint orchestration
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── tree-sitter-langs/      # bundled per-language tree-sitter grammars
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── semgrep-rules/          # rule loader + registry sync
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── semgrep-taint/          # forward/backward dataflow
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── semgrep-output/         # SARIF / JSON / GitLab / text emit
│       ├── Cargo.toml
│       └── src/lib.rs
├── build.bat                   # Windows build → build/lancer-semgrep.exe
├── build-windows.bat           # Windows packaged dist → dist/lancer-semgrep-windows-x86_64/
├── build-linux.sh              # Linux build → build/lancer-semgrep
├── .gitignore                  # plan.md (local-only) + target/ + build/ + dist/
├── README.md                   # public-facing (pushed to GitHub)
└── plan.md                     # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-semgrep.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-semgrep-windows-x86_64\bin\lancer-semgrep.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-semgrep`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by `cc-rs` for tree-sitter grammar C compilation)
- C compiler discoverable on PATH (`cc`/`clang`/`gcc`/MSVC) — each tree-sitter grammar crate compiles its C source via `cc-rs`
- Optional: `git` on PATH for `--baseline-commit` (else uses `git2` libgit2 binding)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
