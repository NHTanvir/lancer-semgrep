# CLAUDE.md

Project-specific instructions for Claude Code sessions working on this repo.

## What this is

`lancer-semgrep` — a Rust clone of [Semgrep](https://github.com/semgrep/semgrep)
with 100% feature parity to upstream OSS, plus a native eframe/egui GUI on
top. Part of the Lancer bug-bounty toolkit (one of 19 sibling tools).

The blueprint lives in `plan.md` (gitignored — local only). Read it first if
you need vocabulary, feature lists, or 2025–2026 upstream deltas.

## Workspace layout

```
.
├── Cargo.toml                    # workspace manifest
├── crates/
│   ├── lancer-semgrep/           # binary + lib (CLI, GUI, MCP, AI, AppSec)
│   ├── semgrep-core/             # vocabulary + matcher + cache + baseline
│   │                             # + supply-chain + secrets + autofix + explain
│   │                             # + generic mode
│   ├── tree-sitter-langs/        # 26 per-language adapters, feature-gated
│   ├── semgrep-rules/            # YAML loader + registry sync + cache
│   ├── semgrep-taint/            # CFG + dataflow + interproc + variadic
│   └── semgrep-output/           # text/JSON/SARIF/GitLab/JUnit/emacs/vim/GHA
├── build.bat                     # Windows debug build
├── build-windows.bat             # Windows dist build
├── build-linux.sh                # Linux/macOS build (`--install` → .desktop)
└── build-mac.sh                  # macOS .app bundle via cargo-bundle
```

## Dependency-graph rule (do not re-add the cycle)

`semgrep-core` defines the vocabulary (`Language`, `SgNode`, `CanonicalKind`,
`Rule`, `Finding`, ...). Other crates depend on it. **`semgrep-core` itself
must not depend on `tree-sitter-langs` or `semgrep-output`** — both depend
back into `semgrep-core`. Cargo will error on a path cycle.

Concretely:
- `tree-sitter-langs` → `semgrep-core` (uses `Language` + `CanonicalKind`)
- `semgrep-output` → `semgrep-core` (serialises `Finding`)
- `semgrep-rules`, `semgrep-taint` → `semgrep-core`
- `lancer-semgrep` (binary) → everyone, since it's the integration layer

Scan orchestration that needs both `semgrep-core` types AND `tree-sitter-langs`
adapters lives in `lancer-semgrep/src/scan/` for this reason — not in
`semgrep-core`.

## Build status

`cargo metadata` parses cleanly. `cargo check` runs into grammar-crate
version conflicts: different community `tree-sitter-*` crates pin
incompatible `tree-sitter` core versions and conflict on the `links =
"tree-sitter"` native-library marker. Resolving this needs a careful pass
that pins every grammar crate to one shared major version of `tree-sitter`
(0.22 or 0.25 across the board).

Until that's done:
- **Don't run `cargo build` / `cargo check --workspace`** without a plan.
- `cargo check -p semgrep-core --no-default-features` will surface the same
  issue (the workspace resolver still walks optional deps).
- Per-crate `cargo metadata` always works.

## Conventions

- **Module per concern.** One file = one responsibility. Files growing past
  ~400 lines should be split.
- **Owned wire types, borrowed engine types.** `Finding`/`MetavarBindingSnapshot`
  are owned + serde. `Match<'a>`/`SgNode<'a>`/`MetavarBindings<'a>` borrow
  source bytes — no serde, no Sync requirement.
- **Stubs return `Err(...OssOnly)` or `Ok(empty)`** for unimplemented
  network/cloud paths. Do not panic.
- **CLI flag names mirror upstream exactly.** No silent rename / drop.
- **Pre-filter before AST unification.** Required-string scan via `memchr`
  is in `match_/pre_filter.rs`.
- **YAML rule shorthand canonicalisation** happens in `semgrep_rules::canonicalise`
  before serde deserialisation — `PatternOp` itself stays strictly typed.

## Where to add new things

- New CLI flag → `lancer-semgrep/src/cli/args.rs`
- New rule operator → `semgrep-core/src/rule/pattern.rs` (variant) + matcher
  arm + match-tree explainer arm
- New language → `tree-sitter-langs/src/adapters/<lang>.rs` + `canonical.rs`
  + Cargo feature flag
- New output format → `semgrep-output/src/<name>.rs` + `format.rs` + `lib.rs`
  dispatcher
- New MCP tool → `lancer-semgrep/src/mcp/tools/<name>.rs` + register in
  `tools/mod.rs::list` and `tools/mod.rs::call`
- New AppSec endpoint → `lancer-semgrep/src/appsec/<name>.rs`
- New AI feature → `lancer-semgrep/src/ai/<name>.rs`
- New supply-chain manifest → `semgrep-core/src/supply_chain/manifests.rs`
  (basename match) + parser stub

## Testing

- Per-crate `#[cfg(test)]` unit tests live next to the code they exercise.
- Cross-crate integration tests live under each crate's `tests/`.
- `tests/upstream_parity/` (under `lancer-semgrep`) is the parity corpus:
  each subdir holds `rule.yaml` + `target.<ext>` + `expected.json`. The
  `--self-test` harness walks it.
- `lancer-semgrep test <dir>` parses `// ruleid:` / `// ok:` annotations.

## Commit hygiene

- Commit messages: short, lowercase, conventional-commits-style
  (`feat:` / `fix:` / `docs:` / `refactor:` / `chore:`).
- Never push to master without explicit user instruction.
- `plan.md` is gitignored. Never commit it.

## Where to look first

| Looking for... | Read |
|---|---|
| Feature list, upstream deltas | `plan.md` |
| CLI surface | `crates/lancer-semgrep/src/cli/args.rs` |
| Workspace deps + versions | top-level `Cargo.toml` `[workspace.dependencies]` |
| Rule data model | `crates/semgrep-core/src/rule/` |
| Pattern matcher engine | `crates/semgrep-core/src/match_/` |
| Taint engine | `crates/semgrep-taint/` |
| Scan orchestrator | `crates/lancer-semgrep/src/scan/run.rs` |
| MCP server | `crates/lancer-semgrep/src/mcp/` |
| GUI | `crates/lancer-semgrep/src/gui/` (feature `gui`) |
