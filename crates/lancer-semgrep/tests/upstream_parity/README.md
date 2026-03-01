# Upstream-parity test corpus

Each subdirectory is one parity case. It contains exactly three files:

- `rule.yaml` — the input rule (or `rules:`) document.
- `target.<ext>` — a single source file. Extension picks the language.
- `expected.json` — the canonical Semgrep-shaped JSON output (`{ results: [...] }`).

The harness loads `rule.yaml`, runs the matcher / taint engine on `target.<ext>`,
emits Semgrep-native JSON, and asserts it matches `expected.json` (after both
are pretty-printed and sorted by `{file, rule_id, range.start.line}`).

Field-level comparisons:
- `version`, `paths.scanned[]` and `time.*` are ignored (volatile).
- `results[].extra.lines` is ignored (can differ in display).
- All other fields must agree exactly.

New parity cases are encouraged — drop a folder in here and the harness picks
it up automatically.
