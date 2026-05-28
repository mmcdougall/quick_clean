# Agent Notes

This repository contains Safe Scan, a diagnostic-only Python CLI for finding
pathological cache directory fanout on macOS. The primary command is `safescan`;
`safe-scan` is also provided as a readable alias.

## Core Rules

- Do not add deletion, cleanup, or mutation behavior unless explicitly requested.
- Use `os.scandir()` for directory enumeration. Avoid recursive helpers such as
  `Path.rglob()`, `os.walk()`, `find`, or `du` for scanner behavior.
- Keep traversal bounded. Preserve max-depth and max-directory safeguards.
- Do not follow symlinks.
- Keep the command output simple enough to pipe into shell tools.

## Development Style

- Keep diffs small and focused. Check `git status --short` before finishing.
- Favor small, readable functions with descriptive names.
- Match the surrounding style, spacing, loop patterns, and file layout.
- Keep side effects local: helpers should either gather data or format output,
  but not both.
- Describe current behavior in comments and docs. Avoid prompt-era phrasing such
  as "now does" unless a historical comparison is the point.
- Keep `TODO` comments concise and tied to specific future work.

## Tests

Good tests are especially important for this project. The tool exists to avoid
expensive filesystem behavior, so tests should lock in both results and safety
properties.

- Add or update unit tests for behavior changes.
- Prefer temporary synthetic directory trees over real cache directories.
- Keep fixtures small and deterministic.
- Cover pruning behavior, `--min-prune-depth`, max-depth/max-dir limits,
  symlink handling, permission/error paths, inspect statistics, and CLI output
  when those areas change.
- Do not weaken tests just to match changed behavior; update expectations only
  when the behavior change is intentional.

Run the test suite:

```bash
PYTHONPATH=src python -m unittest
```
