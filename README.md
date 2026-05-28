# Safe Scan

Safe Scan is a small diagnostic CLI for finding pathological cache
directories on macOS, especially under `~/Library/Caches`.

It is designed for the failure mode where a cache is not merely large in bytes,
but has huge fanout: hundreds of thousands or millions of tiny files or
subdirectories. In that shape, normal cleanup tools can hang because they try to
fully enumerate or stat the tree.

Safe Scan does not delete anything.

The primary command is `safescan`. The install also exposes `safe-scan` as an
alias if you prefer the hyphenated form.

## Install for development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Scan

```bash
safescan scan ~/Library/Caches --threshold 40 --min-prune-depth 2 --max-depth 25
```

The scan command walks depth-first. For each directory it counts only immediate
entries and stops counting once `--threshold` is reached. If the current depth is
at least `--min-prune-depth`, that directory is reported as a candidate and is
not scanned recursively.

Example output:

```text
CANDIDATE depth=4 entries>=40 /Users/mikey/Library/Caches/foo/bar/broken-cache
CANDIDATE depth=5 entries>=40 /Users/mikey/Library/Caches/another/tool/tmp/models
ERROR     depth=3 PermissionError /Users/mikey/Library/Caches/private
```

Useful options:

- `--threshold`: immediate-entry count that marks a candidate. Default: `40`.
- `--min-prune-depth`: do not report or prune above this depth. Default: `2`.
- `--max-depth`: maximum depth to inspect. Default: `25`.
- `--max-dirs`: maximum directories to visit before stopping. Default: `100000`.

Depth starts at `0` for the root path.

## Inspect

```bash
safescan inspect /path/to/candidate --sample 10000
```

The inspect command samples immediate entries only. It reports sampled file and
directory counts, sampled file-size statistics, tiny-file counts, and a simple
`tiny_file_cache_explosion` yes/no signal.

Example output:

```text
INSPECT path=/path/to/candidate
sampled_entries=10000
sampled_files=9988
sampled_dirs=12
sampled_other=0
sample_truncated=yes
entry_errors=0
mean_file_size=1812
median_file_size=1230
tiny_files<=16384=9988
tiny_file_ratio=1.000
tiny_file_cache_explosion=yes
```

The tiny-file signal is intentionally conservative: it returns `yes` when at
least 20 sampled regular files are at or below the tiny-size threshold and at
least 80% of sampled regular files are tiny. The default tiny-size threshold is
16 KiB.

## Run tests

```bash
PYTHONPATH=src python -m unittest
```
