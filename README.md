# Cache Canary

Cache Canary is a small diagnostic CLI for finding pathological cache
directories on macOS, especially under `~/Library/Caches`.

It is designed for the failure mode where a cache is not merely large in bytes,
but has huge fanout: hundreds of thousands or millions of tiny files or
subdirectories. In that shape, normal cleanup tools can hang because they try to
fully enumerate or stat the tree.

Cache Canary does not delete anything. When cleanup looks warranted, it can print
suggested `rm -rf` commands for human review and manual execution outside the
tool.

The primary command is `cache-canary`. The install also exposes `cachecanary`
as a compact alias. Cache Canary requires Python 3.9 or newer and has no runtime
dependencies.

## Install

Install directly from GitHub with [`pipx`](https://pipx.pypa.io/). `pipx`
keeps command-line tools isolated without requiring you to create or activate a
virtual environment.

```bash
brew install pipx
pipx ensurepath
pipx install git+https://github.com/mmcdougall/cache-canary.git
```

Open a new terminal after `pipx ensurepath` if `cache-canary` is not immediately
found. Upgrade or remove the tool with:

```bash
pipx upgrade cache-canary
pipx uninstall cache-canary
```

## Quick start

Scan the standard macOS cache directory:

```bash
cache-canary scan
```

Scan a different directory:

```bash
cache-canary scan /path/to/directory
```

Cache Canary only diagnoses and reports. It never deletes files or runs its
suggested cleanup commands.

## Install for development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Scan

```bash
cache-canary scan
```

The scan command walks depth-first. For each directory it counts only immediate
entries and stops counting once `--threshold` is reached. If the current depth is
at least `--min-prune-depth`, that directory is reported as a candidate and is
not scanned recursively.

By default, `scan` prints a grouped report. It inspects each candidate's
immediate entries with a bounded sample so it can separate directory-fanout
caches, tiny-file caches, and other high-fanout caches without recursively
walking those candidates. It also does a short, time-bounded probe inside each
candidate to provide a little more shape without committing to a full recursive
walk.

Example report:

```text
Cache Canary report: /Users/example/Library/Caches
threshold>=1000 min-depth=1 max-depth=25 max-dirs=100000 sample=10000
candidates=4 errors=1 limits=0

Most Likely Problem Directories (3)
DIR  training-runner/com.apple.e5rt.e5bundlecache/24G517
     dirs=10000/10000 ratio=100.0% probe=dirs:250 entries:10000 stop:dirs,entries
TINY browser/Default/Code Cache/js
     tiny=454/553 ratio=82.1% probe=dirs:1 entries:554 stop:done

Problem Path List (absolute; suitable for review or scripting)
/Users/example/Library/Caches/training-runner/com.apple.e5rt.e5bundlecache/24G517
/Users/example/Library/Caches/browser/Default/Code Cache/js

Suggested Cleanup Commands (not executed by Cache Canary)
# Review carefully before running. Cache Canary only prints these commands.
rm -rf -- /Users/example/Library/Caches/training-runner/com.apple.e5rt.e5bundlecache/24G517
rm -rf -- '/Users/example/Library/Caches/browser/Default/Code Cache/js'

Directory Fanout, CoreML/E5RT-Style (2)
training-runner/com.apple.e5rt.e5bundlecache/24G517  dirs=10000/10000 ratio=100.0% trunc=yes depth=3 tags=e5rt
worker-harness/com.apple.e5rt.e5bundlecache/24G517  dirs=10000/10000 ratio=100.0% trunc=yes depth=3 tags=e5rt

Tiny File Fanout (1)
browser/Default/Code Cache/js  tiny=454/553 ratio=82.1% med=926B sample=554 trunc=no depth=5

Other High Fanout (1)
app-web-cache/Default/Cache/Cache_Data  entries=6792 files=6791 dirs=1 tiny=48.4% med=17.5K trunc=no depth=6
```

Use raw event lines when you want pipe-friendly output:

```text
cache-canary scan ~/Library/Caches --format lines --threshold 40
```

```text
CANDIDATE depth=4 entries>=40 /Users/example/Library/Caches/foo/bar/broken-cache
ERROR     depth=3 PermissionError /Users/example/Library/Caches/private
```

Useful options:

- `--threshold`: immediate-entry count that marks a candidate. Default: `1000`.
- `--min-prune-depth`: do not report or prune above this depth. Default: `1`.
- `--max-depth`: maximum depth to inspect. Default: `25`.
- `--max-dirs`: maximum directories to visit before stopping. Default: `100000`.
- `--sample`: immediate entries to inspect per candidate in report mode.
  Default: `10000`.
- `--dir-threshold`: sampled immediate directories required for the
  directory-fanout section. Default: `1000`.
- `--format`: `report`, `lines`, `paths`, or `commands`. Default: `report`.
- `--absolute-paths`: print absolute paths instead of paths relative to the
  scan root.
- `--probe-seconds`: per-candidate time budget for bounded deeper probing.
  Default: `0.05`.
- `--no-probe`: disable bounded deeper probing.

Depth starts at `0` for the root path.

## Inspect

```bash
cache-canary inspect /path/to/candidate --sample 10000
```

The inspect command samples immediate entries only. It reports sampled file and
directory counts, sampled file-size statistics, tiny-file counts, and simple
yes/no signals for tiny-file and directory-fanout explosions.

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
sampled_directory_ratio=0.001
directory_fanout_threshold=1000
directory_fanout_explosion=no
```

The tiny-file signal is intentionally conservative: it returns `yes` when at
least 20 sampled regular files are at or below the tiny-size threshold and at
least 80% of sampled regular files are tiny. The default tiny-size threshold is
16 KiB.

The directory-fanout signal is aimed at CoreML/E5RT-style cache blowups where a
tool spawns many processes and leaves one small cache directory per process. It
returns `yes` when at least 1000 sampled immediate entries are directories and
at least 80% of sampled entries are directories.

## Suggested Cleanup

Cache Canary cannot delete files. To produce a reviewable command list:

```bash
cache-canary scan ~/Library/Caches --format commands > /tmp/cache-canary-cleanup-commands.sh
```

Review and edit that file before running anything in it. The generated commands
look like this:

```text
rm -rf -- /Users/example/Library/Caches/training-runner/com.apple.e5rt.e5bundlecache/24G517
rm -rf -- '/Users/example/Library/Caches/browser/Default/Code Cache/js'
```

A path-only list is also available for other tooling:

```bash
cache-canary scan ~/Library/Caches --format paths > /tmp/cache-canary-problem-paths.txt
```

## Run tests

```bash
PYTHONPATH=src python -m unittest
```

## License

Cache Canary is released under the zero-condition BSD (`0BSD`) license. You
may use, copy, modify, and distribute it for any purpose, with or without fee.
