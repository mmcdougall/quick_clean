from __future__ import annotations

import argparse
import os
import shlex
import sys
from dataclasses import dataclass
from typing import Iterable

from . import __version__
from .scanner import (
    CandidateEvent,
    DEFAULT_DIRECTORY_THRESHOLD,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_DIRS,
    DEFAULT_MIN_PRUNE_DEPTH,
    DEFAULT_PROBE_ENTRY_LIMIT,
    DEFAULT_PROBE_MAX_DEPTH,
    DEFAULT_PROBE_MAX_DIRS,
    DEFAULT_PROBE_SECONDS,
    DEFAULT_SAMPLE_LIMIT,
    DEFAULT_THRESHOLD,
    DEFAULT_TINY_SIZE,
    ErrorEvent,
    InspectResult,
    LimitEvent,
    ProbeConfig,
    ProbeResult,
    ScanConfig,
    inspect_directory,
    probe_directory,
    scan_directories,
)


@dataclass(frozen=True)
class CandidateInspection:
    event: CandidateEvent
    result: InspectResult
    probe: ProbeResult | None = None


@dataclass(frozen=True)
class ScanTarget:
    path: str
    default_min_prune_depth: int


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cache-canary",
        description="Diagnose pathological cache directory fanout without fully walking trees.",
        epilog=(
            "examples:\n"
            "  cache-canary scan          scan ~/Library/Caches\n"
            "  cache-canary scan --temp   scan the current user's temporary directory\n"
            "  cache-canary scan --all    scan both standard locations\n"
            "  cache-canary inspect PATH  inspect one candidate directory\n\n"
            "Cache Canary never deletes files or runs suggested cleanup commands.\n"
            "Run 'cache-canary COMMAND --help' for command-specific options."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Cautiously scan a directory tree for high-fanout candidate directories.",
        description="Cautiously scan bounded directory trees for high-fanout candidates.",
        epilog=(
            "examples:\n"
            "  cache-canary scan\n"
            "  cache-canary scan --temp\n"
            "  cache-canary scan --all\n"
            "  cache-canary scan /path/to/directory\n"
            "  cache-canary scan --temp --format paths\n\n"
            "Reports are diagnostic only. Suggested cleanup commands are never executed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_target = scan_parser.add_mutually_exclusive_group()
    scan_target.add_argument(
        "root",
        nargs="?",
        help="Directory to scan. Defaults to the user cache directory.",
    )
    scan_target.add_argument(
        "--caches",
        action="store_true",
        help="Scan ~/Library/Caches (the default).",
    )
    scan_target.add_argument(
        "--temp",
        action="store_true",
        help="Scan the current user's temporary directory.",
    )
    scan_target.add_argument(
        "--all",
        dest="all_targets",
        action="store_true",
        help="Scan both the user cache and temporary directories.",
    )
    scan_parser.add_argument(
        "--threshold",
        type=positive_int,
        default=DEFAULT_THRESHOLD,
        help=f"Immediate entries required to report a candidate. Default: {DEFAULT_THRESHOLD}.",
    )
    scan_parser.add_argument(
        "--min-prune-depth",
        type=nonnegative_int,
        default=None,
        help=(
            "Do not report or prune directories above this depth. "
            f"Default: {DEFAULT_MIN_PRUNE_DEPTH} for caches and custom roots; 0 for --temp."
        ),
    )
    scan_parser.add_argument(
        "--max-depth",
        type=nonnegative_int,
        default=DEFAULT_MAX_DEPTH,
        help=f"Maximum directory depth to inspect. Default: {DEFAULT_MAX_DEPTH}.",
    )
    scan_parser.add_argument(
        "--max-dirs",
        type=positive_int,
        default=DEFAULT_MAX_DIRS,
        help=f"Maximum number of directories to visit before stopping. Default: {DEFAULT_MAX_DIRS}.",
    )
    scan_parser.add_argument(
        "--sample",
        type=positive_int,
        default=DEFAULT_SAMPLE_LIMIT,
        help=f"Immediate entries to inspect per candidate in report mode. Default: {DEFAULT_SAMPLE_LIMIT}.",
    )
    scan_parser.add_argument(
        "--tiny-size",
        type=nonnegative_int,
        default=DEFAULT_TINY_SIZE,
        help=f"File size in bytes considered tiny in report mode. Default: {DEFAULT_TINY_SIZE}.",
    )
    scan_parser.add_argument(
        "--dir-threshold",
        type=positive_int,
        default=DEFAULT_DIRECTORY_THRESHOLD,
        help=(
            "Sampled immediate directories required for directory-fanout reports. "
            f"Default: {DEFAULT_DIRECTORY_THRESHOLD}."
        ),
    )
    scan_parser.add_argument(
        "--format",
        choices=("report", "lines", "paths", "commands"),
        default="report",
        help="Output format. 'commands' emits suggested rm commands only. Default: report.",
    )
    scan_parser.add_argument(
        "--absolute-paths",
        action="store_true",
        help="Show absolute paths in report mode instead of paths relative to the scan root.",
    )
    scan_parser.add_argument(
        "--probe-seconds",
        type=positive_float,
        default=DEFAULT_PROBE_SECONDS,
        help=f"Per-candidate time budget for bounded deeper probing. Default: {DEFAULT_PROBE_SECONDS}.",
    )
    scan_parser.add_argument(
        "--probe-max-depth",
        type=nonnegative_int,
        default=DEFAULT_PROBE_MAX_DEPTH,
        help=f"Maximum depth for bounded deeper probing. Default: {DEFAULT_PROBE_MAX_DEPTH}.",
    )
    scan_parser.add_argument(
        "--probe-max-dirs",
        type=positive_int,
        default=DEFAULT_PROBE_MAX_DIRS,
        help=f"Maximum directories to visit per candidate during probing. Default: {DEFAULT_PROBE_MAX_DIRS}.",
    )
    scan_parser.add_argument(
        "--probe-entry-limit",
        type=positive_int,
        default=DEFAULT_PROBE_ENTRY_LIMIT,
        help=f"Maximum immediate entries counted per probed directory. Default: {DEFAULT_PROBE_ENTRY_LIMIT}.",
    )
    scan_parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Disable bounded deeper probing in report and paths modes.",
    )
    scan_parser.set_defaults(func=run_scan)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Sample one candidate directory without recursively walking it.",
    )
    inspect_parser.add_argument("path", help="Candidate directory to inspect.")
    inspect_parser.add_argument(
        "--sample",
        type=positive_int,
        default=DEFAULT_SAMPLE_LIMIT,
        help=f"Maximum immediate entries to sample. Default: {DEFAULT_SAMPLE_LIMIT}.",
    )
    inspect_parser.add_argument(
        "--tiny-size",
        type=nonnegative_int,
        default=DEFAULT_TINY_SIZE,
        help=f"File size in bytes considered tiny. Default: {DEFAULT_TINY_SIZE}.",
    )
    inspect_parser.add_argument(
        "--dir-threshold",
        type=positive_int,
        default=DEFAULT_DIRECTORY_THRESHOLD,
        help=(
            "Sampled immediate directories required for directory-fanout detection. "
            f"Default: {DEFAULT_DIRECTORY_THRESHOLD}."
        ),
    )
    inspect_parser.set_defaults(func=run_inspect)

    return parser


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def normalize_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def run_scan(args: argparse.Namespace) -> int:
    targets = _scan_targets(args)
    for index, target in enumerate(targets):
        if index and args.format == "report":
            print()
        for line in _scan_target(args, target):
            print(line)
    return 0


def _scan_targets(args: argparse.Namespace) -> list[ScanTarget]:
    caches = ScanTarget(normalize_path("~/Library/Caches"), DEFAULT_MIN_PRUNE_DEPTH)
    temporary = ScanTarget(normalize_path(os.environ.get("TMPDIR") or "/tmp"), 0)
    if args.temp:
        return [temporary]
    if args.all_targets:
        if caches.path == temporary.path:
            return [caches]
        return [caches, temporary]
    if args.root is not None:
        return [ScanTarget(normalize_path(args.root), DEFAULT_MIN_PRUNE_DEPTH)]
    return [caches]


def _scan_target(args: argparse.Namespace, target: ScanTarget) -> Iterable[str]:
    min_prune_depth = (
        target.default_min_prune_depth if args.min_prune_depth is None else args.min_prune_depth
    )
    config = ScanConfig(
        threshold=args.threshold,
        min_prune_depth=min_prune_depth,
        max_depth=args.max_depth,
        max_dirs=args.max_dirs,
    )
    events = list(scan_directories(target.path, config))
    if args.format == "lines":
        return format_scan_events(events)
    elif args.format == "paths":
        return format_problem_paths(
            events=events,
            sample_limit=args.sample,
            tiny_size=args.tiny_size,
            directory_threshold=args.dir_threshold,
            probe_config=_probe_config_from_args(args),
        )
    elif args.format == "commands":
        return format_cleanup_commands(
            events=events,
            sample_limit=args.sample,
            tiny_size=args.tiny_size,
            directory_threshold=args.dir_threshold,
            probe_config=_probe_config_from_args(args),
        )
    return format_scan_report(
        root=target.path,
        config=config,
        events=events,
        sample_limit=args.sample,
        tiny_size=args.tiny_size,
        directory_threshold=args.dir_threshold,
        probe_config=_probe_config_from_args(args),
        absolute_paths=args.absolute_paths,
    )


def format_scan_events(events: Iterable[CandidateEvent | ErrorEvent | LimitEvent]) -> Iterable[str]:
    for event in events:
        if isinstance(event, CandidateEvent):
            yield f"CANDIDATE depth={event.depth} entries>={event.threshold} {event.path}"
        elif isinstance(event, ErrorEvent):
            yield f"ERROR     depth={event.depth} {event.error_name} {event.path}"
        else:
            yield f"LIMIT     depth={event.depth} {event.reason} {event.path}"


def format_scan_report(
    root: str,
    config: ScanConfig,
    events: Iterable[CandidateEvent | ErrorEvent | LimitEvent],
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
    tiny_size: int = DEFAULT_TINY_SIZE,
    directory_threshold: int = DEFAULT_DIRECTORY_THRESHOLD,
    probe_config: ProbeConfig | None = ProbeConfig(),
    absolute_paths: bool = False,
) -> Iterable[str]:
    candidates: list[CandidateEvent] = []
    errors: list[ErrorEvent] = []
    limits: list[LimitEvent] = []

    for event in events:
        if isinstance(event, CandidateEvent):
            candidates.append(event)
        elif isinstance(event, ErrorEvent):
            errors.append(event)
        else:
            limits.append(event)

    inspected = _inspect_candidates(candidates, sample_limit, tiny_size, directory_threshold, probe_config)

    directory_fanout = [
        item
        for item in inspected
        if item.result.error_name is None and item.result.directory_fanout_explosion
    ]
    tiny_file_fanout = [
        item
        for item in inspected
        if (
            item.result.error_name is None
            and item.result.tiny_file_cache_explosion
            and not item.result.directory_fanout_explosion
        )
    ]
    inspect_errors = [item for item in inspected if item.result.error_name is not None]
    other_fanout = [
        item
        for item in inspected
        if (
            item.result.error_name is None
            and not item.result.directory_fanout_explosion
            and not item.result.tiny_file_cache_explosion
        )
    ]

    directory_fanout.sort(
        key=lambda item: (
            not item.result.sample_truncated,
            -item.result.sampled_dirs,
            _display_path(root, item.result.path, absolute_paths),
        )
    )
    tiny_file_fanout.sort(
        key=lambda item: (
            -item.result.tiny_files,
            -item.result.tiny_file_ratio,
            _display_path(root, item.result.path, absolute_paths),
        )
    )
    other_fanout.sort(
        key=lambda item: (
            -item.result.sampled_entries,
            _display_path(root, item.result.path, absolute_paths),
        )
    )
    errors.sort(key=lambda event: _display_path(root, event.path, absolute_paths))
    limits.sort(key=lambda event: _display_path(root, event.path, absolute_paths))
    inspect_errors.sort(key=lambda item: _display_path(root, item.result.path, absolute_paths))

    yield f"Cache Canary report: {root}"
    yield (
        f"threshold>={config.threshold} min-depth={config.min_prune_depth} "
        f"max-depth={config.max_depth} max-dirs={config.max_dirs} sample={sample_limit}"
    )
    yield f"candidates={len(candidates)} errors={len(errors)} limits={len(limits)}"
    yield ""

    problem_items = directory_fanout + tiny_file_fanout
    yield from _format_problem_summary(root, problem_items, absolute_paths)
    yield ""
    yield from _format_problem_path_list(problem_items)
    yield ""
    yield from _format_cleanup_command_section(problem_items)
    yield ""
    yield from _format_directory_fanout_section(root, directory_fanout, absolute_paths)
    yield ""
    yield from _format_tiny_file_section(root, tiny_file_fanout, absolute_paths)
    yield ""
    yield from _format_other_fanout_section(root, other_fanout, absolute_paths)

    if inspect_errors:
        yield ""
        yield f"Inspect Errors ({len(inspect_errors)})"
        for item in inspect_errors:
            path = _display_path(root, item.result.path, absolute_paths)
            yield f"{path}  error={item.result.error_name} depth={item.event.depth}"

    if errors:
        yield ""
        yield f"Scan Errors ({len(errors)})"
        for error in errors:
            path = _display_path(root, error.path, absolute_paths)
            yield f"{path}  error={error.error_name} depth={error.depth}"

    if limits:
        yield ""
        yield f"Scan Limits ({len(limits)})"
        for limit in limits:
            path = _display_path(root, limit.path, absolute_paths)
            yield f"{path}  limit={limit.reason} depth={limit.depth}"


def format_problem_paths(
    events: Iterable[CandidateEvent | ErrorEvent | LimitEvent],
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
    tiny_size: int = DEFAULT_TINY_SIZE,
    directory_threshold: int = DEFAULT_DIRECTORY_THRESHOLD,
    probe_config: ProbeConfig | None = ProbeConfig(),
) -> Iterable[str]:
    candidates = [event for event in events if isinstance(event, CandidateEvent)]
    inspected = _inspect_candidates(candidates, sample_limit, tiny_size, directory_threshold, probe_config)
    for item in _problem_items(inspected):
        yield item.result.path


def format_cleanup_commands(
    events: Iterable[CandidateEvent | ErrorEvent | LimitEvent],
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
    tiny_size: int = DEFAULT_TINY_SIZE,
    directory_threshold: int = DEFAULT_DIRECTORY_THRESHOLD,
    probe_config: ProbeConfig | None = ProbeConfig(),
) -> Iterable[str]:
    candidates = [event for event in events if isinstance(event, CandidateEvent)]
    inspected = _inspect_candidates(candidates, sample_limit, tiny_size, directory_threshold, probe_config)
    for item in _problem_items(inspected):
        yield _cleanup_command(item.result.path)


def _inspect_candidates(
    candidates: list[CandidateEvent],
    sample_limit: int,
    tiny_size: int,
    directory_threshold: int,
    probe_config: ProbeConfig | None,
) -> list[CandidateInspection]:
    inspected: list[CandidateInspection] = []
    for event in candidates:
        result = inspect_directory(
            event.path,
            sample_limit=sample_limit,
            tiny_size=tiny_size,
            directory_threshold=directory_threshold,
        )
        probe = None
        if probe_config is not None and result.error_name is None:
            probe = probe_directory(event.path, probe_config, tiny_size=tiny_size)
        inspected.append(CandidateInspection(event=event, result=result, probe=probe))
    return inspected


def _problem_items(items: list[CandidateInspection]) -> list[CandidateInspection]:
    problems = [
        item
        for item in items
        if (
            item.result.error_name is None
            and (item.result.directory_fanout_explosion or item.result.tiny_file_cache_explosion)
        )
    ]
    problems.sort(key=lambda item: (_problem_rank(item), item.result.path))
    return problems


def _problem_rank(item: CandidateInspection) -> tuple[int, int, int]:
    if item.result.directory_fanout_explosion:
        return (0, -item.result.sampled_dirs, -item.result.sampled_entries)
    return (1, -item.result.tiny_files, -item.result.sampled_entries)


def _format_problem_summary(
    root: str,
    items: list[CandidateInspection],
    absolute_paths: bool,
) -> Iterable[str]:
    yield f"Most Likely Problem Directories ({len(items)})"
    if not items:
        yield "none"
        return
    for item in _problem_items(items):
        result = item.result
        label = "DIR" if result.directory_fanout_explosion else "TINY"
        path = _display_path(root, result.path, absolute_paths)
        yield f"{label:<4} {path}"
        yield f"     {_problem_metrics(item)} {_probe_summary(item.probe)}"


def _format_problem_path_list(items: list[CandidateInspection]) -> Iterable[str]:
    yield "Problem Path List (absolute; suitable for review or scripting)"
    problem_items = _problem_items(items)
    if not problem_items:
        yield "none"
        return
    for item in problem_items:
        yield item.result.path


def _format_cleanup_command_section(items: list[CandidateInspection]) -> Iterable[str]:
    yield "Suggested Cleanup Commands (not executed by Cache Canary)"
    problem_items = _problem_items(items)
    if not problem_items:
        yield "none"
        return
    yield "# Review carefully before running. Cache Canary only prints these commands."
    for item in problem_items:
        yield _cleanup_command(item.result.path)


def _cleanup_command(path: str) -> str:
    return f"rm -rf -- {shlex.quote(path)}"


def _format_directory_fanout_section(
    root: str,
    items: list[CandidateInspection],
    absolute_paths: bool,
) -> Iterable[str]:
    yield f"Directory Fanout, CoreML/E5RT-Style ({len(items)})"
    if not items:
        yield "none"
        return
    for item in items:
        result = item.result
        path = _display_path(root, result.path, absolute_paths)
        yield (
            f"{path}  dirs={result.sampled_dirs}/{result.sampled_entries} "
            f"ratio={_percent(result.directory_ratio)} trunc={yes_no(result.sample_truncated)} "
            f"depth={item.event.depth}{_path_tags(result.path)} {_probe_summary(item.probe)}"
        )


def _format_tiny_file_section(
    root: str,
    items: list[CandidateInspection],
    absolute_paths: bool,
) -> Iterable[str]:
    yield f"Tiny File Fanout ({len(items)})"
    if not items:
        yield "none"
        return
    for item in items:
        result = item.result
        path = _display_path(root, result.path, absolute_paths)
        yield (
            f"{path}  tiny={result.tiny_files}/{result.sampled_files} "
            f"ratio={_percent(result.tiny_file_ratio)} med={_format_bytes(result.median_file_size)} "
            f"sample={result.sampled_entries} trunc={yes_no(result.sample_truncated)} "
            f"depth={item.event.depth} {_probe_summary(item.probe)}"
        )


def _format_other_fanout_section(
    root: str,
    items: list[CandidateInspection],
    absolute_paths: bool,
) -> Iterable[str]:
    yield f"Other High Fanout ({len(items)})"
    if not items:
        yield "none"
        return
    for item in items:
        result = item.result
        path = _display_path(root, result.path, absolute_paths)
        yield (
            f"{path}  entries={result.sampled_entries} files={result.sampled_files} "
            f"dirs={result.sampled_dirs} tiny={_percent(result.tiny_file_ratio)} "
            f"med={_format_bytes(result.median_file_size)} trunc={yes_no(result.sample_truncated)} "
            f"depth={item.event.depth}{_path_tags(result.path)} {_probe_summary(item.probe)}"
        )


def _display_path(root: str, path: str, absolute_paths: bool) -> str:
    if absolute_paths:
        return path
    try:
        relative = os.path.relpath(path, root)
    except ValueError:
        return path
    if relative == "." or relative.startswith(".."):
        return path
    return relative


def _path_tags(path: str) -> str:
    lowered = path.lower()
    tags = []
    if "com.apple.e5rt.e5bundlecache" in lowered:
        tags.append("e5rt")
    if "coreml" in lowered or ".mlmodel" in lowered:
        tags.append("coreml")
    return f" tags={','.join(tags)}" if tags else ""


def _problem_metrics(item: CandidateInspection) -> str:
    result = item.result
    if result.directory_fanout_explosion:
        return f"dirs={result.sampled_dirs}/{result.sampled_entries} ratio={_percent(result.directory_ratio)}"
    return f"tiny={result.tiny_files}/{result.sampled_files} ratio={_percent(result.tiny_file_ratio)}"


def _probe_summary(probe: ProbeResult | None) -> str:
    if probe is None:
        return "probe=off"
    if probe.error_name is not None:
        return f"probe=error:{probe.error_name}"

    stops = []
    if probe.stopped_by_time:
        stops.append("time")
    if probe.stopped_by_max_dirs:
        stops.append("dirs")
    if probe.entry_limit_hits:
        stops.append("entries")
    stop_text = ",".join(stops) if stops else "done"
    return (
        f"probe=dirs:{probe.visited_dirs} entries:{probe.sampled_entries} "
        f"max-entry:{probe.max_entries_seen} depth:{probe.max_depth_reached} stop:{stop_text}"
    )


def _probe_config_from_args(args: argparse.Namespace) -> ProbeConfig | None:
    if args.no_probe:
        return None
    return ProbeConfig(
        max_seconds=args.probe_seconds,
        max_depth=args.probe_max_depth,
        max_dirs=args.probe_max_dirs,
        entry_limit=args.probe_entry_limit,
    )


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _format_bytes(value: float) -> str:
    units = ["B", "K", "M", "G"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{size:.0f}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}G"


def run_inspect(args: argparse.Namespace) -> int:
    path = normalize_path(args.path)
    result = inspect_directory(
        path,
        sample_limit=args.sample,
        tiny_size=args.tiny_size,
        directory_threshold=args.dir_threshold,
    )
    if result.error_name is not None:
        print(f"ERROR     {result.error_name} {result.path}", file=sys.stderr)
        return 1

    print(f"INSPECT path={result.path}")
    print(f"sampled_entries={result.sampled_entries}")
    print(f"sampled_files={result.sampled_files}")
    print(f"sampled_dirs={result.sampled_dirs}")
    print(f"sampled_other={result.sampled_other}")
    print(f"sample_truncated={yes_no(result.sample_truncated)}")
    print(f"entry_errors={result.entry_errors}")
    print(f"mean_file_size={result.mean_file_size:.0f}")
    print(f"median_file_size={result.median_file_size:.0f}")
    print(f"tiny_files<={result.tiny_size}={result.tiny_files}")
    print(f"tiny_file_ratio={result.tiny_file_ratio:.3f}")
    print(f"tiny_file_cache_explosion={yes_no(result.tiny_file_cache_explosion)}")
    print(f"sampled_directory_ratio={result.directory_ratio:.3f}")
    print(f"directory_fanout_threshold={result.directory_threshold}")
    print(f"directory_fanout_explosion={yes_no(result.directory_fanout_explosion)}")
    return 0


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments)
    return args.func(args)
