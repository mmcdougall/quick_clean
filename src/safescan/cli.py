from __future__ import annotations

import argparse
import os
import sys
from typing import Iterable

from .scanner import (
    CandidateEvent,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_DIRS,
    DEFAULT_MIN_PRUNE_DEPTH,
    DEFAULT_SAMPLE_LIMIT,
    DEFAULT_THRESHOLD,
    DEFAULT_TINY_SIZE,
    ErrorEvent,
    LimitEvent,
    ScanConfig,
    inspect_directory,
    scan_directories,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safescan",
        description="Diagnose pathological cache directory fanout without fully walking trees.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Cautiously scan a directory tree for high-fanout candidate directories.",
    )
    scan_parser.add_argument("root", help="Root directory to scan, for example ~/Library/Caches.")
    scan_parser.add_argument(
        "--threshold",
        type=positive_int,
        default=DEFAULT_THRESHOLD,
        help=f"Immediate entries required to report a candidate. Default: {DEFAULT_THRESHOLD}.",
    )
    scan_parser.add_argument(
        "--min-prune-depth",
        type=nonnegative_int,
        default=DEFAULT_MIN_PRUNE_DEPTH,
        help=f"Do not report or prune directories above this depth. Default: {DEFAULT_MIN_PRUNE_DEPTH}.",
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


def normalize_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def run_scan(args: argparse.Namespace) -> int:
    root = normalize_path(args.root)
    config = ScanConfig(
        threshold=args.threshold,
        min_prune_depth=args.min_prune_depth,
        max_depth=args.max_depth,
        max_dirs=args.max_dirs,
    )
    for line in format_scan_events(scan_directories(root, config)):
        print(line)
    return 0


def format_scan_events(events: Iterable[CandidateEvent | ErrorEvent | LimitEvent]) -> Iterable[str]:
    for event in events:
        if isinstance(event, CandidateEvent):
            yield f"CANDIDATE depth={event.depth} entries>={event.threshold} {event.path}"
        elif isinstance(event, ErrorEvent):
            yield f"ERROR     depth={event.depth} {event.error_name} {event.path}"
        else:
            yield f"LIMIT     depth={event.depth} {event.reason} {event.path}"


def run_inspect(args: argparse.Namespace) -> int:
    path = normalize_path(args.path)
    result = inspect_directory(path, sample_limit=args.sample, tiny_size=args.tiny_size)
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
    return 0


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
