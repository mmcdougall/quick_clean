from __future__ import annotations

import os
import statistics
from dataclasses import dataclass
from typing import Iterator


DEFAULT_THRESHOLD = 40
DEFAULT_MIN_PRUNE_DEPTH = 2
DEFAULT_MAX_DEPTH = 25
DEFAULT_MAX_DIRS = 100000
DEFAULT_SAMPLE_LIMIT = 10000
DEFAULT_TINY_SIZE = 16 * 1024
TINY_EXPLOSION_MIN_FILES = 20
TINY_EXPLOSION_RATIO = 0.8


@dataclass(frozen=True)
class ScanConfig:
    threshold: int = DEFAULT_THRESHOLD
    min_prune_depth: int = DEFAULT_MIN_PRUNE_DEPTH
    max_depth: int = DEFAULT_MAX_DEPTH
    max_dirs: int = DEFAULT_MAX_DIRS

    def __post_init__(self) -> None:
        if self.threshold <= 0:
            raise ValueError("threshold must be greater than 0")
        if self.min_prune_depth < 0:
            raise ValueError("min_prune_depth must be 0 or greater")
        if self.max_depth < 0:
            raise ValueError("max_depth must be 0 or greater")
        if self.max_dirs <= 0:
            raise ValueError("max_dirs must be greater than 0")


@dataclass(frozen=True)
class CandidateEvent:
    path: str
    depth: int
    threshold: int


@dataclass(frozen=True)
class ErrorEvent:
    path: str
    depth: int
    error_name: str


@dataclass(frozen=True)
class LimitEvent:
    path: str
    depth: int
    reason: str


ScanEvent = CandidateEvent | ErrorEvent | LimitEvent


@dataclass(frozen=True)
class InspectResult:
    path: str
    sampled_entries: int
    sampled_files: int
    sampled_dirs: int
    sampled_other: int
    sample_truncated: bool
    entry_errors: int
    mean_file_size: float
    median_file_size: float
    tiny_size: int
    tiny_files: int
    tiny_file_ratio: float
    tiny_file_cache_explosion: bool
    error_name: str | None = None


def scan_directories(root: str, config: ScanConfig) -> Iterator[ScanEvent]:
    """Depth-first scan that prunes candidate directories before full traversal."""
    stack: list[tuple[str, int]] = [(root, 0)]
    visited_dirs = 0

    while stack:
        path, depth = stack.pop()

        if os.path.islink(path):
            yield ErrorEvent(path=path, depth=depth, error_name="Symlink")
            continue

        if visited_dirs >= config.max_dirs:
            yield LimitEvent(path=path, depth=depth, reason=f"max-dirs={config.max_dirs}")
            return
        visited_dirs += 1

        child_dirs: list[str] = []
        threshold_reached = False
        should_collect_children = depth < config.max_depth

        try:
            entry_count = 0
            threshold_reached = False
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry_count < config.threshold:
                        entry_count += 1
                    if entry_count >= config.threshold:
                        threshold_reached = True

                    if threshold_reached and depth >= config.min_prune_depth:
                        break

                    if should_collect_children:
                        child_path = _child_directory_path(entry)
                        if child_path is not None:
                            child_dirs.append(child_path)
        except PermissionError:
            yield ErrorEvent(path=path, depth=depth, error_name="PermissionError")
            continue
        except OSError as exc:
            yield ErrorEvent(path=path, depth=depth, error_name=type(exc).__name__)
            continue

        if threshold_reached and depth >= config.min_prune_depth:
            yield CandidateEvent(path=path, depth=depth, threshold=config.threshold)
            continue

        if should_collect_children:
            for child_path in reversed(child_dirs):
                stack.append((child_path, depth + 1))


def _child_directory_path(entry: os.DirEntry[str]) -> str | None:
    try:
        if entry.is_dir(follow_symlinks=False):
            return entry.path
    except OSError:
        return None
    return None


def inspect_directory(
    path: str,
    sample_limit: int = DEFAULT_SAMPLE_LIMIT,
    tiny_size: int = DEFAULT_TINY_SIZE,
) -> InspectResult:
    if sample_limit <= 0:
        raise ValueError("sample_limit must be greater than 0")
    if tiny_size < 0:
        raise ValueError("tiny_size must be 0 or greater")

    if os.path.islink(path):
        return _inspect_error(path, "Symlink", tiny_size)

    sampled_entries = 0
    sampled_files = 0
    sampled_dirs = 0
    sampled_other = 0
    entry_errors = 0
    file_sizes: list[int] = []
    sample_truncated = False

    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if sampled_entries >= sample_limit:
                    sample_truncated = True
                    break

                sampled_entries += 1
                try:
                    if entry.is_file(follow_symlinks=False):
                        sampled_files += 1
                        file_sizes.append(entry.stat(follow_symlinks=False).st_size)
                    elif entry.is_dir(follow_symlinks=False):
                        sampled_dirs += 1
                    else:
                        sampled_other += 1
                except OSError:
                    entry_errors += 1
    except PermissionError:
        return _inspect_error(path, "PermissionError", tiny_size)
    except OSError as exc:
        return _inspect_error(path, type(exc).__name__, tiny_size)

    tiny_files = sum(1 for size in file_sizes if size <= tiny_size)
    tiny_file_ratio = tiny_files / sampled_files if sampled_files else 0.0
    tiny_file_cache_explosion = tiny_files >= TINY_EXPLOSION_MIN_FILES and tiny_file_ratio >= TINY_EXPLOSION_RATIO

    return InspectResult(
        path=path,
        sampled_entries=sampled_entries,
        sampled_files=sampled_files,
        sampled_dirs=sampled_dirs,
        sampled_other=sampled_other,
        sample_truncated=sample_truncated,
        entry_errors=entry_errors,
        mean_file_size=statistics.fmean(file_sizes) if file_sizes else 0.0,
        median_file_size=statistics.median(file_sizes) if file_sizes else 0.0,
        tiny_size=tiny_size,
        tiny_files=tiny_files,
        tiny_file_ratio=tiny_file_ratio,
        tiny_file_cache_explosion=tiny_file_cache_explosion,
    )


def _inspect_error(path: str, error_name: str, tiny_size: int) -> InspectResult:
    return InspectResult(
        path=path,
        sampled_entries=0,
        sampled_files=0,
        sampled_dirs=0,
        sampled_other=0,
        sample_truncated=False,
        entry_errors=0,
        mean_file_size=0.0,
        median_file_size=0.0,
        tiny_size=tiny_size,
        tiny_files=0,
        tiny_file_ratio=0.0,
        tiny_file_cache_explosion=False,
        error_name=error_name,
    )
