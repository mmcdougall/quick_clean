from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from safescan.cli import format_scan_events, main
from safescan.scanner import (
    CandidateEvent,
    ErrorEvent,
    LimitEvent,
    ScanConfig,
    inspect_directory,
    scan_directories,
)


def touch(path: str, size: int = 0) -> None:
    with open(path, "wb") as handle:
        handle.write(b"x" * size)


class ScanTests(unittest.TestCase):
    def test_scan_config_rejects_invalid_limits(self) -> None:
        invalid_configs = [
            {"threshold": 0},
            {"min_prune_depth": -1},
            {"max_depth": -1},
            {"max_dirs": 0},
        ]

        for kwargs in invalid_configs:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ScanConfig(**kwargs)

    def test_reports_candidate_and_does_not_recurse_into_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            candidate = os.path.join(tmp, "vendor", "tool", "cache")
            nested = os.path.join(candidate, "nested")
            os.makedirs(nested)
            for index in range(3):
                touch(os.path.join(candidate, f"entry-{index}"))
            for index in range(3):
                touch(os.path.join(nested, f"nested-{index}"))

            events = list(
                scan_directories(
                    tmp,
                    ScanConfig(threshold=3, min_prune_depth=1, max_depth=10, max_dirs=100),
                )
            )

        candidates = [event for event in events if isinstance(event, CandidateEvent)]
        self.assertEqual([candidate], [event.path for event in candidates])

    def test_min_prune_depth_forces_shallow_descent_past_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(5):
                os.makedirs(os.path.join(tmp, f"top-{index}"))
            bad = os.path.join(tmp, "top-4", "bad-cache")
            os.makedirs(bad)
            for index in range(3):
                touch(os.path.join(bad, f"tiny-{index}"))

            events = list(
                scan_directories(
                    tmp,
                    ScanConfig(threshold=3, min_prune_depth=1, max_depth=10, max_dirs=100),
                )
            )

        candidates = [event for event in events if isinstance(event, CandidateEvent)]
        self.assertEqual([bad], [event.path for event in candidates])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_does_not_follow_symlinked_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target")
            os.makedirs(target)
            for index in range(3):
                touch(os.path.join(target, f"entry-{index}"))
            os.symlink(target, os.path.join(tmp, "linked"))

            events = list(
                scan_directories(
                    os.path.join(tmp, "linked"),
                    ScanConfig(threshold=3, min_prune_depth=0, max_depth=10, max_dirs=100),
                )
            )

        self.assertEqual([], [event for event in events if isinstance(event, CandidateEvent)])
        self.assertEqual(["Symlink"], [event.error_name for event in events if isinstance(event, ErrorEvent)])

    def test_max_dirs_limit_stops_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "child"))

            events = list(
                scan_directories(
                    tmp,
                    ScanConfig(threshold=10, min_prune_depth=0, max_depth=10, max_dirs=1),
                )
            )

        self.assertEqual(1, len(events))
        self.assertIsInstance(events[0], LimitEvent)

    def test_max_depth_stops_descent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            too_deep = os.path.join(tmp, "vendor", "cache")
            os.makedirs(too_deep)
            for index in range(3):
                touch(os.path.join(too_deep, f"entry-{index}"))

            events = list(
                scan_directories(
                    tmp,
                    ScanConfig(threshold=3, min_prune_depth=0, max_depth=1, max_dirs=100),
                )
            )

        self.assertEqual([], [event for event in events if isinstance(event, CandidateEvent)])

    def test_scan_reports_permission_error(self) -> None:
        with mock.patch("safescan.scanner.os.scandir", side_effect=PermissionError):
            events = list(scan_directories("/private", ScanConfig()))

        self.assertEqual(1, len(events))
        self.assertIsInstance(events[0], ErrorEvent)
        self.assertEqual("PermissionError", events[0].error_name)

    def test_scan_output_format(self) -> None:
        event = CandidateEvent(path="/tmp/cache", depth=4, threshold=40)

        self.assertEqual(
            ["CANDIDATE depth=4 entries>=40 /tmp/cache"],
            list(format_scan_events([event])),
        )


class CliTests(unittest.TestCase):
    def test_scan_cli_prints_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            candidate = os.path.join(tmp, "vendor", "cache")
            os.makedirs(candidate)
            for index in range(3):
                touch(os.path.join(candidate, f"entry-{index}"))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["scan", tmp, "--threshold", "3", "--min-prune-depth", "1"])

        self.assertEqual(0, exit_code)
        self.assertEqual(f"CANDIDATE depth=2 entries>=3 {candidate}\n", stdout.getvalue())

    def test_inspect_cli_reports_missing_path_on_stderr(self) -> None:
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            exit_code = main(["inspect", "/definitely/missing/safescan/path"])

        self.assertEqual(1, exit_code)
        self.assertIn("ERROR     FileNotFoundError", stderr.getvalue())


class InspectTests(unittest.TestCase):
    def test_inspect_rejects_invalid_limits(self) -> None:
        with self.assertRaises(ValueError):
            inspect_directory("/tmp", sample_limit=0)
        with self.assertRaises(ValueError):
            inspect_directory("/tmp", tiny_size=-1)

    def test_inspect_reports_tiny_file_cache_explosion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(30):
                touch(os.path.join(tmp, f"tiny-{index}"), size=128)
            os.makedirs(os.path.join(tmp, "child-a"))
            os.makedirs(os.path.join(tmp, "child-b"))

            result = inspect_directory(tmp, sample_limit=100, tiny_size=16 * 1024)

        self.assertEqual(32, result.sampled_entries)
        self.assertEqual(30, result.sampled_files)
        self.assertEqual(2, result.sampled_dirs)
        self.assertEqual(30, result.tiny_files)
        self.assertEqual(128, result.mean_file_size)
        self.assertEqual(128, result.median_file_size)
        self.assertTrue(result.tiny_file_cache_explosion)

    def test_inspect_stops_at_sample_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(5):
                touch(os.path.join(tmp, f"entry-{index}"))

            result = inspect_directory(tmp, sample_limit=3, tiny_size=16 * 1024)

        self.assertEqual(3, result.sampled_entries)
        self.assertTrue(result.sample_truncated)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_inspect_does_not_follow_symlinked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target")
            os.makedirs(target)
            os.symlink(target, os.path.join(tmp, "linked"))

            result = inspect_directory(os.path.join(tmp, "linked"), sample_limit=10)

        self.assertEqual("Symlink", result.error_name)

    def test_inspect_reports_permission_error(self) -> None:
        with mock.patch("safescan.scanner.os.scandir", side_effect=PermissionError):
            result = inspect_directory("/private")

        self.assertEqual("PermissionError", result.error_name)


if __name__ == "__main__":
    unittest.main()
