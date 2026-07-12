from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from cachecanary.cli import build_parser, format_scan_events, main
from cachecanary.scanner import (
    CandidateEvent,
    ErrorEvent,
    LimitEvent,
    ProbeConfig,
    ScanConfig,
    inspect_directory,
    probe_directory,
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
        with mock.patch("cachecanary.scanner.os.scandir", side_effect=PermissionError):
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
    def test_scan_cli_defaults_to_user_cache_directory(self) -> None:
        args = build_parser().parse_args(["scan"])

        self.assertEqual("~/Library/Caches", args.root)

    def test_version_flag_prints_version(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            main(["--version"])

        self.assertEqual(0, raised.exception.code)
        self.assertEqual("cache-canary 0.1.0\n", stdout.getvalue())

    def test_scan_cli_prints_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            candidate = os.path.join(tmp, "vendor", "cache")
            os.makedirs(candidate)
            for index in range(3):
                touch(os.path.join(candidate, f"entry-{index}"))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    ["scan", tmp, "--threshold", "3", "--min-prune-depth", "1", "--format", "lines"]
                )

        self.assertEqual(0, exit_code)
        self.assertEqual(f"CANDIDATE depth=2 entries>=3 {candidate}\n", stdout.getvalue())

    def test_scan_cli_report_groups_suspicious_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dir_cache = os.path.join(tmp, "runner", "com.apple.e5rt.e5bundlecache")
            tiny_cache = os.path.join(tmp, "browser", "Code Cache", "js")
            os.makedirs(dir_cache)
            os.makedirs(tiny_cache)
            for index in range(4):
                os.makedirs(os.path.join(dir_cache, f"process-{index}"))
            for index in range(30):
                touch(os.path.join(tiny_cache, f"tiny-{index}"), size=128)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "scan",
                        tmp,
                        "--threshold",
                        "3",
                        "--min-prune-depth",
                        "1",
                        "--sample",
                        "100",
                        "--dir-threshold",
                        "3",
                        "--probe-seconds",
                        "1",
                    ]
                )

            output = stdout.getvalue()
            self.assertEqual(0, exit_code)
            self.assertIn("Most Likely Problem Directories (2)", output)
            self.assertIn("Problem Path List", output)
            self.assertIn("Suggested Cleanup Commands", output)
            self.assertIn("Directory Fanout, CoreML/E5RT-Style (1)", output)
            self.assertIn("Tiny File Fanout (1)", output)
            self.assertIn("runner/com.apple.e5rt.e5bundlecache  dirs=4/4", output)
            self.assertIn("browser/Code Cache/js  tiny=30/30", output)
            self.assertIn(dir_cache, output)
            self.assertIn(tiny_cache, output)
            self.assertIn(f"rm -rf -- {dir_cache}", output)
            self.assertTrue(os.path.isdir(dir_cache))
            self.assertTrue(os.path.isdir(tiny_cache))

    def test_scan_cli_paths_format_outputs_problem_paths_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dir_cache = os.path.join(tmp, "runner", "com.apple.e5rt.e5bundlecache")
            other_cache = os.path.join(tmp, "ordinary")
            os.makedirs(dir_cache)
            os.makedirs(other_cache)
            for index in range(4):
                os.makedirs(os.path.join(dir_cache, f"process-{index}"))
                touch(os.path.join(other_cache, f"file-{index}"), size=1024 * 1024)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "scan",
                        tmp,
                        "--threshold",
                        "3",
                        "--min-prune-depth",
                        "1",
                        "--format",
                        "paths",
                        "--dir-threshold",
                        "3",
                        "--no-probe",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual(f"{dir_cache}\n", stdout.getvalue())
            self.assertTrue(os.path.isdir(dir_cache))
            self.assertTrue(os.path.isdir(other_cache))

    def test_scan_cli_commands_format_outputs_suggested_rm_commands_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dir_cache = os.path.join(tmp, "runner cache", "com.apple.e5rt.e5bundlecache")
            os.makedirs(dir_cache)
            for index in range(4):
                os.makedirs(os.path.join(dir_cache, f"process-{index}"))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "scan",
                        tmp,
                        "--threshold",
                        "3",
                        "--min-prune-depth",
                        "1",
                        "--format",
                        "commands",
                        "--dir-threshold",
                        "3",
                        "--no-probe",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertEqual(f"rm -rf -- '{dir_cache}'\n", stdout.getvalue())
            self.assertTrue(os.path.isdir(dir_cache))

    def test_inspect_cli_reports_missing_path_on_stderr(self) -> None:
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            exit_code = main(["inspect", "/definitely/missing/cachecanary/path"])

        self.assertEqual(1, exit_code)
        self.assertIn("ERROR     FileNotFoundError", stderr.getvalue())


class InspectTests(unittest.TestCase):
    def test_inspect_rejects_invalid_limits(self) -> None:
        with self.assertRaises(ValueError):
            inspect_directory("/tmp", sample_limit=0)
        with self.assertRaises(ValueError):
            inspect_directory("/tmp", tiny_size=-1)
        with self.assertRaises(ValueError):
            inspect_directory("/tmp", directory_threshold=0)

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

    def test_inspect_reports_directory_fanout_explosion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(4):
                os.makedirs(os.path.join(tmp, f"process-cache-{index}"))

            result = inspect_directory(tmp, sample_limit=10, directory_threshold=3)

        self.assertEqual(4, result.sampled_dirs)
        self.assertEqual(1.0, result.directory_ratio)
        self.assertTrue(result.directory_fanout_explosion)

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
        with mock.patch("cachecanary.scanner.os.scandir", side_effect=PermissionError):
            result = inspect_directory("/private")

        self.assertEqual("PermissionError", result.error_name)


class ProbeTests(unittest.TestCase):
    def test_probe_directory_uses_bounded_depth_and_entry_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            child = os.path.join(tmp, "child")
            grandchild = os.path.join(child, "grandchild")
            os.makedirs(grandchild)
            for index in range(5):
                touch(os.path.join(child, f"tiny-{index}"), size=128)

            result = probe_directory(
                tmp,
                ProbeConfig(max_seconds=1, max_depth=1, max_dirs=10, entry_limit=3, child_limit=10),
            )

        self.assertEqual(2, result.visited_dirs)
        self.assertEqual(1, result.max_depth_reached)
        self.assertEqual(1, result.entry_limit_hits)
        self.assertEqual(3, result.max_entries_seen)

    def test_probe_directory_rejects_invalid_config(self) -> None:
        invalid_configs = [
            {"max_seconds": 0},
            {"max_depth": -1},
            {"max_dirs": 0},
            {"entry_limit": 0},
            {"child_limit": 0},
        ]

        for kwargs in invalid_configs:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ProbeConfig(**kwargs)


if __name__ == "__main__":
    unittest.main()
