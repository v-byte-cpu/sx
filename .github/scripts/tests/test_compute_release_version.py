from __future__ import annotations

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch


SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import compute_release_version as release_version


class ComputeReleaseVersionTests(unittest.TestCase):
    def test_normalize_version_strips_leading_v(self) -> None:
        self.assertEqual(release_version.normalize_version("v1.2.3"), "1.2.3")
        self.assertEqual(release_version.normalize_version("1.2.3"), "1.2.3")

    def test_build_git_cliff_args_for_stable_adds_ignore_tags(self) -> None:
        self.assertEqual(
            release_version.build_git_cliff_args("stable"),
            ["git-cliff", "--ignore-tags", release_version.RC_IGNORE_TAGS, "--bumped-version"],
        )

    def test_build_git_cliff_args_for_rc_omits_ignore_tags(self) -> None:
        self.assertEqual(release_version.build_git_cliff_args("rc"), ["git-cliff", "--bumped-version"])

    def test_build_git_cliff_context_args_for_stable_adds_ignore_tags(self) -> None:
        self.assertEqual(
            release_version.build_git_cliff_context_args("stable"),
            [
                "git-cliff",
                "--unreleased",
                "--bump",
                "--context",
                "--ignore-tags",
                release_version.RC_IGNORE_TAGS,
            ],
        )

    def test_build_git_cliff_context_args_for_rc_omits_ignore_tags(self) -> None:
        self.assertEqual(
            release_version.build_git_cliff_context_args("rc"),
            ["git-cliff", "--unreleased", "--bump", "--context"],
        )

    def test_bumped_version_returns_raw_git_cliff_output(self) -> None:
        with patch.object(release_version, "run_command", return_value="v1.2.4"):
            self.assertEqual(release_version.bumped_version("stable"), "v1.2.4")

    def test_bumped_version_falls_back_without_releases_for_stable(self) -> None:
        error = subprocess.CalledProcessError(
            returncode=1,
            cmd=("git-cliff", "--bumped-version"),
            stderr="No releases found, using 0.1.0 as the next version.",
        )

        with patch.object(release_version, "run_command", side_effect=error):
            self.assertEqual(release_version.bumped_version("stable"), "0.1.0")

    def test_bumped_version_falls_back_without_releases_for_rc(self) -> None:
        error = subprocess.CalledProcessError(
            returncode=1,
            cmd=("git-cliff", "--bumped-version"),
            stderr="No releases found, using 0.1.0 as the next version.",
        )

        with patch.object(release_version, "run_command", side_effect=error):
            self.assertEqual(release_version.bumped_version("rc"), "0.1.0")

    def test_release_commit_count_parses_json_context(self) -> None:
        with patch.object(
            release_version,
            "run_command",
            return_value='[{"statistics":{"commit_count":2}}]',
        ):
            self.assertEqual(release_version.release_commit_count("stable"), 2)

    def test_release_commit_count_handles_empty_context(self) -> None:
        with patch.object(release_version, "run_command", return_value="[]"):
            self.assertEqual(release_version.release_commit_count("rc"), 0)

    def test_ensure_new_commits_raises_for_empty_release(self) -> None:
        with patch.object(release_version, "release_commit_count", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "nothing to release"):
                release_version.ensure_new_commits("stable")

    def test_compute_next_tag_for_stable_prefixes_version(self) -> None:
        self.assertEqual(release_version.compute_next_tag("v1.2.4", "stable"), "v1.2.4")

    def test_compute_next_tag_for_rc_keeps_existing_rc_suffix(self) -> None:
        self.assertEqual(release_version.compute_next_tag("v1.2.4-rc.2", "rc"), "v1.2.4-rc.2")

    def test_compute_next_tag_for_rc_adds_first_suffix_for_plain_version(self) -> None:
        self.assertEqual(release_version.compute_next_tag("v1.2.4", "rc"), "v1.2.4-rc.1")

    def test_compute_next_tag_for_stable_rejects_prerelease_version(self) -> None:
        with self.assertRaisesRegex(
            RuntimeError,
            "git-cliff returned a prerelease version for a stable release.",
        ):
            release_version.compute_next_tag("v1.2.4-rc.2", "stable")

    def test_compute_next_tag_for_empty_version_rejects_empty_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "git-cliff did not return a version."):
            release_version.compute_next_tag("   ", "stable")

    def test_tag_exists_returns_true_when_origin_has_tag(self) -> None:
        completed = subprocess.CompletedProcess(args=(), returncode=0, stdout="ref", stderr="")
        with patch.object(release_version.subprocess, "run", return_value=completed):
            self.assertTrue(release_version.tag_exists("v1.2.3"))

    def test_tag_exists_returns_false_when_origin_has_no_tag(self) -> None:
        completed = subprocess.CompletedProcess(args=(), returncode=2, stdout="", stderr="")
        with patch.object(release_version.subprocess, "run", return_value=completed):
            self.assertFalse(release_version.tag_exists("v1.2.3"))

    def test_tag_exists_raises_for_git_errors(self) -> None:
        completed = subprocess.CompletedProcess(args=(), returncode=128, stdout="", stderr="network failed")
        with patch.object(release_version.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "network failed"):
                release_version.tag_exists("v1.2.3")

    def test_ensure_tag_absent_raises_for_existing_tag(self) -> None:
        with patch.object(release_version, "tag_exists", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "tag v1.2.3 already exists in origin"):
                release_version.ensure_tag_absent("v1.2.3")

    def test_main_fails_on_empty_release_when_required(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(release_version, "ensure_new_commits", side_effect=RuntimeError("nothing to release")),
            patch.object(release_version, "bumped_version") as bumped_version,
            redirect_stderr(stderr),
        ):
            self.assertEqual(
                release_version.main(["--release-kind", "stable", "--require-new-commits"]),
                1,
            )
        bumped_version.assert_not_called()
        self.assertEqual(stderr.getvalue().strip(), "nothing to release")

    def test_main_fails_on_existing_tag_when_required(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(release_version, "bumped_version", return_value="v1.2.4"),
            patch.object(release_version, "ensure_tag_absent", side_effect=RuntimeError("tag v1.2.4 already exists in origin")),
            redirect_stderr(stderr),
        ):
            self.assertEqual(
                release_version.main(["--release-kind", "stable", "--require-absent-tag"]),
                1,
            )
        self.assertEqual(stderr.getvalue().strip(), "tag v1.2.4 already exists in origin")


if __name__ == "__main__":
    unittest.main()
