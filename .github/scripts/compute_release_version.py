#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).resolve().parents[2]
RC_IGNORE_TAGS = r"^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$"
RC_VERSION_RE = re.compile(r"^(\d+\.\d+\.\d+)-rc\.(\d+)$")
ReleaseKind = Literal["stable", "rc"]


def bumped_version(release_kind: ReleaseKind) -> str:
    try:
        raw_version = run_command(*build_git_cliff_args(release_kind))
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        if "No releases found" in stderr:
            return "0.1.0"
        raise RuntimeError(stderr or "git-cliff failed while computing the next version.") from exc

    return raw_version


def build_git_cliff_args(release_kind: ReleaseKind) -> list[str]:
    args = ["git-cliff"]
    if release_kind == "stable":
        args.extend(["--ignore-tags", RC_IGNORE_TAGS])
    args.append("--bumped-version")
    return args


def build_git_cliff_context_args(release_kind: ReleaseKind) -> list[str]:
    args = ["git-cliff", "--unreleased", "--bump", "--context"]
    if release_kind == "stable":
        args.extend(["--ignore-tags", RC_IGNORE_TAGS])
    return args


def run_command(*args: str) -> str:
    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def normalize_version(raw_version: str) -> str:
    version = raw_version.strip()
    if version.startswith("v"):
        version = version[1:]
    return version


def compute_next_tag(raw_version: str, release_kind: ReleaseKind) -> str:
    version = normalize_version(raw_version)
    if not version:
        raise RuntimeError("git-cliff did not return a version.")

    if release_kind == "stable":
        if RC_VERSION_RE.fullmatch(version):
            raise RuntimeError("git-cliff returned a prerelease version for a stable release.")
        return f"v{version}"

    if RC_VERSION_RE.fullmatch(version):
        return f"v{version}"
    return f"v{version}-rc.1"


def release_commit_count(release_kind: ReleaseKind) -> int:
    try:
        raw_context = run_command(*build_git_cliff_context_args(release_kind))
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(stderr or "git-cliff failed while checking for new commits.") from exc

    try:
        context = json.loads(raw_context)
    except json.JSONDecodeError as exc:
        raise RuntimeError("git-cliff returned invalid JSON while checking for new commits.") from exc

    if not context:
        return 0

    statistics = context[0].get("statistics", {})
    return int(statistics.get("commit_count", 0))


def ensure_new_commits(release_kind: ReleaseKind) -> None:
    if release_commit_count(release_kind) == 0:
        raise RuntimeError("nothing to release")


def tag_exists(tag: str) -> bool:
    completed = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--tags", "origin", f"refs/tags/{tag}"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 2:
        return False

    stderr = (completed.stderr or completed.stdout or "").strip()
    raise RuntimeError(stderr or f"git failed while checking whether {tag} exists in origin.")


def ensure_tag_absent(tag: str) -> None:
    if tag_exists(tag):
        raise RuntimeError(f"tag {tag} already exists in origin")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compute_release_version.py",
        description="Compute the next release tag for stable or rc workflows.",
    )
    parser.add_argument(
        "--release-kind",
        required=True,
        choices=("stable", "rc"),
        help="Release line to compute the next tag for.",
    )
    parser.add_argument(
        "--require-new-commits",
        action="store_true",
        help="Fail if there are no unreleased commits for the selected release line.",
    )
    parser.add_argument(
        "--require-absent-tag",
        action="store_true",
        help="Fail if the computed release tag already exists in origin.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.require_new_commits:
            ensure_new_commits(args.release_kind)
        next_tag = compute_next_tag(bumped_version(args.release_kind), args.release_kind)
        if args.require_absent_tag:
            ensure_tag_absent(next_tag)
        print(next_tag)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
