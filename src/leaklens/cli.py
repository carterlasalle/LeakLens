"""LeakLens command-line interface and exit-code contract."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .baseline import Baseline, BaselineError, load_baseline, save_baseline
from .config import Config, ConfigError, load_config
from .engine import Scanner
from .filesystem import FileScanner
from .hooks import install_hook, uninstall_hook
from .models import Severity
from .render import render, render_rules
from .repository import GitError, RepositoryScanner
from .rules import Rule, builtin_rules

FORMATS = ("table", "json", "jsonl", "csv", "sarif")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leaklens",
        description="Find committed credentials before attackers do — fully offline",
    )
    parser.add_argument("--version", action="version", version=f"LeakLens {__version__}")
    parser.add_argument("--config", help="path to .leaklens.toml")
    parser.add_argument("--baseline", help="override baseline file")
    parser.add_argument("--no-baseline", action="store_true", help="ignore configured baseline")
    parser.add_argument("--minimum-severity", choices=[item.label() for item in Severity])
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan files, a repository view, or standard input")
    scan.add_argument("paths", nargs="*", default=["."])
    source = scan.add_mutually_exclusive_group()
    source.add_argument("--repo", action="store_true", help="scan Git tracked and untracked files")
    source.add_argument(
        "--staged", action="store_true", help="scan only lines added to the Git index"
    )
    source.add_argument(
        "--history", action="store_true", help="scan first appearances across Git history"
    )
    source.add_argument("--stdin", action="store_true", help="scan standard input")
    scan.add_argument("--stdin-filename", default="<stdin>")
    scan.add_argument("--since", help="history date accepted by git, e.g. '2025-01-01'")
    scan.add_argument("--max-commits", type=_positive_int)
    scan.add_argument("--format", choices=FORMATS, default="table")
    scan.add_argument("--output", help="write report to a file instead of stdout")
    scan.add_argument("--fail-on", choices=[item.label() for item in Severity], default="low")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--quiet", action="store_true", help="print nothing; use the exit code")

    baseline = commands.add_parser(
        "baseline", help="manage fingerprint-only legacy finding baselines"
    )
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_commands.add_parser("create", help="scan and write a new baseline")
    create.add_argument("paths", nargs="*", default=["."])
    create.add_argument("--output", default=".leaklens-baseline.json")
    create.add_argument("--force", action="store_true")
    show = baseline_commands.add_parser("show", help="summarize an existing baseline")
    show.add_argument("path", nargs="?", default=".leaklens-baseline.json")

    rules = commands.add_parser("rules", help="inspect active detector rules")
    rules.add_argument("--format", choices=("table", "json"), default="table")

    hook = commands.add_parser("hook", help="install or remove the managed pre-commit hook")
    hook.add_argument("action", choices=("install", "uninstall"))
    hook.add_argument("--force", action="store_true")

    init = commands.add_parser("init", help="write a documented starter configuration")
    init.add_argument("--force", action="store_true")

    commands.add_parser("doctor", help="validate configuration, Git, and runtime readiness")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        rules = builtin_rules() + config.custom_rules
        if args.command == "rules":
            if args.format == "json":
                print(json.dumps([_rule_dict(rule) for rule in rules], indent=2, sort_keys=True))
            else:
                print(render_rules(rules))
            return 0
        if args.command == "hook":
            if args.action == "install":
                print(f"Installed {install_hook(force=args.force)}")
            else:
                removed = uninstall_hook()
                print(
                    "Removed LeakLens pre-commit hook" if removed else "No LeakLens hook installed"
                )
            return 0
        if args.command == "init":
            return _init_config(force=args.force)
        if args.command == "doctor":
            return _doctor(config, rules)
        if args.command == "baseline":
            return _baseline_command(args, config, rules)
        return _scan_command(args, config, rules)
    except (BaselineError, ConfigError, FileExistsError, GitError, OSError, ValueError) as exc:
        print(f"leaklens: error: {exc}", file=sys.stderr)
        return 2


def _scan_command(args: argparse.Namespace, config: Config, rules: tuple[Rule, ...]) -> int:
    allowed = set(config.allowed_fingerprints)
    baseline_path = args.baseline or config.baseline_path
    if not args.no_baseline and Path(baseline_path).is_file():
        allowed.update(load_baseline(baseline_path).fingerprints)
    minimum = (
        Severity.parse(args.minimum_severity) if args.minimum_severity else config.minimum_severity
    )
    scanner = Scanner(
        rules=rules, minimum_severity=minimum, allowed_fingerprints=frozenset(allowed)
    )
    files = FileScanner(
        scanner,
        excludes=config.excludes,
        max_file_size=config.max_file_size,
        follow_symlinks=config.follow_symlinks,
        scan_hidden=config.scan_hidden,
    )
    if args.stdin:
        result = scanner.scan_text(sys.stdin.read(), path=args.stdin_filename)
    elif args.staged or args.history or args.repo:
        repository = RepositoryScanner(Path.cwd(), scanner, files)
        if args.staged:
            result = repository.scan_staged()
        elif args.history:
            limit = args.max_commits or config.history_max_commits
            result = repository.scan_history(max_commits=limit, since=args.since)
        else:
            result = repository.scan_worktree()
    else:
        result = files.scan_paths(args.paths)
    output = render(result, args.format, rules, color=_color_enabled(args))
    if not args.quiet:
        if args.output:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
    threshold = Severity.parse(args.fail_on)
    if result.errors:
        return 2
    return 1 if any(finding.severity >= threshold for finding in result.findings) else 0


def _baseline_command(args: argparse.Namespace, config: Config, rules: tuple[Rule, ...]) -> int:
    if args.baseline_command == "show":
        baseline = load_baseline(args.path)
        print(
            f"Schema: 1\nGenerated: {baseline.generated_at}\nFingerprints: {len(baseline.fingerprints)}"
        )
        return 0
    destination = Path(args.output)
    if destination.exists() and not args.force:
        raise FileExistsError(f"{destination} exists; pass --force to replace it")
    scanner = Scanner(rules=rules, minimum_severity=config.minimum_severity)
    result = FileScanner(
        scanner, config.excludes, config.max_file_size, config.follow_symlinks, config.scan_hidden
    ).scan_paths(args.paths)
    if result.errors:
        raise OSError("; ".join(result.errors))
    baseline = Baseline.from_findings(result.findings)
    save_baseline(destination, baseline)
    print(
        f"Wrote {destination} with {len(baseline.fingerprints)} fingerprint(s); no secret values stored"
    )
    return 0


def _init_config(*, force: bool) -> int:
    destination = Path(".leaklens.toml")
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} exists; pass --force to replace it")
    destination.write_text(_STARTER_CONFIG, encoding="utf-8")
    print(f"Wrote {destination}")
    return 0


def _doctor(config: Config, rules: tuple[Rule, ...]) -> int:
    checks = [
        (
            "Python",
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            sys.version_info >= (3, 11),
        ),
        ("Git", shutil.which("git") or "not found", shutil.which("git") is not None),
        ("Configuration", f"{len(rules)} active rules", True),
        (
            "Baseline",
            config.baseline_path if Path(config.baseline_path).is_file() else "not configured",
            True,
        ),
        ("Network", "not used", True),
    ]
    for name, detail, healthy in checks:
        print(f"{'✓' if healthy else '✗'} {name}: {detail}")
    return 0 if all(healthy for _, _, healthy in checks) else 2


def _color_enabled(args: argparse.Namespace) -> bool:
    return (
        not args.no_color
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and not args.output
    )


def _rule_dict(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity.label(),
        "confidence": rule.confidence,
        "minimum_entropy": rule.minimum_entropy,
        "tags": list(rule.tags),
        "message": rule.message,
    }


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


_STARTER_CONFIG = """# LeakLens project policy. Runtime scanning is fully offline.
[scan]
minimum_severity = "low"
max_file_size = 5242880
history_max_commits = 1000
exclude = ["tests/fixtures/**"]
follow_symlinks = false
scan_hidden = false

[baseline]
path = ".leaklens-baseline.json"

# Add a project-specific detector:
# [[rules]]
# id = "internal-token"
# title = "Internal service token"
# pattern = "(?P<secret>corp_[A-Za-z0-9]{32})"
# severity = "critical"
# minimum_entropy = 3.0
# tags = ["internal", "token"]
"""


if __name__ == "__main__":
    raise SystemExit(main())
