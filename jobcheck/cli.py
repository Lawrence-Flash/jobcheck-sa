"""Command-line interface for JobCheck SA."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from jobcheck import __version__
from jobcheck.engine import RuleFileError, analyze, load_rules

PROG = "python3 -m jobcheck"
WIDTH = 78


def main(
    argv: list[str] | None = None,
    stdin: object | None = None,
    stdout: object | None = None,
    stderr: object | None = None,
) -> int:
    """Run the CLI. Streams default to the process standard streams."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0

    try:
        ruleset = load_rules(args.rules)
    except RuleFileError as exc:
        print(f"error: {exc}", file=stderr)
        return 1

    if args.command == "check":
        try:
            text = _read_ad(args.path, stdin)
        except OSError as exc:
            print(f"error: {exc}", file=stderr)
            return 1
        source = "stdin" if args.path == "-" else args.path
        report = analyze(text, ruleset)
        _emit(report, source, as_json=args.json, stdout=stdout)
        return 0

    if args.command == "demo":
        try:
            samples = _sample_paths()
        except OSError as exc:
            print(f"error: {exc}", file=stderr)
            return 1
        results = []
        for path in samples:
            text = path.read_text(encoding="utf-8")
            source = _display_path(path)
            results.append((source, analyze(text, ruleset)))
        if args.json:
            payload = {
                "tool": "jobcheck",
                "version": __version__,
                "results": [
                    {"source": source, **report.to_dict()} for source, report in results
                ],
            }
            _print_json(payload, stdout)
        else:
            _write_demo(results, stdout)
        return 0

    print("error: unknown command", file=stderr)
    return 2


def default_samples_dir() -> Path:
    """Return the repository ``samples`` directory next to the package."""
    return Path(__file__).resolve().parent.parent / "samples"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Check a South African job ad for common scam red flags. "
            "Scoring is a local heuristic. It is not a guarantee."
        ),
        epilog=textwrap.dedent(
            """\
            examples:
              python3 -m jobcheck check ad.txt
              cat ad.txt | python3 -m jobcheck check -
              python3 -m jobcheck check --json ad.txt
              python3 -m jobcheck demo
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"jobcheck {__version__}")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON",
    )
    shared.add_argument(
        "--rules",
        type=Path,
        help="path to an alternate rules JSON file (default: the packaged rules)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "check",
        parents=[shared],
        help="score one job ad from a file or from stdin",
    )
    check.add_argument(
        "path",
        help="path to a text file containing the ad, or - to read stdin",
    )
    commands.add_parser(
        "demo",
        parents=[shared],
        help="score the fictional sample ads shipped with JobCheck SA",
    )
    return parser


def _read_ad(path: str, stdin: object) -> str:
    if path == "-":
        return stdin.read()
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"ad file not found: {path}")
    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise OSError(f"ad file is not UTF-8 text: {path}") from exc


def _sample_paths() -> list[Path]:
    directory = default_samples_dir()
    if not directory.is_dir():
        raise FileNotFoundError(f"sample ads not found at {directory}")
    paths = sorted(directory.glob("*.txt"))
    if not paths:
        raise FileNotFoundError(f"no .txt sample ads in {directory}")
    return paths


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _emit(report, source: str, as_json: bool, stdout: object) -> None:
    if as_json:
        payload = {
            "tool": "jobcheck",
            "version": __version__,
            "source": source,
            **report.to_dict(),
        }
        _print_json(payload, stdout)
        return
    _write_report(report, source, stdout)


def _print_json(payload: dict, stdout: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False), file=stdout)


def _write_report(report, source: str, stdout: object) -> None:
    print("JobCheck SA", file=stdout)
    print(f"Source: {source}", file=stdout)
    print(f"Risk score: {report.score}/{report.score_cap}", file=stdout)
    print(f"Band: {report.band}", file=stdout)
    if report.weight_total > report.score:
        print(
            f"Weight total: {report.weight_total} (capped at {report.score_cap})",
            file=stdout,
        )
    for warning in report.warnings:
        print(f"Note: {warning}", file=stdout)
    print(file=stdout)
    if not report.flags:
        print("Flags", file=stdout)
        print("-----", file=stdout)
        print("No rules matched.", file=stdout)
        print(file=stdout)
        print(
            _wrap(
                "A clear result only means these rules did not match. "
                "It does not mean the advert is safe."
            ),
            file=stdout,
        )
        print(file=stdout)
    else:
        heading = f"Flags ({len(report.flags)})"
        print(heading, file=stdout)
        print("-" * len(heading), file=stdout)
        for index, flag in enumerate(report.flags, start=1):
            print(f"{index}. {flag.name} (weight {flag.weight})", file=stdout)
            print(_wrap(flag.explanation, indent="   "), file=stdout)
            for snippet in flag.snippets:
                print(_wrap(f'Matched: "{snippet}"', indent="   "), file=stdout)
            print(file=stdout)
    print("Safe next steps", file=stdout)
    print("---------------", file=stdout)
    for step in report.next_steps:
        print(
            textwrap.fill(
                f"- {step}",
                width=WIDTH,
                subsequent_indent="  ",
                break_long_words=False,
                break_on_hyphens=False,
            ),
            file=stdout,
        )
    print(file=stdout)
    print(_wrap(report.disclaimer), file=stdout)


def _write_demo(results, stdout: object) -> None:
    print("JobCheck SA demo", file=stdout)
    print(f"{len(results)} fictional ads", file=stdout)
    print(file=stdout)
    for source, report in results:
        names = ", ".join(flag.id for flag in report.flags) or "no rules matched"
        print(source, file=stdout)
        print(f"  {report.score}/{report.score_cap}  {report.band}", file=stdout)
        print(_wrap(names, indent="  "), file=stdout)
        print(file=stdout)
    print(
        "Run `python3 -m jobcheck check <file>` for the full report, including snippets.",
        file=stdout,
    )
    print(_wrap(results[0][1].disclaimer), file=stdout)


def _wrap(text: str, indent: str = "") -> str:
    return textwrap.fill(
        text,
        width=WIDTH,
        initial_indent=indent,
        subsequent_indent=indent if indent else "",
        break_long_words=False,
        break_on_hyphens=False,
    )
