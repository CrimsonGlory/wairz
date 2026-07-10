#!/usr/bin/env python3
"""Update current_coverage.txt without re-running the full test suite.

Do not manually edit current_coverage.txt; use this script only.

Miss counts statements (coverage.py executable units), not lines. Missing lists
line numbers; one statement may span multiple lines, and a line may hold
multiple statements. Statement counts use coverage.parser.PythonParser to
match coverage report Stmts.
"""

import argparse
import os
import re
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from coverage.parser import PythonParser

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_FILE = REPO_ROOT / "current_coverage.txt"
LOCK_FILE = REPO_ROOT / "updating_current_coverage.lock"
LOCK_TIMEOUT_SEC = 20
LOCK_RETRY_SEC = 1
HEADER = (
    "Name                                                                            "
    "Stmts   Miss   Cover   Missing\n"
    "------------------------------------------------------------------------------"
    "--------------------------------\n"
)
_STATEMENT_LINES_CACHE = {}


def statement_lines(file_path):
    """Statement start line numbers, matching coverage.py report Stmts."""
    cache_key = str(file_path.resolve())
    if cache_key not in _STATEMENT_LINES_CACHE:
        source = file_path.read_text(encoding="utf-8")
        parser = PythonParser(text=source, filename=str(file_path))
        parser.parse_source()
        _STATEMENT_LINES_CACHE[cache_key] = parser.statements
    return _STATEMENT_LINES_CACHE[cache_key]


def count_statements(file_path):
    return len(statement_lines(file_path))


def count_statements_on_lines(path, line_numbers):
    if not line_numbers:
        return 0
    file_path = REPO_ROOT / path
    line_set = set(line_numbers)
    return len(statement_lines(file_path) & line_set)


def parse_line_spec(spec):
    lines = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            try:
                start = int(start_text.strip())
                end = int(end_text.strip())
            except ValueError:
                raise ValueError("Invalid line interval: %s" % token) from None
            if start > end:
                raise ValueError("Invalid line interval: %s" % token)
            lines.update(range(start, end + 1))
        else:
            try:
                lines.add(int(token))
            except ValueError:
                raise ValueError("Invalid line number: %s" % token) from None
    return lines


def parse_missing(missing):
    if not missing.strip():
        return set()
    return parse_line_spec(missing)


def format_missing(lines):
    if not lines:
        return ""
    sorted_lines = sorted(lines)
    parts = []
    start = sorted_lines[0]
    end = start
    for line in sorted_lines[1:]:
        if line == end + 1:
            end = line
            continue
        if start == end:
            parts.append(str(start))
        else:
            parts.append("%d-%d" % (start, end))
        start = end = line
    if start == end:
        parts.append(str(start))
    else:
        parts.append("%d-%d" % (start, end))
    return ", ".join(parts)


def recompute_cover(row):
    stmts = row["stmts"]
    row["cover"] = 100.0 if stmts == 0 else (stmts - row["miss"]) * 100.0 / stmts


def assert_row_consistent(path, row):
    stmts = row["stmts"]
    expected_cover = 100.0 if stmts == 0 else (stmts - row["miss"]) * 100.0 / stmts
    if abs(row["cover"] - expected_cover) >= 0.005:
        print(
            "Inconsistent cover for %s: cover=%.2f expected=%.2f"
            % (path, row["cover"], expected_cover),
            file=sys.stderr,
        )
        sys.exit(-1)


def is_row_outdated(path, row):
    file_path = REPO_ROOT / path
    if not file_path.exists():
        return True
    return count_statements(file_path) != row["stmts"]


def parse_rows(text):
    rows = {}
    total = None
    for line in text.splitlines():
        if line.startswith("TOTAL"):
            parts = line.split()
            total = {
                "stmts": int(parts[1]),
                "miss": int(parts[2]),
                "cover": float(parts[3].rstrip("%")),
            }
            continue
        work = line
        if work.lstrip().startswith("#"):
            work = work.lstrip()[1:].lstrip()
        sparse_line = work.strip()
        if not sparse_line or sparse_line.startswith("-"):
            continue
        match = re.match(
            r"^(?P<name>\S+)\s+(?P<stmts>\d+)\s+(?P<miss>\d+)\s+(?P<cover>[\d.]+)%"
            r"(?:\s+(?P<missing>.*))?$",
            work,
        )
        if not match:
            continue
        rows[match.group("name")] = {
            "stmts": int(match.group("stmts")),
            "miss": int(match.group("miss")),
            "cover": float(match.group("cover")),
            "missing": match.group("missing") or "",
        }
    return rows, total


def format_row(name, stmts, miss, missing=""):
    cover = 100.0 if stmts == 0 else (stmts - miss) * 100.0 / stmts
    row = "%-79s %5d %6d %6.2f%%" % (name, stmts, miss, cover)
    if missing:
        row += "   %s" % missing
    return row


def active_rows(rows):
    return {name: row for name, row in rows.items() if not is_row_outdated(name, row)}


def recompute_total(rows):
    active = active_rows(rows)
    stmts = sum(row["stmts"] for row in active.values())
    miss = sum(row["miss"] for row in active.values())
    cover = 100.0 if stmts == 0 else (stmts - miss) * 100.0 / stmts
    return {"stmts": stmts, "miss": miss, "cover": cover}


def write_file(rows, total):
    lines = [HEADER.rstrip("\n")]
    for name in sorted(rows.keys()):
        row = rows[name]
        formatted = format_row(name, row["stmts"], row["miss"], row.get("missing", ""))
        if is_row_outdated(name, row):
            lines.append("# " + formatted)
        else:
            lines.append(formatted)
    lines.append(
        "------------------------------------------------------------------------------"
        "--------------------------------"
    )
    lines.append(
        "TOTAL %75s %6d %6d %6.2f%%"
        % ("", total["stmts"], total["miss"], total["cover"])
    )
    COVERAGE_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def set_covered(rows, path):
    if path not in rows:
        raise KeyError("Unknown coverage row: %s" % path)
    row = rows[path]
    row["miss"] = 0
    row["missing"] = ""
    recompute_cover(row)


def add_lines_as_covered(rows, path, spec):
    if path not in rows:
        raise KeyError("Unknown coverage row: %s" % path)
    row = rows[path]
    current_missing = parse_missing(row["missing"])
    covered_lines = current_missing & parse_line_spec(spec)
    row["miss"] -= count_statements_on_lines(path, covered_lines)
    row["missing"] = format_missing(current_missing - covered_lines)
    recompute_cover(row)


def remove_lines_as_covered(rows, path, spec):
    if path not in rows:
        raise KeyError("Unknown coverage row: %s" % path)
    row = rows[path]
    current_missing = parse_missing(row["missing"])
    new_lines = parse_line_spec(spec)
    added_lines = new_lines - current_missing
    row["miss"] += count_statements_on_lines(path, added_lines)
    row["missing"] = format_missing(current_missing | new_lines)
    recompute_cover(row)


def replace_file_missing(rows, path, spec):
    if path not in rows:
        raise KeyError("Unknown coverage row: %s" % path)
    row = rows[path]
    missing = parse_line_spec(spec)
    row["miss"] = count_statements_on_lines(path, missing)
    row["missing"] = format_missing(missing)
    recompute_cover(row)


def add_test_file(rows, path, miss=0):
    file_path = REPO_ROOT / path
    stmts = count_statements(file_path)
    rows[path] = {
        "stmts": stmts,
        "miss": miss,
        "cover": 100.0 if stmts == 0 else (stmts - miss) * 100.0 / stmts,
        "missing": "",
    }


@contextmanager
def coverage_update_lock():
    deadline = time.monotonic() + LOCK_TIMEOUT_SEC
    while True:
        try:
            fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                print(
                    "Timed out after %ds waiting for %s"
                    % (LOCK_TIMEOUT_SEC, LOCK_FILE.name),
                    file=sys.stderr,
                )
                sys.exit(1)
            time.sleep(LOCK_RETRY_SEC)
    try:
        yield
    finally:
        try:
            LOCK_FILE.unlink()
        except OSError:
            pass


def print_rows(rows):
    outdated_paths = []
    for path in sorted(rows.keys()):
        row = rows[path]
        formatted = format_row(path, row["stmts"], row["miss"], row.get("missing", ""))
        if is_row_outdated(path, row):
            print("# " + formatted)
            outdated_paths.append(path)
        else:
            print(formatted)
    if outdated_paths:
        print(
            "Outdated rows (stmts != coverage.py count): %s"
            % ", ".join(sorted(outdated_paths)),
            file=sys.stderr,
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-stmts",
        type=int,
        default=None,
        help="Use this TOTAL Stmts instead of summing parsed rows",
    )
    parser.add_argument(
        "--baseline-miss",
        type=int,
        default=None,
        help="Use this TOTAL Miss instead of summing parsed rows",
    )
    parser.add_argument(
        "--set-file-as-covered",
        action="append",
        default=[],
        metavar="PATH",
        help="Set Miss to 0 and Cover to 100%% for a source file row",
    )
    parser.add_argument(
        "--add-lines-as-covered",
        nargs=2,
        action="append",
        default=[],
        metavar=("PATH", "LINES"),
        help="Remove lines from Missing and decrease Miss by statements on those lines",
    )
    parser.add_argument(
        "--remove-lines-as-covered",
        nargs=2,
        action="append",
        default=[],
        metavar=("PATH", "LINES"),
        help="Add lines to Missing and increase Miss by statements on those lines",
    )
    parser.add_argument(
        "--replace-file-missing",
        nargs=2,
        action="append",
        default=[],
        metavar=("PATH", "LINES"),
        help="Replace Missing entirely; Miss becomes statement count on those lines",
    )
    parser.add_argument(
        "--add-test-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Add a new test file row using coverage.py statement count",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write updated current_coverage.txt",
    )
    args = parser.parse_args(argv)

    with coverage_update_lock():
        rows, _ = parse_rows(COVERAGE_FILE.read_text(encoding="utf-8"))
        modified_paths = set()

        for path in args.set_file_as_covered:
            set_covered(rows, path)
            modified_paths.add(path)

        for path, spec in args.add_lines_as_covered:
            add_lines_as_covered(rows, path, spec)
            modified_paths.add(path)

        for path, spec in args.remove_lines_as_covered:
            remove_lines_as_covered(rows, path, spec)
            modified_paths.add(path)

        for path, spec in args.replace_file_missing:
            replace_file_missing(rows, path, spec)
            modified_paths.add(path)

        for path in args.add_test_file:
            add_test_file(rows, path)
            modified_paths.add(path)

        for path in modified_paths:
            assert_row_consistent(path, rows[path])

        total = recompute_total(rows)
        if args.baseline_stmts is not None:
            total["stmts"] = args.baseline_stmts
        if args.baseline_miss is not None:
            total["miss"] = args.baseline_miss
        if args.baseline_stmts is not None or args.baseline_miss is not None:
            total["cover"] = (
                100.0
                if total["stmts"] == 0
                else (total["stmts"] - total["miss"]) * 100.0 / total["stmts"]
            )

        print_rows(rows)
        print(
            "TOTAL %75s %6d %6d %6.2f%%"
            % ("", total["stmts"], total["miss"], total["cover"])
        )

        if args.write:
            write_file(rows, total)
            print("Wrote %s" % COVERAGE_FILE, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
