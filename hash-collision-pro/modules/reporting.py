"""Terminal presentation and report export (JSON / CSV / TXT)."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .avalanche import AvalancheResult
from .benchmark import BenchmarkResult
from .collision import (
    CollisionResult,
    birthday_bound,
    birthday_bound_precise,
    collision_probability,
    expected_attempts_50_percent,
    search_space,
)
from .hashing import ALGORITHMS, AnalyzerError

__all__ = [
    "Palette",
    "use_colour",
    "banner",
    "section",
    "field_block",
    "table",
    "info",
    "warn",
    "error",
    "success",
    "note",
    "render_collision",
    "render_benchmark",
    "render_avalanche",
    "render_algorithms",
    "render_file_comparison",
    "TRUNCATION_DISCLAIMER",
    "ReportError",
    "supported_formats",
    "export_report",
]

WIDTH = 60
TRUNCATION_DISCLAIMER = (
    "NOTE:\n"
    "The COMPLETE {algorithm} hashes are different.\n\n"
    "This experiment intentionally shortened the hash to {bits} bits so that\n"
    "the birthday-collision principle can be demonstrated on normal hardware.\n"
    "This is NOT a break of {algorithm}."
)


class ReportError(AnalyzerError):
    """Raised when a report cannot be written."""


# --------------------------------------------------------------------------
# Colour handling
# --------------------------------------------------------------------------

class Palette:
    """ANSI colour codes, blanked out when colour is not appropriate."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


_COLOUR_ENABLED = True


def use_colour(enabled: Optional[bool] = None) -> bool:
    """Enable, disable or query coloured output.

    Colour is switched off automatically when stdout is not a terminal or the
    ``NO_COLOR`` environment variable is set.
    """
    global _COLOUR_ENABLED
    if enabled is None:
        return _COLOUR_ENABLED
    _COLOUR_ENABLED = bool(enabled) and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    return _COLOUR_ENABLED


use_colour(True)


def _c(text: str, colour: str) -> str:
    """Wrap ``text`` in an ANSI colour when colour is enabled."""
    if not _COLOUR_ENABLED:
        return text
    return "{}{}{}".format(colour, text, Palette.RESET)


# --------------------------------------------------------------------------
# Building blocks
# --------------------------------------------------------------------------

def banner(title: str) -> str:
    """Return a boxed, centred title block."""
    line = "=" * WIDTH
    return "\n".join([_c(line, Palette.CYAN), _c(title.center(WIDTH), Palette.BOLD), _c(line, Palette.CYAN)])


def section(title: str) -> str:
    """Return an underlined section heading."""
    return "\n{}\n{}".format(_c(title, Palette.BOLD), "-" * WIDTH)


def field_block(label: str, value: Any) -> str:
    """Return a two-line ``label:`` / ``value`` block."""
    return "\n{}\n{}".format(_c(label + ":", Palette.DIM), value)


def table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    """Render a simple aligned text table."""
    all_rows: List[List[str]] = [[str(cell) for cell in row] for row in rows]
    widths = [len(str(header)) for header in headers]
    for row in all_rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(cell))

    def build(cells: Sequence[str]) -> str:
        return "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(cells))

    lines = [_c(build(list(headers)), Palette.BOLD), "-" * len(build(list(headers)))]
    lines.extend(build(row) for row in all_rows)
    return "\n".join(lines)


def info(message: str) -> str:
    """Format an informational line."""
    return "{} {}".format(_c("[*]", Palette.BLUE), message)


def warn(message: str) -> str:
    """Format a warning line."""
    return "{} {}".format(_c("[!]", Palette.YELLOW), message)


def error(message: str) -> str:
    """Format an error line."""
    return "{} {}".format(_c("[x]", Palette.RED), message)


def success(message: str) -> str:
    """Format a success line."""
    return "{} {}".format(_c("[+]", Palette.GREEN), message)


def note(message: str) -> str:
    """Format a multi-line disclaimer block."""
    return "\n{}\n{}\n{}".format("-" * WIDTH, _c(message, Palette.YELLOW), "-" * WIDTH)


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

def render_collision(result: CollisionResult) -> str:
    """Render a :class:`CollisionResult` as a terminal report."""
    out: List[str] = [banner("COLLISION EXPERIMENT"), ""]
    out.append("Algorithm: {}".format(result.algorithm))
    out.append("Full digest size: {} bits".format(result.digest_bits))
    out.append("Effective hash size: {} bits".format(result.effective_bits))
    out.append(
        "Search space: 2^{} = {:,} values".format(
            result.effective_bits, search_space(result.effective_bits)
        )
    )
    out.append("")

    if not result.found:
        out.append(
            warn(
                "No collision within {:,} attempts. Increase --max-attempts "
                "or lower --bits.".format(result.max_attempts)
            )
        )
        out.append(field_block("Elapsed time", "{:.3f} seconds".format(result.elapsed_seconds)))
        return "\n".join(out)

    out.append(_c("[!] COLLISION FOUND", Palette.GREEN))
    out.append(field_block("Input A", result.input_a))
    out.append(field_block("Input B", result.input_b))
    out.append(field_block("Full Hash A", result.full_hash_a))
    out.append(field_block("Full Hash B", result.full_hash_b))
    out.append(field_block("Truncated Hash A", result.truncated_hex))
    out.append(field_block("Truncated Hash B", result.truncated_hex))
    out.append(field_block("Attempts", "{:,}".format(result.attempts)))
    out.append(
        field_block(
            "Expected birthday-bound",
            "~{:,} attempts  (2^({}/2); precise expectation {:,.0f})".format(
                result.birthday_bound,
                result.effective_bits,
                result.birthday_bound_precise,
            ),
        )
    )
    out.append(
        field_block(
            "Collision probability at this attempt count",
            "{:.2%}".format(
                collision_probability(result.effective_bits, result.attempts)
            ),
        )
    )
    out.append(field_block("Elapsed time", "{:.6f} seconds".format(result.elapsed_seconds)))
    out.append(
        field_block("Throughput", "{:,.0f} hashes/second".format(result.attempts_per_second))
    )

    out.append(
        note(
            TRUNCATION_DISCLAIMER.format(
                algorithm=result.algorithm, bits=result.effective_bits
            )
        )
    )
    if result.full_hashes_differ:
        out.append(
            success(
                "Verified: the two full digests differ, so this is a truncated-hash "
                "collision only."
            )
        )
    return "\n".join(out)


def render_benchmark(result: BenchmarkResult) -> str:
    """Render a :class:`BenchmarkResult` as a terminal report."""
    out: List[str] = [banner("COLLISION BENCHMARK"), ""]
    out.append("Algorithm: {}".format(result.algorithm))
    out.append("Full digest size: {} bits".format(result.digest_bits))
    out.append("Effective hash size: {} bits".format(result.effective_bits))
    out.append(
        "Runs: {} completed / {} requested".format(
            result.runs_completed, result.runs_requested
        )
    )
    if result.failures:
        out.append(warn("{} run(s) hit the attempt ceiling.".format(result.failures)))

    out.append(section("ATTEMPT STATISTICS"))
    out.append(
        table(
            ["Metric", "Value"],
            [
                ["Minimum attempts", "{:,}".format(result.min_attempts)],
                ["Maximum attempts", "{:,}".format(result.max_attempts_observed)],
                ["Average attempts", "{:,.2f}".format(result.average_attempts)],
                ["Median attempts", "{:,.2f}".format(result.median_attempts)],
                ["Std deviation", "{:,.2f}".format(result.stdev_attempts)],
            ],
        )
    )

    out.append(section("THEORY VS EXPERIMENT"))
    out.append(
        table(
            ["Metric", "Value"],
            [
                [
                    "Search space",
                    "2^{} = {:,}".format(
                        result.effective_bits, search_space(result.effective_bits)
                    ),
                ],
                [
                    "Birthday bound 2^(n/2)",
                    "{:,}".format(birthday_bound(result.effective_bits)),
                ],
                [
                    "Precise expectation",
                    "{:,.2f}".format(birthday_bound_precise(result.effective_bits)),
                ],
                [
                    "Attempts for 50% chance",
                    "{:,.2f}".format(
                        expected_attempts_50_percent(result.effective_bits)
                    ),
                ],
                ["Observed / theory", "{:.3f}".format(result.theory_ratio)],
            ],
        )
    )

    out.append(section("TIMING"))
    out.append(
        table(
            ["Metric", "Value"],
            [
                ["Total time", "{:.6f} s".format(result.total_seconds)],
                ["Average per run", "{:.6f} s".format(result.average_seconds)],
                ["Median per run", "{:.6f} s".format(result.median_seconds)],
            ],
        )
    )

    if result.attempts:
        out.append(section("PER-RUN RESULTS"))
        out.append(
            table(
                ["Run", "Attempts", "Seconds"],
                [
                    [index + 1, "{:,}".format(attempt), "{:.6f}".format(seconds)]
                    for index, (attempt, seconds) in enumerate(
                        zip(result.attempts, result.elapsed)
                    )
                ],
            )
        )

    out.append(
        note(
            TRUNCATION_DISCLAIMER.format(
                algorithm=result.algorithm, bits=result.effective_bits
            )
        )
    )
    return "\n".join(out)


def render_avalanche(result: AvalancheResult) -> str:
    """Render an :class:`AvalancheResult` as a terminal report."""
    out: List[str] = [banner("AVALANCHE EFFECT TEST"), ""]
    out.append("Algorithm: {}".format(result.algorithm))
    out.append("Digest size: {} bits".format(result.digest_bits))
    out.append(field_block("Input A", result.input_a))
    out.append(field_block("Input B", result.input_b))
    if result.input_changed_bits is not None:
        out.append(
            field_block(
                "Input bits changed", "{} bit(s)".format(result.input_changed_bits)
            )
        )
    out.append(field_block("Hash A", result.hash_a))
    out.append(field_block("Hash B", result.hash_b))

    if result.inputs_identical:
        out.append(warn("Both inputs are identical, so no bits can change."))

    out.append(
        field_block(
            "Changed bits", "{} / {}".format(result.changed_bits, result.digest_bits)
        )
    )
    out.append(field_block("Percentage", "{:.2f}%".format(result.percentage)))
    out.append(field_block("Ideal", "50.00% (deviation {:+.2f} points)".format(result.deviation_from_ideal)))
    out.append(field_block("Verdict", result.verdict))

    out.append(
        note(
            "Cryptographic hash functions are designed so that a very small\n"
            "change to the input causes large, unpredictable changes to the\n"
            "digest. Each output bit should flip with probability 1/2, so about\n"
            "half of all bits change even when a single input bit is flipped.\n"
            "This is called the avalanche effect, and it is what stops an\n"
            "attacker from learning anything about the input from the digest."
        )
    )
    return "\n".join(out)


def render_algorithms() -> str:
    """Render the algorithm comparison table and its explanation."""
    out: List[str] = [banner("ALGORITHM INFORMATION"), ""]
    rows: List[List[str]] = []
    for key, algo in ALGORITHMS.items():
        rows.append(
            [
                algo.name,
                "{} bits".format(algo.digest_bits),
                algo.collision_security,
                algo.status,
                "--algorithm {}".format(key),
            ]
        )
    out.append(
        table(
            ["Algorithm", "Output Size", "Generic Collision Security", "Status", "CLI flag"],
            rows,
        )
    )

    out.append(section("NOTES"))
    for algo in ALGORITHMS.values():
        out.append("{:<9} {}".format(algo.name, algo.note))

    out.append(section("WHY 'GENERIC COLLISION SECURITY' IS 2^(n/2)"))
    out.append(
        "An n-bit hash has 2^n possible digests, but the birthday paradox means\n"
        "a collision becomes likely after roughly 2^(n/2) random inputs, because\n"
        "every new input is compared against all previous ones.\n"
    )
    out.append(
        table(
            ["Hash size", "Possible outputs", "Birthday bound"],
            [
                ["8 bits", "256", "~16 attempts"],
                ["16 bits", "65,536", "~256 attempts"],
                ["24 bits", "16,777,216", "~4,096 attempts"],
                ["128 bits (MD5)", "3.4 x 10^38", "~2^64"],
                ["256 bits (SHA-256)", "1.2 x 10^77", "~2^128"],
            ],
        )
    )
    out.append(
        note(
            "MD5 and SHA-1 are BROKEN: mathematical (differential) attacks find\n"
            "collisions far faster than the generic 2^(n/2) bound. MD5 collisions\n"
            "take seconds; SHA-1 fell publicly in 2017 (SHAttered).\n\n"
            "SHA-256 and SHA-512 have NO practical known full collision attack.\n"
            "Being 'broken' for collisions does not mean MD5/SHA-1 preimages are\n"
            "easy - preimage resistance is a different, still-harder problem."
        )
    )
    return "\n".join(out)


def render_file_comparison(comparison: Dict[str, Any]) -> str:
    """Render the dictionary returned by :func:`modules.file_hasher.compare_files`."""
    file_a = comparison["file_a"]
    file_b = comparison["file_b"]

    out: List[str] = [banner("FILE COMPARISON"), ""]
    out.append("Algorithm: {}".format(comparison["algorithm"]))
    out.append(
        table(
            ["File", "Size (bytes)", "Chunks", "Digest"],
            [
                [file_a["path"], "{:,}".format(file_a["size_bytes"]), file_a["chunks_read"], file_a["hex_digest"]],
                [file_b["path"], "{:,}".format(file_b["size_bytes"]), file_b["chunks_read"], file_b["hex_digest"]],
            ],
        )
    )
    out.append("")

    if not comparison["identical_digest"]:
        out.append(success("Digests DIFFER - the files are not identical."))
    elif comparison["same_path"]:
        out.append(info("Both paths point at the same file, so the digests match."))
    elif comparison["identical_content"]:
        out.append(
            info(
                "Digests match and the byte content is identical: these are copies, "
                "not a collision."
            )
        )
    else:
        out.append(
            warn(
                "REAL COLLISION: the files have DIFFERENT content but the SAME "
                "{} digest.".format(comparison["algorithm"])
            )
        )
        out.append(
            note(
                "This is a genuine full-digest collision for {alg}.\n"
                "It is expected only for algorithms with known collision attacks\n"
                "(MD5, SHA-1) or for a deliberately supplied known collision pair.".format(
                    alg=comparison["algorithm"]
                )
            )
        )
    return "\n".join(out)


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

def supported_formats() -> Tuple[str, ...]:
    """Return the report formats this module can write."""
    return ("json", "csv", "txt")


def _resolve_format(path: str, fmt: Optional[str]) -> str:
    """Decide the output format from an explicit choice or the file extension."""
    if fmt:
        chosen = fmt.strip().lower().lstrip(".")
    else:
        chosen = os.path.splitext(path)[1].lower().lstrip(".")
    if chosen not in supported_formats():
        raise ReportError(
            "Unsupported report format {!r}. Use one of: {}.".format(
                chosen or "(none)", ", ".join(supported_formats())
            )
        )
    return chosen


def _flatten(payload: Dict[str, Any]) -> List[Tuple[str, Any]]:
    """Flatten a payload into ``(key, value)`` pairs, skipping list details."""
    pairs: List[Tuple[str, Any]] = []
    for key, value in payload.items():
        if key == "runs_detail":
            continue
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                pairs.append(("{}.{}".format(key, inner_key), inner_value))
        elif isinstance(value, list):
            pairs.append((key, " ".join(str(item) for item in value)))
        else:
            pairs.append((key, value))
    return pairs


def _write_json(payload: Dict[str, Any], path: str) -> None:
    """Write ``payload`` as pretty-printed JSON."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _write_csv(payload: Dict[str, Any], path: str) -> None:
    """Write a summary block and, for benchmarks, a per-run table."""
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        for key, value in _flatten(payload):
            writer.writerow([key, value])

        rows = payload.get("runs_detail")
        if rows:
            writer.writerow([])
            writer.writerow(["run", "attempts", "elapsed_seconds"])
            for row in rows:
                writer.writerow([row["run"], row["attempts"], row["elapsed_seconds"]])


def _write_txt(payload: Dict[str, Any], path: str, rendered: Optional[str]) -> None:
    """Write the terminal report (colour stripped) or a key/value dump."""
    buffer = io.StringIO()
    buffer.write("Hash Collision Analyzer Pro - report\n")
    buffer.write("Generated: {}\n".format(datetime.now().astimezone().isoformat(timespec="seconds")))
    buffer.write("=" * WIDTH + "\n\n")

    if rendered:
        buffer.write(rendered)
        buffer.write("\n")
    else:
        for key, value in _flatten(payload):
            buffer.write("{}: {}\n".format(key, value))
        rows = payload.get("runs_detail")
        if rows:
            buffer.write("\nrun, attempts, elapsed_seconds\n")
            for row in rows:
                buffer.write(
                    "{}, {}, {}\n".format(row["run"], row["attempts"], row["elapsed_seconds"])
                )

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(buffer.getvalue())


def export_report(
    payload: Dict[str, Any],
    path: str,
    fmt: Optional[str] = None,
    rendered: Optional[str] = None,
) -> str:
    """Write ``payload`` to ``path`` as JSON, CSV or TXT.

    Args:
        payload: A JSON-serialisable dictionary, usually ``result.to_dict()``.
        path: Destination path; the extension selects the format unless ``fmt``
            is given.
        fmt: Explicit format override (``json``, ``csv`` or ``txt``).
        rendered: Optional pre-rendered terminal text, embedded in TXT reports.

    Returns:
        The absolute path that was written.

    Raises:
        ReportError: On an unknown format or any filesystem failure.
    """
    chosen = _resolve_format(path, fmt)
    target = os.path.abspath(os.path.expanduser(path))
    parent = os.path.dirname(target)

    try:
        if parent:
            os.makedirs(parent, exist_ok=True)
        if chosen == "json":
            _write_json(payload, target)
        elif chosen == "csv":
            _write_csv(payload, target)
        else:
            _write_txt(payload, target, _strip_colour(rendered) if rendered else None)
    except OSError as exc:
        raise ReportError("Could not write report to {}: {}".format(path, exc)) from exc

    return target


def _strip_colour(text: str) -> str:
    """Remove ANSI escape sequences so reports stay readable in an editor."""
    result: List[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\033":
            end = text.find("m", index)
            if end == -1:
                break
            index = end + 1
            continue
        result.append(char)
        index += 1
    return "".join(result)
