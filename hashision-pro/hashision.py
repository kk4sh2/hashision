#!/usr/bin/env python3
"""Hashision Pro - command line interface.

An educational cybersecurity tool for demonstrating hash collisions, the
birthday paradox and the avalanche effect.

Scope and honesty statement
---------------------------
Collision experiments are run against a deliberately TRUNCATED digest (8-32
bits). The complete MD5/SHA-1/SHA-256/SHA-512 digests of the two inputs remain
different, and the tool says so on every report. Nothing here breaks a real
hash function, and the tool never generates malicious colliding files.

Examples:
    python3 hashision.py hash-text "hello" --algorithm md5
    python3 hashision.py hash-file example.txt --algorithm sha256
    python3 hashision.py compare-text "hello" "world" --algorithm sha256
    python3 hashision.py compare-files a.txt b.txt --algorithm sha256
    python3 hashision.py collision-demo --algorithm sha256 --bits 16
    python3 hashision.py benchmark --algorithm sha256 --bits 16 --runs 20
    python3 hashision.py avalanche "hello" "Hello" --algorithm sha256
    python3 hashision.py algorithms
    python3 hashision.py interactive
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional, Sequence

from modules import __version__
from modules.avalanche import avalanche_test, avalanche_test_files
from modules.benchmark import MAX_RUNS, run_benchmark
from modules.collision import (
    ABSOLUTE_MAX_ATTEMPTS,
    DEFAULT_INPUT_LENGTH,
    DEFAULT_MAX_ATTEMPTS,
    birthday_bound,
    find_collision,
)
from modules.file_hasher import FileHashResult, compare_files, hash_file
from modules.hashing import (
    CHUNK_SIZE,
    MAX_TRUNCATION_BITS,
    RECOMMENDED_BITS,
    AnalyzerError,
    digest_text,
    format_truncated,
    get_algorithm,
    hash_text,
    supported_algorithms,
    truncate_digest,
    validate_bits,
)
from modules import reporting

PROGRAM = "hashision.py"
DEFAULT_REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


# ==========================================================================
# Small helpers
# ==========================================================================

def _timestamp() -> str:
    """Return an ISO-8601 timestamp with the local timezone."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _save(
    payload: Dict[str, Any],
    output: Optional[str],
    fmt: Optional[str] = None,
    rendered: Optional[str] = None,
) -> None:
    """Export ``payload`` when the user asked for an output file."""
    if not output:
        return
    written = reporting.export_report(payload, output, fmt=fmt, rendered=rendered)
    print()
    print(reporting.success("Report written to {}".format(written)))


# ==========================================================================
# Command implementations
# ==========================================================================

def cmd_hash_text(args: argparse.Namespace) -> int:
    """Hash a single string and print the digest."""
    info = get_algorithm(args.algorithm)
    digest = digest_text(args.text, args.algorithm)
    hex_digest = digest.hex()

    print(reporting.banner("HASH TEXT"))
    print()
    print("Algorithm: {}".format(info.name))
    print("Digest size: {} bits ({} hex characters)".format(info.digest_bits, info.hex_length))
    print(reporting.field_block("Input", repr(args.text)))
    print(reporting.field_block("Input length", "{} bytes (UTF-8)".format(len(args.text.encode("utf-8")))))
    print(reporting.field_block("Hash", hex_digest))

    payload: Dict[str, Any] = {
        "report_type": "hash_text",
        "date": _timestamp(),
        "algorithm": info.name,
        "digest_bits": info.digest_bits,
        "input": args.text,
        "hash": hex_digest,
    }

    if args.bits:
        validate_bits(args.bits, args.algorithm)
        truncated = format_truncated(truncate_digest(digest, args.bits), args.bits)
        print(reporting.field_block("Truncated to {} bits".format(args.bits), truncated))
        payload["truncation_bits"] = args.bits
        payload["truncated_hash"] = truncated

    _save(payload, args.output, args.format)
    return 0


def print_file_hash(result: FileHashResult, chunk_size: int) -> None:
    """Print a :class:`FileHashResult` in the standard report layout."""
    print(reporting.banner("HASH FILE"))
    print()
    print("Algorithm: {}".format(result.algorithm))
    print(reporting.field_block("File", result.path))
    print(reporting.field_block("Size", "{:,} bytes".format(result.size_bytes)))
    print(
        reporting.field_block(
            "Read strategy",
            "{:,} chunk(s) of {:,} bytes (constant memory)".format(
                result.chunks_read, chunk_size
            ),
        )
    )
    print(reporting.field_block("Hash", result.hex_digest))


def cmd_hash_file(args: argparse.Namespace) -> int:
    """Hash a file by streaming it in chunks."""
    result = hash_file(args.path, args.algorithm, chunk_size=args.chunk_size)
    print_file_hash(result, args.chunk_size)

    payload = result.to_dict()
    payload["report_type"] = "hash_file"
    payload["date"] = _timestamp()
    _save(payload, args.output, args.format)
    return 0


def cmd_compare_text(args: argparse.Namespace) -> int:
    """Hash two strings and report whether the digests match."""
    info = get_algorithm(args.algorithm)
    hash_a = hash_text(args.text_a, args.algorithm)
    hash_b = hash_text(args.text_b, args.algorithm)
    identical_input = args.text_a == args.text_b
    identical_hash = hash_a == hash_b

    print(reporting.banner("COMPARE TEXT"))
    print()
    print("Algorithm: {}".format(info.name))
    print(reporting.field_block("Input A", repr(args.text_a)))
    print(reporting.field_block("Input B", repr(args.text_b)))
    print(reporting.field_block("Hash A", hash_a))
    print(reporting.field_block("Hash B", hash_b))
    print()

    if identical_hash and identical_input:
        print(reporting.info("Identical hashes because the inputs are identical. Expected."))
        verdict = "identical_inputs"
    elif identical_hash and not identical_input:
        print(
            reporting.warn(
                "REAL COLLISION: different inputs produced the same full {} digest.".format(
                    info.name
                )
            )
        )
        verdict = "real_collision"
    else:
        print(reporting.success("Hashes differ, as expected for different inputs."))
        verdict = "different"

    # Bonus: how close were they? Useful next to the collision demo.
    changed = avalanche_test(args.text_a, args.text_b, args.algorithm)
    print(
        reporting.field_block(
            "Digest bits that differ",
            "{} / {} ({:.2f}%)".format(
                changed.changed_bits, changed.digest_bits, changed.percentage
            ),
        )
    )

    payload = {
        "report_type": "compare_text",
        "date": _timestamp(),
        "algorithm": info.name,
        "digest_bits": info.digest_bits,
        "input_a": args.text_a,
        "input_b": args.text_b,
        "hash_a": hash_a,
        "hash_b": hash_b,
        "identical_inputs": identical_input,
        "identical_hashes": identical_hash,
        "verdict": verdict,
        "differing_bits": changed.changed_bits,
    }
    _save(payload, args.output, args.format)
    return 0


def cmd_compare_files(args: argparse.Namespace) -> int:
    """Hash two files and report whether the digests match."""
    comparison = compare_files(
        args.path_a, args.path_b, args.algorithm, chunk_size=args.chunk_size
    )
    rendered = reporting.render_file_comparison(comparison)
    print(rendered)

    payload = dict(comparison)
    payload["report_type"] = "compare_files"
    payload["date"] = _timestamp()
    _save(payload, args.output, args.format, rendered)
    return 0


def cmd_collision_demo(args: argparse.Namespace) -> int:
    """Run one truncated-hash collision experiment."""
    validate_bits(args.bits, args.algorithm)

    print(
        reporting.info(
            "Searching for a {}-bit truncated collision in {} "
            "(expected ~{:,} attempts)...".format(
                args.bits,
                get_algorithm(args.algorithm).name,
                birthday_bound(args.bits),
            )
        )
    )
    sys.stdout.flush()

    result = find_collision(
        algorithm=args.algorithm,
        bits=args.bits,
        max_attempts=args.max_attempts,
        input_length=args.length,
        seed=args.seed,
    )

    print()
    rendered = reporting.render_collision(result)
    print(rendered)

    payload = result.to_dict()
    payload["report_type"] = "collision_demo"
    payload["date"] = _timestamp()
    _save(payload, args.output, args.format, rendered)
    return 0 if result.found else 2


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Run several experiments and print the statistics."""
    validate_bits(args.bits, args.algorithm)

    print(
        reporting.info(
            "Running {} experiment(s) at {} bits with {}...".format(
                args.runs, args.bits, get_algorithm(args.algorithm).name
            )
        )
    )

    def progress(index: int, total: int, result) -> None:
        """Print one live progress line per completed run."""
        if args.quiet:
            return
        if result.found:
            line = "run {:>4}/{:<4} attempts={:>10,}  time={:.4f}s".format(
                index, total, result.attempts, result.elapsed_seconds
            )
        else:
            line = "run {:>4}/{:<4} NO COLLISION within {:,} attempts".format(
                index, total, result.max_attempts
            )
        print(reporting.info(line))
        sys.stdout.flush()

    result = run_benchmark(
        algorithm=args.algorithm,
        bits=args.bits,
        runs=args.runs,
        max_attempts=args.max_attempts,
        input_length=args.length,
        seed=args.seed,
        progress=progress,
    )

    print()
    rendered = reporting.render_benchmark(result)
    print(rendered)

    payload = result.to_dict()
    _save(payload, args.output, args.format, rendered)
    return 0 if result.runs_completed else 2


def cmd_avalanche(args: argparse.Namespace) -> int:
    """Measure how many digest bits change between two inputs."""
    if args.files:
        result = avalanche_test_files(args.input_a, args.input_b, args.algorithm)
    else:
        result = avalanche_test(args.input_a, args.input_b, args.algorithm)

    rendered = reporting.render_avalanche(result)
    print(rendered)

    if args.bitmap and not result.inputs_identical:
        digest_a = bytes.fromhex(result.hash_a)
        digest_b = bytes.fromhex(result.hash_b)
        print(reporting.section("CHANGED-BIT MAP  ('X' = flipped)"))
        for row in result.bit_map(digest_a, digest_b):
            print(row)

    payload = result.to_dict()
    payload["date"] = _timestamp()
    _save(payload, args.output, args.format, rendered)
    return 0


def cmd_algorithms(args: argparse.Namespace) -> int:
    """Print the algorithm comparison table."""
    rendered = reporting.render_algorithms()
    print(rendered)

    payload = {
        "report_type": "algorithms",
        "date": _timestamp(),
        "algorithms": [
            {
                "key": key,
                "name": algo.name,
                "digest_bits": algo.digest_bits,
                "collision_security": algo.collision_security,
                "status": algo.status,
                "note": algo.note,
            }
            for key, algo in reporting.ALGORITHMS.items()
        ],
    }
    _save(payload, args.output, args.format, rendered)
    return 0


# ==========================================================================
# Interactive mode
# ==========================================================================

MENU = """
========================================
       HASHISION PRO
========================================

[1] Hash text
[2] Hash file
[3] Compare text
[4] Compare files
[5] Collision demonstration
[6] Collision benchmark
[7] Avalanche test
[8] Algorithm information
[9] Export report
[0] Exit
"""


def _ask(prompt: str, default: str = "") -> str:
    """Prompt for a value, returning ``default`` when the user presses Enter."""
    suffix = " [{}]".format(default) if default else ""
    answer = input("{}{}: ".format(prompt, suffix)).strip()
    return answer or default


def _ask_int(prompt: str, default: int) -> int:
    """Prompt for an integer, re-asking until the input parses."""
    while True:
        raw = _ask(prompt, str(default))
        try:
            return int(raw)
        except ValueError:
            print(reporting.error("Please enter a whole number."))


def _ask_algorithm() -> str:
    """Prompt for one of the supported algorithm keys."""
    options = ", ".join(supported_algorithms())
    while True:
        choice = _ask("Algorithm ({})".format(options), "sha256").lower()
        try:
            get_algorithm(choice)
            return choice
        except AnalyzerError as exc:
            print(reporting.error(str(exc)))


def _ask_bits() -> int:
    """Prompt for a truncation size within the safe range."""
    hint = "/".join(str(value) for value in RECOMMENDED_BITS)
    while True:
        bits = _ask_int("Truncation bits ({})".format(hint), 16)
        if 1 <= bits <= MAX_TRUNCATION_BITS:
            return bits
        print(
            reporting.error(
                "Choose between 1 and {} bits.".format(MAX_TRUNCATION_BITS)
            )
        )


def _namespace(**kwargs: Any) -> argparse.Namespace:
    """Build an argparse-like namespace for reusing the command functions."""
    defaults: Dict[str, Any] = {
        "algorithm": "sha256",
        "output": None,
        "format": None,
        "chunk_size": CHUNK_SIZE,
        "bits": None,
        "max_attempts": DEFAULT_MAX_ATTEMPTS,
        "length": DEFAULT_INPUT_LENGTH,
        "seed": None,
        "quiet": False,
        "files": False,
        "bitmap": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _interactive_export(last_payload: Optional[Dict[str, Any]]) -> None:
    """Menu option 9: export the most recent result, or a fresh benchmark."""
    if last_payload is None:
        print(reporting.warn("No result in memory yet - running a quick benchmark."))
        algorithm = _ask_algorithm()
        bits = _ask_bits()
        runs = _ask_int("Runs", 10)
        result = run_benchmark(algorithm=algorithm, bits=bits, runs=runs)
        last_payload = result.to_dict()
        print(reporting.render_benchmark(result))

    default_name = os.path.join(
        DEFAULT_REPORT_DIR,
        "report-{}.json".format(datetime.now().strftime("%Y%m%d-%H%M%S")),
    )
    path = _ask("Output file (.json/.csv/.txt)", default_name)
    written = reporting.export_report(last_payload, path)
    print(reporting.success("Report written to {}".format(written)))


def cmd_interactive(args: argparse.Namespace) -> int:
    """Run the menu-driven interactive mode."""
    last_payload: Optional[Dict[str, Any]] = None

    while True:
        print(MENU)
        try:
            choice = input("Choice: ").strip()
        except EOFError:
            print()
            return 0

        try:
            if choice == "1":
                text = _ask("Text to hash", "hello")
                algorithm = _ask_algorithm()
                namespace = _namespace(text=text, algorithm=algorithm)
                cmd_hash_text(namespace)
                last_payload = {
                    "report_type": "hash_text",
                    "date": _timestamp(),
                    "algorithm": get_algorithm(algorithm).name,
                    "input": text,
                    "hash": hash_text(text, algorithm),
                }

            elif choice == "2":
                path = _ask("File path")
                algorithm = _ask_algorithm()
                file_result = hash_file(path, algorithm)
                print_file_hash(file_result, CHUNK_SIZE)
                last_payload = file_result.to_dict()
                last_payload["report_type"] = "hash_file"
                last_payload["date"] = _timestamp()

            elif choice == "3":
                text_a = _ask("First text", "hello")
                text_b = _ask("Second text", "world")
                algorithm = _ask_algorithm()
                cmd_compare_text(
                    _namespace(text_a=text_a, text_b=text_b, algorithm=algorithm)
                )
                last_payload = {
                    "report_type": "compare_text",
                    "date": _timestamp(),
                    "algorithm": get_algorithm(algorithm).name,
                    "input_a": text_a,
                    "input_b": text_b,
                    "hash_a": hash_text(text_a, algorithm),
                    "hash_b": hash_text(text_b, algorithm),
                }

            elif choice == "4":
                path_a = _ask("First file")
                path_b = _ask("Second file")
                algorithm = _ask_algorithm()
                comparison = compare_files(path_a, path_b, algorithm)
                print(reporting.render_file_comparison(comparison))
                last_payload = dict(comparison)
                last_payload["report_type"] = "compare_files"
                last_payload["date"] = _timestamp()

            elif choice == "5":
                algorithm = _ask_algorithm()
                bits = _ask_bits()
                max_attempts = _ask_int("Max attempts", DEFAULT_MAX_ATTEMPTS)
                print()
                print(reporting.info("Searching..."))
                result = find_collision(
                    algorithm=algorithm, bits=bits, max_attempts=max_attempts
                )
                print()
                print(reporting.render_collision(result))
                last_payload = result.to_dict()
                last_payload["report_type"] = "collision_demo"
                last_payload["date"] = _timestamp()

            elif choice == "6":
                algorithm = _ask_algorithm()
                bits = _ask_bits()
                runs = _ask_int("Runs", 20)
                result = run_benchmark(algorithm=algorithm, bits=bits, runs=runs)
                print(reporting.render_benchmark(result))
                last_payload = result.to_dict()

            elif choice == "7":
                text_a = _ask("First text", "hello")
                text_b = _ask("Second text", "Hello")
                algorithm = _ask_algorithm()
                result = avalanche_test(text_a, text_b, algorithm)
                print(reporting.render_avalanche(result))
                last_payload = result.to_dict()
                last_payload["date"] = _timestamp()

            elif choice == "8":
                print(reporting.render_algorithms())

            elif choice == "9":
                _interactive_export(last_payload)

            elif choice == "0":
                print()
                print("Goodbye.")
                return 0

            else:
                print(reporting.error("Unknown choice: {!r}".format(choice)))

        except AnalyzerError as exc:
            print(reporting.error(str(exc)))
        except KeyboardInterrupt:
            print()
            print(reporting.warn("Action cancelled."))


# ==========================================================================
# Argument parsing
# ==========================================================================

def _global_options() -> argparse.ArgumentParser:
    """Return a parent parser so global flags also work after the subcommand.

    ``default=SUPPRESS`` keeps the subparser from overwriting a value that was
    already given before the subcommand.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable coloured terminal output.",
    )
    return common


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    """Add the shared ``--output`` / ``--format`` options to a subparser."""
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Write a report to PATH (.json, .csv or .txt).",
    )
    parser.add_argument(
        "--format",
        choices=reporting.supported_formats(),
        help="Force the report format instead of deducing it from the extension.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the full argparse command tree."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description=(
            "Hashision Pro - an educational tool for hash "
            "collisions, the birthday paradox and the avalanche effect. "
            "Collision experiments use deliberately TRUNCATED digests; full "
            "hash functions are never broken."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            '  %(prog)s hash-text "hello" --algorithm md5\n'
            "  %(prog)s hash-file example.txt --algorithm sha256\n"
            '  %(prog)s compare-text "hello" "world" --algorithm sha256\n'
            "  %(prog)s compare-files file1.txt file2.txt --algorithm sha256\n"
            "  %(prog)s collision-demo --algorithm sha256 --bits 16\n"
            "  %(prog)s benchmark --algorithm sha256 --bits 16 --runs 20 -o reports/r.json\n"
            '  %(prog)s avalanche "hello" "Hello" --algorithm sha256\n'
            "  %(prog)s algorithms\n"
            "  %(prog)s interactive\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s {}".format(__version__)
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable coloured terminal output."
    )

    algorithms = list(supported_algorithms())
    common = _global_options()
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # -- hash-text -------------------------------------------------------
    p_hash_text = subparsers.add_parser(
        "hash-text", help="Hash a string.", parents=[common]
    )
    p_hash_text.add_argument("text", help="Text to hash.")
    p_hash_text.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    p_hash_text.add_argument(
        "--bits",
        type=int,
        help="Also show the digest truncated to this many bits (1-{}).".format(
            MAX_TRUNCATION_BITS
        ),
    )
    _add_output_options(p_hash_text)
    p_hash_text.set_defaults(func=cmd_hash_text)

    # -- hash-file -------------------------------------------------------
    p_hash_file = subparsers.add_parser(
        "hash-file", help="Hash a file (streamed in chunks).", parents=[common]
    )
    p_hash_file.add_argument("path", help="Path to the file.")
    p_hash_file.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    p_hash_file.add_argument(
        "--chunk-size",
        type=int,
        default=CHUNK_SIZE,
        help="Bytes read per iteration (default: %(default)s).",
    )
    _add_output_options(p_hash_file)
    p_hash_file.set_defaults(func=cmd_hash_file)

    # -- compare-text ----------------------------------------------------
    p_compare_text = subparsers.add_parser(
        "compare-text",
        help="Hash two strings and compare the digests.",
        parents=[common],
    )
    p_compare_text.add_argument("text_a", metavar="TEXT_A", help="First text.")
    p_compare_text.add_argument("text_b", metavar="TEXT_B", help="Second text.")
    p_compare_text.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    _add_output_options(p_compare_text)
    p_compare_text.set_defaults(func=cmd_compare_text)

    # -- compare-files ---------------------------------------------------
    p_compare_files = subparsers.add_parser(
        "compare-files",
        help="Hash two files and compare the digests.",
        parents=[common],
    )
    p_compare_files.add_argument("path_a", metavar="FILE_A", help="First file.")
    p_compare_files.add_argument("path_b", metavar="FILE_B", help="Second file.")
    p_compare_files.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    p_compare_files.add_argument(
        "--chunk-size",
        type=int,
        default=CHUNK_SIZE,
        help="Bytes read per iteration (default: %(default)s).",
    )
    _add_output_options(p_compare_files)
    p_compare_files.set_defaults(func=cmd_compare_files)

    # -- collision-demo --------------------------------------------------
    p_demo = subparsers.add_parser(
        "collision-demo",
        help="Find two strings sharing a truncated digest (birthday attack).",
        parents=[common],
    )
    p_demo.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    p_demo.add_argument(
        "--bits",
        type=int,
        default=16,
        help="Truncation size in bits, usually {} (default: %(default)s).".format(
            "/".join(str(value) for value in RECOMMENDED_BITS)
        ),
    )
    p_demo.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help="Safety ceiling on generated candidates (default: %(default)s, max {}).".format(
            ABSOLUTE_MAX_ATTEMPTS
        ),
    )
    p_demo.add_argument(
        "--length",
        type=int,
        default=DEFAULT_INPUT_LENGTH,
        help="Length of each random candidate string (default: %(default)s).",
    )
    p_demo.add_argument(
        "--seed", type=int, help="PRNG seed, for a reproducible demonstration."
    )
    _add_output_options(p_demo)
    p_demo.set_defaults(func=cmd_collision_demo)

    # -- benchmark -------------------------------------------------------
    p_bench = subparsers.add_parser(
        "benchmark",
        help="Repeat the collision experiment and report statistics.",
        parents=[common],
    )
    p_bench.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    p_bench.add_argument(
        "--bits", type=int, default=16, help="Truncation size in bits (default: %(default)s)."
    )
    p_bench.add_argument(
        "--runs",
        type=int,
        default=20,
        help="Number of experiments, 1-{} (default: %(default)s).".format(MAX_RUNS),
    )
    p_bench.add_argument(
        "--max-attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help="Per-run attempt ceiling (default: %(default)s).",
    )
    p_bench.add_argument(
        "--length",
        type=int,
        default=DEFAULT_INPUT_LENGTH,
        help="Length of each random candidate string (default: %(default)s).",
    )
    p_bench.add_argument("--seed", type=int, help="Base PRNG seed for reproducibility.")
    p_bench.add_argument(
        "--quiet", action="store_true", help="Hide the per-run progress lines."
    )
    _add_output_options(p_bench)
    p_bench.set_defaults(func=cmd_benchmark)

    # -- avalanche -------------------------------------------------------
    p_aval = subparsers.add_parser(
        "avalanche",
        help="Count how many digest bits change between two inputs.",
        parents=[common],
    )
    p_aval.add_argument("input_a", metavar="INPUT_A", help="First text (or file with --files).")
    p_aval.add_argument("input_b", metavar="INPUT_B", help="Second text (or file with --files).")
    p_aval.add_argument(
        "-a", "--algorithm", choices=algorithms, default="sha256", help="Hash algorithm."
    )
    p_aval.add_argument(
        "--files", action="store_true", help="Treat the two inputs as file paths."
    )
    p_aval.add_argument(
        "--bitmap", action="store_true", help="Print a map of which digest bits flipped."
    )
    _add_output_options(p_aval)
    p_aval.set_defaults(func=cmd_avalanche)

    # -- algorithms ------------------------------------------------------
    p_algos = subparsers.add_parser(
        "algorithms",
        help="Show supported algorithms and their security status.",
        parents=[common],
    )
    _add_output_options(p_algos)
    p_algos.set_defaults(func=cmd_algorithms)

    # -- interactive -----------------------------------------------------
    p_inter = subparsers.add_parser(
        "interactive", help="Menu-driven interactive mode.", parents=[common]
    )
    p_inter.set_defaults(func=cmd_interactive)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    reporting.use_colour(not getattr(args, "no_color", False))

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    try:
        return int(args.func(args))
    except AnalyzerError as exc:
        print(reporting.error(str(exc)), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        print(reporting.warn("Interrupted by user."), file=sys.stderr)
        return 130
    except BrokenPipeError:  # pragma: no cover - piping into head/less
        return 0


if __name__ == "__main__":
    sys.exit(main())
