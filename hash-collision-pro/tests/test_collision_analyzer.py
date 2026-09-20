#!/usr/bin/env python3
"""Automated tests for Hash Collision Analyzer Pro.

Run from the project root:

    python3 -m unittest discover -s tests -v
    python3 tests/test_collision_analyzer.py
"""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import unittest

# Allow "python3 tests/test_collision_analyzer.py" as well as unittest discovery.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import collision_analyzer  # noqa: E402
from modules import avalanche, benchmark, collision, file_hasher, hashing, reporting  # noqa: E402


# ==========================================================================
# hashing
# ==========================================================================

class TestHashing(unittest.TestCase):
    """Known-answer tests and truncation mathematics."""

    def test_known_digests(self):
        """Digests must match the published test vectors for 'hello'."""
        self.assertEqual(
            hashing.hash_text("hello", "md5"),
            "5d41402abc4b2a76b9719d911017c592",
        )
        self.assertEqual(
            hashing.hash_text("hello", "sha1"),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        )
        self.assertEqual(
            hashing.hash_text("hello", "sha256"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        self.assertEqual(hashing.hash_text("", "sha256")[:8], "e3b0c442")

    def test_digest_lengths(self):
        """Each algorithm must report and produce its documented length."""
        expected = {"md5": 128, "sha1": 160, "sha256": 256, "sha512": 512}
        for key, bits in expected.items():
            self.assertEqual(hashing.digest_size_bits(key), bits)
            self.assertEqual(len(hashing.hash_text("x", key)) * 4, bits)

    def test_algorithm_name_normalisation(self):
        """'SHA-256', 'sha_256' and 'sha256' must resolve to the same entry."""
        for name in ("SHA-256", "sha256", "Sha_256", "  sha256  "):
            self.assertEqual(hashing.get_algorithm(name).digest_bits, 256)

    def test_unsupported_algorithm(self):
        """An unknown algorithm raises UnsupportedAlgorithmError."""
        with self.assertRaises(hashing.UnsupportedAlgorithmError):
            hashing.hash_text("hello", "sha3-512")

    def test_truncation_is_bit_exact(self):
        """Truncation keeps leading BITS, not whole hex characters."""
        digest = bytes([0xA8, 0x3F, 0xFF, 0xFF])  # 1010 1000 0011 1111 ...
        self.assertEqual(hashing.truncate_digest(digest, 8), 0xA8)
        self.assertEqual(hashing.truncate_digest(digest, 16), 0xA83F)
        self.assertEqual(hashing.truncate_digest(digest, 4), 0xA)
        # 12 bits = 0xA83, and 10 bits = top ten bits 1010100000 = 0x2A0
        self.assertEqual(hashing.truncate_digest(digest, 12), 0xA83)
        self.assertEqual(hashing.truncate_digest(digest, 10), 0b1010100000)

    def test_truncation_matches_hex_prefix_on_nibbles(self):
        """For multiples of 4 bits, truncation equals the hex prefix."""
        digest = hashing.digest_text("collision", "sha256")
        hex_digest = digest.hex()
        for bits in (4, 8, 12, 16, 20, 24, 32):
            value = hashing.truncate_digest(digest, bits)
            self.assertEqual(value, int(hex_digest[: bits // 4], 16))

    def test_format_truncated_width(self):
        """Formatted truncations are zero-padded to a fixed width."""
        self.assertEqual(hashing.format_truncated(0x0F, 8), "0F")
        self.assertEqual(hashing.format_truncated(0x00F, 12), "00F")
        self.assertEqual(hashing.format_truncated(0xA83F, 16), "A83F")

    def test_validate_bits_limits(self):
        """Bit counts outside the safe range are rejected."""
        self.assertEqual(hashing.validate_bits(16, "sha256"), 16)
        with self.assertRaises(hashing.InvalidParameterError):
            hashing.validate_bits(0, "sha256")
        with self.assertRaises(hashing.InvalidParameterError):
            hashing.validate_bits(hashing.MAX_TRUNCATION_BITS + 1, "sha256")


# ==========================================================================
# collision search
# ==========================================================================

class TestCollision(unittest.TestCase):
    """Birthday mathematics and the search loop."""

    def test_birthday_bounds(self):
        """2^(n/2) for the classroom bound, ~1.2533*sqrt(N) for the precise one."""
        self.assertEqual(collision.birthday_bound(8), 16)
        self.assertEqual(collision.birthday_bound(16), 256)
        self.assertEqual(collision.birthday_bound(24), 4096)
        self.assertEqual(collision.search_space(16), 65536)
        self.assertAlmostEqual(
            collision.birthday_bound_precise(16), 320.6, delta=1.0
        )
        self.assertAlmostEqual(
            collision.expected_attempts_50_percent(16), 301.3, delta=1.0
        )

    def test_collision_probability_range(self):
        """The probability approximation stays inside [0, 1] and increases."""
        low = collision.collision_probability(16, 100)
        high = collision.collision_probability(16, 1000)
        self.assertEqual(collision.collision_probability(16, 1), 0.0)
        self.assertTrue(0.0 <= low < high <= 1.0)

    def test_find_collision_succeeds(self):
        """A 12-bit search must find a truncated collision quickly."""
        result = collision.find_collision(algorithm="sha256", bits=12, seed=1)
        self.assertTrue(result.found)
        self.assertNotEqual(result.input_a, result.input_b)
        self.assertGreater(result.attempts, 1)
        self.assertGreater(result.elapsed_seconds, 0.0)

    def test_collision_is_truncated_not_full(self):
        """The two full digests must differ: this is not a real SHA-256 break."""
        result = collision.find_collision(algorithm="sha256", bits=16, seed=7)
        self.assertTrue(result.found)
        self.assertNotEqual(result.full_hash_a, result.full_hash_b)
        self.assertTrue(result.full_hashes_differ)
        self.assertFalse(result.to_dict()["is_full_hash_collision"])

    def test_truncated_halves_really_match(self):
        """Re-hashing both inputs must reproduce the shared truncated value."""
        result = collision.find_collision(algorithm="md5", bits=16, seed=3)
        self.assertTrue(result.found)
        bits = result.effective_bits
        value_a = hashing.truncate_digest(
            hashing.digest_text(result.input_a, "md5"), bits
        )
        value_b = hashing.truncate_digest(
            hashing.digest_text(result.input_b, "md5"), bits
        )
        self.assertEqual(value_a, value_b)
        self.assertEqual(hashing.format_truncated(value_a, bits), result.truncated_hex)

    def test_seed_is_reproducible(self):
        """The same seed must produce the same experiment."""
        first = collision.find_collision(algorithm="sha256", bits=12, seed=42)
        second = collision.find_collision(algorithm="sha256", bits=12, seed=42)
        self.assertEqual(first.attempts, second.attempts)
        self.assertEqual(first.input_a, second.input_a)
        self.assertEqual(first.input_b, second.input_b)

    def test_max_attempts_is_respected(self):
        """The ceiling stops the loop and reports found=False."""
        result = collision.find_collision(
            algorithm="sha256", bits=32, max_attempts=5, seed=1
        )
        self.assertFalse(result.found)
        self.assertEqual(result.attempts, 5)

    def test_invalid_parameters(self):
        """Bad parameters raise InvalidParameterError, not a traceback."""
        with self.assertRaises(hashing.InvalidParameterError):
            collision.find_collision(bits=64)
        with self.assertRaises(hashing.InvalidParameterError):
            collision.find_collision(bits=16, max_attempts=0)
        with self.assertRaises(hashing.InvalidParameterError):
            collision.find_collision(
                bits=16, max_attempts=collision.ABSOLUTE_MAX_ATTEMPTS + 1
            )

    def test_random_string_shape(self):
        """Generated candidates are alphanumeric and the requested length."""
        value = collision.generate_random_string(10)
        self.assertEqual(len(value), 10)
        self.assertTrue(value.isalnum())

    def test_average_attempts_near_theory(self):
        """Over several runs the mean should land near the precise expectation."""
        result = benchmark.run_benchmark(algorithm="sha256", bits=12, runs=25, seed=100)
        self.assertEqual(result.runs_completed, 25)
        # Generous window: 25 samples of a highly skewed distribution.
        self.assertTrue(0.5 < result.theory_ratio < 2.0, result.theory_ratio)


# ==========================================================================
# benchmark
# ==========================================================================

class TestBenchmark(unittest.TestCase):
    """Statistics produced by repeated experiments."""

    @classmethod
    def setUpClass(cls):
        cls.result = benchmark.run_benchmark(
            algorithm="sha256", bits=12, runs=5, seed=11
        )

    def test_statistics_are_consistent(self):
        """min <= median <= max, and the mean sits inside the range."""
        result = self.result
        self.assertEqual(result.runs_completed, 5)
        self.assertEqual(len(result.attempts), 5)
        self.assertLessEqual(result.min_attempts, result.median_attempts)
        self.assertLessEqual(result.median_attempts, result.max_attempts_observed)
        self.assertLessEqual(result.min_attempts, result.average_attempts)
        self.assertLessEqual(result.average_attempts, result.max_attempts_observed)

    def test_report_payload_keys(self):
        """The exported payload contains every documented field."""
        payload = self.result.to_dict()
        for key in (
            "date",
            "algorithm",
            "digest_size_bits",
            "effective_size_bits",
            "runs_completed",
            "attempts_per_run",
            "minimum_attempts",
            "maximum_attempts",
            "average_attempts",
            "median_attempts",
            "execution_times",
            "birthday_bound_simple",
            "birthday_bound_precise",
        ):
            self.assertIn(key, payload)
        self.assertFalse(payload["is_full_hash_collision"])

    def test_runs_limit(self):
        """Too many runs is refused."""
        with self.assertRaises(hashing.InvalidParameterError):
            benchmark.run_benchmark(runs=benchmark.MAX_RUNS + 1)
        with self.assertRaises(hashing.InvalidParameterError):
            benchmark.run_benchmark(runs=0)

    def test_progress_callback(self):
        """The progress callback fires once per run."""
        seen = []
        benchmark.run_benchmark(
            algorithm="md5",
            bits=8,
            runs=3,
            seed=5,
            progress=lambda index, total, result: seen.append(index),
        )
        self.assertEqual(seen, [1, 2, 3])


# ==========================================================================
# avalanche
# ==========================================================================

class TestAvalanche(unittest.TestCase):
    """Bit-difference measurement."""

    def test_hamming_distance(self):
        """XOR-based bit counting."""
        self.assertEqual(avalanche.hamming_distance(b"\x00", b"\xff"), 8)
        self.assertEqual(avalanche.hamming_distance(b"\x00", b"\x01"), 1)
        self.assertEqual(avalanche.hamming_distance(b"\xab", b"\xab"), 0)
        with self.assertRaises(ValueError):
            avalanche.hamming_distance(b"\x00", b"\x00\x00")

    def test_identical_inputs_change_nothing(self):
        """Hashing the same text twice changes zero bits."""
        result = avalanche.avalanche_test("hello", "hello", "sha256")
        self.assertEqual(result.changed_bits, 0)
        self.assertEqual(result.percentage, 0.0)
        self.assertTrue(result.inputs_identical)

    def test_one_letter_change_is_close_to_half(self):
        """'hello' vs 'Hello' should flip roughly half of the 256 bits."""
        result = avalanche.avalanche_test("hello", "Hello", "sha256")
        self.assertEqual(result.digest_bits, 256)
        self.assertFalse(result.inputs_identical)
        self.assertTrue(80 <= result.changed_bits <= 176, result.changed_bits)
        self.assertTrue(30.0 <= result.percentage <= 70.0)
        # 'h' (0x68) vs 'H' (0x48) differ in exactly one bit.
        self.assertEqual(result.input_changed_bits, 1)

    def test_bit_map_rows(self):
        """The bit map covers every digest bit."""
        result = avalanche.avalanche_test("a", "b", "md5")
        digest_a = bytes.fromhex(result.hash_a)
        digest_b = bytes.fromhex(result.hash_b)
        rows = result.bit_map(digest_a, digest_b, width=32)
        self.assertEqual(sum(len(row) for row in rows), 128)

    def test_payload(self):
        """The exported payload reports both the count and the percentage."""
        payload = avalanche.avalanche_test("hello", "Hello", "sha256").to_dict()
        self.assertEqual(payload["total_bits"], 256)
        self.assertEqual(payload["ideal_percentage"], 50.0)
        self.assertIn("percentage_changed", payload)


# ==========================================================================
# file hashing
# ==========================================================================

class TestFileHasher(unittest.TestCase):
    """Chunked file hashing and error handling."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hca-test-")
        self.file_a = os.path.join(self.tmp, "a.txt")
        self.file_b = os.path.join(self.tmp, "b.txt")
        self.copy_a = os.path.join(self.tmp, "a-copy.txt")
        with open(self.file_a, "w", encoding="utf-8") as handle:
            handle.write("hello")
        with open(self.file_b, "w", encoding="utf-8") as handle:
            handle.write("world")
        with open(self.copy_a, "w", encoding="utf-8") as handle:
            handle.write("hello")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_file_hash_matches_text_hash(self):
        """Hashing a file of 'hello' equals hashing the string 'hello'."""
        result = file_hasher.hash_file(self.file_a, "md5")
        self.assertEqual(result.hex_digest, "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(result.size_bytes, 5)

    def test_chunking_does_not_change_the_digest(self):
        """Tiny chunks give the same digest as the default 64 KiB chunks."""
        big = os.path.join(self.tmp, "big.bin")
        with open(big, "wb") as handle:
            handle.write(b"A" * 300000)
        default = file_hasher.hash_file(big, "sha256")
        tiny = file_hasher.hash_file(big, "sha256", chunk_size=7)
        self.assertEqual(default.hex_digest, tiny.hex_digest)
        self.assertGreater(tiny.chunks_read, default.chunks_read)

    def test_missing_file(self):
        """A missing path raises FileAccessError."""
        with self.assertRaises(file_hasher.FileAccessError):
            file_hasher.hash_file(os.path.join(self.tmp, "nope.txt"))

    def test_directory_instead_of_file(self):
        """A directory raises FileAccessError."""
        with self.assertRaises(file_hasher.FileAccessError):
            file_hasher.hash_file(self.tmp)

    def test_size_limit(self):
        """max_bytes refuses oversized files."""
        with self.assertRaises(file_hasher.FileAccessError):
            file_hasher.hash_file(self.file_a, "sha256", max_bytes=1)

    def test_compare_different_files(self):
        """Different content means different digests and no collision."""
        comparison = file_hasher.compare_files(self.file_a, self.file_b, "sha256")
        self.assertFalse(comparison["identical_digest"])
        self.assertFalse(comparison["real_collision"])

    def test_compare_identical_copies_is_not_a_collision(self):
        """Two copies of one file share a digest, which is not a collision."""
        comparison = file_hasher.compare_files(self.file_a, self.copy_a, "sha256")
        self.assertTrue(comparison["identical_digest"])
        self.assertTrue(comparison["identical_content"])
        self.assertFalse(comparison["real_collision"])


# ==========================================================================
# reporting
# ==========================================================================

class TestReporting(unittest.TestCase):
    """Rendering and export."""

    def setUp(self):
        reporting.use_colour(False)
        self.tmp = tempfile.mkdtemp(prefix="hca-report-")
        self.result = benchmark.run_benchmark(
            algorithm="sha256", bits=8, runs=3, seed=2
        )

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_json_export(self):
        """JSON reports are valid JSON with the expected keys."""
        path = os.path.join(self.tmp, "report.json")
        reporting.export_report(self.result.to_dict(), path)
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["algorithm"], "SHA-256")
        self.assertEqual(payload["effective_size_bits"], 8)
        self.assertEqual(len(payload["runs_detail"]), 3)

    def test_csv_export(self):
        """CSV reports contain a summary block and a per-run table."""
        path = os.path.join(self.tmp, "report.csv")
        reporting.export_report(self.result.to_dict(), path)
        with open(path, encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(rows[0], ["metric", "value"])
        self.assertIn(["run", "attempts", "elapsed_seconds"], rows)

    def test_txt_export(self):
        """TXT reports embed the rendered terminal output without ANSI codes."""
        path = os.path.join(self.tmp, "report.txt")
        rendered = reporting.render_benchmark(self.result)
        reporting.export_report(self.result.to_dict(), path, rendered=rendered)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("COLLISION BENCHMARK", text)
        self.assertNotIn("\033[", text)

    def test_unknown_format(self):
        """An unsupported extension raises ReportError."""
        with self.assertRaises(reporting.ReportError):
            reporting.export_report({}, os.path.join(self.tmp, "report.pdf"))

    def test_renderers_mention_the_disclaimer(self):
        """Every collision report must state that the full digests differ."""
        result = collision.find_collision(algorithm="sha256", bits=12, seed=9)
        text = reporting.render_collision(result)
        self.assertIn("intentionally shortened", text)
        self.assertIn("NOT a break", text)
        self.assertIn("intentionally shortened", reporting.render_benchmark(self.result))

    def test_algorithm_table(self):
        """The algorithm table lists all four hashes and their status."""
        text = reporting.render_algorithms()
        for name in ("MD5", "SHA-1", "SHA-256", "SHA-512"):
            self.assertIn(name, text)
        self.assertIn("Broken", text)
        self.assertIn("2^128", text)


# ==========================================================================
# CLI
# ==========================================================================

class TestCLI(unittest.TestCase):
    """Argument parsing and end-to-end command execution."""

    def setUp(self):
        reporting.use_colour(False)
        self.tmp = tempfile.mkdtemp(prefix="hca-cli-")
        self.sample = os.path.join(self.tmp, "sample.txt")
        with open(self.sample, "w", encoding="utf-8") as handle:
            handle.write("hello")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def test_every_subcommand_is_wired(self):
        """Each documented subcommand parses and has an implementation."""
        parser = collision_analyzer.build_parser()
        commands = [
            ["hash-text", "hello"],
            ["hash-file", self.sample],
            ["compare-text", "hello", "world"],
            ["compare-files", self.sample, self.sample],
            ["collision-demo"],
            ["benchmark"],
            ["avalanche", "hello", "Hello"],
            ["algorithms"],
            ["interactive"],
        ]
        for argv in commands:
            args = parser.parse_args(argv)
            self.assertTrue(callable(args.func), argv[0])

    def test_hash_text_command(self):
        """hash-text runs and exits 0."""
        code = collision_analyzer.main(
            ["--no-color", "hash-text", "hello", "--algorithm", "md5"]
        )
        self.assertEqual(code, 0)

    def test_collision_demo_command(self):
        """collision-demo runs, exits 0 and can write a report."""
        report = os.path.join(self.tmp, "demo.json")
        code = collision_analyzer.main(
            [
                "--no-color",
                "collision-demo",
                "--algorithm",
                "sha256",
                "--bits",
                "12",
                "--seed",
                "4",
                "--output",
                report,
            ]
        )
        self.assertEqual(code, 0)
        with open(report, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertTrue(payload["found"])
        self.assertTrue(payload["full_hashes_differ"])
        self.assertFalse(payload["is_full_hash_collision"])

    def test_benchmark_command_with_csv(self):
        """benchmark honours --runs, --quiet and CSV export."""
        report = os.path.join(self.tmp, "bench.csv")
        code = collision_analyzer.main(
            [
                "--no-color",
                "benchmark",
                "--bits",
                "8",
                "--runs",
                "3",
                "--seed",
                "1",
                "--quiet",
                "--output",
                report,
            ]
        )
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(report))

    def test_avalanche_command(self):
        """avalanche runs against two strings."""
        code = collision_analyzer.main(
            ["--no-color", "avalanche", "hello", "Hello", "--algorithm", "sha256"]
        )
        self.assertEqual(code, 0)

    def test_bad_algorithm_is_rejected_by_argparse(self):
        """argparse rejects an unsupported algorithm with exit code 2."""
        with self.assertRaises(SystemExit) as context:
            collision_analyzer.main(["hash-text", "hi", "--algorithm", "rot13"])
        self.assertEqual(context.exception.code, 2)

    def test_missing_file_exits_cleanly(self):
        """A missing file produces exit code 1, not a traceback."""
        code = collision_analyzer.main(
            ["--no-color", "hash-file", os.path.join(self.tmp, "ghost.txt")]
        )
        self.assertEqual(code, 1)

    def test_no_command_prints_help(self):
        """Running with no subcommand returns 1."""
        self.assertEqual(collision_analyzer.main(["--no-color"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
