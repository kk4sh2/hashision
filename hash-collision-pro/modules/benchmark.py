"""Repeated collision experiments with descriptive statistics.

Running one experiment proves a collision is possible. Running twenty and
comparing the average with ``2 ** (bits / 2)`` shows that the birthday bound
actually predicts reality.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

from .collision import (
    DEFAULT_INPUT_LENGTH,
    DEFAULT_MAX_ATTEMPTS,
    CollisionResult,
    birthday_bound,
    birthday_bound_precise,
    expected_attempts_50_percent,
    find_collision,
    search_space,
)
from .hashing import InvalidParameterError, get_algorithm, validate_bits

__all__ = ["MAX_RUNS", "BenchmarkResult", "run_benchmark"]

#: Safety limit on the number of experiments in a single benchmark.
MAX_RUNS: int = 1000

ProgressCallback = Callable[[int, int, CollisionResult], None]


@dataclass
class BenchmarkResult:
    """Aggregated statistics over several collision experiments."""

    algorithm: str
    digest_bits: int
    effective_bits: int
    runs_requested: int
    runs_completed: int
    attempts: List[int] = field(default_factory=list)
    elapsed: List[float] = field(default_factory=list)
    failures: int = 0
    total_seconds: float = 0.0
    timestamp: str = ""
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    # -- statistics ------------------------------------------------------

    @property
    def min_attempts(self) -> int:
        """Fewest attempts across all successful runs."""
        return min(self.attempts) if self.attempts else 0

    @property
    def max_attempts_observed(self) -> int:
        """Most attempts across all successful runs."""
        return max(self.attempts) if self.attempts else 0

    @property
    def average_attempts(self) -> float:
        """Arithmetic mean of the attempt counts."""
        return statistics.fmean(self.attempts) if self.attempts else 0.0

    @property
    def median_attempts(self) -> float:
        """Median of the attempt counts."""
        return statistics.median(self.attempts) if self.attempts else 0.0

    @property
    def stdev_attempts(self) -> float:
        """Sample standard deviation (0.0 when fewer than two runs)."""
        return statistics.stdev(self.attempts) if len(self.attempts) > 1 else 0.0

    @property
    def average_seconds(self) -> float:
        """Mean wall-clock time of one experiment."""
        return statistics.fmean(self.elapsed) if self.elapsed else 0.0

    @property
    def median_seconds(self) -> float:
        """Median wall-clock time of one experiment."""
        return statistics.median(self.elapsed) if self.elapsed else 0.0

    @property
    def theory_ratio(self) -> float:
        """Observed average divided by the precise birthday expectation.

        A value near 1.0 means the experiment matches the theory.
        """
        expected = birthday_bound_precise(self.effective_bits)
        if expected <= 0:
            return 0.0
        return self.average_attempts / expected

    def to_dict(self) -> dict:
        """Return a JSON-serialisable report payload."""
        return {
            "report_type": "collision_benchmark",
            "date": self.timestamp,
            "algorithm": self.algorithm,
            "digest_size_bits": self.digest_bits,
            "effective_size_bits": self.effective_bits,
            "search_space": search_space(self.effective_bits),
            "runs_requested": self.runs_requested,
            "runs_completed": self.runs_completed,
            "failed_runs": self.failures,
            "max_attempts_per_run": self.max_attempts,
            "minimum_attempts": self.min_attempts,
            "maximum_attempts": self.max_attempts_observed,
            "average_attempts": round(self.average_attempts, 2),
            "median_attempts": round(self.median_attempts, 2),
            "stdev_attempts": round(self.stdev_attempts, 2),
            "birthday_bound_simple": birthday_bound(self.effective_bits),
            "birthday_bound_precise": round(
                birthday_bound_precise(self.effective_bits), 2
            ),
            "attempts_for_50_percent": round(
                expected_attempts_50_percent(self.effective_bits), 2
            ),
            "observed_over_theory": round(self.theory_ratio, 3),
            "total_seconds": round(self.total_seconds, 6),
            "average_seconds": round(self.average_seconds, 6),
            "median_seconds": round(self.median_seconds, 6),
            "attempts_per_run": list(self.attempts),
            "execution_times": [round(value, 6) for value in self.elapsed],
            "runs_detail": [
                {
                    "run": index + 1,
                    "attempts": attempt,
                    "elapsed_seconds": round(seconds, 6),
                }
                for index, (attempt, seconds) in enumerate(
                    zip(self.attempts, self.elapsed)
                )
            ],
            "is_full_hash_collision": False,
            "note": (
                "Collisions were found in a {}-bit truncation of {}. "
                "The full {}-bit digests remain distinct.".format(
                    self.effective_bits, self.algorithm, self.digest_bits
                )
            ),
        }


def run_benchmark(
    algorithm: str = "sha256",
    bits: int = 16,
    runs: int = 20,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    input_length: int = DEFAULT_INPUT_LENGTH,
    seed: Optional[int] = None,
    progress: Optional[ProgressCallback] = None,
) -> BenchmarkResult:
    """Run ``runs`` independent collision experiments and aggregate them.

    Args:
        algorithm: Hash algorithm key.
        bits: Truncation size in bits.
        runs: Number of experiments (1 .. :data:`MAX_RUNS`).
        max_attempts: Per-run attempt ceiling.
        input_length: Length of generated candidate strings.
        seed: Base seed; run *i* uses ``seed + i`` so the whole benchmark is
            reproducible while each run stays independent.
        progress: Optional callback ``(run_index, runs, result)`` invoked after
            each experiment, used by the CLI to print a live progress line.

    Returns:
        A :class:`BenchmarkResult`.

    Raises:
        InvalidParameterError: If ``runs`` is outside 1 .. :data:`MAX_RUNS`.
    """
    info = get_algorithm(algorithm)
    validate_bits(bits, algorithm)

    if runs < 1:
        raise InvalidParameterError("--runs must be at least 1.")
    if runs > MAX_RUNS:
        raise InvalidParameterError(
            "--runs is capped at {} for safety.".format(MAX_RUNS)
        )

    attempts: List[int] = []
    elapsed: List[float] = []
    failures = 0

    started = time.perf_counter()
    for index in range(runs):
        run_seed = None if seed is None else seed + index
        result = find_collision(
            algorithm=algorithm,
            bits=bits,
            max_attempts=max_attempts,
            input_length=input_length,
            seed=run_seed,
        )
        if result.found:
            attempts.append(result.attempts)
            elapsed.append(result.elapsed_seconds)
        else:
            failures += 1

        if progress is not None:
            progress(index + 1, runs, result)

    total = time.perf_counter() - started

    return BenchmarkResult(
        algorithm=info.name,
        digest_bits=info.digest_bits,
        effective_bits=bits,
        runs_requested=runs,
        runs_completed=len(attempts),
        attempts=attempts,
        elapsed=elapsed,
        failures=failures,
        total_seconds=total,
        timestamp=datetime.now().astimezone().isoformat(timespec="seconds"),
        max_attempts=max_attempts,
    )
