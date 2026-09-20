"""Truncated-hash collision search and birthday-bound mathematics.

The search is a textbook birthday attack against a deliberately shortened
digest. It never attempts to break a full hash function.
"""

from __future__ import annotations

import math
import random
import string
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from .hashing import (
    InvalidParameterError,
    digest_text,
    format_truncated,
    get_algorithm,
    truncate_digest,
    validate_bits,
)

__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "ABSOLUTE_MAX_ATTEMPTS",
    "DEFAULT_INPUT_LENGTH",
    "CollisionResult",
    "search_space",
    "birthday_bound",
    "birthday_bound_precise",
    "expected_attempts_50_percent",
    "collision_probability",
    "generate_random_string",
    "find_collision",
]

#: Default ceiling for one search. Keeps an experiment interactive.
DEFAULT_MAX_ATTEMPTS: int = 2_000_000

#: Hard ceiling. Protects memory: the dictionary grows with attempts.
ABSOLUTE_MAX_ATTEMPTS: int = 20_000_000

#: Length of the generated candidate strings.
DEFAULT_INPUT_LENGTH: int = 8

_ALPHABET = string.ascii_letters + string.digits


# --------------------------------------------------------------------------
# Mathematics
# --------------------------------------------------------------------------

def search_space(bits: int) -> int:
    """Return ``2 ** bits``: how many distinct truncated digests exist."""
    return 2 ** bits


def birthday_bound(bits: int) -> int:
    """Return the classroom birthday bound ``2 ** (bits / 2)``.

    For a 16-bit digest this is 256 attempts, the figure quoted in the
    course material.
    """
    return int(2 ** (bits / 2))


def birthday_bound_precise(bits: int) -> float:
    """Return the expected number of draws before the first repeat.

    For a space of ``N`` equally likely values the expectation is
    ``sqrt(pi * N / 2)``, i.e. about ``1.2533 * sqrt(N)``.
    """
    return math.sqrt(math.pi * search_space(bits) / 2.0)


def expected_attempts_50_percent(bits: int) -> float:
    """Return the number of draws giving a 50 % chance of a collision.

    ``sqrt(2 * ln(2) * N)``, about ``1.1774 * sqrt(N)``.
    """
    return math.sqrt(2.0 * math.log(2.0) * search_space(bits))


def collision_probability(bits: int, attempts: int) -> float:
    """Approximate the probability of at least one collision after ``attempts``.

    Uses the standard approximation ``1 - exp(-k*(k-1) / (2N))``, which stays
    accurate while ``k`` is small compared with ``N``.
    """
    if attempts < 2:
        return 0.0
    space = search_space(bits)
    exponent = -(attempts * (attempts - 1)) / (2.0 * space)
    return 1.0 - math.exp(exponent)


# --------------------------------------------------------------------------
# Result container
# --------------------------------------------------------------------------

@dataclass
class CollisionResult:
    """Outcome of one truncated-hash collision experiment."""

    algorithm: str
    digest_bits: int
    effective_bits: int
    attempts: int
    elapsed_seconds: float
    found: bool
    input_a: Optional[str] = None
    input_b: Optional[str] = None
    full_hash_a: Optional[str] = None
    full_hash_b: Optional[str] = None
    truncated_hex: Optional[str] = None
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    distinct_values_seen: int = 0
    birthday_bound: int = field(default=0)
    birthday_bound_precise: float = field(default=0.0)

    @property
    def full_hashes_differ(self) -> bool:
        """``True`` when the two complete digests are *not* equal.

        This is the honesty check printed with every experiment: a truncated
        match is not a full collision.
        """
        return bool(
            self.full_hash_a
            and self.full_hash_b
            and self.full_hash_a != self.full_hash_b
        )

    @property
    def attempts_per_second(self) -> float:
        """Throughput of the search."""
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.attempts / self.elapsed_seconds

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "algorithm": self.algorithm,
            "digest_bits": self.digest_bits,
            "effective_bits": self.effective_bits,
            "search_space": search_space(self.effective_bits),
            "found": self.found,
            "input_a": self.input_a,
            "input_b": self.input_b,
            "full_hash_a": self.full_hash_a,
            "full_hash_b": self.full_hash_b,
            "truncated_hash_a": self.truncated_hex,
            "truncated_hash_b": self.truncated_hex,
            "full_hashes_differ": self.full_hashes_differ,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "distinct_values_seen": self.distinct_values_seen,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "attempts_per_second": round(self.attempts_per_second, 2),
            "birthday_bound": self.birthday_bound,
            "birthday_bound_precise": round(self.birthday_bound_precise, 2),
            "is_full_hash_collision": False,
        }


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------

def generate_random_string(
    length: int = DEFAULT_INPUT_LENGTH, rng: Optional[random.Random] = None
) -> str:
    """Return a random alphanumeric string such as ``Y5fP9qLm``."""
    source = rng or random
    return "".join(source.choice(_ALPHABET) for _ in range(length))


def find_collision(
    algorithm: str = "sha256",
    bits: int = 16,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    input_length: int = DEFAULT_INPUT_LENGTH,
    seed: Optional[int] = None,
) -> CollisionResult:
    """Search for two different strings sharing a truncated digest.

    The algorithm is the standard birthday attack:

    1. Generate a random candidate string.
    2. Hash it with the selected algorithm.
    3. Keep only the leading ``bits`` bits of the digest.
    4. If that value is already in ``seen``, and the stored input differs from
       the candidate, a collision has been found.
    5. Otherwise store ``truncated -> input`` and continue.

    The dictionary makes each step an O(1) lookup, so ``n`` candidates cost
    ``O(n)`` rather than the ``O(n^2)`` of comparing every pair.

    Args:
        algorithm: ``md5``, ``sha1``, ``sha256`` or ``sha512``.
        bits: Truncation size, 1 .. 32 (8/12/16/20/24 are the usual choices).
        max_attempts: Safety ceiling for the loop.
        input_length: Length of each generated candidate.
        seed: Optional PRNG seed, for reproducible demonstrations.

    Returns:
        A :class:`CollisionResult`; ``found`` is ``False`` when the ceiling
        was reached first.

    Raises:
        UnsupportedAlgorithmError: Unknown algorithm.
        InvalidParameterError: Out-of-range ``bits``, ``max_attempts`` or
            ``input_length``.
    """
    info = get_algorithm(algorithm)
    validate_bits(bits, algorithm)

    if max_attempts < 1:
        raise InvalidParameterError("--max-attempts must be at least 1.")
    if max_attempts > ABSOLUTE_MAX_ATTEMPTS:
        raise InvalidParameterError(
            "--max-attempts is capped at {:,} to protect memory and time.".format(
                ABSOLUTE_MAX_ATTEMPTS
            )
        )
    if input_length < 1 or input_length > 256:
        raise InvalidParameterError("Input length must be between 1 and 256.")

    rng = random.Random(seed)

    # truncated digest value -> the input string that produced it
    seen: Dict[int, str] = {}

    attempts = 0
    start = time.perf_counter()

    while attempts < max_attempts:
        attempts += 1

        candidate = generate_random_string(input_length, rng)
        digest = digest_text(candidate, algorithm)
        truncated = truncate_digest(digest, bits)

        previous = seen.get(truncated)
        if previous is not None:
            # Same string twice is not a collision; keep searching.
            if previous != candidate:
                elapsed = time.perf_counter() - start
                return CollisionResult(
                    algorithm=info.name,
                    digest_bits=info.digest_bits,
                    effective_bits=bits,
                    attempts=attempts,
                    elapsed_seconds=elapsed,
                    found=True,
                    input_a=previous,
                    input_b=candidate,
                    full_hash_a=digest_text(previous, algorithm).hex(),
                    full_hash_b=digest.hex(),
                    truncated_hex=format_truncated(truncated, bits),
                    max_attempts=max_attempts,
                    distinct_values_seen=len(seen),
                    birthday_bound=birthday_bound(bits),
                    birthday_bound_precise=birthday_bound_precise(bits),
                )
        else:
            seen[truncated] = candidate

    elapsed = time.perf_counter() - start
    return CollisionResult(
        algorithm=info.name,
        digest_bits=info.digest_bits,
        effective_bits=bits,
        attempts=attempts,
        elapsed_seconds=elapsed,
        found=False,
        max_attempts=max_attempts,
        distinct_values_seen=len(seen),
        birthday_bound=birthday_bound(bits),
        birthday_bound_precise=birthday_bound_precise(bits),
    )
