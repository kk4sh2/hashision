"""Avalanche-effect measurement.

A cryptographic hash is designed so that flipping one bit of the input flips
each output bit with probability 1/2. Measuring the Hamming distance between
two digests shows how close a real algorithm gets to that ideal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .hashing import digest_text, get_algorithm
from .file_hasher import hash_file

__all__ = [
    "AvalancheResult",
    "hamming_distance",
    "avalanche_test",
    "avalanche_test_files",
]


def hamming_distance(digest_a: bytes, digest_b: bytes) -> int:
    """Return the number of differing bits between two equal-length digests.

    XOR sets a bit to 1 exactly where the two digests differ, so counting the
    1 bits of the XOR counts the changed bits.
    """
    if len(digest_a) != len(digest_b):
        raise ValueError("Digests must be the same length to compare bits.")
    xor = int.from_bytes(digest_a, "big") ^ int.from_bytes(digest_b, "big")
    return bin(xor).count("1")


@dataclass
class AvalancheResult:
    """Bit-level difference between the digests of two inputs."""

    algorithm: str
    digest_bits: int
    input_a: str
    input_b: str
    hash_a: str
    hash_b: str
    changed_bits: int
    inputs_identical: bool
    input_changed_bits: Optional[int] = None

    @property
    def percentage(self) -> float:
        """Percentage of digest bits that changed."""
        if self.digest_bits == 0:
            return 0.0
        return (self.changed_bits / self.digest_bits) * 100.0

    @property
    def deviation_from_ideal(self) -> float:
        """Signed distance from the ideal 50 % in percentage points."""
        return self.percentage - 50.0

    @property
    def verdict(self) -> str:
        """Short human-readable judgement of the measurement."""
        if self.inputs_identical:
            return "IDENTICAL INPUT - no avalanche to measure"
        if abs(self.deviation_from_ideal) <= 10.0:
            return "Strong avalanche (close to the ideal 50%)"
        return "Unusual result for a single sample - try more input pairs"

    def bit_map(self, digest_a: bytes, digest_b: bytes, width: int = 64) -> List[str]:
        """Return rows of ``.``/``X`` marking unchanged/changed digest bits."""
        xor = int.from_bytes(digest_a, "big") ^ int.from_bytes(digest_b, "big")
        bits = format(xor, "0{}b".format(self.digest_bits))
        marks = "".join("X" if bit == "1" else "." for bit in bits)
        return [marks[i : i + width] for i in range(0, len(marks), width)]

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "report_type": "avalanche_test",
            "algorithm": self.algorithm,
            "digest_bits": self.digest_bits,
            "input_a": self.input_a,
            "input_b": self.input_b,
            "inputs_identical": self.inputs_identical,
            "input_changed_bits": self.input_changed_bits,
            "hash_a": self.hash_a,
            "hash_b": self.hash_b,
            "changed_bits": self.changed_bits,
            "total_bits": self.digest_bits,
            "percentage_changed": round(self.percentage, 2),
            "ideal_percentage": 50.0,
            "deviation_from_ideal": round(self.deviation_from_ideal, 2),
            "verdict": self.verdict,
        }


def _input_bit_difference(text_a: str, text_b: str) -> Optional[int]:
    """Return how many bits differ between two inputs of equal byte length."""
    raw_a = text_a.encode("utf-8")
    raw_b = text_b.encode("utf-8")
    if len(raw_a) != len(raw_b):
        return None
    return hamming_distance(raw_a, raw_b)


def avalanche_test(text_a: str, text_b: str, algorithm: str = "sha256") -> AvalancheResult:
    """Measure how many digest bits change between two texts.

    Args:
        text_a: First input, for example ``"hello"``.
        text_b: Second input, for example ``"Hello"``.
        algorithm: Hash algorithm key.

    Returns:
        An :class:`AvalancheResult` with the changed-bit count and percentage.
    """
    info = get_algorithm(algorithm)
    digest_a = digest_text(text_a, algorithm)
    digest_b = digest_text(text_b, algorithm)

    return AvalancheResult(
        algorithm=info.name,
        digest_bits=info.digest_bits,
        input_a=text_a,
        input_b=text_b,
        hash_a=digest_a.hex(),
        hash_b=digest_b.hex(),
        changed_bits=hamming_distance(digest_a, digest_b),
        inputs_identical=text_a == text_b,
        input_changed_bits=_input_bit_difference(text_a, text_b),
    )


def avalanche_test_files(
    path_a: str, path_b: str, algorithm: str = "sha256"
) -> AvalancheResult:
    """Same measurement as :func:`avalanche_test` but for two files."""
    info = get_algorithm(algorithm)
    result_a = hash_file(path_a, algorithm)
    result_b = hash_file(path_b, algorithm)

    digest_a = bytes.fromhex(result_a.hex_digest)
    digest_b = bytes.fromhex(result_b.hex_digest)

    return AvalancheResult(
        algorithm=info.name,
        digest_bits=info.digest_bits,
        input_a=path_a,
        input_b=path_b,
        hash_a=result_a.hex_digest,
        hash_b=result_b.hex_digest,
        changed_bits=hamming_distance(digest_a, digest_b),
        inputs_identical=result_a.hex_digest == result_b.hex_digest,
        input_changed_bits=None,
    )
