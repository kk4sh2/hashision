"""Core hashing primitives, algorithm metadata and bit-exact truncation.

Every other module in Hash Collision Analyzer Pro builds on this one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Tuple

__all__ = [
    "AnalyzerError",
    "UnsupportedAlgorithmError",
    "InvalidParameterError",
    "AlgorithmInfo",
    "ALGORITHMS",
    "CHUNK_SIZE",
    "MAX_TRUNCATION_BITS",
    "RECOMMENDED_BITS",
    "supported_algorithms",
    "get_algorithm",
    "new_hasher",
    "digest_bytes",
    "hash_bytes",
    "digest_text",
    "hash_text",
    "digest_size_bits",
    "validate_bits",
    "truncate_digest",
    "format_truncated",
    "truncate_text",
]


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------

class AnalyzerError(Exception):
    """Base class for every error raised by this tool.

    The CLI catches this type, prints a clean message and exits with status 1
    instead of dumping a traceback on the user.
    """


class UnsupportedAlgorithmError(AnalyzerError):
    """Raised when an algorithm name is not one of the four supported hashes."""


class InvalidParameterError(AnalyzerError):
    """Raised when a numeric parameter is outside its safe range."""


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: Number of bytes read per iteration when hashing a file.
CHUNK_SIZE: int = 65536

#: Hard safety limit for truncation. Above 32 bits an experiment on ordinary
#: hardware can consume unreasonable time and memory, so it is refused.
MAX_TRUNCATION_BITS: int = 32

#: The truncation sizes used in the course material.
RECOMMENDED_BITS: Tuple[int, ...] = (8, 12, 16, 20, 24)


@dataclass(frozen=True)
class AlgorithmInfo:
    """Static facts about one hash algorithm."""

    name: str
    digest_bits: int
    collision_security: str
    status: str
    note: str

    @property
    def digest_bytes(self) -> int:
        """Digest length in bytes."""
        return self.digest_bits // 8

    @property
    def hex_length(self) -> int:
        """Digest length in hexadecimal characters."""
        return self.digest_bits // 4


ALGORITHMS: Dict[str, AlgorithmInfo] = {
    "md5": AlgorithmInfo(
        name="MD5",
        digest_bits=128,
        collision_security="Broken",
        status="BROKEN",
        note="Practical chosen-prefix collisions since 2004. Never use for security.",
    ),
    "sha1": AlgorithmInfo(
        name="SHA-1",
        digest_bits=160,
        collision_security="Broken",
        status="BROKEN",
        note="Public collision (SHAttered, 2017). Deprecated for signatures.",
    ),
    "sha256": AlgorithmInfo(
        name="SHA-256",
        digest_bits=256,
        collision_security="~2^128",
        status="SECURE",
        note="No practical collision attack known. Current general-purpose default.",
    ),
    "sha512": AlgorithmInfo(
        name="SHA-512",
        digest_bits=512,
        collision_security="~2^256",
        status="SECURE",
        note="No practical collision attack known. Faster than SHA-256 on 64-bit CPUs.",
    ),
}


# --------------------------------------------------------------------------
# Algorithm helpers
# --------------------------------------------------------------------------

def supported_algorithms() -> Tuple[str, ...]:
    """Return the canonical algorithm keys accepted by the CLI."""
    return tuple(ALGORITHMS.keys())


def get_algorithm(algorithm: str) -> AlgorithmInfo:
    """Look up :class:`AlgorithmInfo` for ``algorithm``.

    Args:
        algorithm: Algorithm key, case-insensitive; ``sha-1`` and ``sha_1``
            are normalised to ``sha1``.

    Raises:
        UnsupportedAlgorithmError: If the name is not supported.
    """
    key = algorithm.strip().lower().replace("-", "").replace("_", "")
    if key not in ALGORITHMS:
        raise UnsupportedAlgorithmError(
            "Unsupported algorithm {!r}. Choose one of: {}.".format(
                algorithm, ", ".join(ALGORITHMS)
            )
        )
    return ALGORITHMS[key]


def new_hasher(algorithm: str):
    """Return a fresh ``hashlib`` object for ``algorithm``."""
    info = get_algorithm(algorithm)
    return hashlib.new(info.name.replace("-", "").lower())


def digest_size_bits(algorithm: str) -> int:
    """Return the digest length of ``algorithm`` in bits."""
    return get_algorithm(algorithm).digest_bits


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def digest_bytes(data: bytes, algorithm: str) -> bytes:
    """Hash raw bytes and return the raw digest."""
    hasher = new_hasher(algorithm)
    hasher.update(data)
    return hasher.digest()


def hash_bytes(data: bytes, algorithm: str) -> str:
    """Hash raw bytes and return the lowercase hexadecimal digest."""
    return digest_bytes(data, algorithm).hex()


def digest_text(text: str, algorithm: str, encoding: str = "utf-8") -> bytes:
    """Hash a string (encoded with ``encoding``) and return the raw digest."""
    return digest_bytes(text.encode(encoding), algorithm)


def hash_text(text: str, algorithm: str, encoding: str = "utf-8") -> str:
    """Hash a string and return the lowercase hexadecimal digest."""
    return digest_text(text, algorithm, encoding).hex()


# --------------------------------------------------------------------------
# Bit-exact truncation
# --------------------------------------------------------------------------

def validate_bits(bits: int, algorithm: str) -> int:
    """Validate a requested truncation size.

    Args:
        bits: Requested number of leading digest bits.
        algorithm: Algorithm the truncation will be applied to.

    Returns:
        The validated value.

    Raises:
        InvalidParameterError: If ``bits`` is not a positive integer, exceeds
            :data:`MAX_TRUNCATION_BITS`, or exceeds the digest size.
    """
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise InvalidParameterError("Truncation size must be an integer.")
    if bits < 1:
        raise InvalidParameterError("Truncation size must be at least 1 bit.")
    if bits > MAX_TRUNCATION_BITS:
        raise InvalidParameterError(
            "Refusing to run with {} bits: the safe limit is {} bits "
            "(a larger search may exhaust time and memory).".format(
                bits, MAX_TRUNCATION_BITS
            )
        )
    available = digest_size_bits(algorithm)
    if bits > available:
        raise InvalidParameterError(
            "Cannot keep {} bits of a {}-bit digest.".format(bits, available)
        )
    return bits


def truncate_digest(digest: bytes, bits: int) -> int:
    """Keep the leading ``bits`` bits of ``digest`` and return them as an int.

    One hexadecimal character is 4 bits, so slicing hex characters can only
    express multiples of 4. Shifting the digest integer is exact for any bit
    count, which is why it is done this way::

        digest_int = int.from_bytes(digest, "big")
        truncated  = digest_int >> (digest_size - requested_bits)

    Args:
        digest: Raw digest bytes.
        bits: Number of leading bits to keep (1 .. len(digest) * 8).

    Raises:
        InvalidParameterError: If ``bits`` does not fit in the digest.
    """
    digest_bits = len(digest) * 8
    if bits < 1 or bits > digest_bits:
        raise InvalidParameterError(
            "Cannot keep {} bits of a {}-bit digest.".format(bits, digest_bits)
        )
    digest_int = int.from_bytes(digest, "big")
    return digest_int >> (digest_bits - bits)


def format_truncated(value: int, bits: int) -> str:
    """Render a truncated value as fixed-width uppercase hex.

    16 bits render as 4 characters (``A83F``), 12 bits as 3 (``A83``) and
    8 bits as 2 (``A8``).
    """
    hex_chars = (bits + 3) // 4
    return format(value, "0{}X".format(hex_chars))


def truncate_text(text: str, algorithm: str, bits: int) -> str:
    """Convenience helper: hash ``text`` and return its truncated hex prefix."""
    validate_bits(bits, algorithm)
    digest = digest_text(text, algorithm)
    return format_truncated(truncate_digest(digest, bits), bits)
