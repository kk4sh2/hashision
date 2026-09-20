"""Hash Collision Analyzer Pro - analysis modules.

Public surface of the package::

    hashing      hash primitives, algorithm metadata, bit-exact truncation
    file_hasher  chunked file hashing and file comparison
    collision    truncated-hash collision search and birthday mathematics
    benchmark    repeated experiments with descriptive statistics
    avalanche    bit-difference (avalanche effect) measurement
    reporting    terminal rendering and JSON/CSV/TXT export

Educational scope: every collision demonstrated by this package is a collision
in a deliberately TRUNCATED digest. The tool never claims, and must never be
described as producing, a full MD5/SHA-1/SHA-256/SHA-512 collision.
"""

from __future__ import annotations

from .hashing import (
    ALGORITHMS,
    AlgorithmInfo,
    AnalyzerError,
    InvalidParameterError,
    UnsupportedAlgorithmError,
    format_truncated,
    hash_bytes,
    hash_text,
    supported_algorithms,
    truncate_digest,
    validate_bits,
)

__version__ = "1.0.0"
__author__ = "Hash Collision Analyzer Pro"

__all__ = [
    "__version__",
    "__author__",
    "ALGORITHMS",
    "AlgorithmInfo",
    "AnalyzerError",
    "InvalidParameterError",
    "UnsupportedAlgorithmError",
    "format_truncated",
    "hash_bytes",
    "hash_text",
    "supported_algorithms",
    "truncate_digest",
    "validate_bits",
]
