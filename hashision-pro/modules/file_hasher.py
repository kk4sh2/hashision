"""Memory-safe file hashing.

Files are streamed in :data:`~modules.hashing.CHUNK_SIZE` blocks, so a 10 GB
image is hashed with the same 64 KiB of RAM as a one-line text file.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional, Sequence

from .hashing import (
    CHUNK_SIZE,
    AnalyzerError,
    get_algorithm,
    new_hasher,
    supported_algorithms,
)

__all__ = [
    "FileAccessError",
    "FileHashResult",
    "hash_file",
    "hash_file_multi",
    "files_have_same_bytes",
    "compare_files",
]


class FileAccessError(AnalyzerError):
    """Raised when a path cannot be read as a regular file."""


@dataclass(frozen=True)
class FileHashResult:
    """Result of hashing one file."""

    path: str
    algorithm: str
    digest_bits: int
    hex_digest: str
    size_bytes: int
    chunks_read: int

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "path": self.path,
            "algorithm": self.algorithm,
            "digest_bits": self.digest_bits,
            "hex_digest": self.hex_digest,
            "size_bytes": self.size_bytes,
            "chunks_read": self.chunks_read,
        }


def _check_path(path: str) -> str:
    """Validate that ``path`` is an existing, readable regular file."""
    if not path:
        raise FileAccessError("No file path was given.")

    expanded = os.path.expanduser(path)

    if not os.path.exists(expanded):
        raise FileAccessError("File does not exist: {}".format(path))
    if os.path.isdir(expanded):
        raise FileAccessError(
            "A directory was supplied instead of a file: {}".format(path)
        )
    if not os.path.isfile(expanded):
        raise FileAccessError(
            "Not a regular file (socket, device or pipe?): {}".format(path)
        )
    if not os.access(expanded, os.R_OK):
        raise FileAccessError("Permission denied: {}".format(path))
    return expanded


def hash_file(
    path: str,
    algorithm: str = "sha256",
    chunk_size: int = CHUNK_SIZE,
    max_bytes: Optional[int] = None,
) -> FileHashResult:
    """Hash a file by streaming it in fixed-size chunks.

    Args:
        path: Path to a readable regular file.
        algorithm: One of ``md5``, ``sha1``, ``sha256``, ``sha512``.
        chunk_size: Bytes read per iteration. Defaults to 64 KiB.
        max_bytes: Optional safety limit; the file is refused if it is larger.

    Returns:
        A :class:`FileHashResult`.

    Raises:
        FileAccessError: The path is missing, a directory, unreadable or too big.
        UnsupportedAlgorithmError: The algorithm name is not supported.
    """
    info = get_algorithm(algorithm)
    real_path = _check_path(path)

    if chunk_size < 1:
        chunk_size = CHUNK_SIZE

    try:
        size = os.path.getsize(real_path)
    except OSError as exc:  # pragma: no cover - defensive
        raise FileAccessError("Cannot stat {}: {}".format(path, exc)) from exc

    if max_bytes is not None and size > max_bytes:
        raise FileAccessError(
            "File is {} bytes, which exceeds the configured limit of {} bytes.".format(
                size, max_bytes
            )
        )

    hasher = new_hasher(algorithm)
    chunks = 0
    read_bytes = 0

    try:
        with open(real_path, "rb") as handle:
            while True:
                block = handle.read(chunk_size)
                if not block:
                    break
                hasher.update(block)
                chunks += 1
                read_bytes += len(block)
    except PermissionError as exc:
        raise FileAccessError("Permission denied: {}".format(path)) from exc
    except IsADirectoryError as exc:  # pragma: no cover - caught earlier
        raise FileAccessError("Is a directory: {}".format(path)) from exc
    except OSError as exc:
        raise FileAccessError("Could not read {}: {}".format(path, exc)) from exc

    return FileHashResult(
        path=path,
        algorithm=info.name,
        digest_bits=info.digest_bits,
        hex_digest=hasher.hexdigest(),
        size_bytes=read_bytes,
        chunks_read=chunks,
    )


def hash_file_multi(
    path: str,
    algorithms: Optional[Sequence[str]] = None,
    chunk_size: int = CHUNK_SIZE,
    max_bytes: Optional[int] = None,
) -> "OrderedDict[str, FileHashResult]":
    """Hash one file with several algorithms in a SINGLE pass over the bytes.

    Hashing a 10 GB file with four algorithms this way reads it once, not four
    times: every chunk is fed to every hasher before the next chunk is read.

    Args:
        path: Path to a readable regular file.
        algorithms: Algorithm keys; defaults to every supported algorithm.
        chunk_size: Bytes read per iteration.
        max_bytes: Optional size limit, as in :func:`hash_file`.

    Returns:
        An ordered mapping of algorithm key to :class:`FileHashResult`.

    Raises:
        FileAccessError: The path is missing, a directory, unreadable or too big.
    """
    keys = list(algorithms) if algorithms else list(supported_algorithms())
    infos = {key: get_algorithm(key) for key in keys}
    real_path = _check_path(path)

    if chunk_size < 1:
        chunk_size = CHUNK_SIZE

    try:
        size = os.path.getsize(real_path)
    except OSError as exc:  # pragma: no cover - defensive
        raise FileAccessError("Cannot stat {}: {}".format(path, exc)) from exc

    if max_bytes is not None and size > max_bytes:
        raise FileAccessError(
            "File is {} bytes, which exceeds the configured limit of {} bytes.".format(
                size, max_bytes
            )
        )

    hashers = {key: new_hasher(key) for key in keys}
    chunks = 0
    read_bytes = 0

    try:
        with open(real_path, "rb") as handle:
            while True:
                block = handle.read(chunk_size)
                if not block:
                    break
                for hasher in hashers.values():
                    hasher.update(block)
                chunks += 1
                read_bytes += len(block)
    except PermissionError as exc:
        raise FileAccessError("Permission denied: {}".format(path)) from exc
    except OSError as exc:
        raise FileAccessError("Could not read {}: {}".format(path, exc)) from exc

    results: "OrderedDict[str, FileHashResult]" = OrderedDict()
    for key in keys:
        results[key] = FileHashResult(
            path=path,
            algorithm=infos[key].name,
            digest_bits=infos[key].digest_bits,
            hex_digest=hashers[key].hexdigest(),
            size_bytes=read_bytes,
            chunks_read=chunks,
        )
    return results


def files_have_same_bytes(
    path_a: str, path_b: str, chunk_size: int = CHUNK_SIZE
) -> bool:
    """Return ``True`` when both files contain exactly the same bytes.

    Streamed like :func:`hash_file`, so it is safe on very large files.
    """
    real_a = _check_path(path_a)
    real_b = _check_path(path_b)

    if os.path.getsize(real_a) != os.path.getsize(real_b):
        return False

    try:
        with open(real_a, "rb") as handle_a, open(real_b, "rb") as handle_b:
            while True:
                block_a = handle_a.read(chunk_size)
                block_b = handle_b.read(chunk_size)
                if block_a != block_b:
                    return False
                if not block_a:
                    return True
    except OSError as exc:
        raise FileAccessError("Could not compare files: {}".format(exc)) from exc


def compare_files(
    path_a: str,
    path_b: str,
    algorithm: str = "sha256",
    chunk_size: int = CHUNK_SIZE,
) -> dict:
    """Hash two files and report whether their digests match.

    A digest match between two files whose *bytes differ* is a real collision
    for that algorithm; this is how a known harmless collision pair (for
    example the two ``shattered`` SHA-1 PDFs) can be verified with this tool.
    Two identical copies sharing a digest is expected behaviour, not a break,
    so the byte content is compared before ``real_collision`` is reported.

    Returns:
        A dictionary with both results plus ``identical_digest``,
        ``identical_content`` and ``real_collision`` flags.
    """
    result_a = hash_file(path_a, algorithm, chunk_size)
    result_b = hash_file(path_b, algorithm, chunk_size)

    identical_digest = result_a.hex_digest == result_b.hex_digest
    same_path = os.path.realpath(os.path.expanduser(path_a)) == os.path.realpath(
        os.path.expanduser(path_b)
    )

    # Only worth reading the files again when the digests actually match.
    identical_content = (
        True
        if same_path
        else (files_have_same_bytes(path_a, path_b, chunk_size) if identical_digest else False)
    )

    return {
        "algorithm": result_a.algorithm,
        "file_a": result_a.to_dict(),
        "file_b": result_b.to_dict(),
        "identical_digest": identical_digest,
        "identical_size": result_a.size_bytes == result_b.size_bytes,
        "identical_content": identical_content,
        "same_path": same_path,
        # A genuine collision needs DIFFERENT inputs producing ONE digest.
        "real_collision": identical_digest and not identical_content,
    }
