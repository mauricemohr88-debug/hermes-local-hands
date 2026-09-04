"""Fail-closed workspace path handling.

The process is intentionally restricted to regular files below an explicitly
allowlisted relative path.  On POSIX systems reads use descriptor-relative
``openat`` semantics and ``O_NOFOLLOW`` for every component.  That makes the
security decision on the same file descriptor that is ultimately read.
"""

from __future__ import annotations

import os
import stat
from pathlib import PurePosixPath

from .errors import UnsafePathError

SENSITIVE_PARTS = frozenset(
    {".git", ".env", ".ssh", ".aws", ".gnupg", ".npmrc", ".pypirc", ".netrc"}
)
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")


def normalise_relative(value: str) -> str:
    """Return an unambiguous POSIX relative path or fail closed."""

    if (
        not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise UnsafePathError("path must be an unambiguous non-empty relative path")
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in raw_parts):
        raise UnsafePathError("path traversal is not allowed")
    if any(part.lower() in SENSITIVE_PARTS for part in path.parts):
        raise UnsafePathError("sensitive path is never readable")
    if path.name.lower().endswith(SENSITIVE_SUFFIXES):
        raise UnsafePathError("sensitive file type is never readable")
    return path.as_posix()


def allowed_relative(path: str, allowlist: tuple[str, ...]) -> str:
    normal = normalise_relative(path)
    prefixes = tuple(normalise_relative(item).rstrip("/") for item in allowlist)
    if not prefixes or not any(
        normal == prefix or normal.startswith(prefix + "/") for prefix in prefixes
    ):
        raise UnsafePathError("path is outside this workspace read allowlist")
    return normal


def _unchanged(before: os.stat_result, after: os.stat_result) -> bool:
    """Compare attributes which reveal replacement or concurrent mutation."""

    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def safe_read(root: str, relative_path: str, allowlist: tuple[str, ...], maximum: int) -> bytes:
    """Read one stable regular file without following any symlink.

    A single ``os.read`` is not guaranteed to return the complete file.  The
    bounded loop plus a before/after ``fstat`` comparison also denies a result
    when another local process mutates the file while it is being read.
    """

    rel = allowed_relative(relative_path, allowlist)
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        raise UnsafePathError("read limit must be a positive integer")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise UnsafePathError("safe descriptor-relative reads are unsupported on this platform")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = -1
    opened: list[int] = []
    try:
        root_fd = os.open(root, directory_flags)
        parent_fd = root_fd
        components = rel.split("/")
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            opened.append(next_fd)
            parent_fd = next_fd

        fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise UnsafePathError("only regular files can be read")
            if before.st_size > maximum:
                raise UnsafePathError(f"file exceeds read limit of {maximum} bytes")

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise UnsafePathError(f"file exceeds read limit of {maximum} bytes")

            after = os.fstat(fd)
            if total != before.st_size or not _unchanged(before, after):
                raise UnsafePathError("file changed while it was being read")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except UnsafePathError:
        raise
    except OSError as exc:
        raise UnsafePathError("unable to safely open requested file") from exc
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        if root_fd >= 0:
            os.close(root_fd)
