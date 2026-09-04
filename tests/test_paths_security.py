from __future__ import annotations

import os
from pathlib import Path

import pytest

from hermes_local_hands.errors import UnsafePathError
from hermes_local_hands.paths import allowed_relative, normalise_relative, safe_read


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/etc/passwd",
        "../secret",
        "src/../secret",
        "src/./secret",
        "src//secret",
        "src/",
        "./src/secret",
        "src\\..\\secret",
        "src/.git/config",
        ".env",
        "src/private.pem",
        "src/name\nother",
        "src/name\x00other",
    ],
)
def test_normalise_relative_rejects_ambiguous_and_sensitive_paths(value: str) -> None:
    with pytest.raises(UnsafePathError):
        normalise_relative(value)


def test_allowlist_matches_complete_path_components() -> None:
    assert allowed_relative("src/nested/file.py", ("src",)) == "src/nested/file.py"
    with pytest.raises(UnsafePathError):
        allowed_relative("src-other/file.py", ("src",))
    with pytest.raises(UnsafePathError):
        allowed_relative("src/file.py", ())


def test_safe_read_loops_until_the_complete_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    target = root / "src" / "data.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"0123456789" * 100)
    original_read = os.read

    def short_read(descriptor: int, maximum: int) -> bytes:
        return original_read(descriptor, min(maximum, 7))

    monkeypatch.setattr(os, "read", short_read)
    assert safe_read(str(root), "src/data.txt", ("src",), 2_000) == target.read_bytes()


def test_safe_read_denies_concurrent_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    target = root / "src" / "data.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"a" * 100_000)
    original_read = os.read
    mutated = False

    def mutate_after_first_read(descriptor: int, maximum: int) -> bytes:
        nonlocal mutated
        result = original_read(descriptor, min(maximum, 4096))
        if not mutated:
            mutated = True
            with target.open("r+b") as stream:
                stream.seek(50_000)
                stream.write(b"b")
                stream.flush()
                os.fsync(stream.fileno())
        return result

    monkeypatch.setattr(os, "read", mutate_after_first_read)
    with pytest.raises(UnsafePathError, match="changed while"):
        safe_read(str(root), "src/data.txt", ("src",), 200_000)


def test_safe_read_denies_growth_beyond_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    target = root / "src" / "data.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"a" * 32)
    original_read = os.read
    grown = False

    def grow_after_first_read(descriptor: int, maximum: int) -> bytes:
        nonlocal grown
        result = original_read(descriptor, min(maximum, 8))
        if not grown:
            grown = True
            with target.open("ab") as stream:
                stream.write(b"b" * 128)
                stream.flush()
                os.fsync(stream.fileno())
        return result

    monkeypatch.setattr(os, "read", grow_after_first_read)
    with pytest.raises(UnsafePathError, match="exceeds read limit"):
        safe_read(str(root), "src/data.txt", ("src",), 64)


def test_safe_read_rejects_symlink_root_and_final_file(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    (real_root / "src").mkdir(parents=True)
    (real_root / "src" / "real.txt").write_text("private")
    (real_root / "src" / "link.txt").symlink_to(real_root / "src" / "real.txt")
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        safe_read(str(real_root), "src/link.txt", ("src",), 100)
    with pytest.raises(UnsafePathError):
        safe_read(str(linked_root), "src/real.txt", ("src",), 100)
