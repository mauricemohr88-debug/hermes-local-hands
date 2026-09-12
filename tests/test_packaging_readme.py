"""Keep the package README independent of the page that renders it."""

from __future__ import annotations

import re
import tomllib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = r"(?:<([^>\n]+)>|([^\s)]+))"


class _HTMLTargets(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attribute, value in attrs:
            if attribute in {"href", "src"} and value is not None:
                self.targets.append(value)


def _link_targets(markdown: str) -> list[str]:
    # Code examples are not rendered links and may deliberately show relative paths.
    prose = re.sub(r"(?ms)^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1\s*$", "", markdown)
    prose = re.sub(r"`+[^`]*`+", "", prose)
    targets = [
        match.group(1) or match.group(2)
        for pattern in (r"\]\(\s*" + DESTINATION, r"(?m)^ {0,3}\[[^\]\n]+\]:\s*" + DESTINATION)
        for match in re.finditer(pattern, prose)
    ]
    parser = _HTMLTargets()
    parser.feed(prose)
    return targets + parser.targets


def _is_portable_target(target: str) -> bool:
    if target.startswith("#"):
        return True
    parsed = urlsplit(target)
    return parsed.scheme in {"https", "http"} and bool(parsed.netloc)


def test_package_readme_has_no_relative_file_or_image_targets() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    readme = metadata["project"]["readme"]
    assert readme == "README.md"
    targets = _link_targets((ROOT / readme).read_text(encoding="utf-8"))
    assert targets, "The package README must contain discoverable documentation links."
    relative = [target for target in targets if not _is_portable_target(target)]
    assert not relative, f"PyPI would resolve these targets against its own page: {relative}"


def test_demo_image_uses_a_direct_absolute_asset_url() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    image_targets = [
        match.group(1) or match.group(2)
        for match in re.finditer(r"!\[[^\]\n]*\]\(\s*" + DESTINATION, readme)
    ]
    assert (
        "https://raw.githubusercontent.com/mauricemohr88-debug/hermes-local-hands/"
        "main/docs/assets/local-demo.gif"
    ) in image_targets


@pytest.mark.parametrize(
    ("markup", "target"),
    [
        ("[Guide](docs/TRY_IT.md)", "docs/TRY_IT.md"),
        ("![Demo](docs/assets/local-demo.gif)", "docs/assets/local-demo.gif"),
        ("[Guide](<docs/TRY_IT.md>)", "docs/TRY_IT.md"),
        ("[Guide][intro]\n\n[intro]: docs/TRY_IT.md", "docs/TRY_IT.md"),
        ("[Guide][intro]\n\n[intro]: <docs/TRY_IT.md>", "docs/TRY_IT.md"),
        ('<a href="docs/TRY_IT.md">Guide</a>', "docs/TRY_IT.md"),
        ("<img src='docs/assets/local-demo.gif'>", "docs/assets/local-demo.gif"),
        ("<img src=docs/assets/local-demo.gif>", "docs/assets/local-demo.gif"),
    ],
)
def test_relative_markdown_and_html_targets_are_detected(markup: str, target: str) -> None:
    assert target in _link_targets(markup)
    assert not _is_portable_target(target)


@pytest.mark.parametrize("target", ["../README.md", "/docs/TRY_IT.md", "//example.org/doc"])
def test_relative_and_scheme_relative_targets_are_not_portable(target: str) -> None:
    assert not _is_portable_target(target)


def test_badges_and_local_anchors_are_supported() -> None:
    targets = _link_targets(
        "[![CI](https://example.org/badge.svg)](https://example.org/ci) [Top](#top)"
    )
    assert targets == ["https://example.org/badge.svg", "https://example.org/ci", "#top"]
    assert all(_is_portable_target(target) for target in targets)


def test_link_syntax_inside_code_is_not_treated_as_a_rendered_target() -> None:
    assert _link_targets("`[Guide](docs/TRY_IT.md)`\n\n```md\n![Image](demo.gif)\n```\n") == []
