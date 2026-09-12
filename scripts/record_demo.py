"""Record only the fixed, generated local demo; never approve a real workspace."""

from __future__ import annotations

import argparse
import errno
import fcntl
import html
import json
import os
import pty
import re
import select
import struct
import subprocess
import tempfile
import termios
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROMPT = "Type this request's approval_code, or press Enter to stop: "
SUCCESS = "PASS: approved patch + linked check + receipt verification; original unchanged."
WIDTH = 110
HEIGHT = 32


def capture() -> tuple[dict[str, object], list[list[object]]]:
    """Drive two fixture-only prompts and retain actual PTY output and timing."""
    executable = ROOT / ".venv" / "bin" / "python"
    if not executable.is_file():
        raise RuntimeError("Install this source checkout in .venv before recording.")
    recording_root = Path(tempfile.mkdtemp(prefix="local-hands-recording-"))
    demo_directory = recording_root / "toy-demo"
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", HEIGHT, WIDTH, 0, 0))
    started = time.monotonic()
    timestamp = int(time.time())
    command = [
        str(executable),
        "-m",
        "hermes_local_hands",
        "demo",
        "--directory",
        str(demo_directory),
    ]
    child = subprocess.Popen(  # noqa: S603 -- fixed local demo, new fixture directory, no command option
        command,
        cwd=ROOT,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env={"PATH": os.defpath, "TERM": "xterm-256color", "COLUMNS": str(WIDTH)},
    )
    os.close(slave)
    events: list[list[object]] = []
    transcript = ""
    approvals = 0
    try:
        while time.monotonic() - started < 45:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    data = os.read(master, 65_536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                output = data.decode("utf-8", errors="strict")
                transcript += output
                events.append([round(time.monotonic() - started, 3), "o", output])
            if transcript.count(PROMPT) > approvals:
                if approvals >= 2 or transcript.count(PROMPT) != approvals + 1:
                    raise RuntimeError("Unexpected approval prompt; recording stopped.")
                review = transcript.rsplit("LOCAL REQUEST REVIEW", 1)[-1].replace("\r", "")
                expected_kind = "patch" if approvals == 0 else "test"
                expected = (
                    f"kind: {expected_kind}\n",
                    "workspace_id: demo\n",
                    "client_id: demo-client\n",
                    "state: pending\n",
                )
                match = re.search(r"^approval_code: ([A-F0-9]{12})$", review, re.MULTILINE)
                if not all(field in review for field in expected) or match is None:
                    raise RuntimeError(
                        "Prompt did not match the generated fixture; nothing approved."
                    )
                # This pause is recorded real elapsed time, not a fabricated event timestamp.
                time.sleep(2.0)
                os.write(master, (match.group(1) + "\n").encode("ascii"))
                approvals += 1
            if child.poll() is not None and not ready:
                break
        else:
            raise RuntimeError("Demo recording exceeded its time bound.")
        returncode = child.wait(timeout=5)
    finally:
        os.close(master)
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    if returncode != 0 or approvals != 2 or SUCCESS not in transcript:
        raise RuntimeError("Demo did not pass; no success recording was saved.")
    if (
        demo_directory / "repository" / "src" / "greeting.txt"
    ).read_text() != "Hello from Hermes.\n":
        raise RuntimeError("Original toy checkout changed; no success recording was saved.")

    redactions = sorted({str(demo_directory), str(demo_directory.resolve())}, key=len, reverse=True)
    for event in events:
        for private_path in redactions:
            event[2] = str(event[2]).replace(private_path, "<generated-demo-directory>")
    rendered = "".join(str(event[2]) for event in events)
    if (
        str(Path.home()) in rendered
        or str(recording_root) in rendered
        or re.search(r"/(?:private/)?var/folders/|/Users/|/home/", rendered)
    ):
        raise RuntimeError("Personal path remained in output; no recording was saved.")
    header: dict[str, object] = {
        "version": 2,
        "width": WIDTH,
        "height": HEIGHT,
        "timestamp": timestamp,
        "title": "Local toy demo; recorded CLI output (unreleased source checkout)",
        "env": {"TERM": "xterm-256color"},
        "local_hands_recording": {
            "approval_driver": "Recorder typed only the two generated toy request codes.",
            "redactions": ["Generated artifact directory replaced with a neutral label."],
            "validation": "Exit 0, final PASS, two approvals, original toy greeting unchanged.",
            "limits": "No remote Hermes, tunnel, real workspace, or sandbox validation.",
        },
    }
    print(f"Verified local toy demo. Private generated files retained at: {recording_root}")
    return header, events


def replay_page(header: dict[str, object], events: list[list[object]]) -> str:
    """Embed the verified recording without remote scripts, fonts, or trackers."""
    payload = json.dumps(events, ensure_ascii=True).replace("<", "\\u003c")
    title = html.escape(str(header["title"]))
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{title}</title>
<style>
:root{{color-scheme:dark;font:16px system-ui;background:#101822;color:#e5edf6}}
body{{max-width:1080px;margin:48px auto;padding:0 24px}}h1{{font-size:clamp(24px,4vw,36px)}}
p{{line-height:1.6;color:#afbed0}}a{{color:#77d4bd}}button{{background:#77d4bd;color:#10251d;
border:0;border-radius:8px;padding:12px 20px;font:inherit;cursor:pointer}}
button:focus-visible{{outline:3px solid white}}
pre{{height:520px;overflow:auto;background:#080e15;padding:24px;border:1px solid #263a4b;
border-radius:12px;font:14px/1.5 ui-monospace,monospace;
white-space:pre-wrap;overflow-wrap:anywhere}}
.label{{color:#77d4bd;font-size:13px;text-transform:uppercase;letter-spacing:1px}}
</style>
<main><div class="label">Recorded CLI output · local toy demo · unreleased</div>
<h1>A request is not an approval.</h1>
<p>Watch a generated patch and linked check reach separate local approval gates.
The fixture-only recorder typed both displayed codes; ordinary demo use remains manual.
The replay preserves actual output and timing. Only the generated directory path is redacted.</p>
<button id="play" type="button">Play recording</button>
<button id="full" type="button">Show full transcript</button>
<pre id="terminal" tabindex="0" aria-label="Recorded terminal output"></pre>
<p>Validated before saving: exit 0, two toy approvals, final PASS, and original greeting unchanged.
This is not remote Hermes, tunnel, real-workspace, or sandbox validation. Approved check code
still runs with the local user's host and network access.</p>
<p><a href="assets/local-demo.cast" download>Download actual cast</a> ·
<a href="TRY_IT.md">Run the walkthrough</a></p></main>
<script>
const events={payload};
const terminal=document.getElementById('terminal');
let timers=[];
function clearTimers(){{timers.forEach(clearTimeout);timers=[];}}
function append(value){{terminal.textContent+=value.replace(/\\r/g,'');
terminal.scrollTop=terminal.scrollHeight;}}
document.getElementById('play').onclick=()=>{{clearTimers();terminal.textContent='';
for(const [at,type,value] of events)
if(type==='o') timers.push(setTimeout(()=>append(value),at*1000));}};
document.getElementById('full').onclick=()=>{{clearTimers();terminal.textContent='';
for(const [,type,value] of events) if(type==='o') append(value);}};
terminal.textContent='Select Play recording. No command will run in your browser.';
</script></html>
"""


def write_gif(events: list[list[object]], target: Path) -> None:
    """Render real output frames; Pillow is an optional recording-only dependency."""
    from PIL import Image, ImageDraw, ImageFont

    candidates = (
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    )
    font_file = next((font for font in candidates if Path(font).is_file()), None)
    if font_file is None:
        raise RuntimeError("No recording font found; cast and HTML remain available.")
    font = ImageFont.truetype(font_file, 15)
    heading = ImageFont.truetype(font_file, 18)
    frames = []
    durations = []
    transcript = ""
    for index, event in enumerate(events):
        transcript += str(event[2]).replace("\r", "")
        lines = []
        for line in transcript.split("\n"):
            lines.extend(textwrap.wrap(line, width=110, replace_whitespace=False) or [""])
        frame = Image.new("RGB", (1080, 780), "#0c141d")
        draw = ImageDraw.Draw(frame)
        draw.text((28, 22), "LOCAL TOY DEMO / recorded CLI output", font=heading, fill="#7ad9ba")
        draw.text(
            (28, 55),
            "Unreleased source checkout. Recorder confirms toy requests only.",
            font=font,
            fill="#aab9ca",
        )
        draw.line((28, 88, 1052, 88), fill="#29404f")
        for row, line in enumerate(lines[-29:]):
            color = (
                "#7ad9ba"
                if line.startswith(("PASS:", "Patch verified", "Check passed"))
                else "#e3edf7"
            )
            draw.text((28, 108 + row * 21), line, font=font, fill=color)
        draw.text(
            (28, 741),
            "No remote/tunnel proof. Checks are not sandboxed.",
            font=font,
            fill="#aab9ca",
        )
        frames.append(frame)
        following = float(events[index + 1][0]) if index + 1 < len(events) else float(event[0]) + 4
        durations.append(max(20, round((following - float(event[0])) * 1000)))
    frames[0].save(
        target, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gif", action="store_true", help="also render GIF using optional Pillow")
    args = parser.parse_args()
    header, events = capture()
    assets = ROOT / "docs" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    cast = "\n".join(json.dumps(item, ensure_ascii=True) for item in [header, *events]) + "\n"
    (assets / "local-demo.cast").write_text(cast, encoding="utf-8")
    (ROOT / "docs" / "demo.html").write_text(replay_page(header, events), encoding="utf-8")
    if args.gif:
        write_gif(events, assets / "local-demo.gif")
    print("Saved verified local-demo.cast and self-contained docs/demo.html.")


if __name__ == "__main__":
    main()
