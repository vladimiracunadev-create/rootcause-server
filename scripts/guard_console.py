#!/usr/bin/env python3
"""Guard the properties the embedded console promises.

The console ships inside the server binary and is served with a strict Content
Security Policy. Those two facts only hold if nobody ever adds an inline
handler, a CDN link or an `innerHTML` assignment "just this once" — so the
check runs on every build instead of living in a review checklist.

Run: python3 scripts/guard_console.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "console"
HEADERS = ROOT / "crates" / "rootcause-server" / "src" / "headers.rs"

# Attributes that would execute script from markup, which the CSP forbids.
INLINE_HANDLERS = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
# Anything that would fetch from a host other than the server itself.
EXTERNAL_ORIGIN = re.compile(r"""(?:src|href)\s*=\s*["']https?://""", re.IGNORECASE)
# Sinks that turn agent-reported text into markup.
DANGEROUS_JS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function(",
    "setTimeout(\"",
    "setInterval(\"",
)


def failures() -> list[str]:
    problems: list[str] = []

    if not CONSOLE.is_dir():
        return [f"missing console directory: {CONSOLE}"]

    html_files = sorted(CONSOLE.glob("*.html"))
    if not html_files:
        problems.append("the console has no HTML entry point")

    for path in html_files:
        text = path.read_text(encoding="utf-8")
        for match in INLINE_HANDLERS.finditer(text):
            line = text[: match.start()].count("\n") + 1
            problems.append(
                f"{path.relative_to(ROOT)}:{line}: inline event handler "
                f"({match.group(0).strip()}) is blocked by the CSP"
            )
        for match in EXTERNAL_ORIGIN.finditer(text):
            line = text[: match.start()].count("\n") + 1
            problems.append(
                f"{path.relative_to(ROOT)}:{line}: external origin is blocked by the CSP"
            )
        if "<style" in text.lower():
            problems.append(f"{path.relative_to(ROOT)}: inline <style> is blocked by the CSP")

    for path in sorted(CONSOLE.glob("*.js")):
        text = path.read_text(encoding="utf-8")
        for marker in DANGEROUS_JS:
            index = text.find(marker)
            if index >= 0:
                line = text[:index].count("\n") + 1
                problems.append(
                    f"{path.relative_to(ROOT)}:{line}: {marker} turns reported text into markup; "
                    "build nodes with the DOM API instead"
                )

    for path in sorted(CONSOLE.glob("*.css")):
        text = path.read_text(encoding="utf-8")
        if "@import" in text or "url(http" in text:
            problems.append(f"{path.relative_to(ROOT)}: the stylesheet reaches an external origin")

    if HEADERS.is_file():
        source = HEADERS.read_text(encoding="utf-8")
        # Only the constant itself, never the tests that assert on its content.
        declaration = re.search(
            r'pub const CONTENT_SECURITY_POLICY: &str =(.*?)";', source, re.DOTALL
        )
        if declaration is None:
            problems.append("headers.rs no longer declares CONTENT_SECURITY_POLICY")
        else:
            policy = declaration.group(1)
            for required in ("frame-ancestors 'none'", "object-src 'none'", "script-src 'self'"):
                if required not in policy:
                    problems.append(f"the CSP no longer declares {required!r}")
            for forbidden in ("unsafe-inline", "unsafe-eval", "*"):
                if forbidden in policy:
                    problems.append(f"the CSP was weakened with {forbidden!r}")
    else:
        problems.append(f"missing {HEADERS}")

    return problems


def main() -> int:
    problems = failures()
    if problems:
        print("console guard failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("console guard passed: no inline script, no external origin, no markup sinks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
