#!/usr/bin/env python3
"""Keep the documentation honest about the code, and the workflows pinned.

Numbers in a README drift the moment somebody adds a rule and forgets the docs.
This script derives every claim from the source of truth and fails when the two
disagree, so "18 reglas" is a fact rather than a memory.

It also refuses any GitHub Actions step that is not pinned to a full commit
SHA: a moving tag is a supply-chain decision made by somebody else.

Run: python3 scripts/guard_claims.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_MANIFEST = ROOT / "Cargo.toml"
RULES_SOURCE = ROOT / "crates" / "rootcause-core" / "src" / "detect" / "mod.rs"
WORKFLOWS = ROOT / ".github" / "workflows"

SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.MULTILINE)


def workspace_version() -> str:
    text = WORKSPACE_MANIFEST.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("could not read the workspace version from Cargo.toml")
    return match.group(1)


def rule_count() -> int:
    text = RULES_SOURCE.read_text(encoding="utf-8")
    body = text.split("pub const RULES: &[RuleInfo] = &[", 1)
    if len(body) != 2:
        raise SystemExit("could not find the rule catalog in detect/mod.rs")
    return body[1].count("RuleInfo {")


def check_documented_numbers(problems: list[str]) -> None:
    rules = rule_count()
    version = workspace_version()

    for relative in ("README.md", "docs/CAPABILITIES.md", "docs/DETECCION_AMENAZAS.md"):
        path = ROOT / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"(\d+)\s+reglas", text):
            if int(match.group(1)) != rules:
                line = text[: match.start()].count("\n") + 1
                problems.append(
                    f"{relative}:{line}: dice {match.group(1)} reglas; el código publica {rules}"
                )

    readme = ROOT / "README.md"
    if readme.is_file():
        text = readme.read_text(encoding="utf-8")
        if f"version-{version}" not in text.replace("%20", " "):
            problems.append(f"README.md: la insignia de versión no dice {version}")


def check_action_pins(problems: list[str]) -> None:
    if not WORKFLOWS.is_dir():
        problems.append("missing .github/workflows")
        return
    workflows = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not workflows:
        problems.append("no workflow files found")
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        for match in USES.finditer(text):
            reference = match.group(1).strip("\"'")
            line = text[: match.start()].count("\n") + 1
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            if "@" not in reference:
                problems.append(f"{path.name}:{line}: {reference} has no version at all")
                continue
            pin = reference.split("@", 1)[1]
            if not SHA_PIN.match(pin):
                problems.append(
                    f"{path.name}:{line}: {reference} is pinned to a movable tag; "
                    "use the full commit SHA"
                )


def check_permissions(problems: list[str]) -> None:
    """Every workflow must declare its token permissions explicitly."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if not re.search(r"^permissions:", text, re.MULTILINE):
            problems.append(f"{path.name}: no declara `permissions:` a nivel de workflow")


def main() -> int:
    problems: list[str] = []
    check_documented_numbers(problems)
    check_action_pins(problems)
    check_permissions(problems)

    if problems:
        print("claims guard failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"claims guard passed: {rule_count()} reglas publicadas, versión {workspace_version()}, "
        "acciones pinneadas a SHA."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
