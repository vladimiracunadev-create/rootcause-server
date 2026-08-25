#!/usr/bin/env python3
"""Guard the text integrity of a bilingual repository.

An English spell-checker is the wrong tool here: the code is in English and the
interface, the documentation and every operator-facing message are in Spanish.
What actually goes wrong in a repository like this is *encoding* — a file
written once as Latin-1, a byte-order mark added by an editor, a line ending
flipped by a checkout on Windows — and the result is a security console that
renders a mangled word to the person it is trying to warn.

Run: python3 scripts/guard_encoding.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {
    ".rs", ".toml", ".md", ".yml", ".yaml", ".sh", ".py", ".js", ".css",
    ".html", ".svg", ".sql", ".json", ".jsonc", ".service", ".plist", ".iss",
}
TEXT_NAMES = {
    "Dockerfile", "LICENSE", "CODEOWNERS", ".env.example", ".gitignore",
    ".dockerignore", ".editorconfig", ".gitattributes", ".hadolint.yaml",
}
SKIP_DIRECTORIES = {".git", "target", "node_modules", "dist"}

# The characters a Spanish text is made of. Their UTF-8 bytes read as Latin-1
# produce exactly the sequences that betray a broken round-trip — deriving the
# list this way keeps the mangled forms out of this file, so the guard cannot
# flag itself.
SPANISH_CHARACTERS = "áéíóúüñÁÉÍÓÚÑ¿¡°«»…—“”’"
MOJIBAKE = tuple(
    sorted({character.encode("utf-8").decode("latin-1") for character in SPANISH_CHARACTERS})
)


def text_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if SKIP_DIRECTORIES.intersection(path.relative_to(ROOT).parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            files.append(path)
    return sorted(files)


def failures() -> list[str]:
    problems: list[str] = []

    for path in text_files():
        relative = path.relative_to(ROOT).as_posix()
        raw = path.read_bytes()

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            problems.append(
                f"{relative}: no es UTF-8 válido ({error.reason} en el byte {error.start})"
            )
            continue

        if raw.startswith(b"\xef\xbb\xbf"):
            problems.append(f"{relative}: empieza con una marca de orden de bytes (BOM)")

        if b"\r\n" in raw:
            problems.append(f"{relative}: usa CRLF; .gitattributes exige LF")

        for marker in MOJIBAKE:
            index = text.find(marker)
            if index >= 0:
                line = text[:index].count("\n") + 1
                problems.append(
                    f"{relative}:{line}: el archivo fue leído como Latin-1 en algún "
                    "punto de su historia y quedó con caracteres corruptos"
                )
                break

    return problems


def main() -> int:
    problems = failures()
    if problems:
        print("encoding guard failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"encoding guard passed: {len(text_files())} archivos en UTF-8, sin BOM, sin CRLF."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
