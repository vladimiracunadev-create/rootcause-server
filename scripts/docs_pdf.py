#!/usr/bin/env python3
"""Render the system documentation to self-contained HTML and to PDF.

Why this lives in the repository instead of being a pandoc invocation: the same
reason `sbom.py` does. A documentation pipeline that depends on a toolchain
nobody pinned is a pipeline that stops working silently. The Markdown-to-HTML
conversion here uses nothing but the standard library, so it produces the same
output on any machine with Python 3.9 or newer.

Two optional pieces upgrade the result and degrade with a printed warning when
they are missing:

* ``mmdc`` (mermaid-cli) turns ```mermaid fences into PNG images embedded as
  data URIs. Without it the diagram is rendered as its source, which is
  readable but not a picture.
* A Chromium-based browser (Chrome, Chromium or Edge) prints the HTML to PDF.
  Without it only the HTML is produced.

Usage:
    python3 scripts/docs_pdf.py                  # HTML + PDF for every document
    python3 scripts/docs_pdf.py --html-only      # skip the browser step
    python3 scripts/docs_pdf.py --only 07        # one document, by number
    python3 scripts/docs_pdf.py --keep-html      # leave the intermediate HTML
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "system-documentation"
PDF_DIR = DOCS / "pdf"
CACHE_DIR = PDF_DIR / ".mermaid-cache"
MANIFEST = ROOT / "Cargo.toml"

SYSTEM_NAME = "RootCause Server"
MERMAID_TIMEOUT = 120
BROWSER_TIMEOUT = 180

# Candidate browsers, in preference order. The first one found is used.
BROWSER_CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "msedge",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


# --------------------------------------------------------------------- context


def workspace_version() -> str:
    """Read the version from the workspace manifest, so it never drifts."""
    in_package = False
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[workspace.package]":
            in_package = True
            continue
        if in_package and stripped.startswith("["):
            break
        if in_package and stripped.startswith("version"):
            return stripped.split('"')[1]
    return "desconocida"


def git_commit() -> str:
    """Short commit of the analysed tree, or a marker when git is unavailable."""
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "sin git"
    return result.stdout.strip() if result.returncode == 0 else "sin git"


def analysis_date() -> str:
    """Date shown on the cover.

    Taken from the documentation index rather than from the clock: the cover
    must say when the repository was analysed, not when the PDF was printed.
    """
    index = DOCS / "README.md"
    if index.exists():
        match = re.search(r"Fecha del análisis \| (\d{4}-\d{2}-\d{2})", index.read_text(encoding="utf-8"))
        if match:
            return match.group(1)
    return "no identificada"


# ------------------------------------------------------------------- diagrams


@dataclass
class Renderer:
    """Turns mermaid sources into embedded PNGs, with a cache keyed by hash."""

    available: bool
    warned: bool = field(default=False)
    rendered: int = field(default=0)

    def data_uri(self, source: str) -> str | None:
        if not self.available:
            if not self.warned:
                print("  aviso: no se encontró 'mmdc'; los diagramas saldrán como código")
                self.warned = True
            return None

        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
        cached = CACHE_DIR / f"{digest}.png"
        if not cached.exists():
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory() as work:
                mmd = Path(work) / "diagram.mmd"
                mmd.write_text(source, encoding="utf-8")
                try:
                    result = subprocess.run(
                        ["mmdc", "-i", str(mmd), "-o", str(cached), "-b", "white", "-s", "2"],
                        capture_output=True,
                        text=True,
                        timeout=MERMAID_TIMEOUT,
                        check=False,
                        shell=os.name == "nt",
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    print(f"  aviso: mmdc falló ({error}); el diagrama sale como código")
                    return None
            if result.returncode != 0 or not cached.exists():
                detail = (result.stderr or result.stdout).strip().splitlines()
                print(f"  aviso: mmdc no pudo dibujar un diagrama: {detail[-1] if detail else '?'}")
                return None
            self.rendered += 1

        encoded = base64.b64encode(cached.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"


# --------------------------------------------------------------------- inline


_INLINE_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?!\*)")


def inline(text: str) -> str:
    """Render the inline subset used by these documents.

    Code spans are extracted first and restored last, so that a `**` inside a
    code span is never mistaken for emphasis.
    """
    spans: list[str] = []

    def stash(match: re.Match[str]) -> str:
        spans.append(html.escape(match.group(1), quote=False))
        return f"\x00{len(spans) - 1}\x00"

    text = _INLINE_CODE.sub(stash, text)
    text = html.escape(text, quote=False)
    text = _LINK.sub(lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">{m.group(1)}</a>', text)
    text = _BOLD.sub(r"<strong>\1</strong>", text)
    text = _ITALIC.sub(r"<em>\1</em>", text)
    for index, span in enumerate(spans):
        text = text.replace(f"\x00{index}\x00", f"<code>{span}</code>")
    return text


def slug(text: str) -> str:
    """Anchor identifier compatible with the links used inside the documents."""
    cleaned = re.sub(r"[^\w\s-]", "", text.lower(), flags=re.UNICODE)
    return re.sub(r"[\s]+", "-", cleaned.strip())


# ---------------------------------------------------------------------- block


class Converter:
    """Markdown to HTML for the subset these documents actually use."""

    def __init__(self, renderer: Renderer) -> None:
        self.renderer = renderer
        self.headings: list[tuple[int, str, str]] = []

    def convert(self, markdown: str) -> str:
        self.headings = []
        lines = markdown.replace("\r\n", "\n").split("\n")
        out: list[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]

            if not line.strip():
                index += 1
                continue

            if line.startswith("```"):
                index = self._fence(lines, index, out)
                continue

            if re.fullmatch(r"\s*(-{3,}|\*{3,}|_{3,})\s*", line):
                out.append("<hr>")
                index += 1
                continue

            heading = re.match(r"^(#{1,6})\s+(.*)$", line)
            if heading:
                level = len(heading.group(1))
                title = heading.group(2).strip()
                anchor = slug(re.sub(r"[*`]", "", title))
                self.headings.append((level, title, anchor))
                out.append(f'<h{level} id="{anchor}">{inline(title)}</h{level}>')
                index += 1
                continue

            if line.lstrip().startswith(">"):
                index = self._quote(lines, index, out)
                continue

            if line.lstrip().startswith("|") and self._is_table(lines, index):
                index = self._table(lines, index, out)
                continue

            if re.match(r"^\s*([-*+]|\d+\.)\s+", line):
                index = self._list(lines, index, out)
                continue

            index = self._paragraph(lines, index, out)
        return "\n".join(out)

    # -- blocks ------------------------------------------------------------

    def _fence(self, lines: list[str], index: int, out: list[str]) -> int:
        language = lines[index][3:].strip().lower()
        index += 1
        body: list[str] = []
        while index < len(lines) and not lines[index].startswith("```"):
            body.append(lines[index])
            index += 1
        index += 1  # closing fence
        source = "\n".join(body)

        if language == "mermaid":
            uri = self.renderer.data_uri(source)
            if uri:
                out.append(f'<figure class="diagram"><img src="{uri}" alt="Diagrama"></figure>')
                return index
            out.append(
                '<pre class="code mermaid-source"><code>'
                + html.escape(source, quote=False)
                + "</code></pre>"
            )
            return index

        classes = f"code lang-{language}" if language else "code"
        out.append(f'<pre class="{classes}"><code>{html.escape(source, quote=False)}</code></pre>')
        return index

    def _quote(self, lines: list[str], index: int, out: list[str]) -> int:
        body: list[str] = []
        while index < len(lines) and lines[index].lstrip().startswith(">"):
            body.append(re.sub(r"^\s*>\s?", "", lines[index]))
            index += 1
        inner = Converter(self.renderer).convert("\n".join(body))
        out.append(f"<blockquote>{inner}</blockquote>")
        return index

    @staticmethod
    def _is_table(lines: list[str], index: int) -> bool:
        following = lines[index + 1] if index + 1 < len(lines) else ""
        return bool(re.fullmatch(r"\s*\|?[\s:|-]+\|[\s:|-]*", following)) and "-" in following

    def _table(self, lines: list[str], index: int, out: list[str]) -> int:
        def cells(row: str) -> list[str]:
            row = row.strip()
            row = row[1:] if row.startswith("|") else row
            row = row[:-1] if row.endswith("|") else row
            return [cell.strip() for cell in row.split("|")]

        header = cells(lines[index])
        index += 2  # header plus alignment row
        rows: list[list[str]] = []
        while index < len(lines) and lines[index].lstrip().startswith("|"):
            rows.append(cells(lines[index]))
            index += 1

        parts = ["<table><thead><tr>"]
        parts += [f"<th>{inline(cell)}</th>" for cell in header]
        parts.append("</tr></thead><tbody>")
        for row in rows:
            parts.append("<tr>")
            parts += [f"<td>{inline(cell)}</td>" for cell in row]
            parts.append("</tr>")
        parts.append("</tbody></table>")
        out.append("".join(parts))
        return index

    def _list(self, lines: list[str], index: int, out: list[str]) -> int:
        """Render one list, honouring a single level of nesting by indent."""
        items: list[tuple[int, str, bool]] = []
        while index < len(lines):
            match = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.*)$", lines[index])
            if match:
                indent = len(match.group(1))
                ordered = match.group(2)[0].isdigit()
                items.append((indent, match.group(3), ordered))
                index += 1
                continue
            # A wrapped continuation line belongs to the previous item.
            if items and lines[index].startswith(("  ", "\t")) and lines[index].strip():
                indent, text, ordered = items[-1]
                items[-1] = (indent, f"{text} {lines[index].strip()}", ordered)
                index += 1
                continue
            break

        base = min(item[0] for item in items)
        tag = "ol" if items[0][2] else "ul"
        parts = [f"<{tag}>"]
        open_nested = False
        for indent, text, _ in items:
            if indent > base:
                if not open_nested:
                    parts.append("<ul>")
                    open_nested = True
                parts.append(f"<li>{inline(text)}</li>")
                continue
            if open_nested:
                parts.append("</ul>")
                open_nested = False
            parts.append(f"<li>{inline(text)}</li>")
        if open_nested:
            parts.append("</ul>")
        parts.append(f"</{tag}>")
        out.append("".join(parts))
        return index

    def _paragraph(self, lines: list[str], index: int, out: list[str]) -> int:
        body: list[str] = []
        while index < len(lines) and lines[index].strip():
            line = lines[index]
            if line.startswith("```") or re.match(r"^#{1,6}\s", line) or line.lstrip().startswith(">"):
                break
            if line.lstrip().startswith("|") or re.match(r"^\s*([-*+]|\d+\.)\s+", line):
                break
            if re.fullmatch(r"\s*(-{3,}|\*{3,}|_{3,})\s*", line):
                break
            body.append(line.strip())
            index += 1
        if body:
            out.append(f"<p>{inline(' '.join(body))}</p>")
        return index


# ----------------------------------------------------------------------- page


STYLE = """
@page { size: A4; margin: 16mm 14mm 16mm 14mm; }
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-size: 10.5pt; line-height: 1.55; color: #16202a; margin: 0;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
.cover { border-bottom: 3px solid #0f6fc5; padding-bottom: 14px; margin-bottom: 26px; }
.cover .system { font-size: 12pt; font-weight: 700; color: #0f6fc5; letter-spacing: .06em;
  text-transform: uppercase; margin: 0 0 4px; }
.cover .doc { font-size: 21pt; font-weight: 700; margin: 0 0 10px; color: #0b1a26; }
.cover .meta { font-size: 8.5pt; color: #55636f; }
.cover .meta span { margin-right: 16px; white-space: nowrap; }
h1, h2, h3, h4, h5, h6 { color: #0b1a26; line-height: 1.28; page-break-after: avoid; }
h1 { font-size: 17pt; margin: 22px 0 10px; }
h2 { font-size: 13.5pt; margin: 20px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #d7dee5; }
h3 { font-size: 11.5pt; margin: 16px 0 6px; }
h4 { font-size: 10.5pt; margin: 13px 0 5px; color: #33414d; }
p { margin: 0 0 9px; }
ul, ol { margin: 0 0 9px; padding-left: 20px; }
li { margin-bottom: 3px; }
a { color: #0f6fc5; text-decoration: none; word-break: break-word; }
code { font-family: "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace;
  font-size: 0.88em; background: #eef2f6; border-radius: 3px; padding: 1px 4px;
  word-break: break-word; }
pre.code { background: #f6f8fa; border: 1px solid #dde4ea; border-left: 3px solid #0f6fc5;
  border-radius: 4px; padding: 9px 11px; margin: 0 0 11px; overflow-wrap: break-word;
  white-space: pre-wrap; word-break: break-word; page-break-inside: avoid; }
pre.code code { background: none; padding: 0; font-size: 8.6pt; line-height: 1.45; }
blockquote { margin: 0 0 12px; padding: 8px 13px; background: #f2f7fb;
  border-left: 3px solid #7aa9d0; color: #34424e; }
blockquote p:last-child { margin-bottom: 0; }
table { width: 100%; border-collapse: collapse; margin: 0 0 13px; font-size: 8.4pt;
  table-layout: auto; page-break-inside: auto; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
/* `break-word` only splits a word that cannot fit on a line of its own, so a
   narrow first column no longer cuts "Funcionalidad" into two. Identifiers
   inside a code span are the exception: they must break anywhere. */
th, td { border: 1px solid #d7dee5; padding: 4px 6px; text-align: left;
  vertical-align: top; word-break: normal; overflow-wrap: break-word; }
th:first-child, td:first-child { min-width: 5.5em; }
th { background: #eaf1f7; font-weight: 700; color: #0b1a26; }
tbody tr:nth-child(even) { background: #fafbfc; }
td code, th code { font-size: 0.92em; padding: 0 2px; overflow-wrap: anywhere; }
figure.diagram { margin: 12px 0 16px; text-align: center; page-break-inside: avoid; }
figure.diagram img { max-width: 100%; height: auto; }
pre.mermaid-source { background: #fbfcfd; border-left-color: #b6c3ce; }
hr { border: none; border-top: 1px solid #dde4ea; margin: 18px 0; }
.toc { background: #f8fafc; border: 1px solid #e2e8ee; border-radius: 5px;
  padding: 12px 16px; margin: 0 0 24px; page-break-inside: avoid; }
.toc h2 { border: none; font-size: 10.5pt; margin: 0 0 7px; text-transform: uppercase;
  letter-spacing: .05em; color: #55636f; }
.toc ul { list-style: none; padding-left: 0; margin: 0; font-size: 9pt; }
.toc li { margin-bottom: 2px; }
.toc li.level-3 { padding-left: 14px; color: #55636f; }
.footer { margin-top: 26px; padding-top: 9px; border-top: 1px solid #dde4ea;
  font-size: 8pt; color: #7b8792; }
"""

PAGE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{style}</style>
</head>
<body>
<header class="cover">
  <p class="system">{system}</p>
  <p class="doc">{title}</p>
  <p class="meta">
    <span><strong>Documento:</strong> {filename}</span>
    <span><strong>Versión analizada:</strong> {version}</span>
    <span><strong>Commit:</strong> {commit}</span>
    <span><strong>Fecha del análisis:</strong> {date}</span>
  </p>
</header>
{toc}
{body}
<p class="footer">{system} · {title} · versión {version} · commit {commit} ·
análisis del {date}. Generado desde {filename} con scripts/docs_pdf.py.</p>
</body>
</html>
"""


def build_toc(headings: list[tuple[int, str, str]]) -> str:
    """Table of contents, only when the document is long enough to need one."""
    entries = [item for item in headings if item[0] in (2, 3)]
    if len(entries) < 6:
        return ""
    rows = [
        f'<li class="level-{level}"><a href="#{anchor}">{inline(re.sub(r"[*`]", "", title))}</a></li>'
        for level, title, anchor in entries
    ]
    return '<nav class="toc"><h2>Contenido</h2><ul>' + "".join(rows) + "</ul></nav>"


def document_title(markdown: str, fallback: str) -> str:
    """Title of the document, taken from its first level-one heading."""
    for line in markdown.splitlines():
        if line.startswith("# "):
            return re.sub(r"[*`]", "", line[2:].strip())
    return fallback


def drop_leading_title(markdown: str) -> str:
    """Remove the first level-one heading; the cover already carries it.

    Printing it twice — once on the cover, once as the opening heading — reads
    like a mistake, which on a document about honesty is a poor first
    impression.
    """
    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("# "):
            return "\n".join(lines[:index] + lines[index + 1 :])
        if line.strip():
            break
    return markdown


# ------------------------------------------------------------------- browser


def find_browser() -> str | None:
    for candidate in BROWSER_CANDIDATES:
        if os.sep in candidate or (os.altsep and os.altsep in candidate):
            if Path(candidate).exists():
                return candidate
            continue
        found = shutil.which(candidate)
        if found:
            return found
    return None


def print_pdf(browser: str, html_path: Path, pdf_path: Path) -> bool:
    with tempfile.TemporaryDirectory() as profile:
        command = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-first-run",
            "--no-pdf-header-footer",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf_path}",
            html_path.as_uri(),
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=BROWSER_TIMEOUT, check=False
            )
        except (OSError, subprocess.SubprocessError) as error:
            print(f"  error: el navegador falló ({error})")
            return False
    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        print(f"  error: no se generó el PDF: {detail[-1] if detail else 'sin salida'}")
        return False
    return True


# ---------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--html-only", action="store_true", help="no invocar el navegador")
    parser.add_argument("--keep-html", action="store_true", help="conservar el HTML intermedio")
    parser.add_argument("--only", help="prefijo del documento, por ejemplo 07 o README")
    arguments = parser.parse_args()

    if not DOCS.is_dir():
        print(f"no existe {DOCS}", file=sys.stderr)
        return 1

    sources = sorted(DOCS.glob("*.md"))
    if arguments.only:
        sources = [path for path in sources if path.name.startswith(arguments.only)]
    if not sources:
        print("no hay documentos que convertir", file=sys.stderr)
        return 1

    PDF_DIR.mkdir(parents=True, exist_ok=True)
    renderer = Renderer(available=shutil.which("mmdc") is not None or os.name == "nt")
    version, commit, date = workspace_version(), git_commit(), analysis_date()

    browser = None
    if not arguments.html_only:
        browser = find_browser()
        if browser is None:
            print("aviso: no se encontró Chrome, Chromium ni Edge; solo se generará HTML")

    print(f"{SYSTEM_NAME} · versión {version} · commit {commit} · análisis del {date}")
    print(f"documentos: {len(sources)}  ·  destino: {PDF_DIR.relative_to(ROOT)}")

    failures = 0
    for source in sources:
        print(f"- {source.name}")
        markdown = source.read_text(encoding="utf-8")
        title = document_title(markdown, source.stem)
        converter = Converter(renderer)
        body = converter.convert(drop_leading_title(markdown))
        page = PAGE.format(
            style=STYLE,
            system=SYSTEM_NAME,
            title=html.escape(title, quote=False),
            filename=source.name,
            version=version,
            commit=commit,
            date=date,
            toc=build_toc(converter.headings),
            body=body,
        )

        html_path = PDF_DIR / f"{source.stem}.html"
        html_path.write_text(page, encoding="utf-8")

        if browser is None:
            continue
        pdf_path = PDF_DIR / f"{source.stem}.pdf"
        if print_pdf(browser, html_path, pdf_path):
            print(f"  {pdf_path.name}  ({pdf_path.stat().st_size // 1024} KiB)")
        else:
            failures += 1
        if not arguments.keep_html:
            html_path.unlink(missing_ok=True)

    if renderer.rendered:
        print(f"diagramas dibujados en esta ejecución: {renderer.rendered}")
    if failures:
        print(f"documentos sin PDF: {failures}", file=sys.stderr)
        return 1
    print("listo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
