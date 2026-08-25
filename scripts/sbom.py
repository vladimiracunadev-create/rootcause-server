#!/usr/bin/env python3
"""Generate a CycloneDX software bill of materials from `cargo metadata`.

Written in-repo on purpose: a security product that pulls a third-party action
into its supply chain in order to *describe* its supply chain has traded the
problem for a bigger one. Everything here is `cargo metadata` plus the standard
library.

Usage:
    python3 scripts/sbom.py --output sbom.cdx.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def cargo_metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features", "--locked"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise SystemExit("cargo metadata failed")
    return json.loads(result.stdout)


def purl(name: str, version: str) -> str:
    return f"pkg:cargo/{name}@{version}"


def component(package: dict, is_root: bool) -> dict:
    entry: dict = {
        "type": "application" if is_root else "library",
        "bom-ref": purl(package["name"], package["version"]),
        "name": package["name"],
        "version": package["version"],
        "purl": purl(package["name"], package["version"]),
    }
    if package.get("description"):
        entry["description"] = package["description"].strip()
    if package.get("license"):
        entry["licenses"] = [
            {"license": {"id": part.strip()}}
            for part in package["license"].replace(" OR ", "/").split("/")
            if part.strip()
        ]
    if package.get("repository"):
        entry["externalReferences"] = [{"type": "vcs", "url": package["repository"]}]
    return entry


def build(metadata: dict, timestamp: str) -> dict:
    workspace = set(metadata.get("workspace_members", []))
    packages = sorted(metadata.get("packages", []), key=lambda item: (item["name"], item["version"]))

    components = [
        component(package, package["id"] in workspace)
        for package in packages
        # The workspace crates are the subject of the BOM, not dependencies of it.
        if package["id"] not in workspace
    ]
    applications = [component(package, True) for package in packages if package["id"] in workspace]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "RootCause", "name": "scripts/sbom.py", "version": "1.0.0"}],
            "component": {
                "type": "application",
                "bom-ref": "rootcause-server",
                "name": "rootcause-server",
                "version": next(
                    (item["version"] for item in applications if item["name"] == "rootcause-server"),
                    "0.0.0",
                ),
            },
        },
        "components": applications + components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="sbom.cdx.json", help="destination file")
    arguments = parser.parse_args()

    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    document = build(cargo_metadata(), timestamp)
    destination = Path(arguments.output)
    destination.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"SBOM escrito en {destination} con {len(document['components'])} componentes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
