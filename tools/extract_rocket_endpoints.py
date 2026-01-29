"""Extract Rocket endpoints from the legacy Vaultwarden-style API.

BeaconWarden is migrating from a Rocket/Diesel/Vaultwarden-style server implementation into a
Cloudflare Workers-only deployment.

This script scans `src/api/**/*.rs` for Rocket route attributes like:

- `#[get("/path")]`
- `#[post("/path", data = "<data>")]`

and prints a Markdown inventory grouped by source file.

This inventory is intended to be used as a **parity checklist** for the Workers routing map.

Usage:

- Print to stdout:
  python tools/extract_rocket_endpoints.py

- Write to a file:
  python tools/extract_rocket_endpoints.py --out docs/Vaultwarden_API_Endpoints_Extracted.md
"""

from __future__ import annotations

import argparse
import pathlib
import re
from collections import defaultdict


ROUTE_RE = re.compile(
    r"^\s*#\[(get|post|put|delete|patch|head|options)\(\"([^\"]+)\"",
    re.IGNORECASE,
)


def extract(repo_root: pathlib.Path) -> list[tuple[str, str, str]]:
    api_root = repo_root / "src" / "api"
    rows: list[tuple[str, str, str]] = []
    for p in api_root.rglob("*.rs"):
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = ROUTE_RE.search(line)
            if not m:
                continue
            method = m.group(1).upper()
            path = m.group(2)
            rows.append((p.relative_to(repo_root).as_posix(), method, path))
    rows.sort()
    return rows


def to_markdown(rows: list[tuple[str, str, str]]) -> str:
    by_file: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for file, method, path in rows:
        by_file[file].append((method, path))

    md: list[str] = []
    md.append("# Vaultwarden API endpoint inventory (extracted)")
    md.append("")
    md.append(
        "This file is auto-extracted from the legacy Rocket API under `src/api/**` in this repository."
    )
    md.append(
        "It represents the **target** Vaultwarden-compatible surface area that the Workers implementation should eventually cover."
    )
    md.append("")
    md.append("> Note: some endpoints may be admin-only, optional, or intentionally dropped (e.g. websocket notifications).")
    md.append("")

    for file in sorted(by_file.keys()):
        md.append(f"## `{file}`")
        md.append("")
        for method, path in by_file[file]:
            md.append(f"- `{method} {path}`")
        md.append("")

    md.append(f"---\n\nTotal endpoints: **{len(rows)}**")
    md.append("")
    return "\n".join(md)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        type=str,
        default="",
        help="Optional output Markdown path (e.g. docs/Vaultwarden_API_Endpoints_Extracted.md)",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    rows = extract(repo_root)
    md = to_markdown(rows)

    if args.out:
        out_path = (repo_root / args.out).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
    else:
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
