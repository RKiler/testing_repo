#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

import asyncpg
import yaml


def load_config() -> dict:
    config_path = Path("/app/config.yaml")
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    data["database"]["password"] = os.getenv("RECON_DB_PASSWORD", data["database"]["password"])
    return data


async def export_view(conn: asyncpg.Connection, view_name: str, output_path: Path) -> None:
    rows = await conn.fetch(f"SELECT review_item FROM {view_name}")
    payload = [dict(row["review_item"]) for row in rows]
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Export AI review queues to JSON files.")
    parser.add_argument("--output-dir", default="/app/exports", help="Directory to write JSON exports into.")
    args = parser.parse_args()

    config = load_config()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    conn = await asyncpg.connect(
        host=config["database"]["host"],
        port=config["database"]["port"],
        database=config["database"]["name"],
        user=config["database"]["user"],
        password=config["database"]["password"],
    )
    try:
        await export_view(conn, "ai_review_endpoint_queue", output_dir / "endpoint_review_queue.json")
        await export_view(conn, "ai_review_js_queue", output_dir / "js_review_queue.json")
        await export_view(conn, "ai_review_findings_queue", output_dir / "findings_review_queue.json")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
