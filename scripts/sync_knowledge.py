"""Synchronize and index configured cybersecurity knowledge sources."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

import config_store  # noqa: E402,F401 - loads the project .env
from knowledge_base import get_knowledge_base  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source",
        nargs="?",
        default="all",
        help="all, sigma, yara, threat_intelligence, nist_cis, playbooks, ...",
    )
    parser.add_argument(
        "--status-output",
        type=Path,
        help="Optional JSON file that receives the final result.",
    )
    args = parser.parse_args()
    result = get_knowledge_base(refresh=True).sync(args.source)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.status_output:
        args.status_output.parent.mkdir(parents=True, exist_ok=True)
        args.status_output.write_text(text, encoding="utf-8")
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
