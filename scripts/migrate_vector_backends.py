"""Reuse a ready Chroma embedding set to activate Qdrant and FAISS.

The expensive semantic model is not called again. Stored normalized vectors,
documents and metadata are copied into each selected backend and every target
receives its own compatibility manifest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config_store  # noqa: E402,F401 - loads project .env
from vector_management import migrate_from_chroma  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targets",
        nargs="*",
        default=["qdrant", "faiss"],
        help="Target backends: qdrant and/or faiss.",
    )
    parser.add_argument(
        "--status-output",
        type=Path,
        help="Optional JSON file that receives the final result.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=128,
        help="Insert batch size for target stores (default: 128).",
    )
    args = parser.parse_args()
    targets = list(dict.fromkeys(item.strip().lower() for item in args.targets))
    invalid = [item for item in targets if item not in {"qdrant", "faiss"}]
    if invalid:
        parser.error(f"Unsupported target backend(s): {', '.join(invalid)}")

    payload = migrate_from_chroma(
        targets,
        batch_size=max(1, args.batch_size),
    )
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    print(text, flush=True)
    if args.status_output:
        args.status_output.parent.mkdir(parents=True, exist_ok=True)
        args.status_output.write_text(text, encoding="utf-8")
    return 0 if payload["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
