"""Verify semantic retrieval across configured vector backends."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config_store  # noqa: E402,F401 - loads project .env
from mitre_rag import AttackSTIXConverter, MITREAttackRAG, RAGConfig  # noqa: E402
from vector_backends import EmbeddingEngine  # noqa: E402


QUERIES = (
    ("credential theft input capture", "T1056"),
    ("send phishing email malicious attachment", "T1566"),
    ("PowerShell command execution", "T1059.001"),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "backends",
        nargs="*",
        default=["chroma", "qdrant", "faiss"],
        help="Backends to verify (default: all).",
    )
    args = parser.parse_args()
    requested = list(
        dict.fromkeys(item.strip().lower() for item in args.backends)
    )
    invalid = [
        item for item in requested if item not in {"chroma", "qdrant", "faiss"}
    ]
    if invalid:
        parser.error(f"Unsupported backend(s): {', '.join(invalid)}")

    base = RAGConfig.from_env()
    converter = AttackSTIXConverter(base.stix_path)
    # One model instance serves every backend; only query embeddings are
    # generated during verification.
    embedding = EmbeddingEngine(base)
    results = {}
    for backend in requested:
        rag = None
        try:
            config = replace(base, vector_backend=backend, auto_rebuild=False)
            rag = MITREAttackRAG(
                config=config,
                converter=converter,
                embedding=embedding,
            )
            status = rag.status()
            if not status["ready"]:
                raise RuntimeError(
                    status.get("incompatibility_reason") or "index not ready"
                )
            checks = []
            for query, expected_prefix in QUERIES:
                matches = rag.retrieve(query, top_k=5)
                ids = [item["technique_id"] for item in matches]
                checks.append(
                    {
                        "query": query,
                        "expected": expected_prefix,
                        "technique_ids": ids,
                        "passed": any(
                            technique_id == expected_prefix
                            or technique_id.startswith(expected_prefix + ".")
                            for technique_id in ids
                        ),
                    }
                )
            results[backend] = {
                "ok": all(item["passed"] for item in checks),
                "status": status,
                "checks": checks,
            }
        except Exception as exc:
            results[backend] = {"ok": False, "error": str(exc)}
        finally:
            close = getattr(getattr(rag, "store", None), "close", None)
            if callable(close):
                close()

    payload = {
        "ok": all(item["ok"] for item in results.values()),
        "embedding": embedding.identity,
        "backends": results,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
    return 0 if payload["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
