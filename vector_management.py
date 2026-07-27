"""Operational helpers for inspecting and activating vector backends."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from mitre_rag import AttackSTIXConverter, RAGConfig
from vector_backends import EmbeddingEngine, create_vector_store

SUPPORTED_BACKENDS = ("chroma", "qdrant", "faiss")


def backend_statuses(active_rag: Any | None = None) -> dict[str, Any]:
    base = RAGConfig.from_env()
    source_hash = AttackSTIXConverter(base.stix_path).source_hash()
    statuses: dict[str, Any] = {}
    for backend in SUPPORTED_BACKENDS:
        store = None
        try:
            if (
                active_rag is not None
                and backend == base.vector_backend
                and getattr(active_rag.config, "vector_backend", None) == backend
            ):
                statuses[backend] = {
                    "available": True,
                    **active_rag.status(),
                }
                continue
            config = replace(base, vector_backend=backend)
            store = create_vector_store(
                config,
                EmbeddingEngine(config),
                config.index_path,
                expected_source_hash=source_hash,
            )
            statuses[backend] = {"available": True, **store.status()}
        except Exception as exc:
            statuses[backend] = {
                "available": False,
                "ready": False,
                "backend": backend,
                "error": str(exc),
            }
        finally:
            close = getattr(store, "close", None)
            if callable(close):
                close()
    return {
        "selected": base.vector_backend,
        "embedding_provider": base.embedding_provider,
        "embedding_model": base.embedding_model,
        "backends": statuses,
    }


def migrate_from_chroma(
    targets: Iterable[str] = ("qdrant", "faiss"),
    *,
    batch_size: int = 128,
) -> dict[str, Any]:
    requested = list(
        dict.fromkeys(str(item).strip().lower() for item in targets if str(item).strip())
    )
    invalid = [item for item in requested if item not in {"qdrant", "faiss"}]
    if invalid:
        raise ValueError(
            "Backend đích không hỗ trợ: "
            f"{', '.join(invalid)}. Chọn qdrant và/hoặc faiss."
        )
    if not requested:
        raise ValueError("Cần ít nhất một backend đích: qdrant hoặc faiss.")

    base = RAGConfig.from_env()
    source_hash = AttackSTIXConverter(base.stix_path).source_hash()
    source_config = replace(
        base,
        vector_backend="chroma",
        embedding_batch_size=max(1, int(batch_size)),
    )
    source_embedding = EmbeddingEngine(source_config)
    source_store = create_vector_store(
        source_config,
        source_embedding,
        source_config.index_path,
        expected_source_hash=source_hash,
    )
    documents, vectors, exported_hash = source_store.export_precomputed()

    results: dict[str, Any] = {}
    for backend in requested:
        target_store = None
        try:
            target_config = replace(source_config, vector_backend=backend)
            target_store = create_vector_store(
                target_config,
                EmbeddingEngine(target_config),
                target_config.index_path,
                expected_source_hash=exported_hash,
            )
            results[backend] = {
                "ok": True,
                "status": target_store.rebuild_precomputed(
                    documents, vectors, exported_hash
                ),
            }
        except Exception as exc:
            results[backend] = {"ok": False, "error": str(exc)}
        finally:
            close = getattr(target_store, "close", None)
            if callable(close):
                close()

    return {
        "ok": all(item["ok"] for item in results.values()),
        "source": {
            "backend": "chroma",
            "documents": len(documents),
            "dimension": len(vectors[0]) if vectors else 0,
            "source_hash": exported_hash,
            "embedding": source_embedding.identity,
        },
        "targets": results,
    }
