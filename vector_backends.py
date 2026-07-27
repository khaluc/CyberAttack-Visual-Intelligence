"""Semantic embedding providers and persistent vector backends for ATT&CK RAG.

The module deliberately keeps embedding generation outside of the vector stores.
That makes Chroma, Qdrant and FAISS use exactly the same vectors and lets tests
inject a small deterministic embedder without downloading a production model.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import numpy as np

from embedding_checkpoint import ResumableEmbeddingCheckpoint

INDEX_SCHEMA_VERSION = "semantic-v2"
DEFAULT_VECTOR_PATH = Path(__file__).resolve().parent / "data" / "vector_db"
LOGGER = logging.getLogger(__name__)


class EmbeddingEngine:
    """Normalized semantic embeddings from SentenceTransformers or an API."""

    def __init__(self, config, model_factory=None):
        self.config = config
        self._model = None
        self._model_factory = model_factory
        configured_dimension = int(getattr(config, "embedding_dimension", 0) or 0)
        self._dimension = configured_dimension or None

    @property
    def provider(self) -> str:
        value = str(self.config.embedding_provider).strip().lower().replace("_", "-")
        return "sentence-transformers" if value == "local" else value

    @property
    def model_name(self) -> str:
        return str(self.config.embedding_model).strip()

    @property
    def identity(self) -> str:
        revision = str(getattr(self.config, "embedding_revision", "") or "default")
        dimension = int(getattr(self.config, "embedding_dimension", 0) or 0)
        dimension_tag = f":d{dimension}" if dimension else ""
        max_length = int(getattr(self.config, "embedding_max_seq_length", 512) or 512)
        sequence_tag = f":seq{max_length}"
        provider = self.provider
        if provider in {"openai", "compatible", "dashscope"}:
            parsed = urlparse(str(self.config.embedding_base_url))
            endpoint = (
                f"{parsed.netloc}{parsed.path.rstrip('/')}" if parsed.netloc else "local"
            )
            return (
                f"{provider}:{endpoint}:{self.model_name}@{revision}"
                f"{dimension_tag}:normalized"
            )
        return (
            f"{provider}:{self.model_name}@{revision}{dimension_tag}"
            f"{sequence_tag}:normalized"
        )

    @property
    def dimension(self) -> int | None:
        if self._dimension:
            return int(self._dimension)
        if self._model is not None and hasattr(self._model, "get_sentence_embedding_dimension"):
            value = self._model.get_sentence_embedding_dimension()
            self._dimension = int(value) if value else None
        return self._dimension

    def encode(self, texts: list[str], purpose: str = "document") -> list[list[float]]:
        """Backward-compatible encoder; prefer encode_documents/encode_query."""
        if purpose == "query":
            return self.encode_query(texts[0] if texts else "")
        return self.encode_documents(texts)

    def encode_documents(self, texts: list[str]) -> list[list[float]]:
        return self._encode(texts, purpose="document")

    def encode_query(self, text: str) -> list[list[float]]:
        return self._encode([text], purpose="query")

    def _encode(self, texts: list[str], purpose: str) -> list[list[float]]:
        if not texts:
            return []
        provider = self.provider
        prepared = self._prepare_texts(texts, purpose)
        if provider in {"sentence-transformers", "sentence_transformers", "local"}:
            vectors = self._sentence_transformer_embeddings(prepared, purpose)
        elif provider in {"openai", "compatible", "dashscope"}:
            vectors = self._remote_embeddings(prepared)
        elif provider == "hashing":
            raise ValueError(
                "EMBEDDING_PROVIDER=hashing đã bị loại khỏi runtime. "
                "Hãy dùng sentence-transformers, openai, compatible hoặc dashscope."
            )
        else:
            raise ValueError(f"Embedding provider không hỗ trợ: {provider}")
        array = _as_normalized_array(vectors)
        self._dimension = int(array.shape[1])
        return array.tolist()

    def _prepare_texts(self, texts: list[str], purpose: str) -> list[str]:
        model = self.model_name.lower()
        # E5 models are trained with asymmetric query/passage prefixes.
        if "e5" in model:
            prefix = "query: " if purpose == "query" else "passage: "
            return [value if value.lower().startswith(prefix) else prefix + value for value in texts]
        return texts

    def _load_model(self):
        if self._model is not None:
            return self._model
        if self._model_factory:
            self._model = self._model_factory(self.model_name)
            self._apply_max_sequence_length()
            return self._model
        # Embedding inference only needs PyTorch; avoid importing TensorFlow/Flax
        # through Transformers in a Flask worker.
        os.environ.setdefault("USE_TF", "0")
        os.environ.setdefault("USE_FLAX", "0")
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "Thiếu sentence-transformers. Chạy: pip install sentence-transformers"
            ) from exc
        kwargs = {}
        device = str(getattr(self.config, "embedding_device", "") or "").strip()
        revision = str(getattr(self.config, "embedding_revision", "") or "").strip()
        if device:
            kwargs["device"] = device
        if revision:
            kwargs["revision"] = revision
        self._model = SentenceTransformer(self.model_name, **kwargs)
        self._apply_max_sequence_length()
        return self._model

    def _apply_max_sequence_length(self):
        max_length = int(getattr(self.config, "embedding_max_seq_length", 512) or 512)
        if hasattr(self._model, "max_seq_length"):
            self._model.max_seq_length = min(int(self._model.max_seq_length), max_length)

    def _sentence_transformer_embeddings(self, texts: list[str], purpose: str):
        model = self._load_model()
        kwargs = {
            "normalize_embeddings": True,
            "show_progress_bar": False,
            "batch_size": max(1, int(getattr(self.config, "embedding_batch_size", 8))),
        }
        # New SentenceTransformers versions expose asymmetric methods. They
        # preserve any model-specific prompt configuration when available.
        method_name = "encode_query" if purpose == "query" else "encode_document"
        method = getattr(model, method_name, None)
        if callable(method):
            return method(texts, **kwargs)
        return model.encode(texts, **kwargs)

    def _remote_embeddings(self, texts: list[str]):
        import time
        import urllib.error
        import urllib.request

        api_key = str(self.config.embedding_api_key or "").strip()
        if not api_key:
            raise RuntimeError("Thiếu EMBEDDING_API_KEY cho embedding API.")
        payload = {"model": self.model_name, "input": texts}
        requested_dimension = int(getattr(self.config, "embedding_dimension", 0) or 0)
        if requested_dimension:
            payload["dimensions"] = requested_dimension
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        request = urllib.request.Request(
            f"{str(self.config.embedding_base_url).rstrip('/')}/embeddings",
            body,
            method="POST",
            headers=headers,
        )
        data = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=180) as response:
                    data = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if not retryable or attempt == 2:
                    raise RuntimeError(
                        f"Embedding API HTTP {exc.code}: {detail[:500]}"
                    ) from exc
                time.sleep(2**attempt)
            except urllib.error.URLError as exc:
                if attempt == 2:
                    raise RuntimeError(f"Không kết nối được embedding API: {exc}") from exc
                time.sleep(2**attempt)
        if data is None:
            raise RuntimeError("Embedding API không trả về dữ liệu.")
        if not isinstance(data.get("data"), list):
            raise RuntimeError("Embedding API trả về payload không hợp lệ.")
        ordered = sorted(data["data"], key=lambda item: item.get("index", 0))
        if len(ordered) != len(texts):
            raise RuntimeError(
                f"Embedding API trả về {len(ordered)}/{len(texts)} vectors."
            )
        return [item["embedding"] for item in ordered]


class AttackVectorStore(ABC):
    backend_name = "abstract"

    def __init__(self, config, embedding, path=None, expected_source_hash=""):
        self.config = config
        self.embedding = embedding
        self.root = Path(path or DEFAULT_VECTOR_PATH) / self.backend_name
        self.root.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", config.collection_name)
        self.manifest_path = self.root / f"{safe_name}.manifest.json"
        self.expected_source_hash = expected_source_hash

    @abstractmethod
    def rebuild(self, documents, source_hash, progress_callback=None):
        raise NotImplementedError

    @abstractmethod
    def rebuild_precomputed(self, documents, vectors, source_hash):
        """Replace the backend using already-computed normalized vectors."""
        raise NotImplementedError

    def export_precomputed(self):
        """Return ``(documents, vectors, source_hash)`` when supported."""
        raise RuntimeError(
            f"Backend {self.backend_name} không hỗ trợ export vector trực tiếp."
        )

    @abstractmethod
    def _search_chunks(self, query: str, limit: int) -> list[tuple[dict, float]]:
        raise NotImplementedError

    @abstractmethod
    def _documents_for_technique(self, technique_id: str) -> list[dict]:
        raise NotImplementedError

    @abstractmethod
    def _count(self) -> int:
        raise NotImplementedError

    def search(self, query, top_k):
        top_k = max(1, int(top_k))
        status = self.status()
        if not status["ready"]:
            reason = status.get("incompatibility_reason") or "index chưa được xây dựng"
            raise RuntimeError(f"MITRE vector index chưa sẵn sàng: {reason}.")
        rows = self._search_chunks(query, min(max(top_k * 4, top_k), status["chunks"]))
        return self._group_results(rows, top_k)

    def _group_results(self, rows, top_k):
        grouped = {}
        for document, raw_score in rows:
            metadata = document["metadata"]
            technique_id = metadata["technique_id"]
            score = max(0.0, min(1.0, float(raw_score)))
            item = grouped.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "technique_name": metadata["technique_name"],
                    "tactics": metadata["tactics"],
                    "score": score,
                    "description": "",
                    "detection": [],
                    "mitigation": [],
                    "procedure": [],
                },
            )
            item["score"] = max(item["score"], score)
            _append_document_detail(item, document)
        ranked = sorted(grouped.values(), key=lambda item: item["score"], reverse=True)[:top_k]
        for item in ranked:
            for document in self._documents_for_technique(item["technique_id"]):
                _append_document_detail(item, document)
        return ranked

    def status(self):
        count = self._count()
        manifest = self._read_manifest()
        reasons = []
        if not manifest:
            reasons.append("missing_manifest")
        else:
            expected = {
                "schema_version": INDEX_SCHEMA_VERSION,
                "backend": self.backend_name,
                "collection": self.config.collection_name,
                "embedding": self.embedding.identity,
            }
            if self.expected_source_hash:
                expected["source_hash"] = self.expected_source_hash
            for key, value in expected.items():
                if manifest.get(key) != value:
                    reasons.append(f"{key}_changed")
            if int(manifest.get("chunks", count) or 0) != count:
                reasons.append("chunk_count_changed")
        if count <= 0:
            reasons.append("empty_index")
        compatible = not reasons
        return {
            "ready": compatible,
            "indexed": count > 0,
            "compatible": compatible,
            "requires_rebuild": not compatible,
            "incompatibility_reason": ", ".join(reasons),
            "backend": self.backend_name,
            "collection": self.config.collection_name,
            "chunks": count,
            "source_hash": manifest.get("source_hash", ""),
            "expected_source_hash": self.expected_source_hash,
            "embedding": manifest.get("embedding", self.embedding.identity),
            "embedding_provider": manifest.get(
                "embedding_provider", self.embedding.provider
            ),
            "embedding_model": manifest.get(
                "embedding_model", self.embedding.model_name
            ),
            "configured_embedding": self.embedding.identity,
            "configured_embedding_provider": self.embedding.provider,
            "configured_embedding_model": self.embedding.model_name,
            "embedding_device": str(
                getattr(self.config, "embedding_device", "") or "auto"
            ),
            "indexed_embedding": manifest.get("embedding", ""),
            "indexed_embedding_provider": manifest.get("embedding_provider", ""),
            "indexed_embedding_model": manifest.get("embedding_model", ""),
            "dimension": int(manifest.get("dimension", self.embedding.dimension or 0)),
            "distance_metric": "cosine",
            "normalized": True,
            "built_at": manifest.get("built_at", ""),
            "schema_version": manifest.get("schema_version", ""),
            "available_backends": vector_backend_capabilities(),
        }

    def _write_manifest(self, source_hash: str, dimension: int, chunks: int):
        manifest = {
            "schema_version": INDEX_SCHEMA_VERSION,
            "backend": self.backend_name,
            "collection": self.config.collection_name,
            "source_hash": source_hash,
            "embedding": self.embedding.identity,
            "embedding_provider": self.embedding.provider,
            "embedding_model": self.embedding.model_name,
            "dimension": int(dimension),
            "chunks": int(chunks),
            "distance_metric": "cosine",
            "normalized": True,
            "built_at": datetime.now(timezone.utc).isoformat(),
        }
        temporary = self.manifest_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.manifest_path)

    def _read_manifest(self):
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _embed_documents(self, documents, source_hash, progress_callback=None):
        documents = list(documents)
        checkpoint = ResumableEmbeddingCheckpoint(
            root=self.root.parent / ".embedding_checkpoints",
            documents=documents,
            source_hash=source_hash,
            embedding=self.embedding,
            batch_size=max(1, int(self.config.embedding_batch_size)),
        )
        return checkpoint.encode(progress_callback=progress_callback)


class ChromaAttackStore(AttackVectorStore):
    backend_name = "chroma"

    def __init__(self, config, embedding, path=None, expected_source_hash=""):
        try:
            import chromadb
        except ImportError as exc:
            raise RuntimeError("Thiếu ChromaDB. Chạy: pip install chromadb") from exc
        super().__init__(config, embedding, path, expected_source_hash)
        self.client = chromadb.PersistentClient(path=str(self.root))
        self.collection = self.client.get_or_create_collection(
            name=config.collection_name, metadata={"hnsw:space": "cosine"}
        )

    def rebuild(self, documents, source_hash):
        documents = list(documents)
        vectors = []
        batches = list(_batches(documents, max(1, int(self.config.embedding_batch_size))))
        for batch_number, batch in enumerate(batches, start=1):
            vectors.extend(
                self.embedding.encode_documents([doc["text"] for doc in batch])
            )
            _log_embedding_progress(self.backend_name, batch_number, len(batches))
        if not vectors:
            raise ValueError("Không có ATT&CK document để tạo Chroma index.")
        return self.rebuild_precomputed(documents, vectors, source_hash)

    def rebuild_precomputed(self, documents, vectors, source_hash):
        documents = list(documents)
        matrix = _validate_precomputed(documents, vectors)
        dimension = int(matrix.shape[1])
        # Embeddings are prepared before touching the live collection. A model
        # download/API failure therefore cannot erase a usable previous index.
        try:
            self.client.delete_collection(self.config.collection_name)
        except Exception:
            pass
        self.collection = self.client.create_collection(
            name=self.config.collection_name,
            metadata={
                "hnsw:space": "cosine",
                "source_hash": source_hash,
                "embedding": self.embedding.identity,
                "schema_version": INDEX_SCHEMA_VERSION,
            },
        )
        batch_size = max(1, int(self.config.embedding_batch_size))
        for start in range(0, len(documents), batch_size):
            batch = documents[start : start + batch_size]
            batch_vectors = matrix[start : start + batch_size].tolist()
            texts = [doc["text"] for doc in batch]
            self.collection.add(
                ids=[doc["id"] for doc in batch],
                documents=texts,
                metadatas=[doc["metadata"] for doc in batch],
                embeddings=batch_vectors,
            )
        self._write_manifest(source_hash, dimension, len(documents))
        return self.status()

    def export_precomputed(self):
        status = self.status()
        if not status["ready"]:
            raise RuntimeError(
                "Chroma source index chưa sẵn sàng để migrate: "
                f"{status['incompatibility_reason']}."
            )
        result = self.collection.get(
            include=["documents", "metadatas", "embeddings"]
        )
        raw_vectors = result.get("embeddings")
        if raw_vectors is None:
            raise RuntimeError("Chroma không trả về embedding đã lưu.")
        ids = list(result.get("ids") or [])
        texts = list(result.get("documents") or [])
        metadatas = list(result.get("metadatas") or [])
        matrix = _as_normalized_array(raw_vectors)
        if not (len(ids) == len(texts) == len(metadatas) == matrix.shape[0]):
            raise RuntimeError("Chroma export không đồng bộ id/document/embedding.")
        documents = [
            {"id": item_id, "text": text, "metadata": metadata}
            for item_id, text, metadata in zip(ids, texts, metadatas)
        ]
        return documents, matrix.tolist(), status["source_hash"]

    def _read_manifest(self):
        manifest = super()._read_manifest()
        if manifest:
            return manifest
        metadata = self.collection.metadata or {}
        identity = str(metadata.get("embedding", ""))
        if not identity and not metadata.get("source_hash"):
            return {}
        provider, _, model = identity.partition(":")
        dimension = 0
        if self.collection.count():
            try:
                embeddings = self.collection.peek(limit=1).get("embeddings")
                if embeddings is not None and len(embeddings):
                    dimension = len(embeddings[0])
            except Exception:
                pass
        return {
            "schema_version": metadata.get("schema_version", "legacy"),
            "backend": "chroma",
            "collection": self.config.collection_name,
            "source_hash": metadata.get("source_hash", ""),
            "embedding": identity,
            "embedding_provider": provider,
            "embedding_model": model,
            "dimension": dimension,
            "chunks": self.collection.count(),
        }

    def _search_chunks(self, query, limit):
        result = self.collection.query(
            query_embeddings=self.embedding.encode_query(query),
            n_results=limit,
            include=["documents", "metadatas", "distances"],
        )
        rows = []
        for text, metadata, distance in zip(
            result["documents"][0], result["metadatas"][0], result["distances"][0]
        ):
            rows.append(({"text": text, "metadata": metadata}, 1.0 - float(distance)))
        return rows

    def _documents_for_technique(self, technique_id):
        result = self.collection.get(
            where={"technique_id": technique_id}, include=["documents", "metadatas"]
        )
        return [
            {"text": text, "metadata": metadata}
            for text, metadata in zip(result["documents"], result["metadatas"])
        ]

    def _count(self):
        try:
            return int(self.collection.count())
        except Exception:
            # Another worker may have atomically replaced the named collection.
            try:
                self.collection = self.client.get_collection(self.config.collection_name)
                return int(self.collection.count())
            except Exception:
                return 0


class QdrantAttackStore(AttackVectorStore):
    backend_name = "qdrant"

    def __init__(self, config, embedding, path=None, expected_source_hash=""):
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:
            raise RuntimeError("Thiếu Qdrant client. Chạy: pip install qdrant-client") from exc
        super().__init__(config, embedding, path, expected_source_hash)
        qdrant_url = str(getattr(config, "qdrant_url", "") or "").strip()
        if qdrant_url:
            self.client = QdrantClient(
                url=qdrant_url,
                api_key=str(getattr(config, "qdrant_api_key", "") or "") or None,
            )
            self.mode = "server"
        else:
            self.client = QdrantClient(path=str(self.root))
            self.mode = "local"

    def rebuild(self, documents, source_hash):
        documents = list(documents)
        if not documents:
            raise ValueError("Không có ATT&CK document để tạo Qdrant index.")
        vectors = []
        batches = list(_batches(documents, max(1, int(self.config.embedding_batch_size))))
        for batch_number, batch in enumerate(batches, start=1):
            vectors.extend(
                self.embedding.encode_documents([doc["text"] for doc in batch])
            )
            _log_embedding_progress(self.backend_name, batch_number, len(batches))
        return self.rebuild_precomputed(documents, vectors, source_hash)

    def rebuild_precomputed(self, documents, vectors, source_hash):
        from qdrant_client import models

        documents = list(documents)
        matrix = _validate_precomputed(documents, vectors)
        dimension = int(matrix.shape[1])
        if self.client.collection_exists(self.config.collection_name):
            self.client.delete_collection(self.config.collection_name)
        self.client.create_collection(
            collection_name=self.config.collection_name,
            vectors_config=models.VectorParams(size=dimension, distance=models.Distance.COSINE),
        )
        batch_size = max(1, int(self.config.embedding_batch_size))
        for start in range(0, len(documents), batch_size):
            batch = documents[start : start + batch_size]
            batch_vectors = matrix[start : start + batch_size]
            points = []
            for document, vector in zip(batch, batch_vectors):
                points.append(
                    models.PointStruct(
                        id=str(uuid.uuid5(uuid.NAMESPACE_URL, document["id"])),
                        vector=vector.tolist(),
                        payload={
                            "document_id": document["id"],
                            "text": document["text"],
                            "metadata": document["metadata"],
                        },
                    )
                )
            self.client.upsert(
                collection_name=self.config.collection_name, points=points, wait=True
            )
        self._write_manifest(source_hash, dimension, len(documents))
        return self.status()

    def status(self):
        status = super().status()
        status["qdrant_mode"] = self.mode
        if self.mode == "server":
            parsed = urlparse(str(self.config.qdrant_url))
            status["qdrant_endpoint"] = f"{parsed.scheme}://{parsed.netloc}"
        return status

    def _search_chunks(self, query, limit):
        vector = self.embedding.encode_query(query)[0]
        if hasattr(self.client, "query_points"):
            hits = self.client.query_points(
                collection_name=self.config.collection_name,
                query=vector,
                limit=limit,
                with_payload=True,
            ).points
        else:
            hits = self.client.search(
                collection_name=self.config.collection_name,
                query_vector=vector,
                limit=limit,
                with_payload=True,
            )
        return [
            (
                {"text": hit.payload["text"], "metadata": hit.payload["metadata"]},
                float(hit.score),
            )
            for hit in hits
        ]

    def _documents_for_technique(self, technique_id):
        from qdrant_client import models

        records, _ = self.client.scroll(
            collection_name=self.config.collection_name,
            scroll_filter=models.Filter(
                must=[
                    models.FieldCondition(
                        key="metadata.technique_id",
                        match=models.MatchValue(value=technique_id),
                    )
                ]
            ),
            limit=100,
            with_payload=True,
            with_vectors=False,
        )
        return [
            {"text": record.payload["text"], "metadata": record.payload["metadata"]}
            for record in records
        ]

    def _count(self):
        if not self.client.collection_exists(self.config.collection_name):
            return 0
        info = self.client.get_collection(self.config.collection_name)
        return int(info.points_count or 0)

    def close(self):
        close = getattr(self.client, "close", None)
        if callable(close):
            close()


class FAISSAttackStore(AttackVectorStore):
    backend_name = "faiss"

    def __init__(self, config, embedding, path=None, expected_source_hash=""):
        try:
            import faiss
        except ImportError as exc:
            raise RuntimeError(
                "VECTOR_DB=faiss cần package faiss-cpu. Chạy: pip install faiss-cpu"
            ) from exc
        super().__init__(config, embedding, path, expected_source_hash)
        self.faiss = faiss
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", config.collection_name)
        self.index_path = self.root / f"{safe_name}.index"
        self.documents_path = self.root / f"{safe_name}.documents.json"
        self._index = None
        self._documents = None

    def rebuild(self, documents, source_hash):
        documents = list(documents)
        if not documents:
            raise ValueError("Không có ATT&CK document để tạo FAISS index.")
        vectors = []
        batches = list(_batches(documents, max(1, int(self.config.embedding_batch_size))))
        for batch_number, batch in enumerate(batches, start=1):
            vectors.extend(self.embedding.encode_documents([doc["text"] for doc in batch]))
            _log_embedding_progress(self.backend_name, batch_number, len(batches))
        return self.rebuild_precomputed(documents, vectors, source_hash)

    def rebuild_precomputed(self, documents, vectors, source_hash):
        documents = list(documents)
        matrix = _validate_precomputed(documents, vectors)
        index = self.faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        temporary_index = self.index_path.with_suffix(self.index_path.suffix + ".tmp")
        temporary_documents = self.documents_path.with_suffix(
            self.documents_path.suffix + ".tmp"
        )
        self.faiss.write_index(index, str(temporary_index))
        temporary_documents.write_text(
            json.dumps(documents, ensure_ascii=False), encoding="utf-8"
        )
        temporary_index.replace(self.index_path)
        temporary_documents.replace(self.documents_path)
        self._index, self._documents = index, documents
        self._write_manifest(source_hash, matrix.shape[1], len(documents))
        return self.status()

    def _load(self):
        if self._index is None and self.index_path.exists():
            self._index = self.faiss.read_index(str(self.index_path))
        if self._documents is None and self.documents_path.exists():
            self._documents = json.loads(self.documents_path.read_text(encoding="utf-8"))

    def _search_chunks(self, query, limit):
        self._load()
        vector = _as_normalized_array(self.embedding.encode_query(query))
        scores, indexes = self._index.search(vector, limit)
        rows = []
        for index, score in zip(indexes[0], scores[0]):
            if index >= 0:
                rows.append((self._documents[int(index)], float(score)))
        return rows

    def _documents_for_technique(self, technique_id):
        self._load()
        return [
            document
            for document in (self._documents or [])
            if document["metadata"]["technique_id"] == technique_id
        ]

    def _count(self):
        if not self.index_path.exists() or not self.documents_path.exists():
            return 0
        try:
            self._load()
        except (OSError, ValueError, json.JSONDecodeError):
            return 0
        if self._index is None or self._documents is None:
            return 0
        if int(self._index.ntotal) != len(self._documents):
            return 0
        return int(self._index.ntotal)


def create_vector_store(config, embedding, path=None, expected_source_hash=""):
    backend = str(config.vector_backend).strip().lower()
    stores = {
        "chroma": ChromaAttackStore,
        "qdrant": QdrantAttackStore,
        "faiss": FAISSAttackStore,
    }
    try:
        store_class = stores[backend]
    except KeyError as exc:
        raise ValueError(
            f"VECTOR_DB không hỗ trợ: {backend}. Chọn chroma, qdrant hoặc faiss."
        ) from exc
    return store_class(config, embedding, path, expected_source_hash)


def vector_backend_capabilities():
    return {
        "chroma": importlib.util.find_spec("chromadb") is not None,
        "qdrant": importlib.util.find_spec("qdrant_client") is not None,
        "faiss": importlib.util.find_spec("faiss") is not None,
    }


def _append_document_detail(item, document):
    metadata = document["metadata"]
    content = document["text"].split("\n", 1)[-1]
    kind = metadata["document_type"]
    if kind == "technique" and not item["description"]:
        item["description"] = content
    elif kind == "detects" and content not in item["detection"]:
        item["detection"].append(content)
    elif kind == "mitigates" and content not in item["mitigation"]:
        item["mitigation"].append(content)
    elif kind == "uses" and content not in item["procedure"]:
        item["procedure"].append(content)


def _as_normalized_array(vectors) -> np.ndarray:
    array = np.asarray(vectors, dtype=np.float32)
    if array.ndim != 2 or array.shape[0] == 0 or array.shape[1] == 0:
        raise RuntimeError("Embedding provider trả về vector rỗng hoặc sai shape.")
    norms = np.linalg.norm(array, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return np.ascontiguousarray(array / norms, dtype=np.float32)


def _validate_precomputed(documents, vectors) -> np.ndarray:
    if not documents:
        raise ValueError("Không có ATT&CK document để tạo vector index.")
    matrix = _as_normalized_array(vectors)
    if matrix.shape[0] != len(documents):
        raise ValueError(
            "Số embedding không khớp số document: "
            f"{matrix.shape[0]} != {len(documents)}."
        )
    return matrix


def _batches(items: list, size: int) -> Iterable[list]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _log_embedding_progress(backend: str, current: int, total: int):
    if current == 1 or current == total or current % 25 == 0:
        LOGGER.info("Embedding ATT&CK for %s: batch %s/%s", backend, current, total)
