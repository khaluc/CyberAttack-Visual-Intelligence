"""Resumable, atomic document-embedding checkpoints.

The checkpoint is deliberately separate from every vector backend.  A failed
model download, API request, or interrupted CPU run therefore never modifies a
live Chroma/Qdrant/FAISS index.  Completed shards can also be reused when the
same source and embedding configuration are rebuilt for another backend.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import numpy as np

CHECKPOINT_SCHEMA_VERSION = "embedding-checkpoint-v1"
LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[dict], None]


class ResumableEmbeddingCheckpoint:
    """Encode documents into independently committed NumPy shards."""

    def __init__(
        self,
        *,
        root: str | Path,
        documents: list[dict],
        source_hash: str,
        embedding,
        batch_size: int,
    ):
        self.documents = list(documents)
        self.source_hash = str(source_hash)
        self.embedding = embedding
        self.batch_size = max(1, int(batch_size))
        self.document_hash = _documents_hash(self.documents)
        self.safe_identity = _safe_embedding_identity(embedding)
        self.key_payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "source_hash": self.source_hash,
            "document_hash": self.document_hash,
            "document_count": len(self.documents),
            "embedding": self.safe_identity,
            "embedding_provider": str(getattr(embedding, "provider", "")),
            "embedding_model": str(getattr(embedding, "model_name", "")),
            "batch_size": self.batch_size,
        }
        encoded_key = json.dumps(
            self.key_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.key = hashlib.sha256(encoded_key).hexdigest()
        self.root = Path(root)
        self.path = self.root / self.key
        self.metadata_path = self.path / "checkpoint.json"

    @property
    def total_batches(self) -> int:
        if not self.documents:
            return 0
        return math.ceil(len(self.documents) / self.batch_size)

    def encode(self, progress_callback: ProgressCallback | None = None) -> list[list[float]]:
        if not self.documents:
            raise ValueError("Không có document để tạo embedding checkpoint.")
        self.path.mkdir(parents=True, exist_ok=True)
        self._ensure_metadata()

        started = time.monotonic()
        resumed_documents = self._count_valid_documents()
        resumed = resumed_documents > 0
        dimension = self._known_dimension()
        completed_documents = 0
        newly_encoded = 0

        self._emit(
            progress_callback,
            state="running",
            completed_documents=resumed_documents,
            resumed_documents=resumed_documents,
            resumed=resumed,
            elapsed_seconds=0.0,
            eta_seconds=None,
        )

        for batch_number, start in enumerate(
            range(0, len(self.documents), self.batch_size), start=1
        ):
            end = min(start + self.batch_size, len(self.documents))
            expected_rows = end - start
            shard_path = self._shard_path(start, end)
            shard = self._load_valid_shard(shard_path, expected_rows, dimension)
            if shard is None:
                texts = [item["text"] for item in self.documents[start:end]]
                shard = _normalized_matrix(
                    self.embedding.encode_documents(texts), expected_rows
                )
                if dimension is not None and int(shard.shape[1]) != dimension:
                    raise RuntimeError(
                        "Embedding dimension changed during checkpoint build: "
                        f"{shard.shape[1]} != {dimension}."
                    )
                dimension = int(shard.shape[1])
                _atomic_save_npy(shard_path, shard)
                newly_encoded += expected_rows
            elif dimension is None:
                dimension = int(shard.shape[1])

            completed_documents = end
            elapsed = max(0.0, time.monotonic() - started)
            session_done = max(0, completed_documents - resumed_documents)
            remaining = max(0, len(self.documents) - completed_documents)
            eta = (
                elapsed * remaining / session_done
                if session_done > 0 and remaining > 0
                else 0.0 if remaining == 0 else None
            )
            self._emit(
                progress_callback,
                state="running" if remaining else "embedded",
                completed_documents=completed_documents,
                resumed_documents=resumed_documents,
                resumed=resumed,
                elapsed_seconds=elapsed,
                eta_seconds=eta,
                current_batch=batch_number,
            )
            _log_progress(
                batch_number=batch_number,
                total_batches=self.total_batches,
                completed_documents=completed_documents,
                total_documents=len(self.documents),
                elapsed_seconds=elapsed,
                eta_seconds=eta,
                resumed=resumed and newly_encoded == 0,
            )

        shards = []
        for start in range(0, len(self.documents), self.batch_size):
            end = min(start + self.batch_size, len(self.documents))
            shard = self._load_valid_shard(
                self._shard_path(start, end), end - start, dimension
            )
            if shard is None:
                raise RuntimeError(
                    f"Embedding checkpoint thiếu hoặc hỏng shard {start}:{end}."
                )
            shards.append(shard)
        matrix = np.ascontiguousarray(np.concatenate(shards, axis=0), dtype=np.float32)
        if matrix.shape[0] != len(self.documents):
            raise RuntimeError("Embedding checkpoint không khớp số document.")
        self._write_metadata(
            {
                **self.key_payload,
                "checkpoint_key": self.key,
                "dimension": int(matrix.shape[1]),
                "completed_documents": len(self.documents),
                "total_batches": self.total_batches,
                "state": "complete",
                "updated_at": _utc_now(),
            }
        )
        return matrix.tolist()

    def _ensure_metadata(self):
        existing = self._read_metadata()
        expected = {**self.key_payload, "checkpoint_key": self.key}
        if existing:
            mismatched = [
                key for key, value in expected.items() if existing.get(key) != value
            ]
            if mismatched:
                raise RuntimeError(
                    "Embedding checkpoint metadata không tương thích: "
                    + ", ".join(mismatched)
                )
            return
        self._write_metadata(
            {
                **expected,
                "dimension": 0,
                "completed_documents": 0,
                "total_batches": self.total_batches,
                "state": "running",
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
            }
        )

    def _write_metadata(self, payload: dict):
        _atomic_write_json(self.metadata_path, payload)

    def _read_metadata(self) -> dict:
        try:
            return json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _known_dimension(self) -> int | None:
        dimension = int(self._read_metadata().get("dimension", 0) or 0)
        if dimension:
            return dimension
        for start in range(0, len(self.documents), self.batch_size):
            end = min(start + self.batch_size, len(self.documents))
            shard = self._load_valid_shard(
                self._shard_path(start, end), end - start, None
            )
            if shard is not None:
                return int(shard.shape[1])
        return None

    def _count_valid_documents(self) -> int:
        dimension = self._known_dimension()
        completed = 0
        for start in range(0, len(self.documents), self.batch_size):
            end = min(start + self.batch_size, len(self.documents))
            if self._load_valid_shard(
                self._shard_path(start, end), end - start, dimension
            ) is None:
                break
            completed = end
        return completed

    def _shard_path(self, start: int, end: int) -> Path:
        return self.path / f"vectors-{start:08d}-{end:08d}.npy"

    @staticmethod
    def _load_valid_shard(
        path: Path, expected_rows: int, expected_dimension: int | None
    ) -> np.ndarray | None:
        try:
            matrix = np.load(path, allow_pickle=False)
        except (FileNotFoundError, OSError, ValueError):
            return None
        if (
            matrix.dtype != np.float32
            or matrix.ndim != 2
            or matrix.shape[0] != expected_rows
            or matrix.shape[1] <= 0
            or (
                expected_dimension is not None
                and matrix.shape[1] != expected_dimension
            )
            or not np.isfinite(matrix).all()
        ):
            return None
        return np.ascontiguousarray(matrix, dtype=np.float32)

    def _emit(
        self,
        callback: ProgressCallback | None,
        *,
        state: str,
        completed_documents: int,
        resumed_documents: int,
        resumed: bool,
        elapsed_seconds: float,
        eta_seconds: float | None,
        current_batch: int | None = None,
    ):
        if callback is None:
            return
        total = len(self.documents)
        completed_batches = (
            math.ceil(completed_documents / self.batch_size)
            if completed_documents
            else 0
        )
        callback(
            {
                "event": "vector_index_progress",
                "stage": "embedding",
                "state": state,
                "checkpoint_key": self.key,
                "source_hash": self.source_hash,
                "embedding": self.safe_identity,
                "embedding_provider": str(getattr(self.embedding, "provider", "")),
                "embedding_model": str(getattr(self.embedding, "model_name", "")),
                "current_batch": current_batch or completed_batches,
                "completed_batches": completed_batches,
                "total_batches": self.total_batches,
                "completed_documents": completed_documents,
                "total_documents": total,
                "percent": round(100 * completed_documents / total, 2),
                "resumed": resumed,
                "resumed_documents": resumed_documents,
                "elapsed_seconds": round(elapsed_seconds, 2),
                "eta_seconds": round(eta_seconds, 2) if eta_seconds is not None else None,
                "updated_at": _utc_now(),
            }
        )


def _documents_hash(documents: list[dict]) -> str:
    digest = hashlib.sha256()
    for document in documents:
        stable = {
            "id": document.get("id", ""),
            "text": document.get("text", ""),
            "metadata": document.get("metadata", {}),
        }
        digest.update(
            json.dumps(
                stable, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _safe_embedding_identity(embedding) -> str:
    # EmbeddingEngine.identity deliberately excludes API keys and URL queries.
    # Strip control characters as a final defence before writing logs/status.
    value = str(getattr(embedding, "identity", ""))
    return "".join(char for char in value if char >= " " and char not in "\r\n")


def _normalized_matrix(vectors, expected_rows: int) -> np.ndarray:
    matrix = np.asarray(vectors, dtype=np.float32)
    if (
        matrix.ndim != 2
        or matrix.shape[0] != expected_rows
        or matrix.shape[1] <= 0
        or not np.isfinite(matrix).all()
    ):
        raise RuntimeError(
            "Embedding provider trả về vector rỗng, không hữu hạn hoặc sai shape."
        )
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return np.ascontiguousarray(matrix / norms, dtype=np.float32)


def _atomic_save_npy(path: Path, matrix: np.ndarray):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as stream:
            np.save(stream, matrix, allow_pickle=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_write_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _log_progress(
    *,
    batch_number: int,
    total_batches: int,
    completed_documents: int,
    total_documents: int,
    elapsed_seconds: float,
    eta_seconds: float | None,
    resumed: bool,
):
    percent = 100 * completed_documents / total_documents
    eta_text = "unknown" if eta_seconds is None else f"{eta_seconds:.0f}s"
    LOGGER.info(
        "Embedding ATT&CK: batch %s/%s, documents %s/%s (%.2f%%), "
        "elapsed %.0fs, ETA %s%s",
        batch_number,
        total_batches,
        completed_documents,
        total_documents,
        percent,
        elapsed_seconds,
        eta_text,
        " [checkpoint]" if resumed else "",
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
