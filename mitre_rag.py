"""PHASE 4 — MITRE ATT&CK document, embedding and vector retrieval pipeline."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from vector_backends import (
    ChromaAttackStore,
    EmbeddingEngine,
    FAISSAttackStore,
    QdrantAttackStore,
    create_vector_store,
)

ROOT = Path(__file__).resolve().parent
DEFAULT_STIX_PATH = ROOT / "data" / "mitre" / "enterprise-attack.json"
DEFAULT_INDEX_PATH = ROOT / "data" / "vector_db"
_RAG = None
_RAG_LOCK = Lock()


@dataclass
class RAGConfig:
    enabled: bool = True
    stix_path: str = str(DEFAULT_STIX_PATH)
    vector_backend: str = "chroma"
    embedding_provider: str = "sentence-transformers"
    embedding_model: str = "BAAI/bge-m3"
    embedding_base_url: str = "https://api.openai.com/v1"
    embedding_api_key: str = ""
    embedding_dimension: int = 0
    embedding_revision: str = ""
    embedding_device: str = ""
    embedding_batch_size: int = 8
    embedding_max_seq_length: int = 512
    collection_name: str = "mitre_enterprise_attack"
    index_path: str = str(DEFAULT_INDEX_PATH)
    qdrant_url: str = ""
    qdrant_api_key: str = ""
    top_k: int = 5
    auto_rebuild: bool = True

    @classmethod
    def from_env(cls):
        provider = os.getenv("EMBEDDING_PROVIDER", "sentence-transformers").lower()
        stix_path = Path(os.getenv("MITRE_STIX_PATH", str(DEFAULT_STIX_PATH)))
        if not stix_path.is_absolute():
            stix_path = ROOT / stix_path
        index_path = Path(os.getenv("VECTOR_INDEX_PATH", str(DEFAULT_INDEX_PATH)))
        if not index_path.is_absolute():
            index_path = ROOT / index_path
        default_embedding_url = (
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
            if provider == "dashscope"
            else "https://api.openai.com/v1"
        )
        return cls(
            enabled=os.getenv("MITRE_RAG_ENABLED", "true").lower() == "true",
            stix_path=str(stix_path),
            vector_backend=os.getenv("VECTOR_DB", "chroma").lower(),
            embedding_provider=provider,
            embedding_model=os.getenv("EMBEDDING_MODEL", "BAAI/bge-m3"),
            embedding_base_url=os.getenv(
                "EMBEDDING_BASE_URL", default_embedding_url
            ).rstrip("/"),
            embedding_api_key=os.getenv("EMBEDDING_API_KEY", "")
            or (
                os.getenv("DASHSCOPE_API_KEY", "")
                if provider == "dashscope"
                else os.getenv("OPENAI_API_KEY", "") if provider == "openai" else ""
            ),
            embedding_dimension=max(0, int(os.getenv("EMBEDDING_DIMENSION", "0"))),
            embedding_revision=os.getenv("EMBEDDING_REVISION", ""),
            embedding_device=os.getenv("EMBEDDING_DEVICE", ""),
            embedding_batch_size=max(1, int(os.getenv("EMBEDDING_BATCH_SIZE", "8"))),
            embedding_max_seq_length=max(
                64, int(os.getenv("EMBEDDING_MAX_SEQ_LENGTH", "512"))
            ),
            collection_name=os.getenv(
                "VECTOR_COLLECTION",
                os.getenv("CHROMA_COLLECTION", "mitre_enterprise_attack"),
            ),
            index_path=str(index_path),
            qdrant_url=os.getenv("QDRANT_URL", "").rstrip("/"),
            qdrant_api_key=os.getenv("QDRANT_API_KEY", ""),
            top_k=max(1, min(20, int(os.getenv("RAG_TOP_K", "5")))),
            auto_rebuild=os.getenv("VECTOR_AUTO_REBUILD", "true").lower() == "true",
        )


class AttackSTIXConverter:
    def __init__(self, path=DEFAULT_STIX_PATH):
        self.path = Path(path)

    def load(self):
        if not self.path.exists():
            raise FileNotFoundError(f"Chưa có Enterprise ATT&CK: {self.path}")
        return json.loads(self.path.read_text(encoding="utf-8"))["objects"]

    def convert(self):
        objects = self.load()
        by_id = {obj["id"]: obj for obj in objects if "id" in obj}
        relationships = [obj for obj in objects if obj.get("type") == "relationship"
                         and not obj.get("revoked") and not obj.get("x_mitre_deprecated")]
        related = {}
        for rel in relationships:
            related.setdefault(rel.get("target_ref"), []).append(rel)
        documents = []
        techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"
                      and not obj.get("revoked") and not obj.get("x_mitre_deprecated")]
        for technique in techniques:
            technique_id = _external_id(technique)
            if not technique_id:
                continue
            tactics = [phase.get("phase_name", "Unknown").replace("-", " ").title()
                       for phase in technique.get("kill_chain_phases", [])]
            base_metadata = {
                "technique_id": technique_id, "technique_name": technique.get("name", ""),
                "tactics": ", ".join(tactics) or "Unknown", "stix_id": technique["id"],
            }
            documents.append(_document(
                f"{technique_id}:technique", "technique",
                f"Technique: {technique_id} {technique.get('name', '')}\n"
                f"Tactics: {', '.join(tactics) or 'Unknown'}\n"
                f"Description: {_clean(technique.get('description', ''))}", base_metadata,
            ))
            buckets = {"mitigates": [], "detects": [], "uses": []}
            for rel in related.get(technique["id"], []):
                rel_type = rel.get("relationship_type")
                if rel_type not in buckets:
                    continue
                source = by_id.get(rel.get("source_ref"), {})
                description = _clean(rel.get("description") or source.get("description", ""))
                if not description:
                    continue
                label = {
                    "mitigates": f"Mitigation: {source.get('name', 'Unknown')}",
                    "detects": f"Detection: {source.get('name', 'Unknown')}",
                    "uses": f"Procedure: {source.get('name', 'Unknown')}",
                }[rel_type]
                buckets[rel_type].append((label, description))
            for kind, entries in buckets.items():
                limit = 8 if kind == "uses" else 5
                for index, (label, description) in enumerate(entries[:limit]):
                    documents.append(_document(
                        f"{technique_id}:{kind}:{index}", kind,
                        f"Technique: {technique_id} {technique.get('name', '')}\n{label}\n{description}",
                        base_metadata,
                    ))
        return documents

    def source_hash(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


class MITREAttackRAG:
    def __init__(self, config=None, converter=None, embedding=None, store=None):
        self.config = config or RAGConfig.from_env()
        self.converter = converter or AttackSTIXConverter(self.config.stix_path)
        self.embedding = embedding or EmbeddingEngine(self.config)
        self._index_lock = Lock()
        self._source_stat = self._source_signature()
        expected_hash = self.converter.source_hash() if self._source_stat else ""
        self.store = store or create_vector_store(
            self.config,
            self.embedding,
            self.config.index_path,
            expected_source_hash=expected_hash,
        )

    def build_index(self):
        with self._index_lock:
            return self._build_index_unlocked()

    def _build_index_unlocked(self):
        documents = self.converter.convert()
        source_hash = self.converter.source_hash()
        self.store.expected_source_hash = source_hash
        self._source_stat = self._source_signature()
        status = self.store.rebuild(documents, source_hash)
        status.update({"techniques": len({d["metadata"]["technique_id"] for d in documents})})
        return status

    def ensure_index(self):
        """Build/rebuild an empty or incompatible index before retrieval."""
        self._refresh_expected_source_hash()
        status = self.store.status()
        if status["ready"]:
            return status
        if not self.config.auto_rebuild:
            raise RuntimeError(
                "Vector index không tương thích cấu hình semantic hiện tại. "
                "Gọi POST /api/rag/index hoặc bật VECTOR_AUTO_REBUILD=true."
            )
        with self._index_lock:
            status = self.store.status()
            if status["ready"]:
                return status
            return self._build_index_unlocked()

    def status(self):
        self._refresh_expected_source_hash()
        return self.store.status()

    def _source_signature(self):
        try:
            stat = self.converter.path.stat()
            return stat.st_mtime_ns, stat.st_size
        except OSError:
            return None

    def _refresh_expected_source_hash(self):
        signature = self._source_signature()
        if signature and signature != self._source_stat:
            self.store.expected_source_hash = self.converter.source_hash()
            self._source_stat = signature

    def retrieve(self, query, top_k=None):
        self.ensure_index()
        limit = top_k or self.config.top_k
        candidates = self.store.search(_augment_security_query(query), max(limit * 3, 10))
        lowered = query.lower()
        for item in candidates:
            item["retrieval_score"] = round(
                item["score"] + _security_hint_bonus(lowered, item["technique_id"]), 4
            )
        candidates.sort(key=lambda item: item["retrieval_score"], reverse=True)
        return candidates[:limit]

    def enrich(self, structured):
        self.ensure_index()
        result = json.loads(json.dumps(structured))
        for step in result["steps"]:
            retrieval_query = str(
                (step.get("retrieval") or {}).get("query_en") or ""
            ).strip()
            if retrieval_query.lower() in ("", "unknown", "none", "n/a"):
                retrieval_query = " | ".join(
                    (
                        step["action"], step["actor"], step["target"],
                        step["asset"], step["mitre"]["tactic"],
                    )
                )
            query = " | ".join(
                part for part in (
                    retrieval_query,
                    step["mitre"].get("technique_id", ""),
                    step["mitre"]["tactic"],
                ) if part and str(part).lower() != "unknown"
            )
            query = _augment_security_query(query)
            matches = self.retrieve(query, max(self.config.top_k * 3, 10))
            expected_tactic = step["mitre"]["tactic"].lower()
            if expected_tactic != "unknown":
                for match in matches:
                    tactic_match = expected_tactic in match["tactics"].lower()
                    query_lower = query.lower()
                    name_lower = match["technique_name"].lower()
                    name_bonus = 0.12 if name_lower and name_lower in query_lower else 0
                    hint_bonus = _security_hint_bonus(query_lower, match["technique_id"])
                    match["rerank_score"] = round(
                        match["score"] + (0.15 if tactic_match else 0) + name_bonus + hint_bonus, 4
                    )
                matches.sort(key=lambda item: item["rerank_score"], reverse=True)
            matches = matches[:self.config.top_k]
            step["rag"] = {"query": query, "matches": matches}
            if matches:
                best = matches[0]
                step["mitre"]["technique_id"] = best["technique_id"]
                if step["mitre"]["tactic"] == "Unknown":
                    step["mitre"]["tactic"] = best["tactics"].split(",")[0]
                step["detection"] = best["detection"][0] if best["detection"] else "Unknown"
                step["mitigation"] = best["mitigation"][0] if best["mitigation"] else "Unknown"
                step["procedure"] = best["procedure"][0] if best["procedure"] else "Unknown"
                step["rag_confidence"] = round(best["score"], 4)
        result["metadata"]["pipeline"].append("phase_4_mitre_rag")
        result["metadata"]["rag"] = self.store.status()
        _recalculate_rag_confidence(result)
        return result


def get_rag():
    global _RAG
    if _RAG is None:
        with _RAG_LOCK:
            if _RAG is None:
                _RAG = MITREAttackRAG()
    return _RAG


def reset_rag(config=None):
    """Close and replace the process-wide RAG instance after config changes."""
    global _RAG
    with _RAG_LOCK:
        previous = _RAG
        close = getattr(getattr(previous, "store", None), "close", None)
        if callable(close):
            close()
        _RAG = MITREAttackRAG(config) if config else None
        return _RAG


def _external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _clean(text):
    text = re.sub(r"\[(.*?)\]\(https?://[^)]+\)", r"\1", str(text))
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _document(doc_id, kind, text, metadata):
    return {"id": doc_id, "text": text, "metadata": {**metadata, "document_type": kind}}


def _security_hint_bonus(query, technique_id):
    """Domain-aware reranker; retrieval still supplies every candidate."""
    hints = (
        (("phishing", "spearphishing"), ("T1566",)),
        (("open malicious", "open file", "user execution"), ("T1204", "T1204.002")),
        (("macro",), ("T1204.002", "T1137")),
        (("powershell",), ("T1059.001",)),
        (("credential theft", "input capture"), ("T1056",)),
        (("browser credential",), ("T1555.003",)),
        (("exfiltrate", "exfiltration"), ("T1041", "T1567")),
    )
    for phrases, technique_ids in hints:
        if any(phrase in query for phrase in phrases) and technique_id in technique_ids:
            return 0.25
    return 0


def _augment_security_query(query):
    lowered = query.lower()
    additions = []
    if "macro" in lowered:
        additions.append("Office macro user execution malicious file")
    if "credential" in lowered:
        additions.append("credential theft input capture credential access")
    if "c2" in lowered or "command and control" in lowered:
        additions.append("command and control application layer protocol dynamic resolution")
    return query + (" | " + " ".join(additions) if additions else "")


def _recalculate_rag_confidence(structured):
    """Blend structural confidence with calibrated retrieval quality."""
    steps = structured["steps"]
    total = max(1, len(steps))
    mapped = [step for step in steps if step["mitre"]["technique_id"] != "Unknown"]
    coverage = len(mapped) / total
    raw_scores = [float(step.get("rag_confidence", 0)) for step in mapped]
    mean_score = sum(raw_scores) / len(raw_scores) if raw_scores else 0.0
    # Normalized semantic cosine scores for ATT&CK text commonly sit around .15-.50.
    # Normalize that observed range instead of presenting cosine as a percent.
    calibrated_rag = max(0.0, min(1.0, (mean_score - 0.15) / 0.35))
    structure_score = structured["confidence"] / 100
    final = round(100 * (0.45 * structure_score + 0.35 * calibrated_rag + 0.20 * coverage))
    structured["confidence"] = max(0, min(100, final))
    breakdown = structured.setdefault("confidence_breakdown", {})
    breakdown.update({
        "stage": "phase_4_mitre_rag",
        "rag_coverage": round(coverage, 4),
        "rag_mean_score": round(mean_score, 4),
        "rag_calibrated_quality": round(calibrated_rag, 4),
        "pre_rag_confidence": round(structure_score * 100),
        "final_confidence": structured["confidence"],
        "methodology": "weighted_pipeline_quality_v1",
    })
