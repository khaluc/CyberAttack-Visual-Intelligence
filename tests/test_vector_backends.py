import importlib.util
import json
from dataclasses import replace
from unittest.mock import patch

import numpy as np
import pytest

from mitre_rag import MITREAttackRAG, RAGConfig
from vector_backends import EmbeddingEngine, create_vector_store
from llm_service import LLMConfig


class FakeSemanticEmbedding:
    provider = "fake-semantic"
    model_name = "fake-bge"
    identity = "fake-semantic:fake-bge@test:normalized"
    dimension = 4

    @staticmethod
    def _vector(text):
        lowered = text.lower()
        vector = np.array(
            [
                1 + lowered.count("phishing"),
                1 + lowered.count("credential"),
                1 + lowered.count("powershell"),
                0.25,
            ],
            dtype=np.float32,
        )
        return (vector / np.linalg.norm(vector)).tolist()

    def encode_documents(self, texts):
        return [self._vector(text) for text in texts]

    def encode_query(self, text):
        return [self._vector(text)]


def _documents():
    return [
        {
            "id": "T1566:technique",
            "text": "Technique: T1566 Phishing\nDescription: phishing malicious email",
            "metadata": {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactics": "Initial Access",
                "stix_id": "attack-pattern--1",
                "document_type": "technique",
            },
        },
        {
            "id": "T1056:technique",
            "text": "Technique: T1056 Input Capture\nDescription: credential theft input capture",
            "metadata": {
                "technique_id": "T1056",
                "technique_name": "Input Capture",
                "tactics": "Credential Access",
                "stix_id": "attack-pattern--2",
                "document_type": "technique",
            },
        },
    ]


def _config(tmp_path, backend):
    return RAGConfig(
        vector_backend=backend,
        embedding_provider="sentence-transformers",
        embedding_model="BAAI/bge-m3",
        collection_name=f"test_{backend}_collection",
        index_path=str(tmp_path),
        embedding_batch_size=2,
        auto_rebuild=False,
    )


def test_semantic_embedding_is_the_runtime_default():
    config = RAGConfig()
    assert config.embedding_provider == "sentence-transformers"
    assert config.embedding_model == "BAAI/bge-m3"


def test_hashing_provider_is_rejected():
    engine = EmbeddingEngine(
        RAGConfig(embedding_provider="hashing", embedding_model="legacy")
    )
    with pytest.raises(ValueError, match="đã bị loại"):
        engine.encode_documents(["legacy"])


def test_e5_sentence_transformer_uses_asymmetric_prefixes_and_normalizes():
    class FakeModel:
        max_seq_length = 8192

        def __init__(self):
            self.document_input = None
            self.query_input = None

        def encode_document(self, texts, **kwargs):
            self.document_input = texts
            return np.array([[3.0, 4.0]])

        def encode_query(self, texts, **kwargs):
            self.query_input = texts
            return np.array([[0.0, 2.0]])

        def get_sentence_embedding_dimension(self):
            return 2

    fake_model = FakeModel()
    config = RAGConfig(
        embedding_provider="sentence-transformers",
        embedding_model="intfloat/multilingual-e5-large",
        embedding_max_seq_length=256,
    )
    engine = EmbeddingEngine(config, model_factory=lambda _: fake_model)
    document_vector = engine.encode_documents(["credential theft"])[0]
    query_vector = engine.encode_query("credential theft")[0]

    assert fake_model.document_input == ["passage: credential theft"]
    assert fake_model.query_input == ["query: credential theft"]
    assert fake_model.max_seq_length == 256
    assert np.isclose(np.linalg.norm(document_vector), 1.0)
    assert np.isclose(np.linalg.norm(query_vector), 1.0)
    assert engine.dimension == 2


def test_openai_compatible_embedding_adapter_sends_model_and_dimension():
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps(
                {"data": [{"index": 0, "embedding": [0.0, 3.0, 4.0]}]}
            ).encode()

    config = RAGConfig(
        embedding_provider="compatible",
        embedding_model="text-embedding-3-large",
        embedding_base_url="https://embedding.example/v1",
        embedding_api_key="test-key",
        embedding_dimension=3,
    )
    engine = EmbeddingEngine(config)
    with patch("urllib.request.urlopen", return_value=FakeResponse()) as mocked:
        vector = engine.encode_query("credential theft")[0]

    request = mocked.call_args.args[0]
    payload = json.loads(request.data)
    assert request.full_url == "https://embedding.example/v1/embeddings"
    assert request.headers["Authorization"] == "Bearer test-key"
    assert payload == {
        "model": "text-embedding-3-large",
        "input": ["credential theft"],
        "dimensions": 3,
    }
    assert np.isclose(np.linalg.norm(vector), 1.0)
    assert engine.dimension == 3


def test_persisting_llm_settings_preserves_vector_configuration(tmp_path):
    from config_store import _write_env

    env_path = tmp_path / ".env"
    env_path.write_text(
        'VECTOR_DB="qdrant"\nEMBEDDING_MODEL="BAAI/bge-m3"\n',
        encoding="utf-8",
    )
    with patch("config_store.ENV_PATH", env_path):
        _write_env(LLMConfig(enabled=True, provider="dashscope", api_key="secret"))
    persisted = env_path.read_text(encoding="utf-8")
    assert 'VECTOR_DB="qdrant"' in persisted
    assert 'EMBEDDING_MODEL="BAAI/bge-m3"' in persisted
    assert 'LLM_PROVIDER="dashscope"' in persisted


@pytest.mark.parametrize("backend", ["chroma", "qdrant"])
def test_persistent_backends_report_real_embedding_metadata(tmp_path, backend):
    config = _config(tmp_path, backend)
    embedding = FakeSemanticEmbedding()
    store = create_vector_store(config, embedding, tmp_path, expected_source_hash="source-a")
    status = store.rebuild(_documents(), "source-a")

    assert status["ready"] is True
    assert status["backend"] == backend
    assert status["dimension"] == 4
    assert status["embedding_provider"] == "fake-semantic"
    assert status["embedding_model"] == "fake-bge"
    assert status["chunks"] == 2
    assert store.search("credential theft", 1)[0]["technique_id"] == "T1056"
    if hasattr(store, "close"):
        store.close()


def test_manifest_detects_embedding_model_mismatch(tmp_path):
    config = _config(tmp_path, "chroma")
    store = create_vector_store(
        config, FakeSemanticEmbedding(), tmp_path, expected_source_hash="source-a"
    )
    store.rebuild(_documents(), "source-a")

    class ChangedEmbedding(FakeSemanticEmbedding):
        model_name = "fake-e5"
        identity = "fake-semantic:fake-e5@test:normalized"

    changed = create_vector_store(
        replace(config, embedding_model="fake-e5"),
        ChangedEmbedding(),
        tmp_path,
        expected_source_hash="source-a",
    )
    status = changed.status()
    assert status["ready"] is False
    assert status["requires_rebuild"] is True
    assert "embedding_changed" in status["incompatibility_reason"]


def test_rag_auto_rebuilds_incompatible_index_before_retrieval(tmp_path):
    class TinyConverter:
        path = tmp_path / "attack.json"

        def convert(self):
            return _documents()

        def source_hash(self):
            return "source-a"

    TinyConverter.path.write_text("{}", encoding="utf-8")
    config = replace(_config(tmp_path, "chroma"), auto_rebuild=True)
    rag = MITREAttackRAG(
        config=config, converter=TinyConverter(), embedding=FakeSemanticEmbedding()
    )
    assert rag.store.status()["ready"] is False
    assert rag.retrieve("credential theft", 1)[0]["technique_id"] == "T1056"
    assert rag.store.status()["ready"] is True

    class ChangedEmbedding(FakeSemanticEmbedding):
        model_name = "fake-e5"
        identity = "fake-semantic:fake-e5@test:normalized"

    changed_rag = MITREAttackRAG(
        config=replace(config, embedding_model="fake-e5"),
        converter=TinyConverter(),
        embedding=ChangedEmbedding(),
    )
    assert changed_rag.store.status()["ready"] is False
    assert changed_rag.retrieve("credential theft", 1)[0]["technique_id"] == "T1056"
    changed_status = changed_rag.store.status()
    assert changed_status["ready"] is True
    assert changed_status["embedding_model"] == "fake-e5"


@pytest.mark.skipif(importlib.util.find_spec("faiss") is None, reason="faiss-cpu not installed")
def test_faiss_backend_round_trip(tmp_path):
    config = _config(tmp_path, "faiss")
    store = create_vector_store(
        config, FakeSemanticEmbedding(), tmp_path, expected_source_hash="source-a"
    )
    assert store.rebuild(_documents(), "source-a")["ready"] is True
    assert store.search("phishing email", 1)[0]["technique_id"] == "T1566"


@pytest.mark.parametrize("target_backend", ["qdrant", "faiss"])
def test_chroma_precomputed_vectors_migrate_without_reencoding(
    tmp_path, target_backend
):
    if (
        target_backend == "faiss"
        and importlib.util.find_spec("faiss") is None
    ):
        pytest.skip("faiss-cpu not installed")

    embedding = FakeSemanticEmbedding()
    source_config = _config(tmp_path, "chroma")
    source = create_vector_store(
        source_config,
        embedding,
        tmp_path,
        expected_source_hash="source-a",
    )
    source.rebuild(_documents(), "source-a")
    documents, vectors, source_hash = source.export_precomputed()

    class NoEncodeEmbedding(FakeSemanticEmbedding):
        def encode_documents(self, texts):
            raise AssertionError("Migration must reuse stored embeddings")

    target_config = replace(
        source_config,
        vector_backend=target_backend,
        collection_name=f"migrated_{target_backend}",
    )
    target = create_vector_store(
        target_config,
        NoEncodeEmbedding(),
        tmp_path,
        expected_source_hash=source_hash,
    )
    status = target.rebuild_precomputed(documents, vectors, source_hash)

    assert status["ready"] is True
    assert status["backend"] == target_backend
    assert status["chunks"] == 2
    assert target.search("credential theft", 1)[0]["technique_id"] == "T1056"
    if hasattr(target, "close"):
        target.close()
