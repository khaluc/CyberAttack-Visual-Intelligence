"""Build the configured MITRE ATT&CK semantic vector index."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Importing config_store loads the project .env before RAGConfig.from_env().
import config_store  # noqa: F401
from mitre_rag import MITREAttackRAG, RAGConfig


config = RAGConfig.from_env()
print(
    json.dumps(
        {
            "event": "start",
            "backend": config.vector_backend,
            "provider": config.embedding_provider,
            "model": config.embedding_model,
            "batch_size": config.embedding_batch_size,
            "max_seq_length": config.embedding_max_seq_length,
        },
        ensure_ascii=False,
    ),
    flush=True,
)
rag = MITREAttackRAG(config)
print(json.dumps(rag.build_index(), ensure_ascii=False), flush=True)
