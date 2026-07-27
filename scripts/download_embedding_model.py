"""Pre-download and validate the configured SentenceTransformer model."""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("USE_TF", "0")
os.environ.setdefault("USE_FLAX", "0")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config_store  # noqa: E402,F401
from mitre_rag import RAGConfig  # noqa: E402
from sentence_transformers import SentenceTransformer


config = RAGConfig.from_env()
model_name = config.embedding_model
kwargs = {}
if config.embedding_device:
    kwargs["device"] = config.embedding_device
if config.embedding_revision:
    kwargs["revision"] = config.embedding_revision
model = SentenceTransformer(model_name, **kwargs)
print(f"model={model_name} dimension={model.get_sentence_embedding_dimension()}", flush=True)
