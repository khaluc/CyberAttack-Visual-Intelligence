"""Runtime orchestration for the PHASE 2 -> PHASE 5 incident pipeline.

The project can use LangChain (default), LlamaIndex Workflows, or a small
native runner.  All three modes execute the same deterministic stage
functions, so switching orchestration libraries never changes the canonical
PHASE 3 schema.
"""
from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from importlib import metadata
from time import perf_counter
from typing import Any, Callable

from analysis_engine import analyze_incident
from graph_generation import build_graph_model
from knowledge_enrichment import enrich_with_knowledge
from llm_service import understand_phase2
from mitre_rag import get_rag
from structured_attack import build_structured_incident, to_ui_result


Stage = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class OrchestratorConfig:
    engine: str = "langchain"

    def __post_init__(self) -> None:
        if self.engine not in {"langchain", "llamaindex", "native"}:
            raise ValueError(
                "PIPELINE_ORCHESTRATOR phải là langchain, llamaindex hoặc native."
            )

    @classmethod
    def from_env(cls) -> "OrchestratorConfig":
        engine = os.getenv("PIPELINE_ORCHESTRATOR", "langchain").strip().lower()
        return cls(engine=engine)


class IncidentPipeline:
    """Execute and trace the complete analysis pipeline."""

    def __init__(
        self,
        config: OrchestratorConfig | None = None,
        *,
        phase2_fn: Callable[..., list[dict[str, Any]]] = understand_phase2,
        local_fn: Callable[[str], dict[str, Any]] = analyze_incident,
        rag_factory: Callable[[], Any] = get_rag,
    ) -> None:
        self.config = config or OrchestratorConfig.from_env()
        self.phase2_fn = phase2_fn
        self.local_fn = local_fn
        self.rag_factory = rag_factory

    def run(self, description: str, llm_config: Any) -> dict[str, Any]:
        context: dict[str, Any] = {
            "description": description,
            "llm_config": llm_config,
            "trace": [],
        }
        engine = self.config.engine
        started = perf_counter()
        if engine == "langchain":
            context = self._run_langchain(context)
        elif engine == "llamaindex":
            context = self._run_llamaindex(context)
        else:
            context = self._run_native(context)

        structured = context["structured"]
        structured["metadata"]["orchestration"] = {
            "engine": engine,
            "library_version": _library_version(engine),
            "stages": context["trace"],
            "duration_ms": round((perf_counter() - started) * 1000, 2),
        }
        result = to_ui_result(structured)
        # Keep the PHASE 2 tab faithful to the model/local extractor output.
        # PHASE 4 may fill an Unknown tactic or technique on the canonical
        # incident, but that enrichment must not rewrite what PHASE 2 showed.
        result["phase2"] = [
            dict(step) for step in context.get("phase2_steps", [])
        ]
        result["fallback"] = bool(context.get("fallback"))
        if context.get("llm_error"):
            result["llmError"] = context["llm_error"]
        result["orchestration"] = structured["metadata"]["orchestration"]
        return result

    def _run_native(self, context: dict[str, Any]) -> dict[str, Any]:
        for name, stage in self._stages():
            context = self._timed_stage(name, stage, context)
        return context

    def _run_langchain(self, context: dict[str, Any]) -> dict[str, Any]:
        try:
            from langchain_core.runnables import RunnableLambda
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "Chưa cài langchain-core; hãy cài requirements.txt."
            ) from exc

        chain = None
        for name, stage in self._stages():
            runnable = RunnableLambda(
                lambda value, n=name, fn=stage: self._timed_stage(n, fn, value)
            ).with_config({"run_name": name})
            chain = runnable if chain is None else chain | runnable
        return chain.invoke(
            context,
            config={
                "run_name": "cybervision_incident_pipeline",
                "tags": ["cybersecurity", "phase-2-to-5"],
            },
        )

    def _run_llamaindex(self, context: dict[str, Any]) -> dict[str, Any]:
        try:
            from llama_index.core.workflow import (
                Event,
                StartEvent,
                StopEvent,
                Workflow,
                step,
            )
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "Chưa cài llama-index-core; hãy cài requirements.txt."
            ) from exc

        owner = self

        class Phase2Event(Event):
            payload: dict

        class Phase3Event(Event):
            payload: dict

        class Phase4Event(Event):
            payload: dict

        class IncidentWorkflow(Workflow):
            @step
            async def phase2(self, ev: StartEvent) -> Phase2Event:
                return Phase2Event(
                    payload=owner._timed_stage(
                        "phase_2_understand", owner._phase2, ev.get("payload")
                    )
                )

            @step
            async def phase3(self, ev: Phase2Event) -> Phase3Event:
                return Phase3Event(
                    payload=owner._timed_stage(
                        "phase_3_structure", owner._phase3, ev.payload
                    )
                )

            @step
            async def phase4(self, ev: Phase3Event) -> Phase4Event:
                return Phase4Event(
                    payload=owner._timed_stage(
                        "phase_4_mitre_rag", owner._phase4, ev.payload
                    )
                )

            @step
            async def phase5(self, ev: Phase4Event) -> StopEvent:
                return StopEvent(
                    result=owner._timed_stage(
                        "phase_5_graph_model", owner._phase5, ev.payload
                    )
                )

        return _run_coroutine(
            lambda: IncidentWorkflow(timeout=300).run(payload=context)
        )

    def _stages(self) -> tuple[tuple[str, Stage], ...]:
        return (
            ("phase_2_understand", self._phase2),
            ("phase_3_structure", self._phase3),
            ("phase_4_mitre_rag", self._phase4),
            ("phase_5_graph_model", self._phase5),
        )

    @staticmethod
    def _timed_stage(name: str, stage: Stage, context: dict[str, Any]):
        started = perf_counter()
        outcome = stage(context)
        outcome["trace"].append(
            {"stage": name, "duration_ms": round((perf_counter() - started) * 1000, 2)}
        )
        return outcome

    def _phase2(self, context: dict[str, Any]) -> dict[str, Any]:
        description = context["description"]
        config = context["llm_config"]
        if getattr(config, "enabled", False):
            try:
                context["phase2_steps"] = self.phase2_fn(description, config)
                context["model"] = config.model
                context["provider"] = config.provider
                context["fallback"] = False
                return context
            except Exception as exc:
                context["llm_error"] = str(exc)

        local = self.local_fn(description)
        context["phase2_steps"] = local["phase2"]
        context["model"] = "local-engine"
        context["provider"] = "local"
        context["fallback"] = True
        return context

    @staticmethod
    def _phase3(context: dict[str, Any]) -> dict[str, Any]:
        context["structured"] = build_structured_incident(
            context["description"],
            context["phase2_steps"],
            model=context["model"],
            provider=context["provider"],
            fallback=context["fallback"],
        )
        return context

    def _phase4(self, context: dict[str, Any]) -> dict[str, Any]:
        structured = context["structured"]
        if not getattr(context["llm_config"], "rag_enabled", True):
            structured["metadata"]["rag_disabled"] = True
        else:
            try:
                rag = self.rag_factory()
                if rag.config.enabled:
                    structured = rag.enrich(structured)
                else:
                    structured["metadata"]["rag_disabled"] = True
            except Exception as exc:
                structured["metadata"]["rag_error"] = str(exc)
        try:
            structured = enrich_with_knowledge(structured)
        except Exception as exc:
            structured["metadata"]["knowledge_error"] = str(exc)
        context["structured"] = structured
        return context

    @staticmethod
    def _phase5(context: dict[str, Any]) -> dict[str, Any]:
        graph = build_graph_model(context["structured"])
        context["graph"] = graph
        context["structured"]["metadata"]["graph"] = {
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            "model": "canonical-directed-attack-graph",
        }
        return context


def run_pipeline(
    description: str,
    llm_config: Any,
    *,
    phase2_fn: Callable[..., list[dict[str, Any]]] = understand_phase2,
    local_fn: Callable[[str], dict[str, Any]] = analyze_incident,
    rag_factory: Callable[[], Any] = get_rag,
    engine: str | None = None,
) -> dict[str, Any]:
    config = OrchestratorConfig(
        engine=(engine or os.getenv("PIPELINE_ORCHESTRATOR", "langchain")).lower()
    )
    return IncidentPipeline(
        config,
        phase2_fn=phase2_fn,
        local_fn=local_fn,
        rag_factory=rag_factory,
    ).run(description, llm_config)


def orchestration_status() -> dict[str, Any]:
    selected = OrchestratorConfig.from_env().engine
    return {
        "selected": selected,
        "available": {
            "langchain": _optional_version("langchain-core"),
            "llamaindex": _optional_version("llama-index-core"),
            "native": "builtin",
        },
        "stages": [
            "phase_2_understand",
            "phase_3_structure",
            "phase_4_mitre_rag",
            "phase_5_graph_model",
        ],
    }


def _optional_version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def _library_version(engine: str) -> str:
    if engine == "langchain":
        return _optional_version("langchain-core") or "unavailable"
    if engine == "llamaindex":
        return _optional_version("llama-index-core") or "unavailable"
    return "builtin"


def _run_coroutine(awaitable_factory):
    """Run a workflow from sync Flask code, even under an existing event loop."""
    async def runner():
        return await awaitable_factory()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(runner())
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(runner())).result()
