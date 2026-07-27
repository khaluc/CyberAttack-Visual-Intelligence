"""PHASE 5 — graph model and Graphviz/Mermaid/NetworkX renderers."""
from __future__ import annotations

import io
import json
import math
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from functools import lru_cache
from pathlib import Path

from structured_attack import validate_structured_incident


TACTIC_COLORS = {
    "Initial Access": "#1d78b5", "Execution": "#8b5cf6",
    "Persistence": "#b35fca", "Privilege Escalation": "#d15c97",
    "Defense Evasion": "#d66a63", "Credential Access": "#e08d3f",
    "Discovery": "#d1a83b", "Lateral Movement": "#42a37a",
    "Collection": "#2aa1a1", "Command And Control": "#317bc2",
    "Command and Control": "#317bc2", "Exfiltration": "#dc5a75",
    "Impact": "#df4654", "Unknown": "#607086",
}

PROJECT_ROOT = Path(__file__).resolve().parent


@dataclass
class GraphNode:
    id: str
    order: int
    label: str
    actor: str
    target: str
    asset: str
    severity: str
    tactic: str
    technique_id: str
    color: str


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    label: str
    weight: float


def build_graph_model(structured):
    data = validate_structured_incident(structured)
    nodes = []
    for step in data["steps"]:
        tactic = step["mitre"]["tactic"]
        nodes.append(GraphNode(
            id=f"step_{step['order']}", order=step["order"], label=step["action"],
            actor=step["actor"], target=step["target"], asset=step["asset"],
            severity=step["severity"], tactic=tactic,
            technique_id=step["mitre"]["technique_id"],
            color=TACTIC_COLORS.get(tactic, TACTIC_COLORS["Unknown"]),
        ))
    edges = []
    for left, right in zip(nodes, nodes[1:]):
        confidence = data["steps"][right.order - 1].get("rag_confidence", data["confidence"] / 100)
        edges.append(GraphEdge(
            id=f"edge_{left.order}_{right.order}", source=left.id, target=right.id,
            label=f"{left.order} → {right.order}", weight=round(float(confidence), 4),
        ))
    return {
        "directed": True, "multigraph": False,
        "incident_id": data["incident_id"], "incident_name": data["incident_name"],
        "nodes": [asdict(node) for node in nodes], "edges": [asdict(edge) for edge in edges],
    }


def to_dot(graph):
    lines = [
        "digraph CyberVisionAttack {", '  graph [rankdir=LR, bgcolor="#07111f", pad="0.35", nodesep="0.5", ranksep="0.65"];',
        '  node [shape=box, style="rounded,filled", fontname="Arial", fontcolor="white", color="#274057", penwidth=1.2, margin="0.14,0.10"];',
        '  edge [color="#3d6883", fontname="Arial", fontcolor="#7994aa", arrowsize=0.75, penwidth=1.4];',
        f'  label="{_dot(graph["incident_name"])}"; labelloc="t"; fontname="Arial"; fontcolor="#dce8f4"; fontsize=18;',
    ]
    for node in graph["nodes"]:
        label = (
            f'{node["order"]:02d}  {node["label"]}\n'
            f'{node["technique_id"]} · {node["tactic"]}'
        )
        lines.append(f'  {node["id"]} [label="{_dot(label)}", fillcolor="{node["color"]}"];')
    for edge in graph["edges"]:
        lines.append(f'  {edge["source"]} -> {edge["target"]} [label="{edge["weight"]:.2f}"];')
    lines.append("}")
    return "\n".join(lines)


def to_mermaid(graph):
    lines = ["flowchart LR"]
    for node in graph["nodes"]:
        label = _mermaid(f'{node["order"]:02d} · {node["label"]}<br/>{node["technique_id"]} · {node["tactic"]}')
        lines.append(f'  {node["id"]}["{label}"]')
        lines.append(f'  style {node["id"]} fill:{node["color"]},stroke:#4b6b82,color:#fff')
    for edge in graph["edges"]:
        lines.append(f'  {edge["source"]} -->|{edge["weight"]:.2f}| {edge["target"]}')
    return "\n".join(lines)


def to_networkx_json(graph):
    return {
        "directed": True, "multigraph": False,
        "graph": {"incident_id": graph["incident_id"], "incident_name": graph["incident_name"]},
        "nodes": [{"id": node["id"], **{k: v for k, v in node.items() if k != "id"}} for node in graph["nodes"]],
        "links": graph["edges"],
    }


def render_png(graph, engine="networkx"):
    if engine == "graphviz":
        return _render_graphviz(graph, "png")
    if engine == "mermaid":
        return _render_mermaid(graph, "png")
    if engine == "networkx":
        return _networkx_png(graph)
    raise ValueError(f"Graph engine không được hỗ trợ: {engine}")


def render_svg(graph, engine="graphviz"):
    if engine == "graphviz":
        return _normalize_svg(_render_graphviz(graph, "svg"))
    if engine == "mermaid":
        return _normalize_svg(_render_mermaid(graph, "svg"))
    if engine == "networkx":
        # NetworkX is a graph-object/Matplotlib engine.  Its SVG is generated
        # by Matplotlib, not by the old hand-written fallback renderer.
        return _normalize_svg(_networkx_svg(graph))
    raise ValueError(f"Graph engine không được hỗ trợ: {engine}")


@lru_cache(maxsize=1)
def renderer_status():
    dot = _dot_executable()
    node, cli, chrome = _mermaid_runtime()
    return {
        "graphviz": {
            "ready": bool(dot),
            "binary": str(dot) if dot else None,
            "version": _command_version([str(dot), "-V"]) if dot else None,
            "native": True,
        },
        "mermaid": {
            "ready": bool(node and cli and chrome),
            "node": str(node) if node else None,
            "cli": str(cli) if cli else None,
            "chrome": str(chrome) if chrome else None,
            "version": (
                _command_version([str(node), str(cli), "--version"])
                if node and cli else None
            ),
            "native": True,
        },
        "networkx": {
            "ready": True,
            "version": _package_version("networkx"),
            "native": True,
        },
    }


def _render_graphviz(graph, output_format):
    dot = _dot_executable()
    if not dot:
        raise RuntimeError(
            "Không tìm thấy Graphviz system binary dot. "
            "Đặt GRAPHVIZ_DOT hoặc cài Graphviz vào .tools/graphviz."
        )
    env = os.environ.copy()
    env["PATH"] = str(dot.parent) + os.pathsep + env.get("PATH", "")
    process = subprocess.run(
        [str(dot), f"-T{output_format}"],
        input=to_dot(graph).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=90,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(
            "Graphviz dot render thất bại: "
            + process.stderr.decode("utf-8", errors="replace").strip()
        )
    if not process.stdout:
        raise RuntimeError("Graphviz dot không tạo artifact.")
    return process.stdout


def _render_mermaid(graph, output_format):
    node, cli, chrome = _mermaid_runtime()
    if not node or not cli:
        raise RuntimeError(
            "Không tìm thấy Mermaid CLI. Cài @mermaid-js/mermaid-cli "
            "vào .tools/mermaid hoặc đặt MERMAID_CLI."
        )
    if not chrome:
        raise RuntimeError(
            "Không tìm thấy Chrome/Chromium cho Mermaid CLI. "
            "Đặt PUPPETEER_EXECUTABLE_PATH."
        )
    with tempfile.TemporaryDirectory(prefix="cybervision-mermaid-") as raw_dir:
        directory = Path(raw_dir)
        source = directory / "attack-graph.mmd"
        output = directory / f"attack-graph.{output_format}"
        puppeteer = directory / "puppeteer-config.json"
        source.write_text(to_mermaid(graph), encoding="utf-8")
        puppeteer.write_text(
            json.dumps(
                {
                    "executablePath": str(chrome),
                    "headless": True,
                    "args": ["--no-sandbox", "--disable-setuid-sandbox"],
                }
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PATH"] = str(node.parent) + os.pathsep + env.get("PATH", "")
        env["PUPPETEER_EXECUTABLE_PATH"] = str(chrome)
        process = subprocess.run(
            [
                str(node),
                str(cli),
                "--input",
                str(source),
                "--output",
                str(output),
                "--theme",
                "dark",
                "--backgroundColor",
                "transparent",
                "--puppeteerConfigFile",
                str(puppeteer),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=120,
            check=False,
        )
        if process.returncode or not output.exists():
            details = (
                process.stderr.decode("utf-8", errors="replace").strip()
                or process.stdout.decode("utf-8", errors="replace").strip()
            )
            raise RuntimeError(f"Mermaid CLI render thất bại: {details}")
        return output.read_bytes()


def _dot_executable():
    configured = os.getenv("GRAPHVIZ_DOT", "").strip()
    candidates = [
        Path(configured) if configured else None,
        Path(found) if (found := shutil.which("dot")) else None,
    ]
    candidates.extend(
        sorted(
            (PROJECT_ROOT / ".tools" / "graphviz").glob("**/bin/dot.exe"),
            reverse=True,
        )
    )
    return next(
        (path.resolve() for path in candidates if path and path.is_file()),
        None,
    )


def _mermaid_runtime():
    node_config = os.getenv("NODE_BINARY", "").strip()
    cli_config = os.getenv("MERMAID_CLI", "").strip()
    chrome_config = os.getenv("PUPPETEER_EXECUTABLE_PATH", "").strip()

    node_candidates = [Path(node_config) if node_config else None]
    if found := shutil.which("node"):
        node_candidates.append(Path(found))
    node_candidates.extend(
        sorted((PROJECT_ROOT / ".tools").glob("node*/**/node.exe"), reverse=True)
    )

    cli_candidates = [Path(cli_config) if cli_config else None]
    if found := shutil.which("mmdc"):
        cli_candidates.append(Path(found))
    cli_candidates.extend(
        [
            PROJECT_ROOT
            / ".tools"
            / "mermaid"
            / "node_modules"
            / "@mermaid-js"
            / "mermaid-cli"
            / "src"
            / "cli.js",
            PROJECT_ROOT
            / "node_modules"
            / "@mermaid-js"
            / "mermaid-cli"
            / "src"
            / "cli.js",
        ]
    )

    chrome_candidates = [Path(chrome_config) if chrome_config else None]
    for executable in ("chrome", "chrome.exe", "chromium", "chromium.exe"):
        if found := shutil.which(executable):
            chrome_candidates.append(Path(found))
    chrome_candidates.extend(
        [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))
            / "Google"
            / "Chrome"
            / "Application"
            / "chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)"))
            / "Google"
            / "Chrome"
            / "Application"
            / "chrome.exe",
        ]
    )

    pick = lambda values: next(
        (path.resolve() for path in values if path and path.is_file()), None
    )
    return pick(node_candidates), pick(cli_candidates), pick(chrome_candidates)


def _command_version(command):
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        text = (process.stdout or process.stderr).decode(
            "utf-8", errors="replace"
        ).strip()
        return text.splitlines()[0] if text else None
    except (OSError, subprocess.SubprocessError):
        return None


def _package_version(package):
    try:
        from importlib import metadata

        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def _normalize_svg(content):
    marker = content.find(b"<svg")
    return content[marker:] if marker >= 0 else content


def _networkx_png(graph):
    return _networkx_artifact(graph, "png")


def _networkx_svg(graph):
    return _networkx_artifact(graph, "svg")


def _networkx_artifact(graph, output_format):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    network = nx.DiGraph()
    for node in graph["nodes"]:
        network.add_node(node["id"], **node)
    for edge in graph["edges"]:
        network.add_edge(edge["source"], edge["target"], weight=edge["weight"], label=edge["label"])
    count = len(graph["nodes"])
    figure, axis = plt.subplots(figsize=(max(10, count * 2.35), 5.3), facecolor="#07111f")
    axis.set_facecolor("#07111f")
    positions = {node["id"]: (index * 2.4, math.sin(index * .7) * .12) for index, node in enumerate(graph["nodes"])}
    colors = [node["color"] for node in graph["nodes"]]
    labels = {node["id"]: f'{node["order"]:02d}\n{node["label"]}\n{node["technique_id"]}' for node in graph["nodes"]}
    nx.draw_networkx_nodes(network, positions, node_color=colors, node_size=4100,
                           edgecolors="#52738a", linewidths=1.3, node_shape="s", ax=axis)
    nx.draw_networkx_edges(network, positions, edge_color="#4c8098", width=1.8,
                           arrows=True, arrowsize=18, connectionstyle="arc3,rad=0.02", ax=axis)
    nx.draw_networkx_labels(network, positions, labels, font_color="white", font_size=8, ax=axis)
    axis.set_title(graph["incident_name"], color="#dfeaf5", fontsize=16, pad=18)
    axis.axis("off")
    figure.tight_layout()
    output = io.BytesIO()
    figure.savefig(
        output,
        format=output_format,
        dpi=160,
        facecolor=figure.get_facecolor(),
        bbox_inches="tight",
    )
    plt.close(figure)
    return output.getvalue()


def _dot(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _mermaid(value):
    return str(value).replace('"', "#quot;").replace("[", "&#91;").replace("]", "&#93;")
