"""Multi-source cybersecurity knowledge base.

The module intentionally keeps ingestion independent from Flask and from the
vector backend used by PHASE 4.  It provides a durable document registry,
full-text search, source synchronization, and an enterprise asset inventory.
All counts reported by :meth:`KnowledgeBase.status` are calculated from the
filesystem and SQLite; no demo counters are embedded in the code.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

try:
    import yaml
except ImportError:  # pragma: no cover - the dependency is declared by the project
    yaml = None


ROOT = Path(__file__).resolve().parent
DEFAULT_KB_ROOT = ROOT / "data" / "knowledge_base"
DEFAULT_MITRE_PATH = ROOT / "data" / "mitre" / "enterprise-attack.json"

SOURCE_ORDER = (
    "mitre_attack",
    "sigma",
    "yara",
    "threat_intelligence",
    "nist_cis",
    "playbooks",
    "enterprise_assets",
)

SOURCE_LABELS = {
    "mitre_attack": "MITRE ATT&CK",
    "sigma": "Sigma Detection Rules",
    "yara": "YARA Rules",
    "threat_intelligence": "Threat Intelligence",
    "nist_cis": "NIST / CIS Guidance",
    "playbooks": "Incident Response Playbooks",
    "enterprise_assets": "Enterprise Assets",
}

SOURCE_ALIASES = {
    "mitre": "mitre_attack",
    "attack": "mitre_attack",
    "mitre_attack": "mitre_attack",
    "sigma": "sigma",
    "yara": "yara",
    "threat_intel": "threat_intelligence",
    "threat_intelligence": "threat_intelligence",
    "ti": "threat_intelligence",
    "nist": "nist_cis",
    "cis": "nist_cis",
    "nist_cis": "nist_cis",
    "playbook": "playbooks",
    "playbooks": "playbooks",
    "asset": "enterprise_assets",
    "assets": "enterprise_assets",
    "enterprise_assets": "enterprise_assets",
}


@dataclass(frozen=True)
class DownloadTarget:
    """One downloadable artifact belonging to a knowledge source."""

    url: str
    filename: str
    archive: str = ""
    include_prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceSpec:
    """Manifest entry for a source that may be synchronized."""

    key: str
    label: str
    downloads: tuple[DownloadTarget, ...] = ()
    description: str = ""


def official_source_manifest() -> dict[str, SourceSpec]:
    """Return maintained upstream defaults.

    URLs point to first-party publishers where one exists.  YARA is a language
    rather than a centrally maintained ruleset, so the community
    ``Yara-Rules/rules`` repository is used and is identified as such in the
    source description.
    """

    specs = {
        "mitre_attack": SourceSpec(
            key="mitre_attack",
            label=SOURCE_LABELS["mitre_attack"],
            description="MITRE CTI Enterprise ATT&CK STIX bundle",
            downloads=(DownloadTarget(
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                "master/enterprise-attack/enterprise-attack.json",
                "enterprise-attack.json",
            ),),
        ),
        "sigma": SourceSpec(
            key="sigma",
            label=SOURCE_LABELS["sigma"],
            description="Official SigmaHQ detection rule repository",
            downloads=(DownloadTarget(
                "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
                "sigma-master.zip",
                archive="zip",
                include_prefixes=(
                    "sigma-master/rules/",
                    "sigma-master/rules-dfir/",
                    "sigma-master/rules-emerging-threats/",
                    "sigma-master/rules-threat-hunting/",
                    "sigma-master/rules-compliance/",
                ),
            ),),
        ),
        "yara": SourceSpec(
            key="yara",
            label=SOURCE_LABELS["yara"],
            description=(
                "Community-maintained Yara-Rules/rules repository metadata. "
                "The safe tree index avoids antivirus quarantine of signature archives."
            ),
            downloads=(DownloadTarget(
                "https://api.github.com/repos/Yara-Rules/rules/"
                "git/trees/master?recursive=1",
                "yara-rules-tree.json",
            ),),
        ),
        "threat_intelligence": SourceSpec(
            key="threat_intelligence",
            label=SOURCE_LABELS["threat_intelligence"],
            description=(
                "CISA Known Exploited Vulnerabilities JSON from the official "
                "cisagov/kev-data mirror"
            ),
            downloads=(DownloadTarget(
                "https://raw.githubusercontent.com/cisagov/kev-data/"
                "develop/known_exploited_vulnerabilities.json",
                "cisa-known-exploited-vulnerabilities.json",
            ),),
        ),
        "nist_cis": SourceSpec(
            key="nist_cis",
            label=SOURCE_LABELS["nist_cis"],
            description="NIST incident-response guidance and CIS Controls landing page",
            downloads=(
                DownloadTarget(
                    "https://nvlpubs.nist.gov/nistpubs/specialpublications/"
                    "nist.sp.800-61r3.pdf",
                    "NIST.SP.800-61r3.pdf",
                ),
                DownloadTarget(
                    "https://www.cisecurity.org/controls/v8-1",
                    "cis-controls-v8-1.html",
                ),
            ),
        ),
        "playbooks": SourceSpec(
            key="playbooks",
            label=SOURCE_LABELS["playbooks"],
            description=(
                "CISA Incident and Vulnerability Response Playbooks, mirrored "
                "by the Western Australia Government Cyber Security Unit"
            ),
            downloads=(DownloadTarget(
                "https://soc.cyber.wa.gov.au/pdfs/"
                "Federal_Government_Cybersecurity_Incident_and_"
                "Vulnerability_Response_Playbooks_508C.pdf",
                "cisa-incident-vulnerability-response-playbooks.pdf",
            ),),
        ),
        "enterprise_assets": SourceSpec(
            key="enterprise_assets",
            label=SOURCE_LABELS["enterprise_assets"],
            description="Organization-provided CSV or JSON inventory; no remote default",
        ),
    }
    return _apply_manifest_environment_overrides(specs)


def _apply_manifest_environment_overrides(
    specs: dict[str, SourceSpec],
) -> dict[str, SourceSpec]:
    """Allow deployments to replace upstream URLs without editing source code."""

    result = dict(specs)
    for key, spec in specs.items():
        env_name = f"KB_{key.upper()}_URLS"
        raw = os.getenv(env_name, "").strip()
        if not raw:
            continue
        urls = [value.strip() for value in raw.split(",") if value.strip()]
        targets = []
        for index, url in enumerate(urls, start=1):
            name = Path(urllib.parse.urlparse(url).path).name or f"{key}-{index}.dat"
            archive = "zip" if name.lower().endswith(".zip") else ""
            targets.append(DownloadTarget(url=url, filename=name, archive=archive))
        result[key] = SourceSpec(
            key=spec.key,
            label=spec.label,
            description=f"{spec.description} (configured by {env_name})",
            downloads=tuple(targets),
        )
    return result


@dataclass
class KnowledgeBaseConfig:
    root: Path = DEFAULT_KB_ROOT
    mitre_path: Path = DEFAULT_MITRE_PATH
    database_path: Path | None = None
    request_timeout: int = 180
    max_download_mb: int = 750

    def __post_init__(self):
        self.root = Path(self.root)
        self.mitre_path = Path(self.mitre_path)
        if self.database_path is None:
            self.database_path = self.root / "knowledge.sqlite3"
        else:
            self.database_path = Path(self.database_path)

    @classmethod
    def from_env(cls) -> "KnowledgeBaseConfig":
        root = Path(os.getenv("KNOWLEDGE_BASE_PATH", str(DEFAULT_KB_ROOT)))
        return cls(
            root=root,
            mitre_path=Path(os.getenv("MITRE_STIX_PATH", str(DEFAULT_MITRE_PATH))),
            database_path=Path(os.getenv("KNOWLEDGE_DB_PATH", str(root / "knowledge.sqlite3"))),
            request_timeout=max(5, int(os.getenv("KB_SYNC_TIMEOUT", "180"))),
            max_download_mb=max(1, int(os.getenv("KB_MAX_DOWNLOAD_MB", "750"))),
        )


@dataclass
class KnowledgeDocument:
    id: str
    source: str
    document_type: str
    title: str
    text: str
    origin: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        source: str,
        document_type: str,
        title: str,
        text: str,
        origin: str,
        native_id: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> "KnowledgeDocument":
        normalized_text = _normalize_text(text)
        identity = native_id or hashlib.sha256(
            f"{title}\n{normalized_text}".encode("utf-8")
        ).hexdigest()
        doc_id = hashlib.sha256(
            f"{source}|{origin}|{identity}".encode("utf-8")
        ).hexdigest()
        return cls(
            id=doc_id,
            source=source,
            document_type=document_type,
            title=_normalize_text(title) or Path(origin).stem,
            text=normalized_text,
            origin=origin,
            metadata=_json_safe(dict(metadata or {})),
        )


class KnowledgeBase:
    """Durable registry and search layer for the system knowledge sources."""

    def __init__(
        self,
        config: KnowledgeBaseConfig | None = None,
        manifest: Mapping[str, SourceSpec] | None = None,
    ):
        self.config = config or KnowledgeBaseConfig.from_env()
        self.manifest = dict(manifest or official_source_manifest())
        self.config.root.mkdir(parents=True, exist_ok=True)
        for source in SOURCE_ORDER:
            if source != "mitre_attack":
                self.source_path(source).mkdir(parents=True, exist_ok=True)
        Path(self.config.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._fts_enabled = False
        self._initialize_database()

    def source_path(self, source: str) -> Path:
        key = normalize_source(source)
        if key == "mitre_attack":
            return self.config.mitre_path
        return self.config.root / "sources" / key

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.config.database_path), timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    document_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    text TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_documents_source
                    ON documents(source);
                CREATE INDEX IF NOT EXISTS idx_documents_type
                    ON documents(document_type);

                CREATE TABLE IF NOT EXISTS source_state (
                    source TEXT PRIMARY KEY,
                    last_sync_at TEXT,
                    last_index_at TEXT,
                    last_error TEXT NOT NULL DEFAULT '',
                    files_indexed INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    asset_type TEXT NOT NULL DEFAULT '',
                    owner TEXT NOT NULL DEFAULT '',
                    hostname TEXT NOT NULL DEFAULT '',
                    ip_address TEXT NOT NULL DEFAULT '',
                    criticality TEXT NOT NULL DEFAULT '',
                    environment TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    source_file TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
                CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
                """
            )
            try:
                connection.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                        id UNINDEXED,
                        source UNINDEXED,
                        title,
                        text,
                        tokenize='unicode61 remove_diacritics 2'
                    )
                    """
                )
                self._fts_enabled = True
            except sqlite3.OperationalError:
                self._fts_enabled = False

    def status(self) -> dict[str, Any]:
        """Return live source/index statistics suitable for an API or UI."""

        with self._connect() as connection:
            indexed_rows = {
                row["source"]: int(row["count"])
                for row in connection.execute(
                    "SELECT source, COUNT(*) AS count FROM documents GROUP BY source"
                )
            }
            state_rows = {
                row["source"]: dict(row)
                for row in connection.execute("SELECT * FROM source_state")
            }
            asset_count = int(
                connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            )

        sources: dict[str, dict[str, Any]] = {}
        total_files = 0
        total_bytes = 0
        total_documents = 0
        for key in SOURCE_ORDER:
            files = list(self._iter_source_files(key))
            file_bytes = sum(path.stat().st_size for path in files if path.exists())
            documents = indexed_rows.get(key, 0)
            state = state_rows.get(key, {})
            source_status = {
                "key": key,
                "label": SOURCE_LABELS[key],
                "configured": bool(self.manifest.get(key, SourceSpec(key, "")).downloads)
                or key == "enterprise_assets",
                "ready": documents > 0,
                "files": len(files),
                "bytes": file_bytes,
                "documents": documents,
                "last_sync_at": state.get("last_sync_at"),
                "last_index_at": state.get("last_index_at"),
                "last_error": state.get("last_error", ""),
                "path": str(self.source_path(key)),
            }
            if key == "enterprise_assets":
                source_status["assets"] = asset_count
                source_status["ready"] = asset_count > 0
            sources[key] = source_status
            total_files += len(files)
            total_bytes += file_bytes
            total_documents += documents

        return {
            "ready": total_documents > 0,
            "database": str(self.config.database_path),
            "search_engine": "sqlite-fts5" if self._fts_enabled else "sqlite-lexical",
            "sources": sources,
            "totals": {
                "files": total_files,
                "bytes": total_bytes,
                "documents": total_documents,
                "assets": asset_count,
            },
        }

    def source_manifest(self) -> dict[str, dict[str, Any]]:
        return {
            key: {
                **asdict(spec),
                "downloads": [asdict(target) for target in spec.downloads],
            }
            for key, spec in self.manifest.items()
        }

    def sync(self, source: str = "all") -> dict[str, Any]:
        """Synchronize one source (or all configured sources) and index it."""

        requested = (
            [key for key in SOURCE_ORDER if self.manifest.get(key, SourceSpec(key, "")).downloads]
            if source.strip().lower() == "all"
            else [normalize_source(source)]
        )
        results: dict[str, Any] = {}
        for key in requested:
            spec = self.manifest.get(key)
            if spec is None:
                raise ValueError(f"Nguồn không có trong manifest: {key}")
            if not spec.downloads:
                results[key] = {
                    "ok": False,
                    "source": key,
                    "error": "Nguồn này yêu cầu dữ liệu do tổ chức cung cấp.",
                }
                continue
            try:
                downloaded = self._sync_source_files(spec)
                index_result = self.ingest_source(key)
                self._update_source_state(key, last_sync_at=_utcnow(), last_error="")
                results[key] = {
                    "ok": True,
                    "source": key,
                    "downloaded": downloaded,
                    "index": index_result,
                }
            except Exception as exc:
                self._update_source_state(key, last_error=str(exc))
                results[key] = {"ok": False, "source": key, "error": str(exc)}
        return {
            "ok": all(result["ok"] for result in results.values()) if results else False,
            "results": results,
            "status": self.status(),
        }

    def _sync_source_files(self, spec: SourceSpec) -> list[dict[str, Any]]:
        if spec.key == "mitre_attack":
            return self._sync_mitre_file(spec)
        source_root = self.source_path(spec.key)
        source_root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{spec.key}-", dir=str(source_root)))
        official_staging = staging / "official"
        official_staging.mkdir(parents=True, exist_ok=True)
        downloaded: list[dict[str, Any]] = []
        try:
            for target in spec.downloads:
                artifact = (staging / target.filename).resolve()
                if staging.resolve() not in artifact.parents:
                    raise ValueError(f"Tên tệp tải xuống không an toàn: {target.filename}")
                size = self._download(target.url, artifact)
                if target.archive == "zip":
                    extracted = self._extract_zip(
                        artifact, official_staging, target.include_prefixes
                    )
                    downloaded.append({
                        "url": target.url,
                        "archive": target.filename,
                        "bytes": size,
                        "files": extracted,
                    })
                else:
                    destination = official_staging / target.filename
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    artifact.replace(destination)
                    downloaded.append({
                        "url": target.url,
                        "file": target.filename,
                        "bytes": size,
                    })

            official = source_root / "official"
            backup = source_root / ".official-previous"
            if backup.exists():
                _safe_rmtree(backup, source_root)
            if official.exists():
                official.replace(backup)
            try:
                official_staging.replace(official)
            except Exception:
                if backup.exists() and not official.exists():
                    backup.replace(official)
                raise
            else:
                if backup.exists():
                    _safe_rmtree(backup, source_root)
        finally:
            if staging.exists():
                _safe_rmtree(staging, source_root, ignore_errors=True)
        return downloaded

    def _sync_mitre_file(self, spec: SourceSpec) -> list[dict[str, Any]]:
        if len(spec.downloads) != 1 or spec.downloads[0].archive:
            raise ValueError("MITRE ATT&CK sync yêu cầu đúng một tệp STIX JSON.")
        target = spec.downloads[0]
        destination = self.config.mitre_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.download")
        try:
            size = self._download(target.url, temporary)
            # Reject an HTML error page before it can replace a valid STIX bundle.
            payload = json.loads(temporary.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
                raise ValueError("Tệp tải về không phải MITRE STIX bundle hợp lệ.")
            temporary.replace(destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return [{"url": target.url, "file": destination.name, "bytes": size}]

    def _download(self, url: str, destination: Path) -> int:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"https", "http", "file"}:
            raise ValueError(f"Giao thức tải không được hỗ trợ: {parsed.scheme}")
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Cybersecurity-Visual-Intelligence-KB/1.0",
                "Accept": "application/json, application/pdf, text/html, */*",
            },
        )
        max_bytes = self.config.max_download_mb * 1024 * 1024
        destination = destination.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        received = 0
        with urllib.request.urlopen(request, timeout=self.config.request_timeout) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise ValueError(
                    f"Tệp vượt giới hạn {self.config.max_download_mb} MB: {url}"
                )
            with destination.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > max_bytes:
                        raise ValueError(
                            f"Tệp vượt giới hạn {self.config.max_download_mb} MB: {url}"
                        )
                    output.write(chunk)
        return received

    @staticmethod
    def _extract_zip(
        archive: Path,
        destination: Path,
        include_prefixes: Sequence[str] = (),
    ) -> int:
        count = 0
        destination_resolved = destination.resolve()
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                if member.is_dir():
                    continue
                normalized = member.filename.replace("\\", "/").lstrip("/")
                if include_prefixes and not any(
                    normalized.startswith(prefix) for prefix in include_prefixes
                ):
                    continue
                parts = Path(normalized).parts
                relative_parts = parts[1:] if len(parts) > 1 else parts
                relative = Path(*relative_parts)
                target = (destination / relative).resolve()
                if destination_resolved != target and destination_resolved not in target.parents:
                    raise ValueError(f"Đường dẫn ZIP không an toàn: {member.filename}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.open(member) as source_file, target.open("wb") as output:
                    shutil.copyfileobj(source_file, output)
                count += 1
        return count

    def ingest_source(self, source: str) -> dict[str, Any]:
        """Parse and replace the indexed documents for one source."""

        key = normalize_source(source)
        if key == "enterprise_assets":
            return self._reindex_assets()
        files = list(self._iter_source_files(key))
        documents: list[KnowledgeDocument] = []
        errors: list[dict[str, str]] = []
        for path in files:
            try:
                documents.extend(self._parse_file(key, path))
            except Exception as exc:
                errors.append({"file": str(path), "error": str(exc)})
        self._replace_documents(key, documents)
        self._update_source_state(
            key,
            last_index_at=_utcnow(),
            files_indexed=len(files),
            last_error="\n".join(
                f"{item['file']}: {item['error']}" for item in errors[:20]
            ),
        )
        return {
            "source": key,
            "files": len(files),
            "documents": len(documents),
            "errors": errors,
        }

    def ingest_all(self) -> dict[str, Any]:
        results = {}
        for source in SOURCE_ORDER:
            results[source] = self.ingest_source(source)
        return {"results": results, "status": self.status()}

    def iter_documents(
        self, sources: Sequence[str] | None = None
    ) -> Iterator[dict[str, Any]]:
        selected = [normalize_source(item) for item in sources] if sources else []
        query = (
            "SELECT * FROM documents WHERE source IN "
            f"({','.join('?' for _ in selected)}) ORDER BY source, title"
            if selected
            else "SELECT * FROM documents ORDER BY source, title"
        )
        with self._connect() as connection:
            for row in connection.execute(query, selected):
                yield self._row_to_document(row)

    def search(
        self,
        query: str,
        sources: Sequence[str] | str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Search indexed knowledge with optional source filters."""

        cleaned = _normalize_text(query)
        if not cleaned:
            raise ValueError("Từ khóa tìm kiếm không được để trống.")
        selected = _normalize_sources(sources)
        limit = max(1, min(100, int(limit)))
        results = (
            self._search_fts(cleaned, selected, limit)
            if self._fts_enabled
            else self._search_lexical(cleaned, selected, limit)
        )
        return {
            "query": cleaned,
            "sources": selected or list(SOURCE_ORDER),
            "count": len(results),
            "results": results,
        }

    def _search_fts(
        self, query: str, sources: list[str], limit: int
    ) -> list[dict[str, Any]]:
        tokens = _query_tokens(query)
        if not tokens:
            return []
        expression = " OR ".join(f'"{token}"' for token in tokens)
        clauses = ["documents_fts MATCH ?"]
        parameters: list[Any] = [expression]
        if sources:
            clauses.append(f"d.source IN ({','.join('?' for _ in sources)})")
            parameters.extend(sources)
        parameters.append(limit)
        sql = f"""
            SELECT d.*, bm25(documents_fts, 1.0, 2.0) AS rank
            FROM documents_fts
            JOIN documents d ON d.id = documents_fts.id
            WHERE {' AND '.join(clauses)}
            ORDER BY rank
            LIMIT ?
        """
        with self._connect() as connection:
            rows = list(connection.execute(sql, parameters))
        results = []
        for position, row in enumerate(rows):
            item = self._row_to_document(row)
            # FTS bm25 values are collection-relative; expose a stable, bounded
            # rank-derived score while retaining the raw rank for diagnostics.
            item["score"] = round(1.0 / (1.0 + position), 4)
            item["rank"] = float(row["rank"])
            item["snippet"] = _best_snippet(item["text"], tokens)
            results.append(item)
        return results

    def _search_lexical(
        self, query: str, sources: list[str], limit: int
    ) -> list[dict[str, Any]]:
        tokens = _query_tokens(query)
        if not tokens:
            return []
        clauses: list[str] = []
        parameters: list[Any] = []
        if sources:
            clauses.append(f"source IN ({','.join('?' for _ in sources)})")
            parameters.extend(sources)
        sql = "SELECT * FROM documents"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        with self._connect() as connection:
            rows = list(connection.execute(sql, parameters))
        ranked = []
        for row in rows:
            haystack_title = row["title"].lower()
            haystack = f"{row['title']} {row['text']}".lower()
            matches = sum(token in haystack for token in tokens)
            if not matches:
                continue
            title_matches = sum(token in haystack_title for token in tokens)
            score = (matches + title_matches * 1.5) / (len(tokens) * 2.5)
            ranked.append((score, row))
        ranked.sort(key=lambda item: (-item[0], item[1]["title"]))
        results = []
        for score, row in ranked[:limit]:
            item = self._row_to_document(row)
            item["score"] = round(min(1.0, score), 4)
            item["snippet"] = _best_snippet(item["text"], tokens)
            results.append(item)
        return results

    def _parse_file(self, source: str, path: Path) -> list[KnowledgeDocument]:
        if source == "mitre_attack":
            return _parse_mitre_stix(path)
        if source == "sigma":
            return _parse_sigma(path)
        if source == "yara":
            return (
                _parse_yara_repository_index(path)
                if path.suffix.lower() == ".json"
                else _parse_yara(path)
            )
        if source == "threat_intelligence":
            return _parse_threat_intelligence(path)
        if source in {"nist_cis", "playbooks"}:
            return _parse_guidance(path, source)
        raise ValueError(f"Không có parser cho nguồn {source}")

    def _replace_documents(
        self, source: str, documents: Sequence[KnowledgeDocument]
    ) -> None:
        now = _utcnow()
        with self._connect() as connection:
            connection.execute("DELETE FROM documents WHERE source = ?", (source,))
            if self._fts_enabled:
                connection.execute("DELETE FROM documents_fts WHERE source = ?", (source,))
            for document in documents:
                self._insert_document(connection, document, now)

    def _upsert_document(
        self, connection: sqlite3.Connection, document: KnowledgeDocument
    ) -> None:
        if self._fts_enabled:
            connection.execute("DELETE FROM documents_fts WHERE id = ?", (document.id,))
        self._insert_document(connection, document, _utcnow())

    def _insert_document(
        self,
        connection: sqlite3.Connection,
        document: KnowledgeDocument,
        updated_at: str,
    ) -> None:
        content_hash = hashlib.sha256(document.text.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO documents(
                id, source, document_type, title, text, origin,
                metadata_json, content_hash, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source=excluded.source,
                document_type=excluded.document_type,
                title=excluded.title,
                text=excluded.text,
                origin=excluded.origin,
                metadata_json=excluded.metadata_json,
                content_hash=excluded.content_hash,
                updated_at=excluded.updated_at
            """,
            (
                document.id,
                document.source,
                document.document_type,
                document.title,
                document.text,
                document.origin,
                json.dumps(document.metadata, ensure_ascii=False, default=str),
                content_hash,
                updated_at,
            ),
        )
        if self._fts_enabled:
            connection.execute(
                "INSERT INTO documents_fts(id, source, title, text) VALUES(?, ?, ?, ?)",
                (document.id, document.source, document.title, document.text),
            )

    def import_assets(
        self,
        data: str | bytes | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        filename: str = "enterprise-assets.json",
        mode: str = "merge",
    ) -> dict[str, Any]:
        """Import a CSV/JSON enterprise asset inventory.

        ``mode='merge'`` upserts by asset id. ``mode='replace'`` replaces only
        the enterprise asset inventory and leaves all other sources untouched.
        """

        if mode not in {"merge", "replace"}:
            raise ValueError("mode phải là 'merge' hoặc 'replace'.")
        rows = _read_asset_rows(data, filename)
        normalized = [
            _normalize_asset(row, filename, index)
            for index, row in enumerate(rows, start=1)
        ]
        normalized = [asset for asset in normalized if asset is not None]
        now = _utcnow()
        with self._connect() as connection:
            if mode == "replace":
                connection.execute("DELETE FROM assets")
                connection.execute(
                    "DELETE FROM documents WHERE source = 'enterprise_assets'"
                )
                if self._fts_enabled:
                    connection.execute(
                        "DELETE FROM documents_fts WHERE source = 'enterprise_assets'"
                    )
            for asset in normalized:
                connection.execute(
                    """
                    INSERT INTO assets(
                        asset_id, name, asset_type, owner, hostname, ip_address,
                        criticality, environment, tags_json, metadata_json,
                        source_file, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        name=excluded.name,
                        asset_type=excluded.asset_type,
                        owner=excluded.owner,
                        hostname=excluded.hostname,
                        ip_address=excluded.ip_address,
                        criticality=excluded.criticality,
                        environment=excluded.environment,
                        tags_json=excluded.tags_json,
                        metadata_json=excluded.metadata_json,
                        source_file=excluded.source_file,
                        updated_at=excluded.updated_at
                    """,
                    (
                        asset["asset_id"],
                        asset["name"],
                        asset["asset_type"],
                        asset["owner"],
                        asset["hostname"],
                        asset["ip_address"],
                        asset["criticality"],
                        asset["environment"],
                        json.dumps(asset["tags"], ensure_ascii=False),
                        json.dumps(asset["metadata"], ensure_ascii=False, default=str),
                        filename,
                        now,
                    ),
                )
                self._upsert_document(
                    connection, _asset_to_document(asset, filename)
                )
        self._update_source_state(
            "enterprise_assets",
            last_index_at=now,
            files_indexed=len(list(self._iter_source_files("enterprise_assets"))),
            last_error="",
        )
        return {
            "source": "enterprise_assets",
            "mode": mode,
            "imported": len(normalized),
            "assets": self.query_assets(limit=1_000_000)["count"],
            "status": self.status()["sources"]["enterprise_assets"],
        }

    def query_assets(
        self,
        query: str = "",
        *,
        asset_type: str = "",
        criticality: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> dict[str, Any]:
        clauses = []
        parameters: list[Any] = []
        if query.strip():
            value = f"%{query.strip()}%"
            clauses.append(
                "(name LIKE ? OR hostname LIKE ? OR ip_address LIKE ? "
                "OR owner LIKE ? OR tags_json LIKE ?)"
            )
            parameters.extend([value] * 5)
        for column, value in (
            ("asset_type", asset_type),
            ("criticality", criticality),
            ("environment", environment),
        ):
            if value.strip():
                clauses.append(f"LOWER({column}) = LOWER(?)")
                parameters.append(value.strip())
        count_sql = "SELECT COUNT(*) FROM assets"
        sql = "SELECT * FROM assets"
        if clauses:
            suffix = " WHERE " + " AND ".join(clauses)
            count_sql += suffix
            sql += suffix
        sql += " ORDER BY criticality DESC, name LIMIT ?"
        limit = max(1, min(1_000_000, int(limit)))
        with self._connect() as connection:
            count = int(connection.execute(count_sql, parameters).fetchone()[0])
            rows = list(connection.execute(sql, [*parameters, limit]))
        assets = []
        for row in rows:
            item = dict(row)
            item["tags"] = json.loads(item.pop("tags_json") or "[]")
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            assets.append(item)
        return {"count": count, "assets": assets}

    def _reindex_assets(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = list(connection.execute("SELECT * FROM assets"))
            connection.execute(
                "DELETE FROM documents WHERE source = 'enterprise_assets'"
            )
            if self._fts_enabled:
                connection.execute(
                    "DELETE FROM documents_fts WHERE source = 'enterprise_assets'"
                )
            for row in rows:
                asset = dict(row)
                asset["tags"] = json.loads(asset.pop("tags_json") or "[]")
                asset["metadata"] = json.loads(asset.pop("metadata_json") or "{}")
                self._insert_document(
                    connection,
                    _asset_to_document(asset, asset.get("source_file", "")),
                    _utcnow(),
                )
        now = _utcnow()
        self._update_source_state(
            "enterprise_assets", last_index_at=now, files_indexed=0, last_error=""
        )
        return {
            "source": "enterprise_assets",
            "files": 0,
            "documents": len(rows),
            "errors": [],
        }

    def _iter_source_files(self, source: str) -> Iterator[Path]:
        key = normalize_source(source)
        path = self.source_path(key)
        if path.is_file():
            yield path
            return
        if not path.exists():
            return
        extensions = {
            "sigma": {".yml", ".yaml"},
            "yara": {".yar", ".yara", ".json"},
            "threat_intelligence": {".json", ".stix", ".csv"},
            "nist_cis": {".pdf", ".docx", ".txt", ".md", ".html", ".htm"},
            "playbooks": {
                ".pdf", ".docx", ".txt", ".md", ".html", ".htm",
                ".yml", ".yaml", ".json",
            },
            "enterprise_assets": {".csv", ".json"},
        }.get(key, set())
        for candidate in sorted(path.rglob("*")):
            if (
                candidate.is_file()
                and candidate.suffix.lower() in extensions
                and not any(part.startswith(".") for part in candidate.relative_to(path).parts)
            ):
                yield candidate

    def _update_source_state(self, source: str, **values: Any) -> None:
        allowed = {"last_sync_at", "last_index_at", "last_error", "files_indexed"}
        update = {key: value for key, value in values.items() if key in allowed}
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO source_state(source) VALUES(?)", (source,)
            )
            if update:
                assignments = ", ".join(f"{key} = ?" for key in update)
                connection.execute(
                    f"UPDATE source_state SET {assignments} WHERE source = ?",
                    [*update.values(), source],
                )

    @staticmethod
    def _row_to_document(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "source": row["source"],
            "document_type": row["document_type"],
            "title": row["title"],
            "text": row["text"],
            "origin": row["origin"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
            "content_hash": row["content_hash"],
            "updated_at": row["updated_at"],
        }


def normalize_source(source: str) -> str:
    value = str(source).strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return SOURCE_ALIASES[value]
    except KeyError as exc:
        raise ValueError(
            f"Nguồn không hợp lệ: {source}. Hỗ trợ: {', '.join(SOURCE_ORDER)}"
        ) from exc


def _normalize_sources(sources: Sequence[str] | str | None) -> list[str]:
    if sources is None:
        return []
    values = sources.split(",") if isinstance(sources, str) else list(sources)
    return list(dict.fromkeys(normalize_source(item) for item in values if str(item).strip()))


def _parse_mitre_stix(path: Path) -> list[KnowledgeDocument]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    objects = payload.get("objects", []) if isinstance(payload, dict) else []
    supported = {
        "attack-pattern": "technique",
        "course-of-action": "mitigation",
        "x-mitre-data-source": "data_source",
        "x-mitre-data-component": "detection",
        "intrusion-set": "threat_actor",
        "malware": "malware",
        "tool": "tool",
        "campaign": "campaign",
        "relationship": "procedure",
    }
    documents = []
    names = {
        item.get("id"): item.get("name", item.get("id", ""))
        for item in objects
        if isinstance(item, dict)
    }
    for item in objects:
        if not isinstance(item, dict):
            continue
        stix_type = item.get("type", "")
        document_type = supported.get(stix_type)
        if not document_type or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        external_id = _stix_external_id(item)
        title = item.get("name") or external_id or item.get("id", stix_type)
        if stix_type == "relationship":
            source_name = names.get(item.get("source_ref"), item.get("source_ref", ""))
            target_name = names.get(item.get("target_ref"), item.get("target_ref", ""))
            title = f"{source_name} {item.get('relationship_type', '')} {target_name}"
        tactics = [
            phase.get("phase_name", "").replace("-", " ").title()
            for phase in item.get("kill_chain_phases", [])
            if isinstance(phase, dict)
        ]
        text = "\n".join(filter(None, (
            f"Name: {title}",
            f"MITRE ID: {external_id}" if external_id else "",
            f"Type: {stix_type}",
            f"Tactics: {', '.join(tactics)}" if tactics else "",
            _normalize_text(item.get("description", "")),
        )))
        if not text.strip():
            continue
        documents.append(KnowledgeDocument.create(
            source="mitre_attack",
            document_type=document_type,
            title=title,
            text=text,
            origin=str(path),
            native_id=item.get("id", external_id),
            metadata={
                "stix_id": item.get("id", ""),
                "external_id": external_id,
                "tactics": tactics,
                "modified": item.get("modified", ""),
                "relationship_type": item.get("relationship_type", ""),
                "source_ref": item.get("source_ref", ""),
                "target_ref": item.get("target_ref", ""),
            },
        ))
    return documents


def _parse_sigma(path: Path) -> list[KnowledgeDocument]:
    if path.suffix.lower() not in {".yml", ".yaml"}:
        return []
    if yaml is None:
        raise RuntimeError("Cần cài PyYAML để đọc Sigma rules.")
    content = path.read_text(encoding="utf-8-sig", errors="replace")
    documents = []
    for position, rule in enumerate(yaml.safe_load_all(content), start=1):
        if not isinstance(rule, dict) or rule.get("action") in {"global", "reset", "repeat"}:
            continue
        title = str(rule.get("title") or rule.get("name") or f"{path.stem} #{position}")
        native_id = str(rule.get("id") or f"{path}:{position}")
        logsource = rule.get("logsource") or {}
        detection = rule.get("detection") or {}
        tags = _as_string_list(rule.get("tags"))
        false_positives = _as_string_list(rule.get("falsepositives"))
        text = "\n".join(filter(None, (
            f"Sigma rule: {title}",
            f"Description: {_stringify(rule.get('description'))}",
            f"Status: {_stringify(rule.get('status'))}",
            f"Level: {_stringify(rule.get('level'))}",
            f"Log source: {_stringify(logsource)}",
            f"Detection: {_stringify(detection)}",
            f"Tags: {', '.join(tags)}" if tags else "",
            f"False positives: {', '.join(false_positives)}" if false_positives else "",
        )))
        documents.append(KnowledgeDocument.create(
            source="sigma",
            document_type="detection_rule",
            title=title,
            text=text,
            origin=str(path),
            native_id=native_id,
            metadata={
                "rule_id": native_id,
                "status": rule.get("status", ""),
                "level": rule.get("level", ""),
                "author": rule.get("author", ""),
                "tags": tags,
                "logsource": _json_safe(logsource),
                "references": _as_string_list(rule.get("references")),
            },
        ))
    return documents


def _parse_yara(path: Path) -> list[KnowledgeDocument]:
    if path.suffix.lower() not in {".yar", ".yara"}:
        return []
    content = path.read_text(encoding="utf-8-sig", errors="replace")
    documents = []
    for rule in _iter_yara_rules(content):
        meta = _parse_yara_meta(rule["body"])
        title = rule["name"]
        description = meta.get("description") or meta.get("desc") or ""
        text = "\n".join(filter(None, (
            f"YARA rule: {title}",
            f"Tags: {', '.join(rule['tags'])}" if rule["tags"] else "",
            f"Description: {description}" if description else "",
            f"Metadata: {_stringify(meta)}" if meta else "",
            rule["source"],
        )))
        documents.append(KnowledgeDocument.create(
            source="yara",
            document_type="malware_detection_rule",
            title=title,
            text=text,
            origin=str(path),
            native_id=f"{path}:{title}",
            metadata={
                "rule_name": title,
                "tags": rule["tags"],
                "meta": meta,
            },
        ))
    return documents


def _parse_yara_repository_index(path: Path) -> list[KnowledgeDocument]:
    """Create searchable YARA records from a GitHub recursive tree response.

    Full signature archives are frequently quarantined by endpoint protection
    because they intentionally contain malware byte patterns. The repository
    tree is still authoritative metadata: it provides the real rule paths,
    blob SHAs and provenance without weakening host antivirus controls.
    Organization-provided ``.yar``/``.yara`` files continue to use the full
    parser above.
    """

    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("tree"), list):
        raise ValueError("YARA repository index không đúng GitHub tree schema.")
    repository = "https://github.com/Yara-Rules/rules"
    documents = []
    for item in payload["tree"]:
        if not isinstance(item, dict) or item.get("type") != "blob":
            continue
        rule_path = str(item.get("path") or "")
        suffix = Path(rule_path).suffix.lower()
        if suffix not in {".yar", ".yara"}:
            continue
        title = Path(rule_path).stem
        category = str(Path(rule_path).parent).replace("\\", "/")
        blob_sha = str(item.get("sha") or "")
        browser_url = f"{repository}/blob/master/{urllib.parse.quote(rule_path)}"
        text = "\n".join(
            (
                f"YARA rule: {title}",
                f"Repository path: {rule_path}",
                f"Category: {category or 'root'}",
                f"Source repository: {repository}",
            )
        )
        documents.append(
            KnowledgeDocument.create(
                source="yara",
                document_type="malware_detection_rule_index",
                title=title,
                text=text,
                origin=browser_url,
                native_id=blob_sha or rule_path,
                metadata={
                    "rule_name": title,
                    "repository_path": rule_path,
                    "category": category,
                    "blob_sha": blob_sha,
                    "blob_url": item.get("url", ""),
                    "size": item.get("size", 0),
                    "content_mode": "safe_repository_metadata",
                },
            )
        )
    if not documents:
        raise ValueError("YARA repository index không chứa tệp .yar/.yara.")
    return documents


def _iter_yara_rules(content: str) -> Iterator[dict[str, Any]]:
    header_pattern = re.compile(
        r"(?im)^\s*(?:private\s+|global\s+)*rule\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?:\s*:\s*(?P<tags>[^\r\n{]+))?\s*\{"
    )
    for match in header_pattern.finditer(content):
        open_brace = match.end() - 1
        close_brace = _find_balanced_brace(content, open_brace)
        if close_brace is None:
            continue
        source = content[match.start():close_brace + 1]
        body = content[open_brace + 1:close_brace]
        tags = [item for item in re.split(r"\s+", (match.group("tags") or "").strip()) if item]
        yield {"name": match.group("name"), "tags": tags, "body": body, "source": source}


def _find_balanced_brace(content: str, opening: int) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(content):
        char = content[index]
        next_char = content[index + 1] if index + 1 < len(content) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
        elif block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char == "/" and next_char == "/":
            line_comment = True
            index += 1
        elif char == "/" and next_char == "*":
            block_comment = True
            index += 1
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _parse_yara_meta(body: str) -> dict[str, str]:
    match = re.search(r"(?is)\bmeta\s*:(.*?)(?:\bstrings\s*:|\bcondition\s*:)", body)
    if not match:
        return {}
    metadata = {}
    for line in match.group(1).splitlines():
        item = re.match(r'\s*([A-Za-z_][\w]*)\s*=\s*(?:"([^"]*)"|([^\r\n]+))', line)
        if item:
            metadata[item.group(1)] = (item.group(2) or item.group(3) or "").strip()
    return metadata


def _parse_threat_intelligence(path: Path) -> list[KnowledgeDocument]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            rows = list(csv.DictReader(handle))
        return [
            _threat_record_to_document(row, path, index)
            for index, row in enumerate(rows, start=1)
            if row
        ]
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    records = _threat_records(payload)
    return [
        _threat_record_to_document(record, path, index)
        for index, record in enumerate(records, start=1)
        if isinstance(record, dict)
    ]


def _threat_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("objects"), list):
        return [item for item in payload["objects"] if isinstance(item, dict)]
    for key in (
        "vulnerabilities", "indicators", "items", "results", "data",
        "threats", "iocs",
    ):
        if isinstance(payload.get(key), list):
            return [item for item in payload[key] if isinstance(item, dict)]
    return [payload]


def _threat_record_to_document(
    record: Mapping[str, Any], path: Path, index: int
) -> KnowledgeDocument:
    native_id = _first(record, "id", "cveID", "cve", "indicator", "value", "name")
    title = _first(
        record,
        "name",
        "vulnerabilityName",
        "title",
        "cveID",
        "indicator",
        "value",
    ) or f"{path.stem} #{index}"
    record_type = str(record.get("type") or (
        "known_exploited_vulnerability" if record.get("cveID") else "threat_record"
    ))
    description = _first(
        record,
        "description",
        "shortDescription",
        "notes",
        "summary",
        "pattern",
    )
    text = "\n".join(filter(None, (
        f"Threat intelligence: {title}",
        f"Type: {record_type}",
        f"Description: {description}" if description else "",
        f"Vendor/Product: {_first(record, 'vendorProject')} "
        f"{_first(record, 'product')}".strip(),
        f"Required action: {_first(record, 'requiredAction')}",
        f"Due date: {_first(record, 'dueDate')}",
        _stringify(record),
    )))
    return KnowledgeDocument.create(
        source="threat_intelligence",
        document_type=record_type,
        title=str(title),
        text=text,
        origin=str(path),
        native_id=str(native_id or index),
        metadata={
            "native_id": native_id,
            "record_type": record_type,
            "labels": _as_string_list(record.get("labels")),
            "created": record.get("created", record.get("dateAdded", "")),
            "modified": record.get("modified", ""),
        },
    )


def _parse_guidance(path: Path, source: str) -> list[KnowledgeDocument]:
    suffix = path.suffix.lower()
    if suffix in {".yml", ".yaml"}:
        if yaml is None:
            raise RuntimeError("Cần cài PyYAML để đọc playbook YAML.")
        payload = list(yaml.safe_load_all(
            path.read_text(encoding="utf-8-sig", errors="replace")
        ))
        text = _stringify(payload)
    elif suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        text = _stringify(payload)
    elif suffix in {".html", ".htm"}:
        parser = _HTMLTextExtractor()
        parser.feed(path.read_text(encoding="utf-8-sig", errors="replace"))
        text = parser.text()
    elif suffix in {".pdf", ".docx", ".txt", ".md"}:
        from document_parser import parse_document

        text = parse_document(path.name, path.read_bytes()).text
    else:
        return []
    title = _guidance_title(path, text)
    chunks = _chunk_text(text)
    document_type = (
        "incident_response_playbook" if source == "playbooks"
        else _infer_framework_type(path.name, text)
    )
    return [
        KnowledgeDocument.create(
            source=source,
            document_type=document_type,
            title=f"{title} — phần {index}/{len(chunks)}" if len(chunks) > 1 else title,
            text=chunk,
            origin=str(path),
            native_id=f"{path}:{index}",
            metadata={
                "document_title": title,
                "chunk": index,
                "chunks": len(chunks),
                "format": suffix.lstrip("."),
            },
        )
        for index, chunk in enumerate(chunks, start=1)
    ]


class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self.ignored_depth += 1
        elif tag in {"p", "br", "li", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self.ignored_depth:
            self.ignored_depth -= 1
        elif tag in {"p", "li", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.ignored_depth:
            self.parts.append(data)

    def text(self) -> str:
        return _normalize_text(" ".join(self.parts))


def _guidance_title(path: Path, text: str) -> str:
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if 8 <= len(first_line) <= 160:
        return first_line
    return path.stem.replace("_", " ").replace("-", " ").strip()


def _infer_framework_type(filename: str, text: str) -> str:
    value = f"{filename} {text[:500]}".lower()
    if "nist" in value:
        return "nist_guidance"
    if re.search(r"\bcis\b|center for internet security", value):
        return "cis_control"
    return "security_framework"


def _chunk_text(text: str, size: int = 1800, overlap: int = 250) -> list[str]:
    cleaned = _normalize_text(text)
    if not cleaned:
        return []
    chunks = []
    start = 0
    while start < len(cleaned):
        end = min(len(cleaned), start + size)
        if end < len(cleaned):
            boundary = max(
                cleaned.rfind("\n", start + size // 2, end),
                cleaned.rfind(". ", start + size // 2, end),
            )
            if boundary > start:
                end = boundary + 1
        chunk = cleaned[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(cleaned):
            break
        start = max(start + 1, end - overlap)
    return chunks


def _read_asset_rows(
    data: str | bytes | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
    filename: str,
) -> list[Mapping[str, Any]]:
    if isinstance(data, Path):
        filename = data.name
        raw: str | bytes = data.read_bytes()
    elif isinstance(data, Mapping):
        if isinstance(data.get("assets"), list):
            return [item for item in data["assets"] if isinstance(item, Mapping)]
        return [data]
    elif isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return [item for item in data if isinstance(item, Mapping)]
    else:
        raw = data
    if isinstance(raw, bytes):
        text = raw.decode("utf-8-sig", errors="replace")
    else:
        candidate = Path(raw)
        if "\n" not in raw and candidate.exists() and candidate.is_file():
            filename = candidate.name
            text = candidate.read_text(encoding="utf-8-sig", errors="replace")
        else:
            text = raw
    suffix = Path(filename).suffix.lower()
    if suffix == ".csv":
        return [dict(row) for row in csv.DictReader(io.StringIO(text))]
    if suffix == ".json" or text.lstrip().startswith(("[", "{")):
        payload = json.loads(text)
        if isinstance(payload, dict) and isinstance(payload.get("assets"), list):
            payload = payload["assets"]
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, Mapping)]
        raise ValueError("JSON inventory phải là object, array hoặc có trường assets.")
    raise ValueError("Enterprise Assets chỉ hỗ trợ CSV hoặc JSON.")


def _normalize_asset(
    row: Mapping[str, Any], filename: str, index: int
) -> dict[str, Any] | None:
    lowered = {_canonical_key(str(key)): value for key, value in row.items()}

    def value(*keys: str) -> str:
        for key in keys:
            candidate = lowered.get(_canonical_key(key))
            if candidate is not None and str(candidate).strip():
                return str(candidate).strip()
        return ""

    name = value("name", "asset_name", "system_name", "device_name")
    hostname = value("hostname", "host_name", "fqdn")
    ip_address = value("ip_address", "ip", "address")
    explicit_id = value("asset_id", "id", "ci_id", "device_id")
    if not any((name, hostname, ip_address, explicit_id)):
        return None
    asset_id = explicit_id or hashlib.sha256(
        f"{name}|{hostname}|{ip_address}".encode("utf-8")
    ).hexdigest()[:24]
    tags_raw = lowered.get("tags", lowered.get("tag", []))
    if isinstance(tags_raw, list):
        tags = [str(item).strip() for item in tags_raw if str(item).strip()]
    else:
        tags = [
            item.strip() for item in re.split(r"[,;|]", str(tags_raw))
            if item.strip()
        ]
    known = {
        _canonical_key(item)
        for item in (
            "asset_id", "id", "ci_id", "device_id", "name", "asset_name",
            "system_name", "device_name", "asset_type", "type", "category",
            "owner", "business_owner", "custodian", "hostname", "host_name",
            "fqdn", "ip_address", "ip", "address", "criticality", "severity",
            "business_impact", "environment", "env", "zone", "tags", "tag",
        )
    }
    metadata = {
        key: _json_safe(value)
        for key, value in row.items()
        if _canonical_key(str(key)) not in known
    }
    return {
        "asset_id": asset_id,
        "name": name or hostname or ip_address or explicit_id or f"Asset {index}",
        "asset_type": value("asset_type", "type", "category"),
        "owner": value("owner", "business_owner", "custodian"),
        "hostname": hostname,
        "ip_address": ip_address,
        "criticality": value("criticality", "severity", "business_impact"),
        "environment": value("environment", "env", "zone"),
        "tags": tags,
        "metadata": metadata,
        "source_file": filename,
    }


def _asset_to_document(asset: Mapping[str, Any], filename: str) -> KnowledgeDocument:
    text = "\n".join(filter(None, (
        f"Enterprise asset: {asset.get('name', '')}",
        f"Asset ID: {asset.get('asset_id', '')}",
        f"Type: {asset.get('asset_type', '')}",
        f"Owner: {asset.get('owner', '')}",
        f"Hostname: {asset.get('hostname', '')}",
        f"IP address: {asset.get('ip_address', '')}",
        f"Criticality: {asset.get('criticality', '')}",
        f"Environment: {asset.get('environment', '')}",
        f"Tags: {', '.join(asset.get('tags', []))}" if asset.get("tags") else "",
        f"Metadata: {_stringify(asset.get('metadata', {}))}" if asset.get("metadata") else "",
    )))
    document = KnowledgeDocument.create(
        source="enterprise_assets",
        document_type="enterprise_asset",
        title=str(asset.get("name", "Enterprise asset")),
        text=text,
        origin=filename,
        native_id=str(asset.get("asset_id", "")),
        metadata={
            "asset_id": asset.get("asset_id", ""),
            "asset_type": asset.get("asset_type", ""),
            "criticality": asset.get("criticality", ""),
            "environment": asset.get("environment", ""),
            "hostname": asset.get("hostname", ""),
            "ip_address": asset.get("ip_address", ""),
            "source_file": filename,
        },
    )
    # Asset identity belongs to the CMDB record, not to the uploaded filename.
    # This makes a later import from another file update the existing document.
    document.id = hashlib.sha256(
        f"enterprise_assets|{asset.get('asset_id', '')}".encode("utf-8")
    ).hexdigest()
    return document


def _stix_external_id(item: Mapping[str, Any]) -> str:
    for reference in item.get("external_references", []) or []:
        if isinstance(reference, dict) and reference.get("external_id"):
            return str(reference["external_id"])
    return ""


def _first(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)] if str(value).strip() else []


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return _normalize_text(value)
    return json.dumps(_json_safe(value), ensure_ascii=False, default=str, sort_keys=True)


def _normalize_text(value: Any) -> str:
    text = str(value or "").replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _safe_rmtree(path: Path, root: Path, *, ignore_errors: bool = False) -> None:
    """Recursively remove only descendants of the configured source root."""
    resolved = Path(path).resolve()
    allowed = Path(root).resolve()
    if resolved == allowed or allowed not in resolved.parents:
        raise ValueError(f"Từ chối xóa đường dẫn ngoài source root: {resolved}")
    shutil.rmtree(resolved, ignore_errors=ignore_errors)


def _canonical_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _query_tokens(query: str) -> list[str]:
    return list(dict.fromkeys(
        token.lower()
        for token in re.findall(r"[\w.-]+", query, flags=re.UNICODE)
        if len(token) > 1
    ))


def _best_snippet(text: str, tokens: Sequence[str], length: int = 360) -> str:
    lowered = text.lower()
    positions = [lowered.find(token.lower()) for token in tokens]
    positions = [position for position in positions if position >= 0]
    start = max(0, (min(positions) if positions else 0) - length // 4)
    end = min(len(text), start + length)
    snippet = text[start:end].strip()
    if start:
        snippet = "… " + snippet
    if end < len(text):
        snippet += " …"
    return snippet


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


_DEFAULT_KB: KnowledgeBase | None = None


def get_knowledge_base(*, refresh: bool = False) -> KnowledgeBase:
    global _DEFAULT_KB
    if _DEFAULT_KB is None or refresh:
        _DEFAULT_KB = KnowledgeBase()
    return _DEFAULT_KB


def status() -> dict[str, Any]:
    """Flask-callable status facade."""

    return get_knowledge_base().status()


def sync(source: str = "all") -> dict[str, Any]:
    """Flask-callable synchronization facade."""

    return get_knowledge_base().sync(source)


def search(
    query: str,
    sources: Sequence[str] | str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Flask-callable search facade."""

    return get_knowledge_base().search(query, sources=sources, limit=limit)


def import_assets(
    data: str | bytes | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
    filename: str = "enterprise-assets.json",
    mode: str = "merge",
) -> dict[str, Any]:
    """Flask-callable asset import facade."""

    return get_knowledge_base().import_assets(data, filename=filename, mode=mode)


def query_assets(query: str = "", **filters: Any) -> dict[str, Any]:
    """Flask-callable enterprise inventory query facade."""

    return get_knowledge_base().query_assets(query, **filters)
