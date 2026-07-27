"""Safe runtime configuration with optional .env persistence."""
from pathlib import Path
from threading import Lock
from llm_service import LLMConfig, PROVIDER_DEFAULTS

ENV_PATH = Path(__file__).resolve().parent / ".env"
_lock = Lock()


def _load_env_file():
    """Load the project .env without adding a dependency."""
    if not ENV_PATH.exists():
        return
    import os
    for raw in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1].replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")
        os.environ.setdefault(key.strip(), value)


_load_env_file()
_runtime = LLMConfig.from_env()


def get_config():
    return _runtime


def preview_config(data):
    """Validate a settings payload without changing the live runtime."""
    current = _runtime
    provider = str(data.get("provider", current.provider)).lower()
    if provider not in PROVIDER_DEFAULTS:
        raise ValueError(
            "Provider không được hỗ trợ: "
            f"{provider}. Chọn {', '.join(PROVIDER_DEFAULTS)}."
        )
    default_url, default_model = PROVIDER_DEFAULTS[provider]
    api_key = str(data.get("api_key", "")).strip()
    retained_api_key = current.api_key if provider == current.provider else ""
    return LLMConfig(
        enabled=bool(data.get("enabled", current.enabled)),
        provider=provider,
        api_key=api_key if api_key else retained_api_key,
        base_url=str(data.get("base_url", "") or default_url).rstrip("/"),
        model=str(data.get("model", "") or default_model),
        temperature=max(0, min(2, float(data.get("temperature", current.temperature)))),
        timeout=max(5, min(300, int(data.get("timeout", current.timeout)))),
        rag_enabled=bool(data.get("rag_enabled", current.rag_enabled)),
        system_prompt=str(data.get("system_prompt", current.system_prompt)),
        azure_api_version=str(data.get("azure_api_version", current.azure_api_version)),
    )


def update_config(data, persist=False):
    global _runtime
    _runtime = preview_config(data)
    if persist:
        _write_env(_runtime)
    return _runtime


def _write_env(config):
    values = {
        "LLM_ENABLED": str(config.enabled).lower(), "LLM_PROVIDER": config.provider,
        "LLM_API_KEY": config.api_key, "LLM_BASE_URL": config.base_url,
        "LLM_MODEL": config.model, "LLM_TEMPERATURE": config.temperature,
        "LLM_TIMEOUT": config.timeout, "RAG_ENABLED": str(config.rag_enabled).lower(),
        "LLM_SYSTEM_PROMPT": config.system_prompt,
        "AZURE_OPENAI_API_VERSION": config.azure_api_version,
    }
    if config.provider == "dashscope":
        values["DASHSCOPE_API_KEY"] = config.api_key
    def quote(value):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    with _lock:
        existing_lines = (
            ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
        )
        output, written = [], set()
        for raw in existing_lines:
            stripped = raw.strip()
            key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
            if key in values:
                output.append(f"{key}={quote(values[key])}")
                written.add(key)
            else:
                output.append(raw)
        for key, value in values.items():
            if key not in written:
                output.append(f"{key}={quote(value)}")
        ENV_PATH.write_text("\n".join(output) + "\n", encoding="utf-8")
