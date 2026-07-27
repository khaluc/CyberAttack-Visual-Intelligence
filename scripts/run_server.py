"""Run the Flask application without the development reloader."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# Several supported settings intentionally use project-relative paths.  Keep
# them stable even when this script is invoked from another working directory.
os.chdir(PROJECT_ROOT)

from app import app  # noqa: E402


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local CyberVision Flask server without a reloader."
    )
    parser.add_argument("--host", default=os.getenv("CVI_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port",
        type=_port,
        default=os.getenv("CVI_PORT", "5000"),
    )
    parser.add_argument(
        "--debug",
        action=argparse.BooleanOptionalAction,
        default=_env_flag("CVI_DEBUG"),
        help="Enable Flask debug mode (the reloader always remains disabled).",
    )
    args = parser.parse_args()
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
