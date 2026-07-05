from __future__ import annotations

import os
import sys
from pathlib import Path

import psutil
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.web.alert_store import AlertStore
from src.web.pipeline_manager import DEFAULT_CLASSIFICATION_MODEL_PATH, PipelineManager
from src.web.schemas import (
    AlertResponse,
    ClassificationResponse,
    ConfigOptionsResponse,
    PipelineStatusResponse,
    ResultSummaryResponse,
    StartPipelineRequest,
)


DEFAULT_ALERT_DB_PATH = PROJECT_ROOT / "data" / "web" / "alerts.sqlite3"
STATIC_DIR = Path(__file__).resolve().parent / "static"

load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

app = FastAPI(title="Suricata ML Web", version="1.0.0")
alert_store = AlertStore(DEFAULT_ALERT_DB_PATH)
pipeline_manager = PipelineManager(PROJECT_ROOT, alert_store)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config/options", response_model=ConfigOptionsResponse)
def config_options() -> ConfigOptionsResponse:
    interfaces = sorted(available_network_interfaces())
    defaults = {
        "alert_db_path": str(DEFAULT_ALERT_DB_PATH.relative_to(PROJECT_ROOT)),
        "capture_output_dir": "data/raw/captures",
        "flow_output_dir": "data/processed/flows",
        "classification_enabled": True,
        "classification_model_path": display_path(configured_model_path()),
        "threat_response_mode": "internal",
        "rotation_seconds": 60,
    }
    return ConfigOptionsResponse(interfaces=interfaces, defaults=defaults)


@app.post("/api/pipeline/start", response_model=PipelineStatusResponse)
def start_pipeline(request: StartPipelineRequest) -> PipelineStatusResponse:
    network_interface = request.network_interface.strip()
    available_interfaces = available_network_interfaces()
    if network_interface not in available_interfaces:
        raise HTTPException(status_code=400, detail="Interface de rede invalida.")

    model_path = configured_model_path()
    ignored_ips = [ip.strip() for ip in request.ignored_source_ips if ip.strip()]
    try:
        pipeline_manager.start(
            network_interface=network_interface,
            model_path=model_path,
            ignored_source_ips=ignored_ips,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PipelineStatusResponse(**pipeline_manager.status())


@app.post("/api/pipeline/pause", response_model=PipelineStatusResponse)
def pause_pipeline() -> PipelineStatusResponse:
    pipeline_manager.pause()
    return PipelineStatusResponse(**pipeline_manager.status())


@app.get("/api/pipeline/status", response_model=PipelineStatusResponse)
def pipeline_status() -> PipelineStatusResponse:
    return PipelineStatusResponse(**pipeline_manager.status())


@app.get("/api/alerts", response_model=list[AlertResponse])
def alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    label: str | None = Query(default=None),
) -> list[AlertResponse]:
    return [AlertResponse(**record.__dict__) for record in alert_store.list_alerts(
        limit=limit,
        offset=offset,
        label=label,
    )]


@app.get("/api/results/summary", response_model=ResultSummaryResponse)
def result_summary() -> ResultSummaryResponse:
    return ResultSummaryResponse(**pipeline_manager.result_summary())


@app.get("/api/results/classifications", response_model=list[ClassificationResponse])
def recent_classifications(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[ClassificationResponse]:
    return [
        ClassificationResponse(**record)
        for record in pipeline_manager.recent_classifications(limit=limit, offset=offset)
    ]


def configured_model_path() -> Path:
    return resolve_config_path(
        os.getenv("CLASSIFICATION_MODEL_PATH", DEFAULT_CLASSIFICATION_MODEL_PATH)
    )


def available_network_interfaces() -> set[str]:
    try:
        return set(psutil.net_if_addrs().keys())
    except OSError:
        return set()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def resolve_config_path(raw_path: str) -> Path:
    path = Path(raw_path.strip() or DEFAULT_CLASSIFICATION_MODEL_PATH)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def main() -> None:
    import uvicorn

    host = os.getenv("WEB_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_PORT", "8000"))
    uvicorn.run("src.web.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
