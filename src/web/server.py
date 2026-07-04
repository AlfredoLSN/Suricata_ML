from __future__ import annotations

import os
import sys
from pathlib import Path

import psutil
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.web.alert_store import AlertStore
from src.web.pipeline_manager import PipelineManager, discover_model_paths
from src.web.schemas import (
    AlertResponse,
    ConfigOptionsResponse,
    PipelineStatusResponse,
    ResultSummaryResponse,
    StartPipelineRequest,
)


DEFAULT_ALERT_DB_PATH = PROJECT_ROOT / "data" / "web" / "alerts.sqlite3"
STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Suricata ML Web", version="1.0.0")
alert_store = AlertStore(DEFAULT_ALERT_DB_PATH)
pipeline_manager = PipelineManager(PROJECT_ROOT, alert_store)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config/options", response_model=ConfigOptionsResponse)
def config_options() -> ConfigOptionsResponse:
    interfaces = sorted(psutil.net_if_addrs().keys())
    models = discover_model_paths(PROJECT_ROOT)
    defaults = {
        "alert_db_path": str(DEFAULT_ALERT_DB_PATH.relative_to(PROJECT_ROOT)),
        "capture_output_dir": "data/raw/captures",
        "flow_output_dir": "data/processed/flows",
        "classified_flow_output_dir": "data/processed/classified_flows",
        "classification_enabled": True,
        "threat_response_mode": "internal",
        "rotation_seconds": 60,
    }
    return ConfigOptionsResponse(interfaces=interfaces, models=models, defaults=defaults)


@app.post("/api/pipeline/start", response_model=PipelineStatusResponse)
def start_pipeline(request: StartPipelineRequest) -> PipelineStatusResponse:
    model_path = resolve_model_path(request.model_path)
    ignored_ips = [ip.strip() for ip in request.ignored_source_ips if ip.strip()]
    try:
        pipeline_manager.start(
            network_interface=request.network_interface.strip(),
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


def resolve_model_path(raw_path: str) -> Path:
    path = Path(raw_path.strip())
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
