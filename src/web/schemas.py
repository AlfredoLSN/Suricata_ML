from __future__ import annotations

from pydantic import BaseModel, Field


class StartPipelineRequest(BaseModel):
    network_interface: str = Field(min_length=1)
    ignored_source_ips: list[str] = Field(default_factory=list)


class PipelineStatusResponse(BaseModel):
    state: str
    run_id: str | None = None
    started_at: str | None = None
    stopped_at: str | None = None
    network_interface: str | None = None
    model_path: str | None = None
    last_error: str | None = None
    pcap_count: int = 0
    flow_csv_count: int = 0
    classified_count: int = 0
    classification_total: int = 0
    alert_count: int = 0
    capture_running: bool = False
    extraction_running: bool = False


class ConfigOptionsResponse(BaseModel):
    interfaces: list[str]
    defaults: dict[str, object]


class AlertResponse(BaseModel):
    id: int
    run_id: str | None
    created_at: str
    source_ip: str | None
    destination_ip: str | None
    source_port: str | None
    destination_port: str | None
    protocol: str | None
    prediction_label: str
    prediction_confidence: float | None


class ClassificationResponse(BaseModel):
    file_path: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: str | None = None
    destination_port: str | None = None
    protocol: str | None = None
    prediction_label: str
    prediction_confidence: float | None = None


class EventResponse(BaseModel):
    id: int
    run_id: str | None
    created_at: str
    level: str
    message: str


class ResultSummaryResponse(BaseModel):
    prediction_counts: dict[str, int]
    recent_events: list[EventResponse]
