from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AlertRecord:
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


@dataclass(frozen=True)
class PipelineEventRecord:
    id: int
    run_id: str | None
    created_at: str
    level: str
    message: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AlertStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    stopped_at TEXT,
                    status TEXT NOT NULL,
                    network_interface TEXT NOT NULL,
                    model_path TEXT NOT NULL,
                    ignored_source_ips TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    created_at TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port TEXT,
                    destination_port TEXT,
                    protocol TEXT,
                    prediction_label TEXT NOT NULL,
                    prediction_confidence REAL,
                    FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS pipeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    created_at TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES pipeline_runs(run_id)
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                    ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_label
                    ON alerts(prediction_label);
                CREATE INDEX IF NOT EXISTS idx_alerts_run_id
                    ON alerts(run_id);
                CREATE INDEX IF NOT EXISTS idx_pipeline_events_created_at
                    ON pipeline_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_pipeline_events_run_id
                    ON pipeline_events(run_id);
                """
            )
            connection.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )

    def create_run(
        self,
        *,
        network_interface: str,
        model_path: str,
        ignored_source_ips: Iterable[str],
    ) -> str:
        run_id = str(uuid.uuid4())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pipeline_runs (
                    run_id,
                    started_at,
                    status,
                    network_interface,
                    model_path,
                    ignored_source_ips
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    utc_now_iso(),
                    "running",
                    network_interface,
                    model_path,
                    ",".join(ignored_source_ips),
                ),
            )
        return run_id

    def finish_run(self, run_id: str | None, status: str) -> None:
        if not run_id:
            return
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE pipeline_runs
                SET stopped_at = ?, status = ?
                WHERE run_id = ?
                """,
                (utc_now_iso(), status, run_id),
            )

    def add_event(self, *, run_id: str | None, level: str, message: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pipeline_events (run_id, created_at, level, message)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, utc_now_iso(), level.upper(), message),
            )

    def add_alerts(self, run_id: str | None, threat_flows: Iterable[object]) -> int:
        rows = []
        for threat_flow in threat_flows:
            rows.append(
                (
                    run_id,
                    utc_now_iso(),
                    getattr(threat_flow, "source_ip", None),
                    getattr(threat_flow, "destination_ip", None),
                    getattr(threat_flow, "source_port", None),
                    getattr(threat_flow, "destination_port", None),
                    getattr(threat_flow, "protocol", None),
                    str(getattr(threat_flow, "prediction_label")),
                    getattr(threat_flow, "prediction_confidence", None),
                )
            )
        if not rows:
            return 0
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO alerts (
                    run_id,
                    created_at,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    protocol,
                    prediction_label,
                    prediction_confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def list_alerts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        label: str | None = None,
    ) -> list[AlertRecord]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        filters: list[str] = []
        params: list[object] = []
        if label:
            filters.append("prediction_label = ?")
            params.append(label)

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        query = f"""
            SELECT
                id,
                run_id,
                created_at,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
                prediction_label,
                prediction_confidence
            FROM alerts
            {where_clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [AlertRecord(**dict(row)) for row in rows]

    def list_events(self, *, limit: int = 10) -> list[PipelineEventRecord]:
        limit = max(1, min(limit, 100))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, run_id, created_at, level, message
                FROM pipeline_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [PipelineEventRecord(**dict(row)) for row in rows]

    def count_alerts(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()
        return int(row["count"])

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()
