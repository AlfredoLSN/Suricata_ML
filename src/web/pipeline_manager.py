from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.web.alert_store import AlertStore


PROCESS_STOP_TIMEOUT_SECONDS = 15
EXTRACTION_QUIET_SECONDS = 8
DEFAULT_CAPTURE_OUTPUT_DIR = "data/raw/captures"
DEFAULT_FLOW_OUTPUT_DIR = "data/processed/flows"
DEFAULT_CLASSIFIED_FLOW_OUTPUT_DIR = "data/processed/classified_flows"
DEFAULT_CLASSIFICATION_MODEL_PATH = "modelo/pipeline.joblib"
DEFAULT_CLASSIFICATION_LABEL_ENCODER_PATH = "modelo/label_encoder.joblib"
DEFAULT_WEB_LOG_DIR = "data/web/logs"
LOG_TAIL_LINES = 8


@dataclass(frozen=True)
class PipelinePaths:
    capture_dir: Path
    flow_output_dir: Path
    classified_flow_output_dir: Path
    alert_db_path: Path


@dataclass
class PipelineSnapshot:
    state: str = "stopped"
    run_id: str | None = None
    started_at: str | None = None
    stopped_at: str | None = None
    network_interface: str | None = None
    model_path: str | None = None
    last_error: str | None = None


class PipelineManager:
    def __init__(self, project_root: Path, alert_store: AlertStore) -> None:
        self.project_root = project_root
        self.alert_store = alert_store
        self.paths = PipelinePaths(
            capture_dir=project_root / DEFAULT_CAPTURE_OUTPUT_DIR,
            flow_output_dir=project_root / DEFAULT_FLOW_OUTPUT_DIR,
            classified_flow_output_dir=project_root / DEFAULT_CLASSIFIED_FLOW_OUTPUT_DIR,
            alert_db_path=alert_store.db_path,
        )
        self._lock = threading.RLock()
        self._snapshot = PipelineSnapshot()
        self._capture_process: subprocess.Popen[str] | None = None
        self._extraction_process: subprocess.Popen[str] | None = None
        self._monitor_thread: threading.Thread | None = None

    def start(
        self,
        *,
        network_interface: str,
        model_path: Path,
        ignored_source_ips: list[str],
    ) -> PipelineSnapshot:
        with self._lock:
            self._refresh_process_state_locked()
            if self._snapshot.state in {"starting", "capturing", "pausing", "processing_pending"}:
                raise RuntimeError("O pipeline ja esta em execucao.")
            if not model_path.is_file():
                raise ValueError(f"Modelo nao encontrado: {model_path}")

            self._ensure_directories()
            run_id = self.alert_store.create_run(
                network_interface=network_interface,
                model_path=str(model_path),
                ignored_source_ips=ignored_source_ips,
            )
            started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._snapshot = PipelineSnapshot(
                state="starting",
                run_id=run_id,
                started_at=started_at,
                network_interface=network_interface,
                model_path=str(model_path),
            )
            self.alert_store.add_event(
                run_id=run_id,
                level="INFO",
                message="Iniciando captura, extracao e classificacao.",
            )

            env = self._build_child_environment(
                network_interface=network_interface,
                model_path=model_path,
                ignored_source_ips=ignored_source_ips,
                run_id=run_id,
            )
            try:
                self._extraction_process = self._start_python_script(
                    Path("src/capture/flow_extraction_service.py"),
                    env=env,
                    run_id=run_id,
                )
                self._capture_process = self._start_python_script(
                    Path("src/capture/traffic_capture.py"),
                    env=env,
                    run_id=run_id,
                )
            except Exception as exc:
                self._snapshot.state = "error"
                self._snapshot.last_error = str(exc)
                self.alert_store.add_event(run_id=run_id, level="ERROR", message=str(exc))
                self._terminate_processes_locked()
                self.alert_store.finish_run(run_id, "error")
                raise

            self._snapshot.state = "capturing"
            self._monitor_thread = threading.Thread(
                target=self._monitor_processes,
                name="pipeline-monitor",
                daemon=True,
            )
            self._monitor_thread.start()
            return self._copy_snapshot_locked()

    def pause(self) -> PipelineSnapshot:
        with self._lock:
            self._refresh_process_state_locked()
            if self._snapshot.state not in {"capturing", "starting"}:
                return self._copy_snapshot_locked()

            self._snapshot.state = "pausing"
            self.alert_store.add_event(
                run_id=self._snapshot.run_id,
                level="INFO",
                message="Pausa solicitada pela interface.",
            )
            self._terminate_process(self._capture_process)
            self._capture_process = None
            self._snapshot.state = "processing_pending"

        threading.Thread(
            target=self._stop_extraction_after_quiet_period,
            name="pipeline-pause-finalizer",
            daemon=True,
        ).start()
        with self._lock:
            return self._copy_snapshot_locked()

    def status(self) -> dict[str, object]:
        with self._lock:
            self._refresh_process_state_locked()
            snapshot = self._copy_snapshot_locked()
            return {
                "state": snapshot.state,
                "run_id": snapshot.run_id,
                "started_at": snapshot.started_at,
                "stopped_at": snapshot.stopped_at,
                "network_interface": snapshot.network_interface,
                "model_path": snapshot.model_path,
                "last_error": snapshot.last_error,
                "pcap_count": self._count_files(self.paths.capture_dir, "*.pcap"),
                "flow_csv_count": self._count_files(self.paths.flow_output_dir, "*.csv"),
                "classified_csv_count": self._count_files(
                    self.paths.classified_flow_output_dir,
                    "*.csv",
                ),
                "alert_count": self.alert_store.count_alerts(),
                "capture_running": self._is_running(self._capture_process),
                "extraction_running": self._is_running(self._extraction_process),
            }

    def result_summary(self) -> dict[str, object]:
        prediction_counts: dict[str, int] = {}
        recent_files = sorted(
            self.paths.classified_flow_output_dir.glob("*.csv"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:5]
        for csv_path in recent_files:
            try:
                df = pd.read_csv(csv_path, usecols=["Prediction Label"])
            except Exception:
                continue
            counts = df["Prediction Label"].astype(str).value_counts().to_dict()
            for label, count in counts.items():
                prediction_counts[str(label)] = prediction_counts.get(str(label), 0) + int(count)

        return {
            "prediction_counts": prediction_counts,
            "recent_classified_files": [str(path.relative_to(self.project_root)) for path in recent_files],
            "recent_events": [
                event.__dict__ for event in self.alert_store.list_events(limit=10)
            ],
        }

    def _build_child_environment(
        self,
        *,
        network_interface: str,
        model_path: Path,
        ignored_source_ips: list[str],
        run_id: str,
    ) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.project_root)
        env["NETWORK_INTERFACE"] = network_interface
        env["CAPTURE_SUDO_NON_INTERACTIVE"] = "true"
        env["CAPTURE_OUTPUT_DIR"] = str(self.paths.capture_dir)
        env["FLOW_OUTPUT_DIR"] = str(self.paths.flow_output_dir)
        env["CLASSIFIED_FLOW_OUTPUT_DIR"] = str(self.paths.classified_flow_output_dir)
        env["CLASSIFICATION_ENABLED"] = "true"
        env["CLASSIFICATION_MODEL_PATH"] = str(model_path)
        default_encoder = self.project_root / DEFAULT_CLASSIFICATION_LABEL_ENCODER_PATH
        env["CLASSIFICATION_LABEL_ENCODER_PATH"] = str(default_encoder) if default_encoder.is_file() else ""
        env["CLASSIFICATION_EXCLUDED_SRC_IP"] = ",".join(ignored_source_ips)
        env["CLASSIFICATION_REMOVE_SRC_IP"] = "true"
        env["CLASSIFICATION_BENIGN_LABELS"] = "BENIGN,0"
        env["THREAT_RESPONSE_MODE"] = "internal"
        env["INTERNAL_ALERT_DB_PATH"] = str(self.paths.alert_db_path)
        env["PIPELINE_RUN_ID"] = run_id
        return env

    def _start_python_script(
        self,
        relative_script: Path,
        *,
        env: dict[str, str],
        run_id: str,
    ) -> subprocess.Popen[str]:
        command = [sys.executable, str(self.project_root / relative_script)]
        log_path = self._script_log_path(run_id, relative_script)
        log_file = log_path.open("a", encoding="utf-8")
        kwargs: dict[str, object] = {
            "cwd": str(self.project_root),
            "env": env,
            "stdout": log_file,
            "stderr": subprocess.STDOUT,
            "text": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["process_group"] = 0
        try:
            return subprocess.Popen(command, **kwargs)
        finally:
            log_file.close()

    def _monitor_processes(self) -> None:
        while True:
            time.sleep(2)
            with self._lock:
                self._refresh_process_state_locked()
                if self._snapshot.state in {"stopped", "error"}:
                    return

    def _refresh_process_state_locked(self) -> None:
        if self._snapshot.state in {"stopped", "error", "processing_pending"}:
            return
        capture_returncode = self._capture_process.poll() if self._capture_process else None
        extraction_returncode = self._extraction_process.poll() if self._extraction_process else None
        if capture_returncode not in (None, 0):
            self._snapshot.state = "error"
            self._snapshot.last_error = self._format_process_error(
                "Captura",
                capture_returncode,
                Path("src/capture/traffic_capture.py"),
            )
            self.alert_store.add_event(
                run_id=self._snapshot.run_id,
                level="ERROR",
                message=self._snapshot.last_error,
            )
            self.alert_store.finish_run(self._snapshot.run_id, "error")
        if extraction_returncode not in (None, 0):
            self._snapshot.state = "error"
            self._snapshot.last_error = self._format_process_error(
                "Extracao/classificacao",
                extraction_returncode,
                Path("src/capture/flow_extraction_service.py"),
            )
            self.alert_store.add_event(
                run_id=self._snapshot.run_id,
                level="ERROR",
                message=self._snapshot.last_error,
            )
            self.alert_store.finish_run(self._snapshot.run_id, "error")

    def _stop_extraction_after_quiet_period(self) -> None:
        last_counts = self._file_counts()
        last_change = time.monotonic()
        while time.monotonic() - last_change < EXTRACTION_QUIET_SECONDS:
            time.sleep(1)
            current_counts = self._file_counts()
            if current_counts != last_counts:
                last_counts = current_counts
                last_change = time.monotonic()

        with self._lock:
            self._terminate_process(self._extraction_process)
            self._extraction_process = None
            self._snapshot.state = "stopped"
            self._snapshot.stopped_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self.alert_store.add_event(
                run_id=self._snapshot.run_id,
                level="INFO",
                message="Pipeline pausado com seguranca.",
            )
            self.alert_store.finish_run(self._snapshot.run_id, "paused")

    def _terminate_processes_locked(self) -> None:
        self._terminate_process(self._capture_process)
        self._terminate_process(self._extraction_process)
        self._capture_process = None
        self._extraction_process = None

    def _terminate_process(self, process: subprocess.Popen[str] | None) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGINT)
            process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
            return
        except Exception:
            pass
        try:
            process.terminate()
            process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def _ensure_directories(self) -> None:
        self.paths.capture_dir.mkdir(parents=True, exist_ok=True)
        self.paths.flow_output_dir.mkdir(parents=True, exist_ok=True)
        self.paths.classified_flow_output_dir.mkdir(parents=True, exist_ok=True)
        (self.project_root / DEFAULT_WEB_LOG_DIR).mkdir(parents=True, exist_ok=True)

    def _format_process_error(
        self,
        process_label: str,
        returncode: int,
        relative_script: Path,
    ) -> str:
        message = f"{process_label} encerrou com codigo {returncode}."
        log_tail = self._read_recent_log_lines(relative_script)
        if log_tail:
            message = f"{message} Ultimas mensagens: {log_tail}"
        return message

    def _read_recent_log_lines(self, relative_script: Path) -> str:
        run_id = self._snapshot.run_id
        if not run_id:
            return ""
        log_path = self._script_log_path(run_id, relative_script)
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        useful_lines = [line.strip() for line in lines if line.strip()]
        return " | ".join(useful_lines[-LOG_TAIL_LINES:])

    def _script_log_path(self, run_id: str, relative_script: Path) -> Path:
        log_dir = self.project_root / DEFAULT_WEB_LOG_DIR
        log_dir.mkdir(parents=True, exist_ok=True)
        script_name = relative_script.stem.replace("_", "-")
        return log_dir / f"{run_id}-{script_name}.log"

    def _file_counts(self) -> tuple[int, int, int]:
        return (
            self._count_files(self.paths.capture_dir, "*.pcap"),
            self._count_files(self.paths.flow_output_dir, "*.csv"),
            self._count_files(self.paths.classified_flow_output_dir, "*.csv"),
        )

    @staticmethod
    def _count_files(directory: Path, pattern: str) -> int:
        if not directory.is_dir():
            return 0
        return sum(1 for path in directory.glob(pattern) if path.is_file())

    @staticmethod
    def _is_running(process: subprocess.Popen[str] | None) -> bool:
        return process is not None and process.poll() is None

    def _copy_snapshot_locked(self) -> PipelineSnapshot:
        return PipelineSnapshot(**self._snapshot.__dict__)


def discover_model_paths(project_root: Path) -> list[str]:
    model_dir = project_root / "modelo"
    candidates = []
    if model_dir.is_dir():
        candidates.extend(model_dir.glob("*.joblib"))
    default_model = project_root / DEFAULT_CLASSIFICATION_MODEL_PATH
    if default_model.is_file() and default_model not in candidates:
        candidates.insert(0, default_model)
    return [str(path.relative_to(project_root)) for path in sorted(candidates)]
