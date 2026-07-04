from __future__ import annotations

import logging
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.classification.flow_classifier import FlowClassifier
from src.response.threat_response import (
    TelegramSettings,
    ThreatResponder,
    ThreatResponseSettings,
    parse_threat_response_mode,
)

DEFAULT_CAPTURE_OUTPUT_DIR = "data/raw/captures"
DEFAULT_FLOW_OUTPUT_DIR = "data/processed/flows"
DEFAULT_CLASSIFIED_FLOW_OUTPUT_DIR = "data/processed/classified_flows"
DEFAULT_WORKER_COUNT = 1
DEFAULT_CICFLOWMETER_BIN = "cicflowmeter"
DEFAULT_CLASSIFICATION_MODEL_PATH = "modelo/pipeline.joblib"
DEFAULT_CLASSIFICATION_LABEL_ENCODER_PATH = "modelo/label_encoder.joblib"
QUEUE_POLL_TIMEOUT_SECONDS = 1.0
SHUTDOWN_POLL_SECONDS = 0.5

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FlowExtractionSettings:
    capture_dir: Path
    flow_output_dir: Path
    worker_count: int
    cicflowmeter_bin: str
    cicflowmeter_cwd: Path | None
    classification_enabled: bool
    classification_model_path: Path
    classification_label_encoder_path: Path | None
    classified_flow_output_dir: Path
    classification_label_names: list[str]
    classification_benign_label_names: list[str]
    classification_excluded_src_ips: list[str]
    classification_remove_src_ip: bool
    threat_response_settings: ThreatResponseSettings


class ShutdownRequested(Exception):
    pass


class ClosedPcapPublisher(FileSystemEventHandler):
    def __init__(self, pcap_queue: queue.Queue[Path | None]) -> None:
        self._pcap_queue = pcap_queue

    def on_closed(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        pcap_path = Path(event.src_path)
        if pcap_path.suffix.lower() != ".pcap":
            logger.debug("Ignoring closed non-PCAP file: %s", pcap_path)
            return

        self._pcap_queue.put(pcap_path)
        logger.info(
            "Closed PCAP published to queue: %s | queued=%s",
            pcap_path,
            self._pcap_queue.qsize(),
        )


def get_project_root() -> Path:
    return PROJECT_ROOT


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(threadName)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def resolve_project_path(project_root: Path, raw_path: str) -> Path:
    path = Path(raw_path.strip())
    if path.is_absolute():
        return path
    return project_root / path


def resolve_optional_project_path(project_root: Path, raw_path: str) -> Path | None:
    if not raw_path.strip():
        return None
    return resolve_project_path(project_root, raw_path)


def load_settings() -> FlowExtractionSettings:
    project_root = get_project_root()
    load_dotenv(dotenv_path=project_root / ".env")

    capture_dir = resolve_project_path(
        project_root,
        os.getenv("CAPTURE_OUTPUT_DIR", DEFAULT_CAPTURE_OUTPUT_DIR),
    )
    flow_output_dir = resolve_project_path(
        project_root,
        os.getenv("FLOW_OUTPUT_DIR", DEFAULT_FLOW_OUTPUT_DIR),
    )
    classified_flow_output_dir = resolve_project_path(
        project_root,
        os.getenv("CLASSIFIED_FLOW_OUTPUT_DIR", DEFAULT_CLASSIFIED_FLOW_OUTPUT_DIR),
    )
    worker_count = parse_worker_count(os.getenv("FLOW_WORKER_COUNT", ""))
    cicflowmeter_bin = os.getenv("CICFLOWMETER_BIN", DEFAULT_CICFLOWMETER_BIN).strip()
    cicflowmeter_cwd = resolve_optional_project_path(
        project_root,
        os.getenv("CICFLOWMETER_CWD", ""),
    )
    classification_enabled = parse_bool(os.getenv("CLASSIFICATION_ENABLED", "false"))
    classification_model_path = resolve_project_path(
        project_root,
        os.getenv("CLASSIFICATION_MODEL_PATH", DEFAULT_CLASSIFICATION_MODEL_PATH),
    )
    classification_label_encoder_path = resolve_optional_project_path(
        project_root,
        os.getenv("CLASSIFICATION_LABEL_ENCODER_PATH", DEFAULT_CLASSIFICATION_LABEL_ENCODER_PATH),
    )
    classification_label_names = parse_label_names(os.getenv("CLASSIFICATION_LABELS", ""))
    classification_benign_label_names = parse_label_names(
        os.getenv("CLASSIFICATION_BENIGN_LABELS", "BENIGN,0")
    )
    classification_excluded_src_ips = parse_label_names(
        os.getenv("CLASSIFICATION_EXCLUDED_SRC_IP", "")
    )
    classification_remove_src_ip = parse_bool(os.getenv("CLASSIFICATION_REMOVE_SRC_IP", "true"))
    threat_response_settings = ThreatResponseSettings(
        mode=parse_threat_response_mode(os.getenv("THREAT_RESPONSE_MODE", "off")),
        telegram=TelegramSettings(
            token=parse_optional_text(os.getenv("TELEGRAM_BOT_TOKEN", "")),
            chat_id=parse_optional_text(os.getenv("TELEGRAM_CHAT_ID", "")),
            timeout_seconds=parse_positive_float(
                os.getenv("TELEGRAM_TIMEOUT_SECONDS", "15"),
                variable_name="TELEGRAM_TIMEOUT_SECONDS",
            ),
            retry_count=parse_non_negative_int(
                os.getenv("TELEGRAM_RETRY_COUNT", "3"),
                variable_name="TELEGRAM_RETRY_COUNT",
            ),
            retry_backoff_seconds=parse_positive_float(
                os.getenv("TELEGRAM_RETRY_BACKOFF_SECONDS", "2"),
                variable_name="TELEGRAM_RETRY_BACKOFF_SECONDS",
            ),
        ),
        internal_alert_db_path=resolve_optional_project_path(
            project_root,
            os.getenv("INTERNAL_ALERT_DB_PATH", ""),
        ),
        run_id=parse_optional_text(os.getenv("PIPELINE_RUN_ID", "")),
    )

    if not cicflowmeter_bin:
        raise ValueError("A variavel CICFLOWMETER_BIN nao pode ficar vazia.")
    if cicflowmeter_cwd is not None and not cicflowmeter_cwd.is_dir():
        raise ValueError(f"CICFLOWMETER_CWD nao e um diretorio valido: {cicflowmeter_cwd}")
    if classification_enabled and not classification_model_path.is_file():
        raise ValueError(
            f"CLASSIFICATION_MODEL_PATH nao aponta para um arquivo valido: "
            f"{classification_model_path}"
        )

    capture_dir.mkdir(parents=True, exist_ok=True)
    flow_output_dir.mkdir(parents=True, exist_ok=True)
    if classification_enabled:
        classified_flow_output_dir.mkdir(parents=True, exist_ok=True)

    return FlowExtractionSettings(
        capture_dir=capture_dir,
        flow_output_dir=flow_output_dir,
        worker_count=worker_count,
        cicflowmeter_bin=cicflowmeter_bin,
        cicflowmeter_cwd=cicflowmeter_cwd,
        classification_enabled=classification_enabled,
        classification_model_path=classification_model_path,
        classification_label_encoder_path=classification_label_encoder_path,
        classified_flow_output_dir=classified_flow_output_dir,
        classification_label_names=classification_label_names,
        classification_benign_label_names=classification_benign_label_names,
        classification_excluded_src_ips=classification_excluded_src_ips,
        classification_remove_src_ip=classification_remove_src_ip,
        threat_response_settings=threat_response_settings,
    )


def parse_worker_count(raw_value: str) -> int:
    if not raw_value.strip():
        return DEFAULT_WORKER_COUNT

    try:
        worker_count = int(raw_value)
    except ValueError as exc:
        raise ValueError("FLOW_WORKER_COUNT deve ser um numero inteiro positivo.") from exc

    if worker_count < 1:
        raise ValueError("FLOW_WORKER_COUNT deve ser maior ou igual a 1.")

    return worker_count


def parse_bool(raw_value: str) -> bool:
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on", "sim"}:
        return True
    if normalized in {"", "0", "false", "no", "n", "off", "nao", "não"}:
        return False

    raise ValueError(
        "Valores booleanos aceitos: true/false, yes/no, on/off, 1/0, sim/nao."
    )


def parse_label_names(raw_value: str) -> list[str]:
    return [label.strip() for label in raw_value.split(",") if label.strip()]


def parse_optional_text(raw_value: str) -> str | None:
    value = raw_value.strip()
    if not value:
        return None
    return value


def parse_positive_float(raw_value: str, variable_name: str) -> float:
    try:
        value = float(raw_value.strip())
    except ValueError as exc:
        raise ValueError(f"{variable_name} deve ser um numero positivo.") from exc

    if value <= 0:
        raise ValueError(f"{variable_name} deve ser maior que zero.")

    return value


def parse_non_negative_int(raw_value: str, variable_name: str) -> int:
    try:
        value = int(raw_value.strip())
    except ValueError as exc:
        raise ValueError(f"{variable_name} deve ser um numero inteiro maior ou igual a zero.") from exc

    if value < 0:
        raise ValueError(f"{variable_name} deve ser maior ou igual a zero.")

    return value


def build_cicflowmeter_command(settings: FlowExtractionSettings, pcap_path: Path) -> list[str]:
    return [
        settings.cicflowmeter_bin,
        str(pcap_path),
        str(settings.flow_output_dir),
    ]


def process_pcap(settings: FlowExtractionSettings, pcap_path: Path) -> None:
    command = build_cicflowmeter_command(settings, pcap_path)
    started_at = time.monotonic()
    started_at_wall = time.time()

    logger.info("Starting CICFlowMeter extraction: %s", pcap_path)
    logger.debug("Command: %s", " ".join(command))
    if settings.cicflowmeter_cwd is not None:
        logger.debug("CICFlowMeter working directory: %s", settings.cicflowmeter_cwd)

    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            cwd=settings.cicflowmeter_cwd,
        )
    except FileNotFoundError:
        logger.exception(
            "CICFlowMeter executable not found: %s. Check CICFLOWMETER_BIN.",
            settings.cicflowmeter_bin,
        )
        return
    except subprocess.CalledProcessError as exc:
        elapsed = time.monotonic() - started_at
        logger.error(
            "CICFlowMeter failed for %s after %.2fs | returncode=%s",
            pcap_path,
            elapsed,
            exc.returncode,
        )
        log_subprocess_output(exc.stdout, exc.stderr)
        return
    except Exception:
        elapsed = time.monotonic() - started_at
        logger.exception("Unexpected extraction failure for %s after %.2fs", pcap_path, elapsed)
        return

    elapsed = time.monotonic() - started_at
    logger.info("CICFlowMeter extraction finished: %s | elapsed=%.2fs", pcap_path, elapsed)
    log_subprocess_output(completed.stdout, completed.stderr)
    classify_generated_flow_csvs(settings, pcap_path, started_at_wall)


def classify_generated_flow_csvs(
    settings: FlowExtractionSettings,
    pcap_path: Path,
    extraction_started_at: float,
) -> None:
    if not settings.classification_enabled:
        return

    flow_csvs = find_generated_flow_csvs(
        flow_output_dir=settings.flow_output_dir,
        pcap_path=pcap_path,
        extraction_started_at=extraction_started_at,
    )
    if not flow_csvs:
        logger.warning(
            "Classification skipped for %s: no generated CICFlowMeter CSV was found.",
            pcap_path,
        )
        return

    try:
        classifier = FlowClassifier(
            model_path=settings.classification_model_path,
            label_encoder_path=settings.classification_label_encoder_path,
            label_names=settings.classification_label_names,
            benign_label_names=settings.classification_benign_label_names,
            excluded_src_ips=settings.classification_excluded_src_ips,
            remove_src_ip=settings.classification_remove_src_ip,
        )
        threat_responder = ThreatResponder(settings.threat_response_settings)
    except Exception:
        logger.exception(
            "Classification skipped for %s: failed to load model %s",
            pcap_path,
            settings.classification_model_path,
        )
        return

    for flow_csv in flow_csvs:
        output_csv = settings.classified_flow_output_dir / build_classified_csv_name(flow_csv)
        try:
            result = classifier.classify_file(flow_csv, output_csv)
        except Exception:
            logger.exception("Classification failed for generated CSV: %s", flow_csv)
            continue

        logger.info(
            "Classification finished: %s -> %s | rows=%s | invalid_rows_removed=%s | predictions=%s",
            result.input_csv,
            result.output_csv,
            result.rows_classified,
            result.rows_removed_by_invalid_features,
            result.prediction_counts,
        )
        threat_responder.handle_threat_flows(result.threat_flows)
        if result.rows_removed_by_src_ip:
            logger.info(
                "Classification input filter: %s row(s) removed from %s by Src IP == %s",
                result.rows_removed_by_src_ip,
                result.rows_before_filter,
                ", ".join(settings.classification_excluded_src_ips),
            )


def find_generated_flow_csvs(
    flow_output_dir: Path,
    pcap_path: Path,
    extraction_started_at: float,
) -> list[Path]:
    expected_names = [
        f"{pcap_path.name}_Flow.csv",
        f"{pcap_path.stem}_Flow.csv",
        f"{pcap_path.name}.csv",
        f"{pcap_path.stem}.csv",
    ]
    expected_paths = [flow_output_dir / name for name in expected_names]
    existing_expected_paths = [path for path in expected_paths if path.is_file()]
    if existing_expected_paths:
        return existing_expected_paths

    candidates = [
        path
        for path in flow_output_dir.glob("*.csv")
        if path.is_file() and path.stat().st_mtime >= extraction_started_at
    ]
    return sorted(candidates, key=lambda path: path.stat().st_mtime)


def build_classified_csv_name(flow_csv: Path) -> str:
    return f"{flow_csv.stem}_classified{flow_csv.suffix}"


def log_subprocess_output(stdout: str | None, stderr: str | None) -> None:
    stdout_text = (stdout or "").strip()
    stderr_text = (stderr or "").strip()

    if stdout_text:
        logger.info("CICFlowMeter stdout: %s", stdout_text)
    if stderr_text:
        logger.warning("CICFlowMeter stderr: %s", stderr_text)


def worker_loop(
    worker_id: int,
    settings: FlowExtractionSettings,
    pcap_queue: queue.Queue[Path | None],
) -> None:
    logger.info("Worker %s started.", worker_id)

    while True:
        try:
            pcap_path = pcap_queue.get(timeout=QUEUE_POLL_TIMEOUT_SECONDS)
        except queue.Empty:
            continue

        try:
            if pcap_path is None:
                logger.info("Worker %s received shutdown signal.", worker_id)
                return

            logger.info(
                "Worker %s consumed PCAP: %s | queued=%s",
                worker_id,
                pcap_path,
                pcap_queue.qsize(),
            )
            process_pcap(settings, pcap_path)
        finally:
            pcap_queue.task_done()


def start_workers(
    settings: FlowExtractionSettings,
    pcap_queue: queue.Queue[Path | None],
) -> list[threading.Thread]:
    workers: list[threading.Thread] = []
    for worker_id in range(1, settings.worker_count + 1):
        worker = threading.Thread(
            target=worker_loop,
            name=f"flow-worker-{worker_id}",
            args=(worker_id, settings, pcap_queue),
        )
        worker.start()
        workers.append(worker)
    return workers


def request_shutdown(signum: int, _frame: object) -> None:
    signal_name = signal.Signals(signum).name
    raise ShutdownRequested(f"Sinal recebido: {signal_name}")


def run_service(settings: FlowExtractionSettings) -> None:
    pcap_queue: queue.Queue[Path | None] = queue.Queue()
    event_handler = ClosedPcapPublisher(pcap_queue)
    observer = Observer()
    workers: list[threading.Thread] = []

    previous_sigterm_handler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, request_shutdown)

    try:
        observer.schedule(event_handler, str(settings.capture_dir), recursive=False)
        observer.start()
        workers = start_workers(settings, pcap_queue)

        logger.info("Watching for closed PCAP files in: %s", settings.capture_dir)
        logger.info("Writing CICFlowMeter CSV output to: %s", settings.flow_output_dir)
        if settings.cicflowmeter_cwd is not None:
            logger.info("Running CICFlowMeter subprocesses from: %s", settings.cicflowmeter_cwd)
        logger.info("Worker subscribers: %s", settings.worker_count)
        logger.info("Existing PCAP files are not backfilled; only new close events are processed.")

        while True:
            time.sleep(SHUTDOWN_POLL_SECONDS)
    except (KeyboardInterrupt, ShutdownRequested) as exc:
        logger.info("Shutdown requested: %s", exc)
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm_handler)
        stop_service(observer, workers, pcap_queue)


def stop_service(
    observer: Observer,
    workers: list[threading.Thread],
    pcap_queue: queue.Queue[Path | None],
) -> None:
    logger.info("Stopping capture directory observer...")
    if observer.is_alive():
        observer.stop()
        observer.join()

    logger.info("Sending shutdown signal to %s worker(s)...", len(workers))
    for _worker in workers:
        pcap_queue.put(None)

    for worker in workers:
        worker.join()

    logger.info("Flow extraction service stopped.")


def main() -> None:
    configure_logging()

    try:
        settings = load_settings()
        run_service(settings)
    except Exception as exc:
        logger.exception("Flow extraction service failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
