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

DEFAULT_CAPTURE_OUTPUT_DIR = "data/raw/captures"
DEFAULT_FLOW_OUTPUT_DIR = "data/processed/flows"
DEFAULT_WORKER_COUNT = 1
DEFAULT_CICFLOWMETER_BIN = "cicflowmeter"
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
    return Path(__file__).resolve().parents[2]


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
    worker_count = parse_worker_count(os.getenv("FLOW_WORKER_COUNT", ""))
    cicflowmeter_bin = os.getenv("CICFLOWMETER_BIN", DEFAULT_CICFLOWMETER_BIN).strip()
    cicflowmeter_cwd = resolve_optional_project_path(
        project_root,
        os.getenv("CICFLOWMETER_CWD", ""),
    )

    if not cicflowmeter_bin:
        raise ValueError("A variavel CICFLOWMETER_BIN nao pode ficar vazia.")
    if cicflowmeter_cwd is not None and not cicflowmeter_cwd.is_dir():
        raise ValueError(f"CICFLOWMETER_CWD nao e um diretorio valido: {cicflowmeter_cwd}")

    capture_dir.mkdir(parents=True, exist_ok=True)
    flow_output_dir.mkdir(parents=True, exist_ok=True)

    return FlowExtractionSettings(
        capture_dir=capture_dir,
        flow_output_dir=flow_output_dir,
        worker_count=worker_count,
        cicflowmeter_bin=cicflowmeter_bin,
        cicflowmeter_cwd=cicflowmeter_cwd,
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


def build_cicflowmeter_command(settings: FlowExtractionSettings, pcap_path: Path) -> list[str]:
    return [
        settings.cicflowmeter_bin,
        str(pcap_path),
        str(settings.flow_output_dir),
    ]


def process_pcap(settings: FlowExtractionSettings, pcap_path: Path) -> None:
    command = build_cicflowmeter_command(settings, pcap_path)
    started_at = time.monotonic()

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
