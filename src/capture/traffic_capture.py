from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROTATION_SECONDS = 60
SHUTDOWN_TIMEOUT_SECONDS = 20
FORCED_SHUTDOWN_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class CaptureSettings:
    network_interface: str
    output_dir: Path


class ShutdownRequested(Exception):
    pass


def info(message: str) -> None:
    print(f"[INFO] {message}")


def error(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)


def get_project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_settings() -> CaptureSettings:
    project_root = get_project_root()
    env_path = project_root / ".env"

    load_dotenv(dotenv_path=env_path)

    network_interface = os.getenv("NETWORK_INTERFACE", "").strip()
    output_dir_raw = os.getenv("CAPTURE_OUTPUT_DIR", "data/raw/captures").strip()

    if not network_interface:
        raise ValueError("A variavel NETWORK_INTERFACE nao foi definida no .env.")

    output_dir = Path(output_dir_raw)
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    return CaptureSettings(
        network_interface=network_interface,
        output_dir=output_dir,
    )


def build_output_pcap_pattern(output_dir: Path) -> Path:
    return output_dir / "capture_%Y%m%d_%H%M%S.pcap"


def build_capture_command(settings: CaptureSettings) -> list[str]:
    return [
        "sudo",
        "tcpdump",
        "-i",
        settings.network_interface,
        "-nn",
        "-s",
        "0",
        "-G",
        str(ROTATION_SECONDS),
        "-w",
        str(build_output_pcap_pattern(settings.output_dir)),
        "-Z",
        "root",
    ]


def request_shutdown(signum: int, _frame: object) -> None:
    signal_name = signal.Signals(signum).name
    raise ShutdownRequested(f"Sinal recebido: {signal_name}")


def terminate_tcpdump(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    info("Interrupcao recebida. Encerrando tcpdump com SIGINT...")
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        error("Encerramento gracioso excedeu timeout. Forcando finalizacao...")
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=FORCED_SHUTDOWN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            error("Finalizacao por SIGTERM excedeu timeout. Enviando SIGKILL...")
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def run_capture_until_interrupted(settings: CaptureSettings) -> None:
    command = build_capture_command(settings)
    output_pattern = build_output_pcap_pattern(settings.output_dir)

    info(f"Iniciando captura continua na interface {settings.network_interface}...")
    info(f"Rotacao nativa do tcpdump: {ROTATION_SECONDS}s")
    info(f"Padrao de saida: {output_pattern}")
    info(f"Comando: {' '.join(command)}")
    info("Pressione Ctrl+C para finalizar com seguranca.")

    previous_sigterm_handler = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, request_shutdown)

    process = subprocess.Popen(command)

    try:
        return_code = process.wait()
    except (KeyboardInterrupt, ShutdownRequested):
        terminate_tcpdump(process)
        return_code = process.returncode
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm_handler)

    if return_code not in (0, 130, -signal.SIGINT):
        raise RuntimeError(f"Tcpdump encerrou com codigo inesperado: {return_code}")

    info("Captura finalizada com sucesso.")


def main() -> None:
    try:
        settings = load_settings()
        run_capture_until_interrupted(settings)
    except Exception as exc:
        error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
