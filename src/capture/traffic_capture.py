from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

CAPTURE_DURATION_SECONDS = 60
SHUTDOWN_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class CaptureSettings:
    cicflowmeter_path: Path
    network_interface: str
    output_dir: Path


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

    cicflowmeter_raw = os.getenv("CICFLOWMETER_PATH", "").strip()
    network_interface = os.getenv("NETWORK_INTERFACE", "").strip()
    output_dir_raw = os.getenv("CAPTURE_OUTPUT_DIR", "data/raw/captures").strip()

    if not cicflowmeter_raw:
        raise ValueError("A variavel CICFLOWMETER_PATH nao foi definida no .env.")
    if not network_interface:
        raise ValueError("A variavel NETWORK_INTERFACE nao foi definida no .env.")

    cicflowmeter_path = Path(cicflowmeter_raw)
    if not cicflowmeter_path.is_absolute():
        raise ValueError("CICFLOWMETER_PATH deve ser um caminho absoluto.")
    if not cicflowmeter_path.exists():
        raise FileNotFoundError(
            f"Caminho CICFLOWMETER_PATH nao encontrado: {cicflowmeter_path}"
        )
    if not os.access(cicflowmeter_path, os.X_OK):
        raise PermissionError(
            f"CICFLOWMETER_PATH nao e executavel: {cicflowmeter_path}"
        )

    output_dir = Path(output_dir_raw)
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    return CaptureSettings(
        cicflowmeter_path=cicflowmeter_path,
        network_interface=network_interface,
        output_dir=output_dir,
    )


def build_output_csv_path(output_dir: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return output_dir / f"flows_{timestamp}.csv"


def build_capture_command(settings: CaptureSettings, output_csv: Path) -> list[str]:
    return [
        "sudo",
        str(settings.cicflowmeter_path),
        "-i",
        settings.network_interface,
        "-c",
        str(output_csv),
    ]


def run_capture_for_60_seconds(settings: CaptureSettings) -> Path:
    output_csv = build_output_csv_path(settings.output_dir)
    command = build_capture_command(settings, output_csv)

    info(f"Iniciando captura na interface {settings.network_interface}...")
    info(f"Arquivo de saida: {output_csv}")
    info(f"Comando: {' '.join(command)}")

    process = subprocess.Popen(command)

    if process.poll() is not None:
        raise RuntimeError(
            "O processo do cicflowmeter encerrou imediatamente apos iniciar."
        )

    start_time = time.monotonic()
    end_time = start_time + CAPTURE_DURATION_SECONDS
    while True:
        if process.poll() is not None:
            raise RuntimeError(
                f"O cicflowmeter encerrou antes do tempo esperado com codigo {process.returncode}."
            )

        remaining = end_time - time.monotonic()
        if remaining <= 0:
            break

        time.sleep(min(1.0, remaining))

    if process.poll() is None:
        # Envia Ctrl+C para encerrar e finalizar o CSV sem corrupcao.
        info("Tempo de captura concluido (60s). Enviando SIGINT...")
        process.send_signal(signal.SIGINT)

    try:
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        error("Encerramento gracioso excedeu timeout. Forcando finalizacao...")
        process.kill()
        process.wait(timeout=5)

    if process.returncode not in (0, 130):
        raise RuntimeError(
            f"Cicflowmeter encerrou com codigo inesperado: {process.returncode}"
        )

    if not output_csv.exists():
        raise FileNotFoundError(
            f"CSV de captura nao encontrado apos encerramento: {output_csv}"
        )

    info("Captura finalizada com sucesso.")
    return output_csv


def validate_captured_csv(csv_path: Path) -> pd.DataFrame:
    info(f"Validando CSV gerado: {csv_path}")
    dataframe = pd.read_csv(csv_path)

    null_count = int(dataframe.isna().sum().sum())
    if null_count > 0:
        info(f"Foram encontrados {null_count} valores nulos. Aplicando fillna(0)...")
        dataframe = dataframe.fillna(0)
    else:
        info("Nenhum valor nulo encontrado no CSV.")

    info("Colunas extraidas (features):")
    print(list(dataframe.columns))

    info("Primeiras 5 linhas do CSV:")
    print(dataframe.head())

    return dataframe


def main() -> None:
    try:
        settings = load_settings()
        output_csv = run_capture_for_60_seconds(settings)
        validate_captured_csv(output_csv)
    except Exception as exc:
        error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
