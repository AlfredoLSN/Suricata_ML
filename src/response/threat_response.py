from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from src.classification.flow_classifier import ClassifiedThreatFlow

logger = logging.getLogger(__name__)
TELEGRAM_MESSAGE_LIMIT = 3500


class ThreatResponseMode(Enum):
    OFF = "off"
    IDS = "ids"
    INTERNAL = "internal"


@dataclass(frozen=True)
class TelegramSettings:
    token: str | None
    chat_id: str | None
    timeout_seconds: float = 15.0
    retry_count: int = 3
    retry_backoff_seconds: float = 2.0

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)


@dataclass(frozen=True)
class ThreatResponseSettings:
    mode: ThreatResponseMode
    telegram: TelegramSettings
    internal_alert_db_path: Path | None = None
    run_id: str | None = None


class ThreatResponder:
    def __init__(self, settings: ThreatResponseSettings) -> None:
        self._settings = settings

    def handle_threat_flows(self, threat_flows: list[ClassifiedThreatFlow]) -> None:
        if self._settings.mode is ThreatResponseMode.OFF:
            return
        if not threat_flows:
            return

        if self._settings.mode is ThreatResponseMode.IDS:
            self._send_telegram_warning(threat_flows)
            return

        if self._settings.mode is ThreatResponseMode.INTERNAL:
            self._persist_internal_alerts(threat_flows)
            return

    def _persist_internal_alerts(self, threat_flows: list[ClassifiedThreatFlow]) -> None:
        if self._settings.internal_alert_db_path is None:
            logger.warning("Internal IDS alert skipped: INTERNAL_ALERT_DB_PATH is missing.")
            return

        from src.web.alert_store import AlertStore

        store = AlertStore(self._settings.internal_alert_db_path)
        saved_count = store.add_alerts(self._settings.run_id, threat_flows)
        logger.info("Internal IDS alert persisted: %s flow(s).", saved_count)

    def _send_telegram_warning(self, threat_flows: list[ClassifiedThreatFlow]) -> None:
        if not self._settings.telegram.configured:
            logger.warning("IDS alert skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing.")
            return

        url = f"https://api.telegram.org/bot{self._settings.telegram.token}/sendMessage"

        for message in self._build_telegram_messages(threat_flows):
            self._post_telegram_message(url, message)

    def _post_telegram_message(self, url: str, message: str) -> None:
        telegram = self._settings.telegram
        data = {"chat_id": telegram.chat_id, "text": message}
        max_attempts = telegram.retry_count + 1

        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(
                    url,
                    data=data,
                    timeout=telegram.timeout_seconds,
                )
                response.raise_for_status()
                return
            except requests.RequestException as exc:
                if attempt >= max_attempts:
                    logger.exception(
                        "Failed to send Telegram IDS alert after %s attempt(s).",
                        max_attempts,
                    )
                    return

                logger.warning(
                    "Telegram IDS alert attempt %s/%s failed: %s. Retrying in %.1fs.",
                    attempt,
                    max_attempts,
                    exc,
                    telegram.retry_backoff_seconds,
                )
                time.sleep(telegram.retry_backoff_seconds)

    def _build_telegram_messages(self, threat_flows: list[ClassifiedThreatFlow]) -> list[str]:
        header = [
            "[ALERTA IDS] Trafego malicioso detectado",
            f"Fluxos suspeitos: {len(threat_flows)}",
        ]
        messages: list[str] = []
        lines = header.copy()

        for index, threat_flow in enumerate(threat_flows, start=1):
            line = self._format_threat_flow_line(index, threat_flow)
            candidate = "\n".join([*lines, line])
            if len(candidate) > TELEGRAM_MESSAGE_LIMIT and len(lines) > len(header):
                messages.append("\n".join(lines))
                lines = [
                    "[ALERTA IDS] Trafego malicioso detectado",
                    f"Continuacao - fluxos suspeitos: {len(threat_flows)}",
                    line,
                ]
                continue

            lines.append(line)

        if lines:
            messages.append("\n".join(lines))

        return messages

    def _format_threat_flow_line(
        self,
        index: int,
        threat_flow: ClassifiedThreatFlow,
    ) -> str:
        source = threat_flow.source_ip or "Src IP desconhecido"
        destination = threat_flow.destination_ip or "Dst IP desconhecido"
        source_port = f":{threat_flow.source_port}" if threat_flow.source_port else ""
        destination_port = f":{threat_flow.destination_port}" if threat_flow.destination_port else ""
        protocol = f" proto={threat_flow.protocol}" if threat_flow.protocol else ""
        confidence = ""
        if threat_flow.prediction_confidence is not None:
            confidence = f" conf={threat_flow.prediction_confidence:.2f}"

        return (
            f"{index}. "
            f"{threat_flow.prediction_label}: "
            f"{source}{source_port} -> {destination}{destination_port}"
            f"{protocol}{confidence}"
        )

def parse_threat_response_mode(raw_value: str) -> ThreatResponseMode:
    normalized = raw_value.strip().lower()
    if not normalized:
        return ThreatResponseMode.OFF

    try:
        return ThreatResponseMode(normalized)
    except ValueError as exc:
        allowed_values = ", ".join(mode.value for mode in ThreatResponseMode)
        raise ValueError(f"THREAT_RESPONSE_MODE deve ser um destes valores: {allowed_values}.") from exc
