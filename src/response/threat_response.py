from __future__ import annotations

import ipaddress
import logging
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from src.classification.flow_classifier import ClassifiedThreatFlow

logger = logging.getLogger(__name__)
TELEGRAM_MESSAGE_LIMIT = 3500


class ThreatResponseMode(Enum):
    OFF = "off"
    IDS = "ids"
    IPS = "ips"


@dataclass(frozen=True)
class TelegramSettings:
    token: str | None
    chat_id: str | None
    timeout_seconds: float = 5.0

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)


@dataclass(frozen=True)
class FirewallSettings:
    command: str = "iptables"
    chain: str = "INPUT"
    target: str = "DROP"


@dataclass(frozen=True)
class ThreatResponseSettings:
    mode: ThreatResponseMode
    telegram: TelegramSettings
    firewall: FirewallSettings


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

        if self._settings.mode is ThreatResponseMode.IPS:
            self._block_source_ips(threat_flows)

    def _send_telegram_warning(self, threat_flows: list[ClassifiedThreatFlow]) -> None:
        if not self._settings.telegram.configured:
            logger.warning("IDS alert skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing.")
            return

        url = f"https://api.telegram.org/bot{self._settings.telegram.token}/sendMessage"

        for message in self._build_telegram_messages(threat_flows):
            data = {"chat_id": self._settings.telegram.chat_id, "text": message}

            try:
                response = requests.post(
                    url,
                    data=data,
                    timeout=self._settings.telegram.timeout_seconds,
                )
                response.raise_for_status()
            except requests.RequestException:
                logger.exception("Failed to send Telegram IDS alert.")

    def _block_source_ips(self, threat_flows: list[ClassifiedThreatFlow]) -> None:
        source_ips = sorted(
            {
                threat_flow.source_ip
                for threat_flow in threat_flows
                if threat_flow.source_ip and self._is_valid_ip(threat_flow.source_ip)
            }
        )
        if not source_ips:
            logger.warning("IPS block skipped: no valid source IP found in threat flows.")
            return

        for source_ip in source_ips:
            if self._firewall_rule_exists(source_ip):
                logger.info("Firewall rule already exists for source IP: %s", source_ip)
                continue

            command = self._firewall_command(source_ip, operation="-I")
            try:
                subprocess.run(command, check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as exc:
                logger.error(
                    "Failed to block source IP %s | returncode=%s | stderr=%s",
                    source_ip,
                    exc.returncode,
                    (exc.stderr or "").strip(),
                )
                continue

            logger.warning("Blocked source IP via firewall: %s", source_ip)

    def _firewall_rule_exists(self, source_ip: str) -> bool:
        command = self._firewall_command(source_ip, operation="-C")
        completed = subprocess.run(command, capture_output=True, text=True)
        return completed.returncode == 0

    def _firewall_command(self, source_ip: str, operation: str) -> list[str]:
        firewall = self._settings.firewall
        return [
            firewall.command,
            operation,
            firewall.chain,
            "-s",
            source_ip,
            "-j",
            firewall.target,
        ]

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

    def _is_valid_ip(self, source_ip: str) -> bool:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            logger.warning("Invalid source IP ignored by IPS mode: %s", source_ip)
            return False

        return True


def parse_threat_response_mode(raw_value: str) -> ThreatResponseMode:
    normalized = raw_value.strip().lower()
    if not normalized:
        return ThreatResponseMode.OFF

    try:
        return ThreatResponseMode(normalized)
    except ValueError as exc:
        allowed_values = ", ".join(mode.value for mode in ThreatResponseMode)
        raise ValueError(f"THREAT_RESPONSE_MODE deve ser um destes valores: {allowed_values}.") from exc
