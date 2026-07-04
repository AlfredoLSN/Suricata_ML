from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.classification.flow_classifier import ClassifiedThreatFlow
from src.response.threat_response import (
    TelegramSettings,
    ThreatResponder,
    ThreatResponseMode,
    ThreatResponseSettings,
)
from src.web.alert_store import AlertStore


class ThreatResponseTest(unittest.TestCase):
    def test_internal_mode_persists_threat_flows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "alerts.sqlite3"
            responder = ThreatResponder(
                ThreatResponseSettings(
                    mode=ThreatResponseMode.INTERNAL,
                    telegram=TelegramSettings(token=None, chat_id=None),
                    internal_alert_db_path=db_path,
                    run_id="run-1",
                )
            )

            responder.handle_threat_flows(
                [
                    ClassifiedThreatFlow(
                        source_ip="10.0.0.1",
                        destination_ip="10.0.0.2",
                        source_port="1000",
                        destination_port="80",
                        protocol="6",
                        prediction_label="PORTSCAN",
                        prediction_confidence=0.88,
                    )
                ]
            )

            alerts = AlertStore(db_path).list_alerts()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].prediction_label, "PORTSCAN")


if __name__ == "__main__":
    unittest.main()
