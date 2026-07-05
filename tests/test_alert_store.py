from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from src.web.alert_store import AlertStore


@dataclass(frozen=True)
class FakeThreatFlow:
    source_ip: str
    destination_ip: str
    source_port: str
    destination_port: str
    protocol: str
    prediction_label: str
    prediction_confidence: float


class AlertStoreTest(unittest.TestCase):
    def test_persists_runs_events_and_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = AlertStore(Path(temp_dir) / "alerts.sqlite3")
            run_id = store.create_run(
                network_interface="eth0",
                model_path="modelo/xgboost.joblib",
                ignored_source_ips=["192.168.0.10"],
            )
            store.add_event(run_id=run_id, level="info", message="started")
            saved = store.add_alerts(
                run_id,
                [
                    FakeThreatFlow(
                        source_ip="10.0.0.1",
                        destination_ip="10.0.0.2",
                        source_port="123",
                        destination_port="443",
                        protocol="6",
                        prediction_label="DOS",
                        prediction_confidence=0.97,
                    )
                ],
            )
            classifications_saved = store.add_classifications(
                run_id,
                [
                    FakeThreatFlow(
                        source_ip="10.0.0.3",
                        destination_ip="10.0.0.4",
                        source_port="53",
                        destination_port="53000",
                        protocol="17",
                        prediction_label="BENIGN",
                        prediction_confidence=0.99,
                    )
                ],
                file_path=None,
            )

            self.assertEqual(saved, 1)
            self.assertEqual(classifications_saved, 1)
            self.assertEqual(store.count_alerts(), 1)
            self.assertEqual(store.count_classifications(), 1)
            self.assertEqual(store.list_alerts()[0].prediction_label, "DOS")
            self.assertEqual(store.list_classifications()[0].prediction_label, "BENIGN")
            self.assertEqual(store.classification_counts_by_label(), {"BENIGN": 1})
            self.assertEqual(store.list_events()[0].message, "started")


if __name__ == "__main__":
    unittest.main()
