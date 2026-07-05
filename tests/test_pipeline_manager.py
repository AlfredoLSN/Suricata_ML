from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.web.alert_store import AlertStore
from src.web.pipeline_manager import PipelineManager, PipelineSnapshot


class PipelineManagerTest(unittest.TestCase):
    def test_start_rejects_missing_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manager = PipelineManager(root, AlertStore(root / "alerts.sqlite3"))

            with self.assertRaises(ValueError):
                manager.start(
                    network_interface="eth0",
                    model_path=root / "missing.joblib",
                    ignored_source_ips=[],
                )

    def test_start_sets_capturing_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model = root / "modelo" / "model.joblib"
            model.parent.mkdir(parents=True)
            model.write_text("fake model", encoding="utf-8")
            manager = PipelineManager(root, AlertStore(root / "alerts.sqlite3"))
            fake_process = Mock()
            fake_process.poll.return_value = None

            with patch.object(manager, "_start_python_script", return_value=fake_process):
                snapshot = manager.start(
                    network_interface="eth0",
                    model_path=model,
                    ignored_source_ips=["10.0.0.1"],
                )

            self.assertEqual(snapshot.state, "capturing")
            self.assertTrue(manager.status()["capture_running"])

    def test_status_includes_recent_capture_log_when_capture_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            alert_store = AlertStore(root / "alerts.sqlite3")
            manager = PipelineManager(root, alert_store)
            run_id = alert_store.create_run(
                network_interface="eth0",
                model_path=str(root / "model.joblib"),
                ignored_source_ips=[],
            )
            manager._snapshot = PipelineSnapshot(state="capturing", run_id=run_id)
            manager._capture_process = Mock()
            manager._capture_process.poll.return_value = 1
            log_path = manager._script_log_path(run_id, Path("src/capture/traffic_capture.py"))
            log_path.write_text(
                "[INFO] Iniciando captura continua\n"
                "[ERROR] sudo: a password is required\n",
                encoding="utf-8",
            )

            status = manager.status()

            self.assertEqual(status["state"], "error")
            self.assertIn("Captura encerrou com codigo 1.", str(status["last_error"]))
            self.assertIn("sudo: a password is required", str(status["last_error"]))

    def test_recent_classifications_reads_basic_flow_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            alert_store = AlertStore(root / "alerts.sqlite3")
            manager = PipelineManager(root, alert_store)
            alert_store.add_classifications(
                "run-1",
                [
                    Mock(
                        source_ip="10.0.0.1",
                        destination_ip="10.0.0.2",
                        source_port="12345",
                        destination_port="443",
                        protocol="6",
                        prediction_label="DOS",
                        prediction_confidence=0.97,
                    )
                ],
                file_path="classified.csv",
            )

            records = manager.recent_classifications(limit=10)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["source_ip"], "10.0.0.1")
            self.assertEqual(records[0]["destination_ip"], "10.0.0.2")
            self.assertEqual(records[0]["prediction_label"], "DOS")
            self.assertAlmostEqual(records[0]["prediction_confidence"], 0.97)
            self.assertEqual(manager.recent_classifications(limit=10, offset=1), [])


if __name__ == "__main__":
    unittest.main()
