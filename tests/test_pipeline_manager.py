from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.web.alert_store import AlertStore
from src.web.pipeline_manager import PipelineManager


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


if __name__ == "__main__":
    unittest.main()
