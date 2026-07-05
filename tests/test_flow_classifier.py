from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.classification.flow_classifier import FlowClassifier


class FakeModel:
    feature_names_in_ = ["Flow Duration", "Total Fwd Packets"]

    def predict(self, features: pd.DataFrame) -> list[int]:
        return [1 for _ in range(len(features))]

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return np.array([[0.08, 0.92] for _ in range(len(features))])


class FlowClassifierTest(unittest.TestCase):
    def test_classification_result_includes_basic_flow_metadata_without_output_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model_path = root / "model.joblib"
            input_csv = root / "flows.csv"
            joblib.dump(FakeModel(), model_path)
            pd.DataFrame(
                [
                    {
                        "Src IP": "10.0.0.1",
                        "Dst IP": "10.0.0.2",
                        "Src Port": 12345,
                        "Dst Port": 443,
                        "Protocol": 6,
                        "Flow Duration": 100,
                        "Total Fwd Packets": 4,
                    }
                ]
            ).to_csv(input_csv, index=False)

            classifier = FlowClassifier(
                model_path=model_path,
                label_names=["BENIGN", "DOS"],
                benign_label_names=["BENIGN"],
                remove_src_ip=False,
            )

            result = classifier.classify_file(input_csv)

            self.assertEqual(result.rows_classified, 1)
            self.assertIsNone(result.output_csv)
            self.assertEqual(len(result.classified_flows), 1)
            self.assertEqual(result.classified_flows[0].source_ip, "10.0.0.1")
            self.assertEqual(result.classified_flows[0].destination_ip, "10.0.0.2")
            self.assertEqual(result.classified_flows[0].prediction_label, "DOS")
            self.assertAlmostEqual(result.classified_flows[0].prediction_confidence, 0.92)

    def test_classifies_dataframe_without_csv_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model_path = root / "model.joblib"
            joblib.dump(FakeModel(), model_path)
            classifier = FlowClassifier(
                model_path=model_path,
                label_names=["BENIGN", "DOS"],
                benign_label_names=["BENIGN"],
                remove_src_ip=False,
            )

            result = classifier.classify_dataframe(
                pd.DataFrame(
                    [
                        {
                            "Flow Duration": 100,
                            "Total Fwd Packets": 4,
                        }
                    ]
                )
            )

            self.assertEqual(result.rows_classified, 1)
            self.assertEqual(result.classified_flows[0].prediction_label, "DOS")


if __name__ == "__main__":
    unittest.main()
