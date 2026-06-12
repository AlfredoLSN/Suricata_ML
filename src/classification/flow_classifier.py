from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd

logger = logging.getLogger(__name__)


FEATURE_COLUMN_ALIASES = {
    "Flow Duration": ["Flow Duration"],
    "Total Fwd Packets": ["Total Fwd Packets", "Total Fwd Packet"],
    "Total Backward Packets": ["Total Backward Packets", "Total Bwd packets"],
    "Total Length of Fwd Packets": [
        "Total Length of Fwd Packets",
        "Total Length of Fwd Packet",
    ],
    "Total Length of Bwd Packets": [
        "Total Length of Bwd Packets",
        "Total Length of Bwd Packet",
    ],
    "Fwd Packet Length Max": ["Fwd Packet Length Max"],
    "Fwd Packet Length Min": ["Fwd Packet Length Min"],
    "Fwd Packet Length Mean": ["Fwd Packet Length Mean"],
    "Fwd Packet Length Std": ["Fwd Packet Length Std"],
    "Bwd Packet Length Max": ["Bwd Packet Length Max"],
    "Bwd Packet Length Min": ["Bwd Packet Length Min"],
    "Bwd Packet Length Mean": ["Bwd Packet Length Mean"],
    "Bwd Packet Length Std": ["Bwd Packet Length Std"],
    "Flow Bytes/s": ["Flow Bytes/s"],
    "Flow Packets/s": ["Flow Packets/s"],
    "Flow IAT Mean": ["Flow IAT Mean"],
    "Flow IAT Std": ["Flow IAT Std"],
    "Flow IAT Max": ["Flow IAT Max"],
    "Flow IAT Min": ["Flow IAT Min"],
    "Fwd IAT Total": ["Fwd IAT Total"],
    "Fwd IAT Mean": ["Fwd IAT Mean"],
    "Fwd IAT Std": ["Fwd IAT Std"],
    "Fwd IAT Max": ["Fwd IAT Max"],
    "Fwd IAT Min": ["Fwd IAT Min"],
    "Bwd IAT Total": ["Bwd IAT Total"],
    "Bwd IAT Mean": ["Bwd IAT Mean"],
    "Bwd IAT Std": ["Bwd IAT Std"],
    "Bwd IAT Max": ["Bwd IAT Max"],
    "Bwd IAT Min": ["Bwd IAT Min"],
    "Fwd PSH Flags": ["Fwd PSH Flags"],
    "Bwd PSH Flags": ["Bwd PSH Flags"],
    "Fwd URG Flags": ["Fwd URG Flags"],
    "Bwd URG Flags": ["Bwd URG Flags"],
    "Fwd Header Length": ["Fwd Header Length"],
    "Bwd Header Length": ["Bwd Header Length"],
    "Fwd Packets/s": ["Fwd Packets/s"],
    "Bwd Packets/s": ["Bwd Packets/s"],
    "Min Packet Length": ["Min Packet Length", "Packet Length Min"],
    "Max Packet Length": ["Max Packet Length", "Packet Length Max"],
    "Packet Length Mean": ["Packet Length Mean"],
    "Packet Length Std": ["Packet Length Std"],
    "Packet Length Variance": ["Packet Length Variance"],
    "FIN Flag Count": ["FIN Flag Count"],
    "SYN Flag Count": ["SYN Flag Count"],
    "RST Flag Count": ["RST Flag Count"],
    "PSH Flag Count": ["PSH Flag Count"],
    "ACK Flag Count": ["ACK Flag Count"],
    "URG Flag Count": ["URG Flag Count"],
    "CWE Flag Count": ["CWE Flag Count", "CWR Flag Count"],
    "ECE Flag Count": ["ECE Flag Count"],
    "Down/Up Ratio": ["Down/Up Ratio"],
    "Average Packet Size": ["Average Packet Size"],
    "Avg Fwd Segment Size": ["Avg Fwd Segment Size", "Fwd Segment Size Avg"],
    "Avg Bwd Segment Size": ["Avg Bwd Segment Size", "Bwd Segment Size Avg"],
    "Fwd Header Length.1": ["Fwd Header Length.1", "Fwd Header Length"],
    "Fwd Avg Bytes/Bulk": ["Fwd Avg Bytes/Bulk"],
    "Fwd Avg Packets/Bulk": ["Fwd Avg Packets/Bulk"],
    "Fwd Avg Bulk Rate": ["Fwd Avg Bulk Rate"],
    "Bwd Avg Bytes/Bulk": ["Bwd Avg Bytes/Bulk"],
    "Bwd Avg Packets/Bulk": ["Bwd Avg Packets/Bulk"],
    "Bwd Avg Bulk Rate": ["Bwd Avg Bulk Rate"],
    "Subflow Fwd Packets": ["Subflow Fwd Packets"],
    "Subflow Fwd Bytes": ["Subflow Fwd Bytes"],
    "Subflow Bwd Packets": ["Subflow Bwd Packets"],
    "Subflow Bwd Bytes": ["Subflow Bwd Bytes"],
    "Init_Win_bytes_forward": ["Init_Win_bytes_forward", "FWD Init Win Bytes"],
    "Init_Win_bytes_backward": ["Init_Win_bytes_backward", "Bwd Init Win Bytes"],
    "act_data_pkt_fwd": ["act_data_pkt_fwd", "Fwd Act Data Pkts"],
    "min_seg_size_forward": ["min_seg_size_forward", "Fwd Seg Size Min"],
    "Active Mean": ["Active Mean"],
    "Active Std": ["Active Std"],
    "Active Max": ["Active Max"],
    "Active Min": ["Active Min"],
    "Idle Mean": ["Idle Mean"],
    "Idle Std": ["Idle Std"],
    "Idle Max": ["Idle Max"],
    "Idle Min": ["Idle Min"],
}


@dataclass(frozen=True)
class ClassifiedThreatFlow:
    source_ip: str | None
    destination_ip: str | None
    source_port: str | None
    destination_port: str | None
    protocol: str | None
    prediction_label: str
    prediction_confidence: float | None


@dataclass(frozen=True)
class ClassificationResult:
    input_csv: Path
    output_csv: Path
    rows_before_filter: int
    rows_removed_by_src_ip: int
    rows_classified: int
    prediction_counts: dict[str, int]
    threat_flows: list[ClassifiedThreatFlow]


class FlowClassifier:
    def __init__(
        self,
        model_path: Path,
        label_encoder_path: Path | None = None,
        label_names: list[str] | None = None,
        benign_label_names: list[str] | None = None,
        excluded_src_ip: str | None = None,
        remove_src_ip: bool = True,
    ) -> None:
        self._model_path = model_path
        self._model = joblib.load(model_path)
        self._label_encoder = self._load_label_encoder(label_encoder_path)
        self._feature_names = self._resolve_feature_names()
        self._label_names = label_names or []
        self._benign_label_names = {
            label_name.strip().upper()
            for label_name in (benign_label_names or ["BENIGN", "0"])
            if label_name.strip()
        }
        self._excluded_src_ip = excluded_src_ip.strip() if excluded_src_ip else None
        self._remove_src_ip = remove_src_ip

    def classify_file(self, input_csv: Path, output_csv: Path) -> ClassificationResult:
        df = pd.read_csv(input_csv)
        df.columns = df.columns.str.strip()
        rows_before_filter = len(df)
        df, rows_removed_by_src_ip = self._filter_source_ip(df)

        if df.empty:
            output_csv.parent.mkdir(parents=True, exist_ok=True)
            df.to_csv(output_csv, index=False)
            return ClassificationResult(
                input_csv=input_csv,
                output_csv=output_csv,
                rows_before_filter=rows_before_filter,
                rows_removed_by_src_ip=rows_removed_by_src_ip,
                rows_classified=0,
                prediction_counts={},
                threat_flows=[],
            )

        features = self._prepare_feature_frame(df)
        predictions = self._model.predict(features)

        output_df = features.copy()
        output_df["Prediction"] = predictions
        output_df["Prediction Label"] = [
            self._format_label(prediction) for prediction in predictions
        ]

        if hasattr(self._model, "predict_proba"):
            probabilities = self._model.predict_proba(features)
            output_df["Prediction Confidence"] = probabilities.max(axis=1)

        output_csv.parent.mkdir(parents=True, exist_ok=True)
        output_df.to_csv(output_csv, index=False)

        prediction_counts = output_df["Prediction Label"].value_counts().to_dict()
        threat_flows = self._build_threat_flows(df, output_df)
        return ClassificationResult(
            input_csv=input_csv,
            output_csv=output_csv,
            rows_before_filter=rows_before_filter,
            rows_removed_by_src_ip=rows_removed_by_src_ip,
            rows_classified=len(output_df),
            prediction_counts={str(label): int(count) for label, count in prediction_counts.items()},
            threat_flows=threat_flows,
        )

    def _load_label_encoder(self, label_encoder_path: Path | None) -> object | None:
        if label_encoder_path is None:
            return None
        if not label_encoder_path.is_file():
            return None
        return joblib.load(label_encoder_path)

    def _resolve_feature_names(self) -> list[str]:
        feature_names = getattr(self._model, "feature_names_in_", None)
        if feature_names is not None:
            return [str(feature_name).strip() for feature_name in feature_names]

        named_steps = getattr(self._model, "named_steps", {})
        for step_name in ("imputer", "classifier"):
            step = named_steps.get(step_name)
            feature_names = getattr(step, "feature_names_in_", None)
            if feature_names is not None:
                return [str(feature_name).strip() for feature_name in feature_names]

        for step in named_steps.values():
            feature_names = getattr(step, "feature_names_in_", None)
            if feature_names is not None:
                return [str(feature_name).strip() for feature_name in feature_names]

        raise ValueError(
            f"O modelo {self._model_path} nao possui feature_names_in_ no pipeline "
            "nem nos steps. Salve o pipeline treinado com nomes de colunas ou adapte "
            "a ordem das features."
        )

    def _filter_source_ip(self, df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
        if not self._remove_src_ip or self._excluded_src_ip is None:
            return df, 0

        if "Src IP" not in df.columns:
            raise ValueError("A coluna 'Src IP' nao foi encontrada no CSV capturado.")

        removal_mask = df["Src IP"].astype(str).str.strip() == self._excluded_src_ip
        removed_count = int(removal_mask.sum())
        return df.loc[~removal_mask].copy(), removed_count

    def _prepare_feature_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        missing_features = [
            feature for feature in self._feature_names if self._find_source_column(df, feature) is None
        ]
        if missing_features:
            raise ValueError(
                "CSV de flows nao possui todas as features esperadas pelo modelo. "
                f"Features ausentes: {missing_features}"
            )

        features = pd.DataFrame(index=df.index)
        for feature in self._feature_names:
            source_column = self._find_source_column(df, feature)
            features[feature] = df[source_column]

        features = features.apply(pd.to_numeric, errors="coerce")
        return features

    def _find_source_column(self, df: pd.DataFrame, feature_name: str) -> str | None:
        candidates = FEATURE_COLUMN_ALIASES.get(feature_name, [feature_name])
        for candidate in candidates:
            if candidate in df.columns:
                return candidate
        return None

    def _format_label(self, prediction: object) -> str:
        if self._label_encoder is not None:
            try:
                return str(self._label_encoder.inverse_transform([prediction])[0])
            except (ValueError, TypeError, IndexError):
                logger.warning("Could not decode prediction label: %s", prediction)

        if self._label_names:
            try:
                index = int(prediction)
            except (TypeError, ValueError):
                return str(prediction)

            if 0 <= index < len(self._label_names):
                return self._label_names[index]

        return str(prediction)

    def _build_threat_flows(
        self,
        original_df: pd.DataFrame,
        output_df: pd.DataFrame,
    ) -> list[ClassifiedThreatFlow]:
        threat_flows: list[ClassifiedThreatFlow] = []
        prediction_labels = output_df["Prediction Label"].astype(str)
        benign_mask = prediction_labels.str.strip().str.upper().isin(self._benign_label_names)

        for index in output_df.index[~benign_mask]:
            threat_flows.append(
                ClassifiedThreatFlow(
                    source_ip=self._read_optional_value(original_df, index, "Src IP"),
                    destination_ip=self._read_optional_value(original_df, index, "Dst IP"),
                    source_port=self._read_optional_value(original_df, index, "Src Port"),
                    destination_port=self._read_optional_value(original_df, index, "Dst Port"),
                    protocol=self._read_optional_value(original_df, index, "Protocol"),
                    prediction_label=str(output_df.at[index, "Prediction Label"]),
                    prediction_confidence=self._read_optional_float(
                        output_df,
                        index,
                        "Prediction Confidence",
                    ),
                )
            )

        return threat_flows

    def _read_optional_value(
        self,
        df: pd.DataFrame,
        index: object,
        column: str,
    ) -> str | None:
        if column not in df.columns:
            return None

        value = df.at[index, column]
        if pd.isna(value):
            return None

        value_text = str(value).strip()
        if not value_text:
            return None

        return value_text

    def _read_optional_float(
        self,
        df: pd.DataFrame,
        index: object,
        column: str,
    ) -> float | None:
        if column not in df.columns:
            return None

        value = df.at[index, column]
        if pd.isna(value):
            return None

        try:
            return float(value)
        except (TypeError, ValueError):
            return None
