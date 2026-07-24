"""Standardized Isolation Forest analysis for supplied device metadata."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from statistics import median
from typing import Any

from app.modules.wireless.exceptions import BehaviorEngineUnavailable
from app.modules.wireless.models import (
    BehaviorAnalysisResult,
    DeviceBehaviorAssessment,
    DeviceBehaviorRecord,
)

MINIMUM_MODEL_SAMPLES = 5


class BehaviorAnalysisEngine:
    """Detect multivariate outliers without collecting network traffic."""

    def __init__(
        self,
        scaler_factory: Callable[[], Any] | None = None,
        isolation_factory: Callable[..., Any] | None = None,
        cluster_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._scaler_factory = scaler_factory
        self._isolation_factory = isolation_factory
        self._cluster_factory = cluster_factory

    def analyze(
        self,
        records: Sequence[DeviceBehaviorRecord],
        contamination: float = 0.1,
    ) -> BehaviorAnalysisResult:
        """Standardize aggregate features and execute Isolation Forest."""
        if len(records) < MINIMUM_MODEL_SAMPLES:
            return BehaviorAnalysisResult(
                engine="IsolationForest",
                sample_count=len(records),
                model_executed=False,
                anomaly_count=0,
                assessments=tuple(
                    DeviceBehaviorAssessment(mac=item.mac, anomaly=False)
                    for item in records
                ),
                explanation=(
                    f"At least {MINIMUM_MODEL_SAMPLES} device records are "
                    "required for anomaly modelling."
                ),
            )

        scaler_factory, isolation_factory, cluster_factory = self._factories()
        features = [_features(item) for item in records]
        scaled = scaler_factory().fit_transform(features)
        model = isolation_factory(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=1,
        )
        predictions = model.fit_predict(scaled)
        scores = model.score_samples(scaled)
        clusters = (
            cluster_factory(
                eps=1.5,
                min_samples=2,
                n_jobs=1,
            ).fit_predict(scaled)
            if cluster_factory is not None
            else [0] * len(records)
        )
        cluster_sizes: dict[int, int] = {}
        for cluster in clusters:
            cluster_sizes[int(cluster)] = cluster_sizes.get(int(cluster), 0) + 1
        latest_seen = max(item.last_seen for item in records)
        baselines = tuple(
            median(feature[index] for feature in features)
            for index in range(len(features[0]))
        )
        assessments = tuple(
            DeviceBehaviorAssessment(
                mac=record.mac,
                anomaly=int(predictions[index]) == -1,
                anomaly_score=round(float(-scores[index]), 6),
                cluster=int(clusters[index]),
                rare_cluster=cluster_sizes[int(clusters[index])] == 1,
                newly_appeared=(
                    latest_seen - record.first_seen
                ).total_seconds() <= 86_400,
                evidence=(
                    _outlier_evidence(features[index], baselines)
                    if int(predictions[index]) == -1
                    else ()
                ),
            )
            for index, record in enumerate(records)
        )
        anomaly_count = sum(item.anomaly for item in assessments)
        return BehaviorAnalysisResult(
            engine="StandardScaler + DBSCAN + IsolationForest",
            sample_count=len(records),
            model_executed=True,
            anomaly_count=anomaly_count,
            assessments=assessments,
            explanation=(
                "Anomalies are statistical outliers requiring investigation; "
                "they are not proof of malicious activity."
            ),
        )

    def _factories(self):
        if self._scaler_factory and self._isolation_factory:
            return (
                self._scaler_factory,
                self._isolation_factory,
                self._cluster_factory,
            )
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.cluster import DBSCAN
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:
            raise BehaviorEngineUnavailable(
                "Behavior analysis requires scikit-learn"
            ) from exc
        return StandardScaler, IsolationForest, DBSCAN


def _features(record: DeviceBehaviorRecord) -> list[float]:
    observed_hours = (
        record.last_seen - record.first_seen
    ).total_seconds() / 3600
    return [
        record.traffic_volume_mb,
        record.session_duration_minutes,
        record.connection_frequency,
        max(observed_hours, 0),
    ]


def _outlier_evidence(
    values: Sequence[float],
    baselines: Sequence[float],
) -> tuple[str, ...]:
    names = (
        "traffic volume",
        "session duration",
        "connection frequency",
        "observed time span",
    )
    evidence = []
    for name, value, baseline in zip(names, values, baselines):
        if baseline == 0 and value > 0:
            evidence.append(f"{name} exceeds a zero-valued cohort median")
        elif baseline > 0 and value >= baseline * 3:
            evidence.append(f"{name} is at least three times the cohort median")
    return tuple(evidence) or (
        "Multivariate feature combination differs from the observed cohort",
    )
