"""Tests for bounded behavior and anomaly analysis."""

import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.modules.wireless.analysis.behavior import BehaviorAnalysisEngine
from app.modules.wireless.models import DeviceBehaviorRecord


class FakeScaler:
    def fit_transform(self, values):
        return values


class FakeIsolationForest:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def fit_predict(self, values):
        return [1] * (len(values) - 1) + [-1]

    def score_samples(self, values):
        return [-0.1] * (len(values) - 1) + [-0.9]


def records(count: int) -> list[DeviceBehaviorRecord]:
    now = datetime.now(timezone.utc)
    return [
        DeviceBehaviorRecord(
            mac=f"00:1A:2B:00:00:{index:02X}",
            traffic_volume_mb=10 if index < count - 1 else 1000,
            session_duration_minutes=20,
            connection_frequency=3,
            first_seen=now - timedelta(hours=24),
            last_seen=now,
        )
        for index in range(count)
    ]


class BehaviorAnalysisTests(unittest.TestCase):
    def test_small_dataset_is_not_overinterpreted(self) -> None:
        result = BehaviorAnalysisEngine().analyze(records(4))

        self.assertFalse(result.model_executed)
        self.assertEqual(result.anomaly_count, 0)

    def test_injected_isolation_backend_marks_anomaly(self) -> None:
        engine = BehaviorAnalysisEngine(
            scaler_factory=FakeScaler,
            isolation_factory=FakeIsolationForest,
        )
        result = engine.analyze(records(6), contamination=0.2)

        self.assertTrue(result.model_executed)
        self.assertEqual(result.anomaly_count, 1)
        self.assertTrue(result.assessments[-1].anomaly)
        self.assertTrue(result.assessments[-1].evidence)

    def test_api_handles_insufficient_data_without_ml_import(self) -> None:
        now = datetime.now(timezone.utc)
        response = TestClient(app).post(
            "/api/v1/wireless/behavior",
            json={
                "records": [
                    {
                        "mac": "00:1A:2B:44:55:66",
                        "traffic_volume_mb": 10,
                        "session_duration_minutes": 20,
                        "connection_frequency": 2,
                        "first_seen": (now - timedelta(hours=1)).isoformat(),
                        "last_seen": now.isoformat(),
                    }
                ]
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["data"]["model_executed"])

    def test_api_reports_missing_production_ml_dependency(self) -> None:
        if _sklearn_available():
            self.skipTest("scikit-learn is installed")
        now = datetime.now(timezone.utc)
        payload_records = [
            {
                "mac": f"00:1A:2B:00:00:{index:02X}",
                "traffic_volume_mb": 10 + index,
                "session_duration_minutes": 20,
                "connection_frequency": 2,
                "first_seen": (now - timedelta(hours=1)).isoformat(),
                "last_seen": now.isoformat(),
            }
            for index in range(5)
        ]

        response = TestClient(app).post(
            "/api/v1/wireless/behavior",
            json={"records": payload_records},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"],
            "Behavior analysis requires scikit-learn",
        )

    def test_real_sklearn_api_executes_model_when_installed(self) -> None:
        if not _sklearn_available():
            self.skipTest("scikit-learn is not installed")
        now = datetime.now(timezone.utc)
        payload_records = [
            {
                "mac": f"00:1A:2B:00:01:{index:02X}",
                "traffic_volume_mb": 10 + index if index < 19 else 10_000,
                "session_duration_minutes": 20 + index,
                "connection_frequency": 2 + index / 10,
                "first_seen": (now - timedelta(hours=24)).isoformat(),
                "last_seen": now.isoformat(),
            }
            for index in range(20)
        ]

        response = TestClient(app).post(
            "/api/v1/wireless/behavior",
            json={"records": payload_records, "contamination": 0.05},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertTrue(data["model_executed"])
        self.assertEqual(
            data["engine"],
            "StandardScaler + DBSCAN + IsolationForest",
        )
        self.assertGreaterEqual(data["anomaly_count"], 1)
        self.assertTrue(
            all(item["cluster"] is not None for item in data["assessments"])
        )


def _sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
    except ImportError:
        return False
    return True


if __name__ == "__main__":
    unittest.main()
