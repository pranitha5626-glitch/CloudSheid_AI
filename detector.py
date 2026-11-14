import numpy as np
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "username", "source_ip", "country", "login_hour",
    "failed_attempts", "successful_login", "new_device",
    "unusual_location", "bytes_downloaded", "action"
]

FEATURE_COLUMNS = [
    "login_hour", "failed_attempts", "successful_login",
    "new_device", "unusual_location", "bytes_downloaded"
]


def prepare_logs(df):
    """Validate and convert log fields into numeric ML features."""
    data = df.copy()
    for col in REQUIRED_COLUMNS:
        if col not in data.columns:
            raise ValueError(f"Missing required column: {col}")

    for col in FEATURE_COLUMNS:
        data[col] = pd.to_numeric(data[col], errors="coerce")

    defaults = {
        "login_hour": 12,
        "failed_attempts": 0,
        "successful_login": 1,
        "new_device": 0,
        "unusual_location": 0,
        "bytes_downloaded": 0,
    }
    for col, default in defaults.items():
        data[col] = data[col].fillna(default)

    data["login_hour"] = data["login_hour"].clip(0, 23)
    data["failed_attempts"] = data["failed_attempts"].clip(lower=0)
    data["bytes_downloaded"] = data["bytes_downloaded"].clip(lower=0)

    X = data[FEATURE_COLUMNS].astype(float)
    return X, data


class CloudShieldDetector:
    """Small NumPy-only anomaly detector.

    This replaces scikit-learn's IsolationForest so the application does not
    require sklearn's native Windows DLLs. It uses robust median/MAD scaling
    and a distance-from-normal score, while the existing security heuristics
    provide the final risk score and explanation.
    """

    def __init__(self):
        self.median_ = None
        self.mad_ = None
        self.threshold_ = 3.5

    def fit(self, X):
        values = np.asarray(X, dtype=float)
        self.median_ = np.median(values, axis=0)
        mad = np.median(np.abs(values - self.median_), axis=0)
        # Avoid division by zero for constant columns.
        self.mad_ = np.where(mad < 1e-9, 1.0, mad)
        return self

    def _score(self, X):
        values = np.asarray(X, dtype=float)
        robust_z = 0.6745 * (values - self.median_) / self.mad_
        # Euclidean magnitude of robust z-scores, normalized by feature count.
        return np.sqrt(np.mean(np.square(robust_z), axis=1))

    def predict(self, X):
        return np.where(self._score(X) > self.threshold_, -1, 1)

    def decision_function(self, X):
        # Positive = normal, negative = anomalous, matching sklearn's API.
        return self.threshold_ - self._score(X)


def train_detector(X):
    """Train an unsupervised anomaly detector without native ML DLLs."""
    return CloudShieldDetector().fit(X)


def detect_threats(model, X, clean_logs):
    """Return each event with a heuristic risk score and readable reason."""
    predictions = model.predict(X)
    anomaly_strength = -model.decision_function(X)

    # Convert anomaly strength to a stable 0-100 relative score.
    lo, hi = np.percentile(anomaly_strength, [5, 95]) if len(anomaly_strength) > 1 else (0, 1)
    if hi <= lo:
        normalized = np.zeros(len(anomaly_strength))
    else:
        normalized = np.clip((anomaly_strength - lo) / (hi - lo), 0, 1)
    scores = normalized * 65

    reasons = []
    for i, row in clean_logs.reset_index(drop=True).iterrows():
        flags = []
        if row["failed_attempts"] >= 5:
            flags.append("many failed login attempts")
            scores[i] = max(scores[i], 75)
        if row["new_device"] == 1:
            flags.append("login from a new device")
            scores[i] = max(scores[i], 55)
        if row["unusual_location"] == 1:
            flags.append("unusual login location")
            scores[i] = max(scores[i], 70)
        if row["login_hour"] <= 5 or row["login_hour"] >= 23:
            flags.append("login at an unusual hour")
            scores[i] = max(scores[i], 50)
        if row["bytes_downloaded"] >= 500000:
            flags.append("unusually large data download")
            scores[i] = max(scores[i], 75)
        if predictions[i] == -1:
            flags.append("ML model marked this activity as anomalous")
            scores[i] = max(scores[i], 60)

        reasons.append("; ".join(flags) if flags else "No strong suspicious indicators found.")

    risk_levels = ["HIGH" if s >= 70 else "MEDIUM" if s >= 45 else "LOW" for s in scores]
    output = clean_logs.copy()
    output["risk_score"] = np.round(scores).astype(int)
    output["risk_level"] = risk_levels
    output["reason"] = reasons
    output["ml_anomaly"] = predictions == -1
    return output
