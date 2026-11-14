import numpy as np
import pandas as pd

def generate_demo_logs(n=300, include_anomalies=True, seed=42):
    """Create synthetic cloud-style authentication and activity events."""
    rng = np.random.default_rng(seed)
    rows = []
    countries = ["India", "Singapore", "United States", "Germany", "United Kingdom"]

    for i in range(n):
        anomalous = include_anomalies and rng.random() < 0.10
        if anomalous:
            hour = int(rng.choice([0, 1, 2, 3, 4, 23]))
            failed = int(rng.integers(6, 20))
            success = int(rng.choice([0, 1]))
            new_device = int(rng.choice([0, 1], p=[0.2, 0.8]))
            unusual = int(rng.choice([0, 1], p=[0.15, 0.85]))
            downloaded = int(rng.integers(300000, 1200000))
            country = str(rng.choice(["Unknown", "Russia", "Brazil", "Unknown"]))
        else:
            hour = int(np.clip(rng.normal(13, 3.5), 6, 22))
            failed = int(rng.choice([0, 0, 0, 1, 2, 3]))
            success = 1
            new_device = int(rng.random() < 0.06)
            unusual = 0
            downloaded = int(rng.integers(1000, 180000))
            country = str(rng.choice(countries))

        rows.append({
            "timestamp": (pd.Timestamp.now().floor("min") - pd.Timedelta(minutes=n-i)).isoformat(),
            "username": f"user{int(rng.integers(1, 45)):03d}",
            "source_ip": f"192.0.2.{int(rng.integers(1, 255))}" if not anomalous else f"203.0.113.{int(rng.integers(1, 255))}",
            "country": country,
            "login_hour": hour,
            "failed_attempts": failed,
            "successful_login": success,
            "new_device": new_device,
            "unusual_location": unusual,
            "bytes_downloaded": downloaded,
            "action": str(rng.choice(["login", "file_access", "download"]))
        })
    return pd.DataFrame(rows)
