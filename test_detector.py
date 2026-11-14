from data_generator import generate_demo_logs
from detector import prepare_logs, train_detector, detect_threats

logs = generate_demo_logs(100, include_anomalies=True)
X, clean = prepare_logs(logs)
model = train_detector(X)
result = detect_threats(model, X, clean)
assert len(result) == 100
assert set(result["risk_level"]).issubset({"LOW", "MEDIUM", "HIGH"})
print("CloudShield detector test passed.")
