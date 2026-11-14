import streamlit as st
import pandas as pd
import plotly.express as px
from detector import prepare_logs, train_detector, detect_threats, REQUIRED_COLUMNS
from ollama_client import explain_threat
from data_generator import generate_demo_logs

st.set_page_config(page_title="CloudShield AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main {background-color: #1e3a5f;}
[data-testid="stMetric"] {background: #151f33; padding: 14px; border-radius: 12px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CloudShield AI")
st.caption("Intelligent Cloud Security Guardian • ML-powered anomaly detection with AI explanations")

with st.sidebar:
    st.header("Data source")
    source = st.radio("Choose activity logs", ["Demo security logs", "Upload CSV"])
    st.divider()
    st.subheader("AI explanation")
    use_ollama = st.toggle("Enable Ollama explanations", value=False)
    ollama_model = st.text_input("Ollama model", value="llama3.2")
    st.caption("Ollama must be running locally. The ML detector works without it.")

@st.cache_resource
def get_model():
    training_data = generate_demo_logs(1200, include_anomalies=False)
    X, _ = prepare_logs(training_data)
    return train_detector(X)

if source == "Demo security logs":
    logs = generate_demo_logs(300, include_anomalies=True)
    st.info("Using generated demonstration logs. These are simulated events, not real cloud activity.")
else:
    uploaded = st.file_uploader("Upload a CSV file", type=["csv"])
    if uploaded is None:
        st.warning("Upload a CSV to begin, or select Demo security logs.")
        st.stop()
    try:
        logs = pd.read_csv(uploaded)
    except Exception as exc:
        st.error(f"Could not read CSV: {exc}")
        st.stop()

missing = [c for c in REQUIRED_COLUMNS if c not in logs.columns]
if missing:
    st.error("Your CSV is missing required columns: " + ", ".join(missing))
    st.markdown("Required columns: `" + ", ".join(REQUIRED_COLUMNS) + "`")
    st.stop()

logs = logs.copy()
X, clean_logs = prepare_logs(logs)
model = get_model()
results = detect_threats(model, X, clean_logs)
results.insert(0, "event_id", range(1, len(results) + 1))

# Add a demo event button that appends a conspicuous suspicious event.
if st.button("⚡ Add a simulated suspicious login"):
    extra = pd.DataFrame([{
        "timestamp": pd.Timestamp.now().isoformat(),
        "username": "demo_admin",
        "source_ip": "203.0.113.77",
        "country": "Unknown",
        "login_hour": 3,
        "failed_attempts": 18,
        "successful_login": 1,
        "new_device": 1,
        "unusual_location": 1,
        "bytes_downloaded": 950000,
        "action": "login"
    }])
    st.session_state["extra_event"] = extra
    st.rerun()

if "extra_event" in st.session_state:
    extra = st.session_state["extra_event"]
    logs = pd.concat([logs, extra], ignore_index=True)
    X, clean_logs = prepare_logs(logs)
    results = detect_threats(model, X, clean_logs)
    results.insert(0, "event_id", range(1, len(results) + 1))

total = len(results)
high = int((results["risk_level"] == "HIGH").sum())
medium = int((results["risk_level"] == "MEDIUM").sum())
low = int((results["risk_level"] == "LOW").sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analyzed", f"{total:,}")
c2.metric("High risk", high)
c3.metric("Medium risk", medium)
c4.metric("Low risk", low)

left, right = st.columns([1.25, 1])
with left:
    st.subheader("Security activity")
    timeline = results.copy()
    timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], errors="coerce")
    timeline = timeline.dropna(subset=["timestamp"]).sort_values("timestamp")
    if not timeline.empty:
        counts = timeline.set_index("timestamp").resample("h")["risk_score"].count().reset_index(name="events")
        st.plotly_chart(px.line(counts, x="timestamp", y="events", title="Events over time"), use_container_width=True)
    else:
        st.write("No valid timestamps to plot.")
with right:
    st.subheader("Risk distribution")
    risk_counts = results["risk_level"].value_counts().rename_axis("risk").reset_index(name="events")
    st.plotly_chart(px.pie(risk_counts, names="risk", values="events", hole=0.55), use_container_width=True)

st.subheader("Detected security events")
risk_filter = st.multiselect("Filter by risk", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"])
shown = results[results["risk_level"].isin(risk_filter)].sort_values("risk_score", ascending=False)
display_cols = ["event_id", "timestamp", "username", "source_ip", "country",
                "failed_attempts", "new_device", "unusual_location",
                "risk_score", "risk_level", "reason"]
st.dataframe(shown[display_cols], use_container_width=True, hide_index=True)

st.download_button(
    "⬇️ Download analyzed security report",
    data=results.to_csv(index=False).encode("utf-8"),
    file_name="cloudshield_security_report.csv",
    mime="text/csv"
)

st.subheader("🔎 Investigate an event")
if not results.empty:
    selected_id = st.selectbox("Select event ID", results["event_id"].tolist())
    event = results.loc[results["event_id"] == selected_id].iloc[0]
    a, b = st.columns([1, 1])
    with a:
        st.write("**Selected event**")
        st.json({k: (v.item() if hasattr(v, "item") else v) for k, v in event.to_dict().items()})
    with b:
        st.write("**Security assessment**")
        st.markdown(f"### {event['risk_level']} risk · {event['risk_score']}/100")
        st.write(event["reason"])
        if use_ollama:
            if st.button("Generate AI explanation and recommendations"):
                with st.spinner("Asking Ollama to analyze this event..."):
                    explanation, error = explain_threat(event.to_dict(), ollama_model)
                if error:
                    st.error(error)
                else:
                    st.markdown(explanation)
        else:
            st.caption("Turn on Ollama explanations in the sidebar to generate a natural-language assessment.")

st.divider()
st.caption("Prototype notice: this project analyzes simulated or user-provided logs. It does not connect to AWS or block real users. Validate alerts before taking security action.")
