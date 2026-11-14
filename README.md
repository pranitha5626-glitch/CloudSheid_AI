# CloudShield AI — Intelligent Cloud Security Guardian

A local hackathon prototype that analyzes simulated or uploaded cloud activity logs, detects unusual activity using Isolation Forest, assigns a risk score, and optionally asks a local Ollama model to explain an event.

## Important scope
This starter project does **not** connect to AWS, monitor real accounts, or block users. The included events are synthetic. Treat alerts as investigation leads, not proof of an attack.

## 1. Requirements
- Python 3.10 or newer
- VS Code (recommended)
- Ollama (optional, only for natural-language explanations)

## 2. Setup

Open a terminal in this folder:

```bash
python -m venv .venv
```

Activate it:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

**Windows Command Prompt**
```bat
.venv\\Scripts\\activate.bat
```

**macOS/Linux**
```bash
source .venv/bin/activate
```

Install packages:
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Run the app
```bash
streamlit run app.py
```
The app opens in your browser, normally at `http://localhost:8501`.

## 4. Enable Ollama explanations (optional)
Install and start Ollama, then download a model:
```bash
ollama pull llama3.2
```
Keep Ollama running. In the CloudShield sidebar, enable **Ollama explanations** and use model name `llama3.2`.

## 5. Upload your own CSV
The CSV must contain these columns:

`timestamp, username, source_ip, country, login_hour, failed_attempts, successful_login, new_device, unusual_location, bytes_downloaded, action`

Boolean columns should use 0/1. `login_hour` should be 0–23. `bytes_downloaded` is a number of bytes.

A sample file is included at `data/sample_security_logs.csv`.

## 6. Demo flow
1. Start the app using the command above.
2. Show the event count and risk distribution.
3. Select a high-risk event and inspect its reasons.
4. Click **Add a simulated suspicious login** to add an obvious suspicious event.
5. Enable Ollama explanations and generate an explanation.
6. Download the analyzed CSV report.

## Project structure
- `app.py` — Streamlit dashboard
- `detector.py` — preprocessing, Isolation Forest and risk scoring
- `data_generator.py` — synthetic demonstration logs
- `ollama_client.py` — optional local LLM integration
- `data/sample_security_logs.csv` — sample upload dataset

## Next development step: real cloud logs
For a real deployment, add a controlled AWS integration (for example, read-only CloudTrail event ingestion), authentication, secrets management, access controls, audit logging, and alert review. Never paste cloud access keys into source code. Start in a sandbox AWS account and keep the integration read-only until thoroughly tested.


## Windows compatibility note
The detector uses NumPy instead of scikit-learn IsolationForest. This avoids native scikit-learn DLLs that can be blocked by Windows Application Control/Defender policies.
##Team members
Your Friend's Name
Nidhi Rai D