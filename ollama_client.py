import requests

def explain_threat(event, model="llama3.2"):
    """Ask a locally running Ollama model to explain a flagged event."""
    prompt = f"""
You are a careful cloud security assistant. Analyze this single simulated cloud activity event.
Explain: (1) why it may be suspicious, (2) severity and uncertainty, (3) three safe investigation steps.
Do not claim that a breach definitely happened. Do not recommend destructive actions.
Event data:
{event}
Keep the response concise and understandable for a student security analyst.
"""
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=90
        )
        response.raise_for_status()
        return response.json().get("response", "Ollama returned an empty response."), None
    except requests.exceptions.ConnectionError:
        return None, "Cannot connect to Ollama. Start Ollama and check that it is running at http://localhost:11434."
    except requests.exceptions.Timeout:
        return None, "Ollama took too long to respond. Try a smaller model or retry."
    except Exception as exc:
        return None, f"Ollama error: {exc}"
