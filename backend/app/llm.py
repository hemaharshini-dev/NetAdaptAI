import json
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

# Known BaselineModel fields the engine can act on
NORMALIZED_FIELDS = [
    "ssh_version",
    "telnet_enabled",
    "http_enabled",
    "logging_enabled",
    "admin_timeout_minutes",
]

def suggest_mapping(raw_line: str, categories: list[str]) -> dict:
    """Ask the LLM to classify an unrecognized config line.

    Returns a dict with keys:
      category        – human-readable bucket
      normalized_field – BaselineModel field this line maps to (or 'unknown')
      confidence      – 0–1 float
      provider        – 'ollama' or 'heuristic-fallback'
    """
    prompt = (
        "You classify one network device configuration line. "
        "Return ONLY valid JSON with these keys:\n"
        "  category        (one of: " + json.dumps(categories) + ")\n"
        "  normalized_field (one of: " + json.dumps(NORMALIZED_FIELDS + ["unknown"]) + ")\n"
        "  confidence      (float 0-1)\n\n"
        f"Line: {raw_line}"
    )
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }).encode()
    try:
        request = Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode())
        parsed = json.loads(result.get("response", "{}"))
        return {
            "category": parsed.get("category", "Unrecognized command"),
            "normalized_field": parsed.get("normalized_field", "unknown"),
            "confidence": float(parsed.get("confidence", 0.5)),
            "provider": "ollama",
        }
    except (URLError, TimeoutError, ValueError, KeyError, json.JSONDecodeError):
        return {
            "category": "Unrecognized command",
            "normalized_field": "unknown",
            "confidence": 0.35,
            "provider": "heuristic-fallback",
        }
