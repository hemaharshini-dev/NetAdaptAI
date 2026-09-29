import json
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

from .canonical import coerce_canonical_value

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

CANONICAL_CONTROLS = [
    "management.ssh.version",
    "management.telnet.enabled",
    "management.http.enabled",
    "logging.enabled",
    "logging.remote_logging.enabled",
]

def suggest_mapping(raw_line: str, categories: list[str], vendor: str = "", platform: str = "") -> dict:
    """Ask the LLM to classify an unrecognized config line.

    Returns a dict with keys:
      category        – human-readable bucket
      canonical_control – canonical control this line expresses, if understood
      canonical_value – the proposed configuration value
      confidence      – 0–1 float
      provider        – 'ollama' or 'heuristic-fallback'
    """
    prompt = (
        "Propose a semantic mapping for one network device configuration line. "
        "You are only mapping configuration to a canonical fact. Never decide "
        "PASS, FAIL, compliant, or non-compliant. Return ONLY valid JSON with:\n"
        "  semantic_meaning (short description)\n"
        "  canonical_control (one of: " + json.dumps(CANONICAL_CONTROLS) + ")\n"
        "  canonical_value (the value expressed by the command)\n"
        "  security_category (one of: " + json.dumps(categories) + ")\n"
        "  confidence (float 0-1)\n\n"
        f"Vendor: {vendor or 'unknown'}\n"
        f"Platform: {platform or 'unknown'}\n"
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
        control = parsed.get("canonical_control")
        value = parsed.get("canonical_value")
        if control not in CANONICAL_CONTROLS:
            raise ValueError("Unsupported canonical control")
        category = parsed.get("security_category", "Unrecognized command")
        if category not in categories:
            category = "Unrecognized command"
        value = coerce_canonical_value(control, value)
        return {
            "semantic_meaning": str(parsed.get("semantic_meaning", ""))[:300],
            "category": category,
            "canonical_control": control,
            "canonical_value": value,
            "confidence": max(0.0, min(1.0, float(parsed.get("confidence", 0.5)))),
            "provider": "ollama",
        }
    except (URLError, TimeoutError, ValueError, TypeError, AttributeError, KeyError, json.JSONDecodeError):
        return {
            "semantic_meaning": "No reliable semantic mapping was available.",
            "category": "Unrecognized command",
            "canonical_control": None,
            "canonical_value": None,
            "confidence": 0.35,
            "provider": "heuristic-fallback",
        }
