# NetAdaptAI

NetAdaptAI is a vendor-agnostic network configuration compliance workspace. The first vertical slice ingests arbitrary CLI configuration text, normalizes common security controls, evaluates CIS, NIST, STIG, and ISO starter rules, queues unknown lines for administrator training, and generates a device report.

## Run locally

Frontend:

```powershell
npm install
npm run dev
```

Backend:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --app-dir . --reload --port 8000
```

The default database is SQLite, so no database installation is required. Data is stored in `backend/netadaptai.db`.

Ollama is the default local LLM adapter. Install Ollama separately, pull the configured model, and leave it running at `http://localhost:11434`:

```powershell
ollama pull llama3.2:3b
```

Open `http://localhost:3000`. The frontend falls back to an embedded sample device when the API is unavailable, so the dashboard is inspectable before backend setup is complete.

## Architecture

- `app/` is the Next.js operational UI.
- `backend/app/` contains the FastAPI service, normalization rules, compliance engine, training queue, SQLite persistence, Ollama adapter, and PDF report endpoint.
- Normalization intentionally exposes a small, explicit baseline model first. New vendor syntax is captured as training data rather than silently guessed.

## Current assumptions

The initial release uses deterministic pattern recognition and uploaded files only. SQLite is the local persistence layer. Ollama is preferred for privacy and local operation, with deterministic fallback when it is unavailable. Device polling credentials, full benchmark catalogs, role-based access, and signed PDF delivery remain planned integration decisions.
