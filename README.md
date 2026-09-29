# NetAdaptAI

NetAdaptAI is a local network-configuration assessment prototype. It parses uploaded Cisco IOS XE configuration text into normalized security facts, evaluates the CIS Cisco IOS XE 17.x Benchmark v2.2.1 rule set deterministically, queues unsupported syntax for human-reviewed mapping, stores confirmed mappings in SQLite, and generates a PDF report.

The prototype currently has **one benchmark**. Juniper support is deliberately limited to a built-in SSHv2 mapping used to demonstrate cross-vendor assessment. A Cisco benchmark result applied to Juniper syntax is labelled as a cross-vendor mapped-control assessment; it is not official Juniper benchmark compliance.

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

The backend uses SQLite at `backend/netadaptai.db`. Ollama is optional; when available, the backend uses the configured model to propose mappings for unsupported command lines. Install Ollama and pull the default model with:

```powershell
ollama pull llama3.2:3b
```

Open `http://localhost:3000`. If the API has no saved upload yet, the app shows clearly labelled local demo data. When the API or Ollama is unavailable, basic Cisco normalization and deterministic compliance evaluation remain available; unknown commands stay unknown.

## Assessment behavior

- Cisco IOS XE configurations are parsed into the existing normalized baseline model.
- The evaluator contains 56 unique CIS rule definitions represented by the current prototype. The paired login success/failure commands are combined under the benchmark's single 2.2.8 control. The rules decide PASS, FAIL, or UNKNOWN; the LLM never makes compliance decisions.
- PASS scoring is `PASS findings / all findings`. UNKNOWN findings remain in the denominator and cannot improve the score.
- Unrecognized commands can receive an Ollama mapping proposal. An administrator must approve a canonical control and value before it is stored and applied.
- Approved mappings are checked before requesting another LLM proposal. A matching source command populates its canonical fact and is evaluated by the same deterministic rules.
- A small built-in Juniper mapping supports `set system services ssh protocol-version v2`. The corresponding CIS control is marked `cross_vendor`, with confidence and human-validation status visible in the UI and report.

## Project layout

- `app/` contains the Next.js dashboard and responsive styles.
- `backend/app/canonical.py` defines benchmark metadata and the canonical-control vocabulary.
- `backend/app/models.py` defines API, finding, device, training, and learned-mapping models.
- `backend/app/engine.py` contains Cisco normalization and the 56 CIS rule definitions/evaluator.
- `backend/app/llm.py` proposes mappings for a bounded set of canonical controls.
- `backend/app/database.py` persists devices, training items, and learned mappings and migrates older SQLite tables.
- `backend/app/main.py` exposes ingestion, training, pattern, device, health, and PDF endpoints.
- `test-configs/` contains sample Cisco and Juniper configurations.
- `cisco-rule-engine-green-path.cfg` is a synthetic fixture that passes the current implementation's 56 checks; it is not a production configuration or independent benchmark certification.

## API

- `GET /health`
- `GET /api/devices`
- `POST /api/ingest` with multipart field `file`
- `GET /api/training`
- `POST /api/training/{item_id}/approve`
- `POST /api/training/{item_id}/deny`
- `GET /api/patterns`
- `DELETE /api/patterns/{pattern_id}`
- `GET /api/devices/{device_id}/report`

## Tests

From the `backend` directory, run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover Cisco parsing, deterministic rule outcomes, unknown Juniper controls, the Juniper SSH mapping, the finding API contract, PDF response generation, and the human-approved mapping reuse loop.

Device polling credentials, complete Juniper support, authentication, automatic remediation, and other benchmark catalogs are not implemented.
