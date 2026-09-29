from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from .engine import evaluate, normalize_config
from .database import (
    database_available,
    load_devices,
    load_patterns,
    load_training,
    save_device,
    save_pattern,
    save_training,
)
from .llm import suggest_mapping
from .models import Device, LearnedPattern, TrainingItem, TrainingMapping

app = FastAPI(title="NetAdaptAI Compliance API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Sample device loaded at startup ──────────────────────────────────────────
SAMPLE = (
    "hostname edge-gw-01\nversion 17.9.4 IOS-XE\nChassis serial number FDO2418A0Q7\n"
    "ip ssh version 2\nservice telnet\nip http server\n"
    "logging buffered 16384 informational\nline vty 0 15\n exec-timeout 30 0\n"
    "interface GigabitEthernet1/0/1\n description upstream transit\n"
)

LLM_CATEGORIES = [
    "Interface context",
    "Interface description",
    "Access control",
    "Logging",
    "Unrecognized command",
]


# ── In-memory state (replaced from DB on startup if available) ────────────────
learned_patterns: list[LearnedPattern] = []
training_items: list[TrainingItem] = []


def build_device(filename: str, text: str) -> Device:
    """Normalize + evaluate a config text, using current knowledge base."""
    baseline = normalize_config(text, learned_patterns)
    findings = evaluate(baseline, ["CIS", "NIST", "STIG", "ISO"], learned_patterns)
    scored = [x for x in findings if x.status != "review"]
    score = round(sum(x.status == "pass" for x in scored) / len(scored) * 100) if scored else 0
    failures = sum(x.status == "fail" for x in findings)
    return Device(
        id="dev-edge-gw-01",
        name=baseline.hostname,
        vendor=baseline.vendor,
        platform=baseline.platform,
        version=baseline.version,
        score=score,
        status="critical" if failures >= 8 else "attention" if failures else "compliant",
        findings=findings,
        baseline=baseline,
        source_filename=filename,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
    )


current_device = build_device("edge-gw-01.cfg", SAMPLE)

# Seed training items shown before any upload
training_items = [
    TrainingItem(
        id="train-001",
        raw_line="interface GigabitEthernet1/0/1",
        suggested_category="Interface context",
        suggested_field="unknown",
        confidence=0.91,
    ),
    TrainingItem(
        id="train-002",
        raw_line="description upstream transit",
        suggested_category="Interface description",
        suggested_field="unknown",
        confidence=0.82,
    ),
]

database_enabled = database_available()
if database_enabled:
    saved_devices = load_devices()
    saved_training = load_training()
    saved_patterns = load_patterns()
    if saved_devices:
        current_device = saved_devices[-1]
    if saved_training:
        training_items = saved_training
    if saved_patterns:
        learned_patterns = saved_patterns


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "database": "sqlite", "llm": "ollama"}


# ── Devices ───────────────────────────────────────────────────────────────────

@app.get("/api/devices", response_model=list[Device])
def devices():
    return [current_device]


@app.post("/api/ingest", response_model=Device)
async def ingest(file: UploadFile = File(...)):
    global current_device
    text = (await file.read()).decode("utf-8", errors="replace")

    # Build device — normalize_config will apply all confirmed learned patterns
    current_device = build_device(file.filename or "uploaded-config.txt", text)
    save_device(current_device)

    # Queue unrecognized lines that survived learned-pattern matching
    for index, line in enumerate(current_device.baseline.unrecognized_lines[:5], start=1):
        # Skip if we already have a pending item for this exact line
        if any(t.raw_line == line for t in training_items):
            continue
        suggestion = suggest_mapping(line, LLM_CATEGORIES)
        item = TrainingItem(
            id=f"{current_device.id}-train-{index}-{uuid4().hex[:6]}",
            raw_line=line,
            suggested_category=suggestion["category"],
            suggested_field=suggestion.get("normalized_field", "unknown"),
            confidence=suggestion["confidence"],
            status="pending",
        )
        training_items.append(item)
        save_training(item)

    return current_device


# ── Training queue ────────────────────────────────────────────────────────────

@app.get("/api/training", response_model=list[TrainingItem])
def training():
    return training_items


@app.post("/api/training/{item_id}/approve", response_model=TrainingItem)
def approve_training(item_id: str, mapping: TrainingMapping):
    """Admin approves the AI suggestion (optionally editing the label/field).
    Creates a LearnedPattern entry in the knowledge base.
    """
    item = next((t for t in training_items if t.id == item_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="Training item not found")

    # Update the training item itself
    item.status = "approved"
    item.suggested_category = mapping.category
    item.suggested_field = mapping.normalized_field
    save_training(item)

    # Write to knowledge base
    pattern = LearnedPattern(
        id=f"pattern-{uuid4().hex[:10]}",
        raw_pattern=item.raw_line,
        normalized_field=mapping.normalized_field,
        label=mapping.label,
        vendor=mapping.vendor,
        category=mapping.category,
        confirmed_at=datetime.now(timezone.utc).isoformat(),
        training_item_id=item_id,
    )
    learned_patterns.append(pattern)
    save_pattern(pattern)

    return item


@app.post("/api/training/{item_id}/deny", response_model=TrainingItem)
def deny_training(item_id: str):
    """Admin rejects the AI suggestion — item is marked denied, no pattern is stored."""
    item = next((t for t in training_items if t.id == item_id), None)
    if item is None:
        raise HTTPException(status_code=404, detail="Training item not found")

    item.status = "denied"
    save_training(item)
    return item


# ── Knowledge base (learned patterns) ────────────────────────────────────────

@app.get("/api/patterns", response_model=list[LearnedPattern])
def patterns():
    """Returns the full knowledge base of confirmed patterns."""
    return learned_patterns


@app.delete("/api/patterns/{pattern_id}", response_model=dict)
def delete_pattern(pattern_id: str):
    """Remove a confirmed pattern from the knowledge base."""
    global learned_patterns
    before = len(learned_patterns)
    learned_patterns = [p for p in learned_patterns if p.id != pattern_id]
    if len(learned_patterns) == before:
        raise HTTPException(status_code=404, detail="Pattern not found")
    # Persist the deletion (reload from DB would be cleaner; for now just overwrite)
    from .database import _engine
    from .database import LearnedPatternRecord
    from sqlalchemy.orm import Session
    with Session(_engine) as session:
        record = session.get(LearnedPatternRecord, pattern_id)
        if record:
            session.delete(record)
            session.commit()
    return {"deleted": pattern_id}


# ── PDF report ────────────────────────────────────────────────────────────────

@app.get("/api/devices/{device_id}/report")
def report(device_id: str):
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    pdf.setTitle(f"NetAdaptAI report - {current_device.name}")

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(54, 744, "NetAdaptAI compliance report")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(54, 720, f"Device: {current_device.name} | {current_device.vendor} {current_device.platform}")
    pdf.drawString(54, 702, f"Serial: {current_device.baseline.serial_number} | Score: {current_device.score}%")

    y = 665
    for finding in current_device.findings[:16]:
        tag = " [LEARNED]" if finding.learned else ""
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(
            54,
            y,
            f"[{finding.status.upper()}] {finding.cis_id} - {finding.title}{tag}",
        )
        pdf.setFont("Helvetica", 9)
        pdf.drawString(70, y - 14, finding.summary[:100])
        y -= 38
        if y < 70:
            pdf.showPage()
            y = 744

    pdf.save()
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={current_device.name}-report.pdf"},
    )
