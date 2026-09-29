from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit

from .canonical import BENCHMARK, BENCHMARK_VERSION
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
current_config_text = ""


def build_device(filename: str, text: str) -> Device:
    """Normalize + evaluate a config text, using current knowledge base."""
    baseline = normalize_config(text, learned_patterns)
    findings = evaluate(baseline, learned_patterns=learned_patterns)
    # UNKNOWN stays in the denominator and therefore cannot increase the score.
    score = round(sum(x.status == "pass" for x in findings) / len(findings) * 100) if findings else 0
    failures = sum(x.status == "fail" for x in findings)
    unknowns = sum(x.status == "unknown" for x in findings)
    return Device(
        id="dev-edge-gw-01",
        name=baseline.hostname,
        vendor=baseline.vendor,
        platform=baseline.platform,
        version=baseline.version,
        score=score,
        status="critical" if failures >= 8 else "attention" if failures or unknowns else "compliant",
        benchmark=BENCHMARK,
        benchmark_version=BENCHMARK_VERSION,
        assessment_type="cross_vendor" if baseline.vendor == "Juniper" else "native",
        findings=findings,
        baseline=baseline,
        source_filename=filename,
        uploaded_at=datetime.now(timezone.utc).isoformat(),
    )


current_config_text = SAMPLE
current_device = build_device("edge-gw-01.cfg", SAMPLE)

database_enabled = database_available()
if database_enabled:
    saved_devices = load_devices()
    saved_training = load_training()
    saved_patterns = load_patterns()
    if saved_devices:
        current_device = saved_devices[-1]
        # Raw configurations may contain credentials, so they are not stored.
        # Require a fresh upload before re-evaluating a persisted snapshot.
        current_config_text = ""
    if saved_training:
        training_items = saved_training
        # Older device snapshots predate the upload-to-training relationship.
        # Reconnect pending items using the raw lines still present in the
        # saved normalized snapshot so the current-config page remains useful.
        if saved_devices and not current_device.training_item_ids:
            current_lines = set(current_device.baseline.unrecognized_lines)
            current_device.training_item_ids = [
                item.id for item in saved_training
                if item.status == "pending" and item.raw_line in current_lines
            ]
            if current_device.training_item_ids:
                save_device(current_device)
    if saved_patterns:
        learned_patterns = saved_patterns
        if not saved_devices:
            current_device = build_device("edge-gw-01.cfg", SAMPLE)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "database": "sqlite" if database_enabled else "unavailable",
        "llm": "optional",
    }


# ── Devices ───────────────────────────────────────────────────────────────────

@app.get("/api/devices", response_model=list[Device])
def devices():
    return [current_device]


@app.post("/api/ingest", response_model=Device)
async def ingest(file: UploadFile = File(...)):
    global current_device, current_config_text
    text = (await file.read()).decode("utf-8", errors="replace")
    current_config_text = text

    # Build device — normalize_config will apply all confirmed learned patterns
    current_device = build_device(file.filename or "uploaded-config.txt", text)
    current_device.training_item_ids = []

    # Queue unrecognized lines that survived learned-pattern matching
    for index, line in enumerate(current_device.baseline.unrecognized_lines[:5], start=1):
        # Skip if we already have a pending item for this exact line
        existing_item = next((t for t in training_items if t.raw_line == line and t.status == "pending"), None)
        if existing_item:
            current_device.training_item_ids.append(existing_item.id)
            continue
        suggestion = suggest_mapping(
            line, LLM_CATEGORIES, current_device.vendor, current_device.platform
        )
        item = TrainingItem(
            id=f"{current_device.id}-train-{index}-{uuid4().hex[:6]}",
            raw_line=line,
            suggested_category=suggestion["category"],
            semantic_meaning=suggestion["semantic_meaning"],
            canonical_control=suggestion.get("canonical_control"),
            canonical_value=suggestion.get("canonical_value"),
            confidence=suggestion["confidence"],
            vendor=current_device.vendor,
            platform=current_device.platform,
            provider=suggestion["provider"],
            status="pending",
        )
        training_items.append(item)
        current_device.training_item_ids.append(item.id)
        save_training(item)

    save_device(current_device)
    current_device.persisted = True

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
    item.semantic_meaning = mapping.semantic_meaning or item.semantic_meaning
    item.canonical_control = mapping.canonical_control
    item.canonical_value = mapping.canonical_value
    item.vendor = mapping.vendor or item.vendor
    item.platform = mapping.platform or item.platform
    item.confidence = mapping.confidence
    save_training(item)

    # Write to knowledge base
    pattern = LearnedPattern(
        id=f"pattern-{uuid4().hex[:10]}",
        source_pattern=item.raw_line,
        canonical_control=mapping.canonical_control,
        canonical_value=mapping.canonical_value,
        label=mapping.label,
        vendor=item.vendor,
        platform=item.platform,
        category=mapping.category,
        confidence=mapping.confidence,
        human_validated=True,
        confirmed_at=datetime.now(timezone.utc).isoformat(),
        training_item_id=item_id,
    )
    learned_patterns.append(pattern)
    save_pattern(pattern)

    # Re-apply the just-approved mapping to the configuration that produced
    # this queue item, so approval immediately becomes a canonical fact.
    global current_device
    if item.raw_line.lower() in current_config_text.lower():
        current_device = build_device(current_device.source_filename, current_config_text)
        save_device(current_device)
        current_device.persisted = True

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
    global learned_patterns, current_device
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
    if current_config_text:
        current_device = build_device(current_device.source_filename, current_config_text)
        save_device(current_device)
        current_device.persisted = True
    return {"deleted": pattern_id}


# ── PDF report ────────────────────────────────────────────────────────────────

@app.get("/api/devices/{device_id}/report")
def report(device_id: str):
    if device_id != current_device.id:
        raise HTTPException(status_code=404, detail="Device not found")
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter, pageCompression=0)
    assessment_label = (
        "Cross-Vendor Mapped Control Assessment"
        if current_device.assessment_type == "cross_vendor"
        else "Native Benchmark Assessment"
    )
    pdf.setTitle(f"NetAdaptAI report - {current_device.name}")

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(54, 744, "NetAdaptAI compliance report")
    pdf.setFont("Helvetica", 11)
    pdf.drawString(54, 720, f"Device: {current_device.name}")
    pdf.drawString(54, 704, f"Source vendor/platform: {current_device.vendor} / {current_device.platform}")
    pdf.drawString(54, 688, f"Benchmark: {current_device.benchmark} v{current_device.benchmark_version} | Profile: Level 1")
    pdf.drawString(54, 672, f"Assessment: {assessment_label}")
    pdf.drawString(54, 656, f"Serial: {current_device.baseline.serial_number} | Score: {current_device.score}%")

    counts = {state: sum(f.status == state for f in current_device.findings)
              for state in ("pass", "fail", "unknown")}
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(54, 632, f"Summary: PASS {counts['pass']} | FAIL {counts['fail']} | UNKNOWN {counts['unknown']}")
    pdf.setFont("Helvetica", 9)
    pdf.drawString(54, 616, "Score = PASS findings divided by all findings; UNKNOWN counts as not passed.")

    y = 588
    for finding in current_device.findings:
        tag = " | CROSS-VENDOR SEMANTIC MAPPING" if finding.assessment_type == "cross_vendor" else ""
        heading = f"[{finding.status.upper()}] {finding.control_id} - {finding.title}{tag}"
        pdf.setFont("Helvetica-Bold", 10)
        for line in simpleSplit(heading, "Helvetica-Bold", 10, letter[0] - 108):
            if y < 72:
                pdf.showPage(); y = 744
            pdf.drawString(54, y, line); y -= 13
        pdf.setFont("Helvetica", 9)
        details = [
            f"Expected: {finding.expected}",
            f"Actual: {finding.actual}",
            f"Evidence: {finding.evidence}",
            f"Remediation: {'; '.join(finding.remediation) or 'None specified'}",
        ]
        if finding.assessment_type == "cross_vendor":
            details.extend([
                f"Mapping confidence: {finding.mapping_confidence:.0%}",
                f"Human validated: {'Yes' if finding.human_validated else 'No'}",
            ])
        for detail in details:
            for line in simpleSplit(detail, "Helvetica", 9, letter[0] - 124):
                if y < 72:
                    pdf.showPage(); y = 744
                pdf.drawString(66, y, line); y -= 12
        y -= 8
        if y < 72:
            pdf.showPage()
            y = 744

    pdf.save()
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{current_device.id}-report.pdf"'},
    )
