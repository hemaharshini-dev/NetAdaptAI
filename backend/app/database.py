from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.types import JSON
from .models import Device, LearnedPattern, TrainingItem

DEFAULT_DATABASE_URL = f"sqlite:///{Path(__file__).resolve().parents[1] / 'netadaptai.db'}"
_engine = create_engine(DEFAULT_DATABASE_URL, connect_args={"check_same_thread": False})

class Base(DeclarativeBase):
    pass

class DeviceRecord(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    vendor: Mapped[str] = mapped_column(String(120))
    platform: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(120))
    score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(40))
    source_filename: Mapped[str] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    baseline: Mapped[dict] = mapped_column(JSON)
    findings: Mapped[list] = mapped_column(JSON)
    training_item_ids: Mapped[list] = mapped_column(JSON, default=list)

class TrainingRecord(Base):
    __tablename__ = "training_items"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    raw_line: Mapped[str] = mapped_column(Text)
    suggested_category: Mapped[str] = mapped_column(String(255))
    # AI-suggested normalized field name (e.g. "telnet_enabled") and value
    suggested_field: Mapped[str | None] = mapped_column(String(120), nullable=True)
    suggested_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    semantic_meaning: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_control: Mapped[str | None] = mapped_column(String(160), nullable=True)
    canonical_value: Mapped[object | None] = mapped_column(JSON, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(120), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(80), nullable=True)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(40), default="pending")  # pending | approved | denied

class LearnedPatternRecord(Base):
    """Knowledge base: patterns the admin has confirmed."""
    __tablename__ = "learned_patterns"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    # The exact or partial text fragment used for matching (case-insensitive contains)
    raw_pattern: Mapped[str] = mapped_column(Text)
    # Which BaselineModel field this line populates
    normalized_field: Mapped[str] = mapped_column(String(120))
    # Human-readable label shown in the UI (e.g. "Disable Telnet")
    label: Mapped[str] = mapped_column(String(255))
    # Optional: vendor scope (empty string = any vendor)
    vendor: Mapped[str] = mapped_column(String(120), default="")
    # The category bucket (maps to engine RULES category)
    category: Mapped[str] = mapped_column(String(255))
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Source training item
    training_item_id: Mapped[str] = mapped_column(String(120))
    canonical_control: Mapped[str | None] = mapped_column(String(160), nullable=True)
    canonical_value: Mapped[object | None] = mapped_column(JSON, nullable=True)
    platform: Mapped[str | None] = mapped_column(String(120), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    human_validated: Mapped[bool] = mapped_column(Boolean, default=True)

def database_available() -> bool:
    try:
        with _engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        # Create any brand-new tables (learned_patterns, etc.)
        Base.metadata.create_all(_engine)
        # Migrate existing tables: add columns that didn't exist in older DB files.
        # SQLite has no "ADD COLUMN IF NOT EXISTS" before 3.37, so we check manually.
        _migrate_training_items()
        _migrate_patterns()
        _migrate_devices()
        return True
    except Exception:
        return False


def _migrate_training_items() -> None:
    """Add new columns to training_items if they are missing (schema migration)."""
    with _engine.connect() as conn:
        existing = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(training_items)").fetchall()
        }
        migrations = [
            ("suggested_field", "ALTER TABLE training_items ADD COLUMN suggested_field VARCHAR(120)"),
            ("suggested_value", "ALTER TABLE training_items ADD COLUMN suggested_value VARCHAR(255)"),
            ("semantic_meaning", "ALTER TABLE training_items ADD COLUMN semantic_meaning TEXT"),
            ("canonical_control", "ALTER TABLE training_items ADD COLUMN canonical_control VARCHAR(160)"),
            ("canonical_value", "ALTER TABLE training_items ADD COLUMN canonical_value JSON"),
            ("vendor", "ALTER TABLE training_items ADD COLUMN vendor VARCHAR(120)"),
            ("platform", "ALTER TABLE training_items ADD COLUMN platform VARCHAR(120)"),
            ("provider", "ALTER TABLE training_items ADD COLUMN provider VARCHAR(80)"),
        ]
        for col_name, sql in migrations:
            if col_name not in existing:
                conn.exec_driver_sql(sql)
        conn.commit()


def _migrate_patterns() -> None:
    with _engine.connect() as conn:
        existing = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(learned_patterns)").fetchall()
        }
        migrations = [
            ("canonical_control", "ALTER TABLE learned_patterns ADD COLUMN canonical_control VARCHAR(160)"),
            ("canonical_value", "ALTER TABLE learned_patterns ADD COLUMN canonical_value JSON"),
            ("platform", "ALTER TABLE learned_patterns ADD COLUMN platform VARCHAR(120)"),
            ("confidence", "ALTER TABLE learned_patterns ADD COLUMN confidence FLOAT NOT NULL DEFAULT 1.0"),
            ("human_validated", "ALTER TABLE learned_patterns ADD COLUMN human_validated BOOLEAN NOT NULL DEFAULT 1"),
        ]
        for col_name, sql in migrations:
            if col_name not in existing:
                conn.exec_driver_sql(sql)
        conn.commit()


def _migrate_devices() -> None:
    with _engine.connect() as conn:
        existing = {
            row[1]
            for row in conn.exec_driver_sql("PRAGMA table_info(devices)").fetchall()
        }
        if "training_item_ids" not in existing:
            conn.exec_driver_sql("ALTER TABLE devices ADD COLUMN training_item_ids JSON")
        conn.commit()

# ── Devices ──────────────────────────────────────────────────────────────────

def save_device(device: Device) -> None:
    with Session(_engine) as session:
        record = session.get(DeviceRecord, device.id) or DeviceRecord(id=device.id)
        record.name = device.name; record.vendor = device.vendor; record.platform = device.platform
        record.version = device.version; record.score = device.score; record.status = device.status
        record.source_filename = device.source_filename; record.uploaded_at = datetime.fromisoformat(device.uploaded_at)
        record.baseline = device.baseline.model_dump(); record.findings = [item.model_dump() for item in device.findings]
        record.training_item_ids = device.training_item_ids
        session.add(record); session.commit()

def load_devices() -> list[Device]:
    with Session(_engine) as session:
        devices = []
        for record in session.scalars(select(DeviceRecord)).all():
            # Do not present snapshots from the earlier multi-framework API as
            # if they were assessed by today's CIS rule set. The legacy row is
            # left intact; the local demo device is used until the next upload
            # replaces it with a current-format result.
            if record.findings and any(
                "control_id" not in finding
                or "canonical_control" not in finding
                or finding.get("framework") != "CIS"
                for finding in record.findings
            ):
                continue
            # Older database rows stored findings before cis_id and section
            # were added to the API model. Fill those display fields while
            # loading so an existing local database does not prevent startup.
            findings = []
            for stored_finding in record.findings or []:
                finding = dict(stored_finding)
                finding.setdefault("control_id", finding.get("cis_id", finding.get("id", "legacy")))
                finding["framework"] = "CIS"
                finding["benchmark"] = "CIS Cisco IOS XE 17.x Benchmark"
                finding["benchmark_version"] = "2.2.1"
                finding.setdefault("profile", "Level 1")
                finding.setdefault("section", "Legacy findings")
                finding["status"] = {
                    "review": "unknown",
                    "not_applicable": "unknown",
                }.get(finding.get("status"), finding.get("status", "unknown"))
                finding.setdefault("expected", "Unknown")
                finding.setdefault("actual", "Unknown")
                finding.setdefault("evidence", finding.get("summary", "Legacy saved finding"))
                finding.setdefault("canonical_control", "security.legacy")
                finding.setdefault("assessment_status", "Automated")
                finding.setdefault("assessment_type", "native")
                finding.setdefault("mapping_confidence", 1.0)
                finding.setdefault("human_validated", True)
                if isinstance(finding.get("remediation"), str):
                    finding["remediation"] = [finding["remediation"]]
                if finding.get("severity") not in {"critical", "high", "medium", "low"}:
                    finding["severity"] = "medium"
                findings.append(finding)

            devices.append(Device(**{
                **record.__dict__,
                "baseline": record.baseline,
                "findings": findings,
                "training_item_ids": record.training_item_ids or [],
                "persisted": True,
                "uploaded_at": record.uploaded_at.isoformat(),
            }))
        return devices

# ── Training items ────────────────────────────────────────────────────────────

def save_training(item: TrainingItem) -> None:
    with Session(_engine) as session:
        record = session.get(TrainingRecord, item.id) or TrainingRecord(id=item.id)
        record.raw_line = item.raw_line
        record.suggested_category = item.suggested_category
        record.suggested_field = item.canonical_control
        record.suggested_value = str(item.canonical_value) if item.canonical_value is not None else None
        record.semantic_meaning = item.semantic_meaning
        record.canonical_control = item.canonical_control
        record.canonical_value = item.canonical_value
        record.vendor = item.vendor
        record.platform = item.platform
        record.provider = item.provider
        record.confidence = item.confidence
        record.status = item.status
        session.add(record); session.commit()

def load_training() -> list[TrainingItem]:
    with Session(_engine) as session:
        return [
            TrainingItem(
                id=x.id,
                raw_line=x.raw_line,
                suggested_category=x.suggested_category,
                semantic_meaning=x.semantic_meaning or "",
                canonical_control=x.canonical_control or _legacy_control(x.suggested_field),
                canonical_value=x.canonical_value if x.canonical_value is not None else x.suggested_value,
                confidence=x.confidence,
                vendor=x.vendor or "",
                platform=x.platform or "",
                provider=x.provider or "heuristic-fallback",
                # Normalise legacy status values from old DB rows
                status="pending" if x.status in ("unmapped", None, "") else x.status,
            )
            for x in session.scalars(select(TrainingRecord)).all()
        ]

# ── Learned patterns (knowledge base) ────────────────────────────────────────

def save_pattern(pattern: LearnedPattern) -> None:
    with Session(_engine) as session:
        record = session.get(LearnedPatternRecord, pattern.id) or LearnedPatternRecord(id=pattern.id)
        record.raw_pattern = pattern.source_pattern
        record.normalized_field = pattern.canonical_control
        record.label = pattern.label
        record.vendor = pattern.vendor
        record.category = pattern.category
        record.confirmed_at = datetime.fromisoformat(pattern.confirmed_at)
        record.training_item_id = pattern.training_item_id
        record.canonical_control = pattern.canonical_control
        record.canonical_value = pattern.canonical_value
        record.platform = pattern.platform
        record.confidence = pattern.confidence
        record.human_validated = pattern.human_validated
        session.add(record); session.commit()

def load_patterns() -> list[LearnedPattern]:
    with Session(_engine) as session:
        patterns = []
        for x in session.scalars(select(LearnedPatternRecord)).all():
            control = x.canonical_control or _legacy_control(x.normalized_field)
            if not control:
                continue
            value = x.canonical_value
            if value is None:
                value = _legacy_value(control, x.raw_pattern)
            try:
                patterns.append(LearnedPattern(
                    id=x.id,
                    source_pattern=x.raw_pattern,
                    canonical_control=control,
                    canonical_value=value,
                    label=x.label,
                    vendor=x.vendor,
                    platform=x.platform or "",
                    category=x.category,
                    confidence=x.confidence or 1.0,
                    human_validated=bool(x.human_validated),
                    confirmed_at=x.confirmed_at.isoformat(),
                    training_item_id=x.training_item_id,
                ))
            except (ValueError, TypeError):
                # Ignore only legacy rows whose old free-form field cannot be
                # safely converted to one of the supported canonical facts.
                continue
        return patterns


def _legacy_control(value: str | None) -> str | None:
    aliases = {
        "ssh_version": "management.ssh.version",
        "telnet_enabled": "management.telnet.enabled",
        "http_enabled": "management.http.enabled",
        "logging_enabled": "logging.enabled",
        "admin_timeout_minutes": "management.admin_timeout_minutes",
    }
    return aliases.get(value or "")


def _legacy_value(control: str, source_pattern: str):
    if control == "management.ssh.version":
        return "2" if "v2" in source_pattern.lower() or "version 2" in source_pattern.lower() else "1"
    if control == "management.telnet.enabled":
        return not source_pattern.lower().lstrip().startswith("no ")
    if control == "management.http.enabled":
        return not source_pattern.lower().lstrip().startswith("no ")
    if control == "management.admin_timeout_minutes":
        import re
        match = re.search(r"(\d+)", source_pattern)
        return int(match.group(1)) if match else 0
    return True
