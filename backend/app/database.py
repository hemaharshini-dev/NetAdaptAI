from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, select
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

class TrainingRecord(Base):
    __tablename__ = "training_items"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    raw_line: Mapped[str] = mapped_column(Text)
    suggested_category: Mapped[str] = mapped_column(String(255))
    # AI-suggested normalized field name (e.g. "telnet_enabled") and value
    suggested_field: Mapped[str | None] = mapped_column(String(120), nullable=True)
    suggested_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
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

def database_available() -> bool:
    try:
        with _engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        # Create any brand-new tables (learned_patterns, etc.)
        Base.metadata.create_all(_engine)
        # Migrate existing tables: add columns that didn't exist in older DB files.
        # SQLite has no "ADD COLUMN IF NOT EXISTS" before 3.37, so we check manually.
        _migrate_training_items()
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
        ]
        for col_name, sql in migrations:
            if col_name not in existing:
                conn.exec_driver_sql(sql)
        conn.commit()

# ── Devices ──────────────────────────────────────────────────────────────────

def save_device(device: Device) -> None:
    with Session(_engine) as session:
        record = session.get(DeviceRecord, device.id) or DeviceRecord(id=device.id)
        record.name = device.name; record.vendor = device.vendor; record.platform = device.platform
        record.version = device.version; record.score = device.score; record.status = device.status
        record.source_filename = device.source_filename; record.uploaded_at = datetime.fromisoformat(device.uploaded_at)
        record.baseline = device.baseline.model_dump(); record.findings = [item.model_dump() for item in device.findings]
        session.add(record); session.commit()

def load_devices() -> list[Device]:
    with Session(_engine) as session:
        devices = []
        for record in session.scalars(select(DeviceRecord)).all():
            # Older database rows stored findings before cis_id and section
            # were added to the API model. Fill those display fields while
            # loading so an existing local database does not prevent startup.
            findings = []
            for stored_finding in record.findings or []:
                finding = dict(stored_finding)
                finding.setdefault("cis_id", finding.get("id", "legacy"))
                finding.setdefault("section", finding.get("framework", "Legacy findings"))
                findings.append(finding)

            devices.append(Device(**{
                **record.__dict__,
                "baseline": record.baseline,
                "findings": findings,
                "uploaded_at": record.uploaded_at.isoformat(),
            }))
        return devices

# ── Training items ────────────────────────────────────────────────────────────

def save_training(item: TrainingItem) -> None:
    with Session(_engine) as session:
        record = session.get(TrainingRecord, item.id) or TrainingRecord(id=item.id)
        record.raw_line = item.raw_line
        record.suggested_category = item.suggested_category
        record.suggested_field = item.suggested_field
        record.suggested_value = item.suggested_value
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
                suggested_field=x.suggested_field,
                suggested_value=x.suggested_value,
                confidence=x.confidence,
                # Normalise legacy status values from old DB rows
                status="pending" if x.status in ("unmapped", None, "") else x.status,
            )
            for x in session.scalars(select(TrainingRecord)).all()
        ]

# ── Learned patterns (knowledge base) ────────────────────────────────────────

def save_pattern(pattern: LearnedPattern) -> None:
    with Session(_engine) as session:
        record = session.get(LearnedPatternRecord, pattern.id) or LearnedPatternRecord(id=pattern.id)
        record.raw_pattern = pattern.raw_pattern
        record.normalized_field = pattern.normalized_field
        record.label = pattern.label
        record.vendor = pattern.vendor
        record.category = pattern.category
        record.confirmed_at = datetime.fromisoformat(pattern.confirmed_at)
        record.training_item_id = pattern.training_item_id
        session.add(record); session.commit()

def load_patterns() -> list[LearnedPattern]:
    with Session(_engine) as session:
        return [
            LearnedPattern(
                id=x.id, raw_pattern=x.raw_pattern, normalized_field=x.normalized_field,
                label=x.label, vendor=x.vendor, category=x.category,
                confirmed_at=x.confirmed_at.isoformat(), training_item_id=x.training_item_id,
            )
            for x in session.scalars(select(LearnedPatternRecord)).all()
        ]
