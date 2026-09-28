"use client";
import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  Check,
  ChevronDown,
  CircleHelp,
  FileDown,
  Filter,
  Network,
  Radar,
  Settings2,
  ShieldCheck,
  Sparkles,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

type Finding = {
  id: string;
  title: string;
  framework: string;
  severity: string;
  status: "pass" | "fail" | "review";
  summary: string;
  learned: boolean;
};

type Device = {
  id: string;
  name: string;
  vendor: string;
  platform: string;
  version: string;
  score: number;
  findings: Finding[];
  baseline: { serial_number: string; unrecognized_lines: string[] };
  source_filename: string;
};

type Training = {
  id: string;
  raw_line: string;
  suggested_category: string;
  suggested_field: string | null;
  confidence: number;
  /** pending | approved | denied */
  status: string;
};

type LearnedPattern = {
  id: string;
  raw_pattern: string;
  normalized_field: string;
  label: string;
  vendor: string;
  category: string;
  confirmed_at: string;
};

// ── Sample fallback device ────────────────────────────────────────────────────

const sample: Device = {
  id: "dev-edge-gw-01",
  name: "edge-gw-01",
  vendor: "Cisco",
  platform: "IOS / NX-OS",
  version: "17.9.4",
  score: 44,
  source_filename: "edge-gw-01.cfg",
  baseline: {
    serial_number: "FDO2418A0Q7",
    unrecognized_lines: ["interface GigabitEthernet1/0/1", "description upstream transit"],
  },
  findings: [
    { id: "1", title: "Use SSH protocol version 2",      framework: "CIS",  severity: "high",     status: "pass", summary: "Administrative access must use SSHv2.", learned: false },
    { id: "2", title: "Disable Telnet",                  framework: "CIS",  severity: "critical", status: "fail", summary: "Telnet transmits credentials without encryption.", learned: false },
    { id: "3", title: "Disable unencrypted HTTP management", framework: "NIST", severity: "high", status: "fail", summary: "Management should use HTTPS.", learned: false },
    { id: "4", title: "Enable administrative event logging", framework: "STIG", severity: "medium", status: "pass", summary: "Admin events need a durable audit trail.", learned: false },
  ],
};

const NORMALIZED_FIELDS = [
  "ssh_version",
  "telnet_enabled",
  "http_enabled",
  "logging_enabled",
  "admin_timeout_minutes",
  "unknown",
];

const api = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ── App ───────────────────────────────────────────────────────────────────────

export default function Home() {
  const [device, setDevice]           = useState<Device>(sample);
  const [training, setTraining]       = useState<Training[]>([]);
  const [patterns, setPatterns]       = useState<LearnedPattern[]>([]);
  const [framework, setFramework]     = useState("All frameworks");
  const [tab, setTab]                 = useState("overview");
  const [notice, setNotice]           = useState("");
  const [pasteOpen, setPasteOpen]     = useState(false);
  const [pastedConfig, setPastedConfig] = useState("");

  // Approval modal state
  const [approveItem, setApproveItem] = useState<Training | null>(null);
  const [approveLabel, setApproveLabel] = useState("");
  const [approveField, setApproveField] = useState("unknown");
  const [approveVendor, setApproveVendor] = useState("");

  const pendingCount = training.filter((t) => t.status === "pending").length;

  // ── Fetch on mount ──────────────────────────────────────────────────────────
  useEffect(() => {
    Promise.all([
      fetch(`${api}/api/devices`).then((r) => (r.ok ? r.json() : [])),
      fetch(`${api}/api/training`).then((r) => (r.ok ? r.json() : [])),
      fetch(`${api}/api/patterns`).then((r) => (r.ok ? r.json() : [])),
    ])
      .then(([d, t, p]) => {
        if (d[0]) setDevice(d[0]);
        setTraining(t);
        setPatterns(p);
      })
      .catch(() => {});
  }, []);

  // ── Helpers ─────────────────────────────────────────────────────────────────
  const refreshTrainingAndPatterns = () =>
    Promise.all([
      fetch(`${api}/api/training`).then((r) => (r.ok ? r.json() : [])),
      fetch(`${api}/api/patterns`).then((r) => (r.ok ? r.json() : [])),
    ]).then(([t, p]) => { setTraining(t); setPatterns(p); }).catch(() => {});

  // ── Upload ──────────────────────────────────────────────────────────────────
  const upload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    try {
      const r = await fetch(`${api}/api/ingest`, { method: "POST", body: form });
      if (!r.ok) throw Error();
      setDevice(await r.json());
      setNotice(`${file.name} normalized successfully`);
      refreshTrainingAndPatterns();
    } catch {
      setNotice("API unavailable. Start the backend to ingest this file.");
    }
  };

  // ── Paste config ────────────────────────────────────────────────────────────
  const analyzePastedConfig = async () => {
    if (!pastedConfig.trim()) return;
    const form = new FormData();
    form.append("file", new File([pastedConfig], "pasted-config.txt", { type: "text/plain" }));
    try {
      const r = await fetch(`${api}/api/ingest`, { method: "POST", body: form });
      if (!r.ok) throw Error();
      setDevice(await r.json());
      setNotice("Pasted configuration normalized successfully");
      setPasteOpen(false);
      refreshTrainingAndPatterns();
    } catch {
      setNotice("API unavailable. Start the backend to analyze this configuration.");
    }
  };

  // ── Approve ─────────────────────────────────────────────────────────────────
  const openApproveModal = (item: Training) => {
    setApproveItem(item);
    setApproveLabel(item.suggested_category);
    setApproveField(item.suggested_field || "unknown");
    setApproveVendor("");
  };

  const submitApprove = async () => {
    if (!approveItem) return;
    try {
      const r = await fetch(`${api}/api/training/${approveItem.id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: approveLabel,
          normalized_field: approveField,
          vendor: approveVendor,
          category: approveItem.suggested_category,
        }),
      });
      if (!r.ok) throw Error();
      setNotice(`Pattern approved and added to knowledge base`);
      setApproveItem(null);
      refreshTrainingAndPatterns();
    } catch {
      setNotice("Failed to approve — is the backend running?");
    }
  };

  // ── Deny ────────────────────────────────────────────────────────────────────
  const deny = async (item: Training) => {
    try {
      const r = await fetch(`${api}/api/training/${item.id}/deny`, { method: "POST" });
      if (!r.ok) throw Error();
      setNotice(`Pattern denied`);
      refreshTrainingAndPatterns();
    } catch {
      setNotice("Failed to deny — is the backend running?");
    }
  };

  // ── Delete learned pattern ──────────────────────────────────────────────────
  const deletePattern = async (id: string) => {
    try {
      const r = await fetch(`${api}/api/patterns/${id}`, { method: "DELETE" });
      if (!r.ok) throw Error();
      setPatterns((prev) => prev.filter((p) => p.id !== id));
      setNotice("Pattern removed from knowledge base");
    } catch {
      setNotice("Failed to delete — is the backend running?");
    }
  };

  const findings = device.findings.filter(
    (f) => framework === "All frameworks" || f.framework === framework,
  );
  const failures = findings.filter((f) => f.status === "fail").length;

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <main className="shell">
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Network size={18} /></div>
          <div>
            <strong>NetAdapt<span>AI</span></strong>
            <small>SECURITY OPERATIONS</small>
          </div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav>
          <button className={`nav-item ${tab === "overview" || tab === "findings" ? "active" : ""}`} onClick={() => setTab("overview")}>
            <Radar size={17} /> Compliance overview
          </button>
          <button className={`nav-item ${tab === "training" ? "active" : ""}`} onClick={() => setTab("training")}>
            <Sparkles size={17} /> Training queue
            {pendingCount > 0 && <b>{pendingCount}</b>}
          </button>
          <button className={`nav-item ${tab === "knowledge" ? "active" : ""}`} onClick={() => setTab("knowledge")}>
            <BookOpen size={17} /> Knowledge base
            {patterns.length > 0 && <b>{patterns.length}</b>}
          </button>
          <button className="nav-item"><ShieldCheck size={17} /> Framework library</button>
          <button className="nav-item"><Settings2 size={17} /> Workspace settings</button>
        </nav>
        <div className="sidebar-footer">
          <i className="status-dot" /> Engine online <span>v0.1</span>
        </div>
      </aside>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <section className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY POSTURE / OVERVIEW</p>
            <h1>Compliance command center</h1>
          </div>
          <div className="top-actions">
            <button className="icon-button"><CircleHelp size={18} /></button>
            <label className="upload-button">
              <UploadCloud size={16} /> Ingest config
              <input type="file" accept=".txt,.cfg,.conf,.log" onChange={upload} />
            </label>
            <button className="outline-button paste-trigger" onClick={() => setPasteOpen((o) => !o)}>
              Paste config
            </button>
            <button className="avatar">AK</button>
          </div>
        </header>

        {/* Paste panel */}
        {pasteOpen && (
          <section className="paste-panel">
            <div className="paste-panel-heading">
              <div>
                <p className="eyebrow">TEXT INGESTION</p>
                <h3>Paste a device configuration</h3>
                <p>Paste raw CLI output below. Uses the same normalization and compliance checks as file upload.</p>
              </div>
              <button className="icon-button" onClick={() => setPasteOpen(false)} aria-label="Close paste panel">×</button>
            </div>
            <textarea
              className="config-textarea"
              value={pastedConfig}
              onChange={(e) => setPastedConfig(e.target.value)}
              placeholder={"hostname branch-switch-01\nversion 17.9.4 IOS-XE\nip ssh version 2\nno service telnet"}
              spellCheck={false}
            />
            <div className="paste-panel-footer">
              <span>{pastedConfig.length.toLocaleString()} characters</span>
              <button className="upload-button" onClick={analyzePastedConfig} disabled={!pastedConfig.trim()}>
                <ShieldCheck size={15} /> Analyze configuration
              </button>
            </div>
          </section>
        )}

        {/* Notice banner */}
        {notice && (
          <div className="notice">
            <Check size={15} /> {notice}
            <button className="notice-close" onClick={() => setNotice("")} aria-label="Dismiss"><X size={13} /></button>
          </div>
        )}

        {/* Device strip */}
        <div className="device-strip">
          <div className="device-avatar"><Network size={22} /></div>
          <div>
            <span className="label">ACTIVE DEVICE</span>
            <h2>{device.name}</h2>
            <p>{device.vendor} {device.platform} <span>•</span> {device.version} <span>•</span> {device.source_filename}</p>
          </div>
          <div className="device-meta">
            <div>
              <span className="label">SERIAL NUMBER</span>
              <strong>{device.baseline.serial_number}</strong>
            </div>
            <div>
              <span className="label">LAST ANALYZED</span>
              <strong>Just now</strong>
            </div>
          </div>
          <button className="outline-button" onClick={() => window.open(`${api}/api/devices/${device.id}/report`)}>
            <FileDown size={15} /> PDF report
          </button>
        </div>

        {/* Metrics */}
        <div className="metric-grid">
          <Metric title="POSTURE SCORE"     value={`${device.score}`}           detail="out of 100" />
          <Metric title="CONTROL COVERAGE"  value={`${device.findings.length}`} detail="controls across 4 frameworks" />
          <Metric title="REQUIRES ATTENTION" value={`${failures}`}              detail="findings need remediation" warning />
          <Metric title="TRAINING QUEUE"    value={`${pendingCount}`}            detail="patterns awaiting review" />
        </div>

        {/* Tabs */}
        <div className="section-tabs">
          <button className={tab === "overview" ? "tab active" : "tab"} onClick={() => setTab("overview")}>Overview</button>
          <button className={tab === "findings" ? "tab active" : "tab"} onClick={() => setTab("findings")}>
            Findings <span>{failures}</span>
          </button>
          <button className={tab === "training" ? "tab active" : "tab"} onClick={() => setTab("training")}>
            Training queue <span>{pendingCount}</span>
          </button>
          <button className={tab === "knowledge" ? "tab active" : "tab"} onClick={() => setTab("knowledge")}>
            Knowledge base <span>{patterns.length}</span>
          </button>
        </div>

        {/* Tab content */}
        {tab === "training" ? (
          <TrainingPanel
            training={training}
            onApprove={openApproveModal}
            onDeny={deny}
          />
        ) : tab === "knowledge" ? (
          <KnowledgeBasePanel patterns={patterns} onDelete={deletePattern} />
        ) : (
          <div className="lower-grid">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="eyebrow">CONTROL EVALUATION</p>
                  <h3>{tab === "findings" ? "All findings" : "Priority findings"}</h3>
                </div>
                <div className="filter-wrap">
                  <Filter size={14} />
                  <select value={framework} onChange={(e) => setFramework(e.target.value)}>
                    <option>All frameworks</option>
                    <option>CIS</option>
                    <option>NIST</option>
                    <option>STIG</option>
                    <option>ISO</option>
                  </select>
                  <ChevronDown size={14} />
                </div>
              </div>
              {findings.slice(0, tab === "findings" ? 20 : 4).map((f) => (
                <FindingRow key={f.id} finding={f} />
              ))}
            </section>
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="eyebrow">NORMALIZATION</p>
                  <h3>Security baseline</h3>
                </div>
              </div>
              <Baseline label="SSH protocol"      value="Version 2"         good />
              <Baseline label="Telnet service"    value="Enabled" />
              <Baseline label="HTTP management"   value="Enabled" />
              <Baseline label="Event logging"     value="Buffered + SIEM"   good />
              <Baseline label="Admin timeout"     value="30 minutes" />
              <div className="unknown-box">
                <Sparkles size={15} />
                <div>
                  <strong>{device.baseline.unrecognized_lines.length || 2} patterns need training</strong>
                  <p>Help the engine understand this syntax.</p>
                </div>
                <button onClick={() => setTab("training")}><ArrowUpRight size={15} /></button>
              </div>
            </section>
          </div>
        )}
      </section>

      {/* ── Approval modal ──────────────────────────────────────────────── */}
      {approveItem && (
        <div className="modal-backdrop" onClick={() => setApproveItem(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <p className="eyebrow">APPROVE MAPPING</p>
                <h3>Confirm pattern for knowledge base</h3>
              </div>
              <button className="icon-button" onClick={() => setApproveItem(null)} aria-label="Close">×</button>
            </div>

            <div className="modal-body">
              <div className="modal-field">
                <label className="modal-label">CONFIG LINE</label>
                <code className="modal-code">{approveItem.raw_line}</code>
              </div>

              <div className="modal-field">
                <label className="modal-label" htmlFor="approve-label">LABEL (shown in findings)</label>
                <input
                  id="approve-label"
                  className="modal-input"
                  value={approveLabel}
                  onChange={(e) => setApproveLabel(e.target.value)}
                  placeholder="e.g. Disable Telnet"
                />
              </div>

              <div className="modal-field">
                <label className="modal-label" htmlFor="approve-field">MAP TO FIELD</label>
                <select
                  id="approve-field"
                  className="modal-input"
                  value={approveField}
                  onChange={(e) => setApproveField(e.target.value)}
                >
                  {NORMALIZED_FIELDS.map((f) => (
                    <option key={f} value={f}>{f}</option>
                  ))}
                </select>
                <p className="modal-hint">
                  AI suggested: <strong>{approveItem.suggested_field || "unknown"}</strong> — confidence {Math.round(approveItem.confidence * 100)}%
                </p>
              </div>

              <div className="modal-field">
                <label className="modal-label" htmlFor="approve-vendor">VENDOR SCOPE (optional)</label>
                <input
                  id="approve-vendor"
                  className="modal-input"
                  value={approveVendor}
                  onChange={(e) => setApproveVendor(e.target.value)}
                  placeholder="e.g. Cisco — leave blank to match any vendor"
                />
              </div>
            </div>

            <div className="modal-footer">
              <button className="outline-button" onClick={() => setApproveItem(null)}>Cancel</button>
              <button className="upload-button" onClick={submitApprove} disabled={!approveLabel.trim()}>
                <Check size={14} /> Approve &amp; add to knowledge base
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Metric({ title, value, detail, warning }: { title: string; value: string; detail: string; warning?: boolean }) {
  return (
    <div className="metric-card">
      <div className="metric-heading"><span>{title}</span><ArrowUpRight size={15} /></div>
      <strong className={warning ? "big-number warning-number" : "big-number"}>{value}</strong>
      <p>{detail}</p>
      <div className="mini-bars"><i /><i /><i /></div>
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <div className="finding-row">
      <div className={`finding-status ${finding.status}`}>
        {finding.status === "pass" ? <Check size={13} /> : <AlertTriangle size={13} />}
      </div>
      <div className="finding-copy">
        <div>
          <strong>{finding.title}</strong>
          {finding.learned && <span className="learned-badge">learned</span>}
          <span className={`severity ${finding.severity}`}>{finding.severity}</span>
        </div>
        <p>{finding.summary}</p>
      </div>
      <span className="framework-tag">{finding.framework}</span>
      <button className="row-arrow"><ArrowUpRight size={15} /></button>
    </div>
  );
}

function Baseline({ label, value, good }: { label: string; value: string; good?: boolean }) {
  return (
    <div className="baseline-row">
      <div className={`baseline-check ${good ? "good" : "bad"}`}>
        {good ? <Check size={13} /> : <AlertTriangle size={13} />}
      </div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TrainingPanel({
  training,
  onApprove,
  onDeny,
}: {
  training: Training[];
  onApprove: (item: Training) => void;
  onDeny: (item: Training) => void;
}) {
  const pending  = training.filter((t) => t.status === "pending");
  const resolved = training.filter((t) => t.status !== "pending");

  const items = pending.length
    ? pending
    : [
        {
          id: "local",
          raw_line: "interface GigabitEthernet1/0/1",
          suggested_category: "Interface context",
          suggested_field: "unknown",
          confidence: 0.91,
          status: "pending",
        },
      ];

  return (
    <section className="panel training-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">ADAPTIVE PARSING</p>
          <h3>Teach NetAdaptAI new syntax</h3>
          <p className="panel-subtitle">
            Review AI suggestions. Approve to add to the knowledge base; deny to discard.
          </p>
        </div>
        <span className="training-count">
          <Sparkles size={14} /> {items.length} pending
        </span>
      </div>

      {/* Pending items */}
      <div className="training-table">
        <div className="training-head">
          <span>CONFIG LINE</span>
          <span>AI SUGGESTION</span>
          <span>CONFIDENCE</span>
          <span>ACTION</span>
        </div>
        {items.map((x) => (
          <div className="training-row" key={x.id}>
            <code>{x.raw_line}</code>
            <span className="suggestion">
              <Sparkles size={13} />
              {x.suggested_category}
              {x.suggested_field && x.suggested_field !== "unknown" && (
                <span className="field-tag">→ {x.suggested_field}</span>
              )}
            </span>
            <span>{Math.round(x.confidence * 100)}%</span>
            <div className="training-actions">
              <button
                className="approve-button"
                onClick={() => onApprove(x)}
                title="Approve and add to knowledge base"
              >
                <Check size={13} /> Approve
              </button>
              <button
                className="deny-button"
                onClick={() => onDeny(x)}
                title="Deny — do not learn this pattern"
              >
                <X size={13} /> Deny
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Resolved items */}
      {resolved.length > 0 && (
        <div className="resolved-section">
          <p className="resolved-heading">RESOLVED</p>
          {resolved.map((x) => (
            <div className="resolved-row" key={x.id}>
              <code>{x.raw_line}</code>
              <span className={`resolved-badge ${x.status}`}>{x.status}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function KnowledgeBasePanel({
  patterns,
  onDelete,
}: {
  patterns: LearnedPattern[];
  onDelete: (id: string) => void;
}) {
  return (
    <section className="panel training-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">KNOWLEDGE BASE</p>
          <h3>Confirmed learned patterns</h3>
          <p className="panel-subtitle">
            These patterns are applied automatically on every new config ingestion.
          </p>
        </div>
        <span className="training-count">
          <BookOpen size={14} /> {patterns.length} patterns
        </span>
      </div>

      {patterns.length === 0 ? (
        <div className="kb-empty">
          <Sparkles size={24} />
          <p>No patterns confirmed yet.</p>
          <p>Approve items in the Training Queue to build the knowledge base.</p>
        </div>
      ) : (
        <div className="training-table">
          <div className="kb-head">
            <span>PATTERN</span>
            <span>LABEL</span>
            <span>FIELD</span>
            <span>VENDOR</span>
            <span>CONFIRMED</span>
            <span></span>
          </div>
          {patterns.map((p) => (
            <div className="kb-row" key={p.id}>
              <code>{p.raw_pattern}</code>
              <span>{p.label}</span>
              <span className="field-tag">{p.normalized_field}</span>
              <span className="vendor-tag">{p.vendor || "any"}</span>
              <span className="confirmed-at">{new Date(p.confirmed_at).toLocaleDateString()}</span>
              <button
                className="delete-button"
                onClick={() => onDelete(p.id)}
                title="Remove from knowledge base"
                aria-label="Remove pattern"
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
