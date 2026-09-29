"use client";
import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  Check,
  CircleHelp,
  FileDown,
  House,
  Network,
  Radar,
  ShieldCheck,
  Sparkles,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

type Finding = {
  id: string;
  framework: "CIS";
  benchmark: string;
  benchmark_version: string;
  profile: string;
  control_id: string;
  section: string;
  title: string;
  severity: string;
  status: "pass" | "fail" | "unknown";
  expected: string;
  actual: string;
  evidence: string;
  canonical_control: string;
  remediation: string[];
  assessment_type: "native" | "cross_vendor";
  mapping_confidence: number;
  human_validated: boolean;
  assessment_status: string;
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
  status: "compliant" | "attention" | "critical";
  persisted: boolean;
  benchmark: string;
  benchmark_version: string;
  assessment_type: "native" | "cross_vendor";
  findings: Finding[];
  training_item_ids: string[];
  baseline: {
    serial_number: string;
    unrecognized_lines: string[];
    ssh_version: string | null;
    telnet_enabled: boolean | null;
    http_enabled: boolean | null;
    logging_buffered: boolean;
    logging_host: boolean;
    admin_timeout_minutes: number | null;
    vty_transport_ssh: boolean;
    known_fields: string[];
  };
  source_filename: string;
};

type Training = {
  id: string;
  raw_line: string;
  suggested_category: string;
  semantic_meaning: string;
  canonical_control: string | null;
  canonical_value: string | number | boolean | null;
  confidence: number;
  vendor: string;
  platform: string;
  provider: string;
  /** pending | approved | denied */
  status: string;
};

type LearnedPattern = {
  id: string;
  source_pattern: string;
  canonical_control: string;
  canonical_value: string | number | boolean;
  label: string;
  vendor: string;
  platform: string;
  category: string;
  confidence: number;
  human_validated: boolean;
  confirmed_at: string;
};

// ── Sample fallback device ────────────────────────────────────────────────────

const sample: Device = {
  id: "dev-edge-gw-01",
  name: "edge-gw-01",
  vendor: "Cisco",
  platform: "IOS / NX-OS",
  version: "17.9.4",
  score: 50,
  status: "attention",
  persisted: false,
  benchmark: "CIS Cisco IOS XE 17.x Benchmark",
  benchmark_version: "2.2.1",
  assessment_type: "native",
  source_filename: "edge-gw-01.cfg",
  baseline: {
    serial_number: "FDO2418A0Q7",
    unrecognized_lines: ["interface GigabitEthernet1/0/1", "description upstream transit"],
    ssh_version: "2",
    telnet_enabled: true,
    http_enabled: true,
    logging_buffered: true,
    logging_host: false,
    admin_timeout_minutes: 30,
    known_fields: ["ssh_version", "telnet_enabled", "http_enabled", "logging_buffered", "logging_host", "admin_timeout_minutes", "vty_transport_ssh"],
    vty_transport_ssh: false,
  },
  findings: [
    { id: "cis-2.1.1.2", framework: "CIS", benchmark: "CIS Cisco IOS XE 17.x Benchmark", benchmark_version: "2.2.1", profile: "Level 1", control_id: "2.1.1.2", section: "2.1 SSH & Global Services", title: "Use SSH protocol version 2", severity: "critical", status: "pass", expected: "2", actual: "2", evidence: "ip ssh version 2", canonical_control: "management.ssh.version", remediation: ["ip ssh version 2"], assessment_status: "Automated", assessment_type: "native", mapping_confidence: 1, human_validated: true, summary: "Administrative access must use SSHv2.", learned: false },
    { id: "cis-1.2.2", framework: "CIS", benchmark: "CIS Cisco IOS XE 17.x Benchmark", benchmark_version: "2.2.1", profile: "Level 1", control_id: "1.2.2", section: "1.2 Access Rules", title: "Set 'transport input ssh' for 'line vty'", severity: "critical", status: "fail", expected: "enabled", actual: "disabled", evidence: "line vty transport input telnet", canonical_control: "management.access.vty_transport_ssh", remediation: ["line vty 0 15", " transport input ssh"], assessment_status: "Automated", assessment_type: "native", mapping_confidence: 1, human_validated: true, summary: "Restricts VTY management lines to encrypted SSH sessions only.", learned: false },
  ],
  training_item_ids: [],
};

const CANONICAL_CONTROLS = [
  "management.ssh.version",
  "management.telnet.enabled",
  "management.http.enabled",
  "logging.enabled",
  "logging.remote_logging.enabled",
];

const api = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ── App ───────────────────────────────────────────────────────────────────────

export default function Home() {
  const [device, setDevice]           = useState<Device>(sample);
  const [isDemo, setIsDemo]           = useState(true);
  const [training, setTraining]       = useState<Training[]>([]);
  const [patterns, setPatterns]       = useState<LearnedPattern[]>([]);
  const [tab, setTab]                 = useState("home");
  const [notice, setNotice]           = useState("");
  const [pasteOpen, setPasteOpen]     = useState(false);
  const [pastedConfig, setPastedConfig] = useState("");

  // Approval modal state
  const [approveItem, setApproveItem] = useState<Training | null>(null);
  const [isApproving, setIsApproving] = useState(false);
  const [approveError, setApproveError] = useState("");
  const [approveLabel, setApproveLabel] = useState("");
  const [approveField, setApproveField] = useState("");
  const [approveValue, setApproveValue] = useState("");
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
        if (d[0]) {
          setDevice(d[0]);
          setIsDemo(!d[0].persisted);
        }
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
      setIsDemo(false);
      setTab("current");
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
      setIsDemo(false);
      setTab("current");
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
    setApproveError("");
    setApproveField(item.canonical_control || "");
    setApproveValue(item.canonical_value === null ? "" : String(item.canonical_value));
    setApproveVendor(item.vendor || "");
  };

  const submitApprove = async () => {
    if (!approveItem || isApproving) return;
    setIsApproving(true);
    setApproveError("");
    try {
      const r = await fetch(`${api}/api/training/${approveItem.id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: approveLabel,
          canonical_control: approveField,
          canonical_value: approveValue,
          semantic_meaning: approveItem.semantic_meaning,
          vendor: approveVendor,
          platform: approveItem.platform,
          category: approveItem.suggested_category,
          confidence: approveItem.confidence,
        }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => null);
        const detail = typeof body?.detail === "string" ? body.detail : JSON.stringify(body?.detail || "");
        throw new Error(detail || `The server returned ${r.status}.`);
      }
      setNotice("Mapping approved and added to the knowledge base.");
      setApproveItem(null);
      const [devicesResult] = await Promise.allSettled([
        fetch(`${api}/api/devices`).then((response) => {
          if (!response.ok) throw new Error("Could not refresh the assessment.");
          return response.json();
        }),
        refreshTrainingAndPatterns(),
      ]);
      if (devicesResult.status === "fulfilled" && devicesResult.value[0]) {
        setDevice(devicesResult.value[0]);
      } else {
        setNotice("Mapping saved to the knowledge base. Reload the page to refresh the assessment.");
      }
    } catch (error) {
      setApproveError(error instanceof Error ? error.message : "The mapping could not be saved.");
    } finally {
      setIsApproving(false);
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

  const findings = device.findings;
  const failures = findings.filter((f) => f.status === "fail").length;
  const unknowns = findings.filter((f) => f.status === "unknown").length;
  const passes = findings.filter((f) => f.status === "pass").length;
  const currentTraining = training.filter((item) => device.training_item_ids.includes(item.id));
  const pageTitles: Record<string, string> = {
    home: "What is NetAdaptAI?",
    current: "Current configuration report",
    overview: "Overall project overview",
    findings: "All assessment findings",
    training: "Training queue",
    knowledge: "Knowledge base",
  };

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
        <div className="workspace-label">MENU</div>
        <nav>
          <button className={`nav-item ${tab === "home" ? "active" : ""}`} onClick={() => setTab("home")}>
            <House size={17} /> Home
          </button>
          <button className={`nav-item ${tab === "current" ? "active" : ""}`} onClick={() => setTab("current")}>
            <FileDown size={17} /> Current config report
          </button>
          <button className={`nav-item ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}>
            <Radar size={17} /> Compliance overview
          </button>
          <button className={`nav-item ${tab === "findings" ? "active" : ""}`} onClick={() => setTab("findings")}>
            <ShieldCheck size={17} /> All findings
          </button>
          <button className={`nav-item ${tab === "training" ? "active" : ""}`} onClick={() => setTab("training")}>
            <Sparkles size={17} /> Training queue
            {pendingCount > 0 && <b>{pendingCount}</b>}
          </button>
          <button className={`nav-item ${tab === "knowledge" ? "active" : ""}`} onClick={() => setTab("knowledge")}>
            <BookOpen size={17} /> Knowledge base
            {patterns.length > 0 && <b>{patterns.length}</b>}
          </button>
        </nav>
        <div className="sidebar-footer">
          <i className="status-dot" /> Engine online <span>v0.1</span>
        </div>
      </aside>

      {/* ── Main content ────────────────────────────────────────────────── */}
      <section className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">{tab === "home" ? "ABOUT THE PROJECT" : tab === "current" ? "LATEST UPLOAD / REPORT" : "PROJECT / WORKSPACE"}</p>
            <h1>{pageTitles[tab] || pageTitles.current}</h1>
          </div>
          <div className="top-actions">
            <label className="upload-button">
              <UploadCloud size={16} /> Ingest config
              <input type="file" accept=".txt,.cfg,.conf,.log" onChange={upload} />
            </label>
            <button className="outline-button paste-trigger" onClick={() => setPasteOpen((o) => !o)}>
              Paste config
            </button>
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

        {tab === "home" ? (
          <HomeLanding
            onViewReport={() => setTab("current")}
            onPasteConfig={() => { setPasteOpen(true); setNotice(""); }}
            onUpload={upload}
          />
        ) : tab === "current" ? (
          <div className="current-config-page">
            <section className="panel current-report-panel">
              <div className="current-report-heading">
                <div className="current-device-heading">
                  <div className="device-avatar"><Network size={22} /></div>
                  <div>
                    <span className="label">{isDemo ? "SAMPLE REPORT" : "CURRENT UPLOAD"}</span>
                    <h2>{device.name}</h2>
                    <p>{device.source_filename} · {device.vendor} {device.platform} · {device.version}</p>
                  </div>
                </div>
                <button className="upload-button" onClick={() => window.open(`${api}/api/devices/${device.id}/report`, "_blank", "noopener,noreferrer")}>
                  <FileDown size={15} /> Download PDF report
                </button>
              </div>
              <div className="current-report-meta">
                <span>{device.benchmark} v{device.benchmark_version}</span>
                <span>{device.assessment_type === "cross_vendor" ? "Cross-vendor mapped assessment" : "Native configuration assessment"}</span>
                {isDemo && <span className="demo-tag">Demo data · upload a file to replace</span>}
              </div>
              <div className="current-summary-grid">
                <SummaryCard label="Posture score" value={`${device.score}%`} detail="PASS ÷ all controls" />
                <SummaryCard label="Passed" value={String(passes)} detail="controls meeting the rule" />
                <SummaryCard label="Failed" value={String(failures)} detail="controls needing attention" />
                <SummaryCard label="Unknown" value={String(unknowns)} detail="not counted as passed" />
              </div>
              <div className="panel-header current-findings-heading">
                <div>
                  <p className="eyebrow">THIS FILE ONLY</p>
                  <h3>Assessment report · {findings.length} controls</h3>
                </div>
              </div>
              {findings.map((finding) => <FindingRow key={finding.id} finding={finding} />)}
            </section>
            <TrainingPanel
              training={currentTraining}
              onApprove={openApproveModal}
              onDeny={deny}
              scope="current"
              filename={device.source_filename}
            />
          </div>
        ) : (
        <>
        {/* Device summary is part of the overall workspace views */}
        <div className="device-strip">
          <div className="device-avatar"><Network size={22} /></div>
          <div>
            <span className="label">ACTIVE DEVICE</span>
            <h2>{device.name}</h2>
            <p>{device.vendor} {device.platform} <span>•</span> {device.version} <span>•</span> {device.source_filename}</p>
            <span className="assessment-label">
              {isDemo ? "DEMO DATA · NOT SAVED" : device.assessment_type === "cross_vendor" ? "CROSS-VENDOR SEMANTIC MAPPING" : "CIS NATIVE ASSESSMENT"}
            </span>
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

        {/* Overall project metrics */}
        <div className="metric-grid">
          <Metric title="POSTURE SCORE" value={`${device.score}%`} detail="PASS ÷ all controls; UNKNOWN is not passed" warning={unknowns > 0} />
          <Metric title="CIS CONTROLS" value={`${device.findings.length}`} detail={`${device.benchmark} v${device.benchmark_version}`} />
          <Metric title="FAIL" value={`${failures}`} detail="controls needing remediation" warning={failures > 0} />
          <Metric title="UNKNOWN" value={`${unknowns}`} detail="controls without supported evidence" warning={unknowns > 0} />
          <Metric title="PENDING MAPPINGS" value={`${pendingCount}`} detail="awaiting human review" />
        </div>

        {/* Tab content */}
        {tab === "training" ? (
          <TrainingPanel
            training={training}
            onApprove={openApproveModal}
            onDeny={deny}
            scope="all"
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
              </div>
              {findings.slice(0, tab === "findings" ? findings.length : 4).map((f) => (
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
              <Baseline label="SSH protocol" value={device.baseline.known_fields.includes("ssh_version") && device.baseline.ssh_version ? `Version ${device.baseline.ssh_version}` : "UNKNOWN"} good={device.baseline.known_fields.includes("ssh_version") && device.baseline.ssh_version === "2"} />
              <Baseline label="Telnet service" value={baselineBoolean(device, "telnet_enabled")} good={device.baseline.known_fields.includes("telnet_enabled") && device.baseline.telnet_enabled === false} />
              <Baseline label="HTTP management" value={baselineBoolean(device, "http_enabled")} good={device.baseline.known_fields.includes("http_enabled") && device.baseline.http_enabled === false} />
              <Baseline label="Local buffered logging" value={device.baseline.known_fields.includes("logging_buffered") ? (device.baseline.logging_buffered ? "Enabled" : "Disabled") : "UNKNOWN"} good={device.baseline.known_fields.includes("logging_buffered") && device.baseline.logging_buffered} />
              <Baseline label="Remote logging" value={device.baseline.known_fields.includes("logging_host") ? (device.baseline.logging_host ? "Enabled" : "Disabled") : "UNKNOWN"} good={device.baseline.known_fields.includes("logging_host") && device.baseline.logging_host} />
              <Baseline label="Admin timeout" value={device.baseline.known_fields.includes("admin_timeout_minutes") && device.baseline.admin_timeout_minutes !== null ? `${device.baseline.admin_timeout_minutes} minutes` : "UNKNOWN"} good={device.baseline.known_fields.includes("admin_timeout_minutes") && device.baseline.admin_timeout_minutes !== null && device.baseline.admin_timeout_minutes <= 10} />
              <div className="unknown-box">
                <Sparkles size={15} />
                <div>
                  <strong>{device.baseline.unrecognized_lines.length} unknown command{device.baseline.unrecognized_lines.length === 1 ? "" : "s"}</strong>
                  <p>Help the engine understand this syntax.</p>
                </div>
                <button onClick={() => setTab("training")}><ArrowUpRight size={15} /></button>
              </div>
            </section>
          </div>
        )}
        </>
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
              <button className="icon-button" onClick={() => setApproveItem(null)} aria-label="Close" disabled={isApproving}>×</button>
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
                <label className="modal-label" htmlFor="approve-field">MAP TO CANONICAL CONTROL</label>
                <select
                  id="approve-field"
                  className="modal-input"
                  value={approveField}
                  onChange={(e) => {
                    setApproveField(e.target.value);
                    setApproveValue(e.target.value === "management.ssh.version" ? "2" : "true");
                  }}
                >
                  <option value="">Choose the fact this command represents</option>
                  {CANONICAL_CONTROLS.map((f) => (
                    <option key={f} value={f}>{f}</option>
                  ))}
                </select>
                <label className="modal-label" htmlFor="approve-value">CANONICAL VALUE</label>
                {approveField === "management.ssh.version" ? (
                  <select id="approve-value" className="modal-input" value={approveValue} onChange={(e) => setApproveValue(e.target.value)}>
                    <option value="">Choose a version</option>
                    <option value="1">Version 1</option>
                    <option value="2">Version 2</option>
                  </select>
                ) : (
                  <select id="approve-value" className="modal-input" value={approveValue} onChange={(e) => setApproveValue(e.target.value)}>
                    <option value="">Choose a value</option>
                    <option value="true">Enabled</option>
                    <option value="false">Disabled</option>
                  </select>
                )}
                <p className="modal-hint">
                  AI suggestion: <strong>{approveItem.canonical_control || "unknown"}</strong> = <strong>{String(approveItem.canonical_value ?? "unknown")}</strong> — confidence {Math.round(approveItem.confidence * 100)}%
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

            {approveError && <div className="approval-error" role="alert">{approveError}</div>}

            <div className="modal-footer">
              <button className="outline-button" onClick={() => setApproveItem(null)} disabled={isApproving}>Cancel</button>
              <button className="upload-button" onClick={submitApprove} disabled={isApproving || !approveLabel.trim() || !approveField || !approveValue}>
                <Check size={14} /> {isApproving ? "Saving…" : "Approve & add to knowledge base"}
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function baselineBoolean(device: Device, field: "telnet_enabled" | "http_enabled") {
  if (!device.baseline.known_fields.includes(field) || device.baseline[field] === null) return "UNKNOWN";
  return device.baseline[field] ? "Enabled" : "Disabled";
}

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

function SummaryCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="current-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function HomeLanding({
  onViewReport,
  onPasteConfig,
  onUpload,
}: {
  onViewReport: () => void;
  onPasteConfig: () => void;
  onUpload: (event: React.ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <div className="landing-page">
      <section className="landing-hero">
        <div className="landing-copy">
          <span className="landing-kicker"><Network size={14} /> NETWORK CONFIGURATION ASSESSMENT</span>
          <h2>Make device security settings easier to understand.</h2>
          <p>
            NetAdaptAI reads supported network configuration text, checks it against its current CIS rule set,
            and turns the results into findings with evidence and remediation guidance.
          </p>
          <div className="landing-actions">
            <label className="upload-button landing-upload">
              <UploadCloud size={16} /> Upload a configuration
              <input type="file" accept=".txt,.cfg,.conf,.log" onChange={onUpload} />
            </label>
            <button className="outline-button" onClick={onPasteConfig}>Paste configuration</button>
          </div>
          <button className="landing-text-link" onClick={onViewReport}>
            View the current report <ArrowUpRight size={14} />
          </button>
        </div>
        <div className="landing-preview" aria-label="Example assessment preview">
          <div className="landing-preview-head">
            <div><span className="label">ASSESSMENT PREVIEW</span><strong>From config to findings</strong></div>
            <ShieldCheck size={20} />
          </div>
          <div className="preview-config-line"><span>INPUT</span><code>ip ssh version 2</code><Check size={14} /></div>
          <div className="preview-result-row"><span className="preview-dot pass"><Check size={12} /></span><div><strong>PASS</strong><small>Supported setting meets the rule</small></div><span className="preview-state">evidence found</span></div>
          <div className="preview-result-row"><span className="preview-dot fail"><X size={12} /></span><div><strong>FAIL</strong><small>Supported setting needs attention</small></div><span className="preview-state">remediation shown</span></div>
          <div className="preview-result-row"><span className="preview-dot unknown"><CircleHelp size={12} /></span><div><strong>UNKNOWN</strong><small>Not enough supported evidence</small></div><span className="preview-state">never assumed passed</span></div>
          <div className="preview-foot"><Sparkles size={14} /> Human-reviewed mappings can teach the parser new syntax.</div>
        </div>
      </section>

      <section className="landing-section">
        <div className="landing-section-heading">
          <p className="eyebrow">HOW IT WORKS</p>
          <h3>A simple review workflow</h3>
          <p>Start with configuration text and end with a report you can inspect and share.</p>
        </div>
        <div className="workflow-grid">
          <article className="workflow-card"><span>01</span><UploadCloud size={20} /><h4>Upload or paste</h4><p>Provide a Cisco IOS XE configuration as a file or pasted CLI text.</p></article>
          <article className="workflow-card"><span>02</span><ShieldCheck size={20} /><h4>Assess supported controls</h4><p>Deterministic rules compare normalized facts with the current benchmark rules.</p></article>
          <article className="workflow-card"><span>03</span><Sparkles size={20} /><h4>Review unknown syntax</h4><p>Optional AI suggestions can be checked and approved by a person before reuse.</p></article>
          <article className="workflow-card"><span>04</span><FileDown size={20} /><h4>Download a report</h4><p>Export findings, evidence, expected values, and remediation as a PDF.</p></article>
        </div>
      </section>

      <section className="landing-scope">
        <div className="scope-icon"><CircleHelp size={19} /></div>
        <div>
          <p className="eyebrow">CURRENT PROTOTYPE SCOPE</p>
          <h3>One benchmark, with clear limits</h3>
          <p>
            The current evaluator contains 56 CIS Cisco IOS XE 17.x Benchmark v2.2.1 Level 1 rule definitions.
            Unknown controls remain UNKNOWN. Juniper support is limited to a built-in SSHv2 cross-vendor demonstration;
            it is not a Juniper benchmark assessment.
          </p>
        </div>
        <button className="outline-button" onClick={onViewReport}>Explore the report <ArrowUpRight size={14} /></button>
      </section>

      <div className="landing-footer-note">
        <Check size={15} /> AI can suggest a mapping; deterministic rules decide the assessment result.
      </div>
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <div className="finding-row">
      <div className={`finding-status ${finding.status}`}>
        {finding.status === "pass" ? <Check size={13} /> : finding.status === "unknown" ? <CircleHelp size={13} /> : <AlertTriangle size={13} />}
      </div>
      <div className="finding-copy">
        <div>
          <strong>{finding.title}</strong>
          {finding.learned && <span className="learned-badge">learned</span>}
          {finding.assessment_type === "cross_vendor" && <span className="learned-badge">CROSS-VENDOR</span>}
          <span className={`severity ${finding.severity}`}>{finding.severity}</span>
        </div>
        <p>{finding.summary} Expected: {finding.expected}; actual: {finding.actual}.</p>
        <small className="finding-evidence">Evidence: {finding.evidence}</small>
        {finding.remediation.length > 0 && <small className="finding-evidence">Remediation: {finding.remediation.join(" ")}</small>}
        {finding.assessment_type === "cross_vendor" && (
          <small className="finding-evidence">Mapping confidence {Math.round(finding.mapping_confidence * 100)}% · {finding.human_validated ? "Human validated" : "Built-in mapping; not human validated"}</small>
        )}
      </div>
      <span className="framework-tag">{finding.framework} {finding.control_id}</span>
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
  scope = "all",
  filename,
}: {
  training: Training[];
  onApprove: (item: Training) => void;
  onDeny: (item: Training) => void;
  scope?: "all" | "current";
  filename?: string;
}) {
  const pending  = training.filter((t) => t.status === "pending");
  const resolved = training.filter((t) => t.status !== "pending");

  const items = pending;

  return (
    <section className="panel training-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">ADAPTIVE PARSING</p>
          <h3>{scope === "current" ? "Training from this configuration" : "All pending training items"}</h3>
          <p className="panel-subtitle">
            {scope === "current"
              ? `Review unrecognized commands from ${filename || "the current upload"}.`
              : "Review unrecognized commands collected across uploads."} Approve confirmed mappings to add them to the knowledge base.
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
        {items.length === 0 ? (
          <div className="kb-empty"><p>{scope === "current" ? "No commands in this configuration need training." : "No pending mappings require review."}</p></div>
        ) : items.map((x) => (
          <div className="training-row" key={x.id}>
            <div><code>{x.raw_line}</code><small className="finding-evidence">{x.vendor} {x.platform} · {x.provider}</small></div>
            <span className="suggestion">
              <Sparkles size={13} />
              {x.semantic_meaning || x.suggested_category}
              {x.canonical_control && <span className="field-tag">→ {x.canonical_control} = {String(x.canonical_value)}</span>}
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
            <span>SOURCE PATTERN</span>
            <span>LABEL</span>
            <span>CANONICAL FACT</span>
            <span>VENDOR</span>
            <span>PLATFORM</span>
            <span>CONFIDENCE / VALIDATION</span>
            <span></span>
          </div>
          {patterns.map((p) => (
            <div className="kb-row" key={p.id}>
              <code>{p.source_pattern}</code>
              <span>{p.label}</span>
              <span className="field-tag">{p.canonical_control} = {String(p.canonical_value)}</span>
              <span className="vendor-tag">{p.vendor || "any"}</span>
              <span className="vendor-tag">{p.platform || "any"}</span>
              <span className="confirmed-at">{Math.round(p.confidence * 100)}% · validated {p.human_validated ? "yes" : "no"}<br />{new Date(p.confirmed_at).toLocaleDateString()}</span>
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
