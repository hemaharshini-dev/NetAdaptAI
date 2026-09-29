# NetAdaptAI demo video script

**Target length:** 2 minutes 30 seconds  
**Format:** 16:9 screen recording with voice-over  
**Show:** the local Next.js app at `http://localhost:3000` with the FastAPI backend running at `http://localhost:8000`.

## Before recording

1. Start the frontend and backend in separate terminals and open the app.
2. Use `test-configs/cisco-edge-noncompliant.cfg` for the first upload. It includes SSHv2, Telnet, HTTP management, and a long VTY timeout so the report has visible findings.
3. For the learning demonstration, use `test-configs/cisco-unknown-mapping.cfg`. Its `ssh strength two` line is a **synthetic demo alias**, not a real Cisco IOS XE command. Explain that the human reviewer is deliberately mapping this fixture to SSH version 2 to demonstrate the learning flow.
4. Ollama is optional. If it is unavailable, the item can still be reviewed and mapped manually in the approval dialog.
5. Avoid recording real device configurations; the app stores assessment facts and findings, while raw uploaded config text is not saved in SQLite.

## Timed walkthrough

### 0:00–0:15 · Introduce the project

**On screen:** Start on **Current config report**. Keep the full app visible.

**Say:**

> NetAdaptAI is a prototype for reviewing network device configurations. It parses supported configuration lines, evaluates them against its CIS Cisco IOS XE Level 1 rule set, and gives reviewers a place to teach it new syntax.

### 0:15–0:35 · Upload a Cisco configuration

**On screen:** Click **Ingest config** and select `cisco-edge-noncompliant.cfg`. Wait for the latest configuration report to load.

**Say:**

> I’m uploading a sample Cisco IOS XE configuration. The app extracts supported facts such as SSH version, management services, logging settings, and VTY access, then builds a report for this file.

### 0:35–1:00 · Read the current-file report

**On screen:** Show the filename, benchmark label, score summary, and several PASS, FAIL, and UNKNOWN rows. Scroll through a few controls to show expected values, actual values, evidence, and remediation. Click **Compliance overview** briefly, then return to **Current config report**.

**Say:**

> The landing page is focused on the current upload. Each finding shows what the rule expected, what the parser observed, and the configuration evidence. Unsupported evidence stays UNKNOWN; it is not counted as a pass. The score is the number of passing controls divided by all controls.

> The overview and all-findings pages are available separately when I want to inspect the broader workspace view.

### 1:00–1:40 · Review a training item

**On screen:** Upload `cisco-unknown-mapping.cfg`. In **Training from this configuration**, open the review for `ssh strength two`. If the mapping dialog has no suggestion, select `management.ssh.version` and `Version 2` yourself. Click **Approve & add to knowledge base**.

**Say:**

> This file contains an intentionally synthetic command, `ssh strength two`, so I can demonstrate the review workflow. It is not Cisco syntax. The AI may propose a meaning when Ollama is available, but it does not make the compliance decision. I verify the proposed meaning and approve the mapping—or enter it manually when there is no reliable suggestion.

> After approval, the mapping is stored as a reusable pattern. The current configuration is re-evaluated using that confirmed fact.

### 1:40–2:00 · Show the knowledge base and reuse

**On screen:** Open **Knowledge base** and show the new pattern. Re-upload `cisco-unknown-mapping.cfg`, return to **Current config report**, and show that the matching command is recognized and no longer needs a pending training item.

**Say:**

> Confirmed mappings appear in the knowledge base and are checked on later uploads before asking for another AI suggestion. The deterministic rules still produce the PASS, FAIL, or UNKNOWN result.

### 2:00–2:20 · Download the PDF report

**On screen:** Return to the current report and click **Download PDF report**. Show the PDF summary and a finding with its evidence and remediation.

**Say:**

> I can download a PDF for the current device assessment. It includes the benchmark and device details, the PASS, FAIL, and UNKNOWN counts, and the expected value, actual value, evidence, and remediation for each control.

### 2:20–2:35 · State the scope clearly

**On screen:** Optionally upload `juniper-ssh-cross-vendor.set` and show the SSH mapping label. End on the current report page.

**Say:**

> The prototype currently includes one benchmark: CIS Cisco IOS XE 17.x, version 2.2.1. Juniper support is limited to an SSHv2 cross-vendor demonstration; it is not a Juniper compliance benchmark, and unsupported controls remain UNKNOWN.

## Optional short ending

> NetAdaptAI connects configuration parsing, evidence-based checks, human-reviewed learning, and report generation in one local workflow.
