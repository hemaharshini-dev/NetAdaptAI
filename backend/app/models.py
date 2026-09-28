from typing import Literal
from pydantic import BaseModel, Field

Framework = Literal["CIS"]  # CIS IOS XE 17.x Benchmark v2.2.1


class BaselineModel(BaseModel):
    # ── Identity ──────────────────────────────────────────────────────────────
    hostname: str = "Unknown device"
    vendor: str = "Unknown"
    platform: str = "Unknown"
    version: str = "Unknown"
    serial_number: str = "Not discovered"
    ip_domain_name: str | None = None          # 2.1.1.1.2

    # ── 1.1  AAA ─────────────────────────────────────────────────────────────
    aaa_new_model: bool = False                # 1.1.1
    aaa_authentication_login: bool = False     # 1.1.2
    aaa_authentication_enable: bool = False    # 1.1.3
    aaa_login_vty: bool = False                # 1.1.4
    aaa_login_http: bool = False               # 1.1.5
    aaa_accounting_commands15: bool = False    # 1.1.6
    aaa_accounting_connection: bool = False    # 1.1.7
    aaa_accounting_exec: bool = False          # 1.1.8
    aaa_accounting_network: bool = False       # 1.1.9
    aaa_accounting_system: bool = False        # 1.1.10

    # ── 1.2  Access rules ────────────────────────────────────────────────────
    vty_transport_ssh: bool = False            # 1.2.2  transport input ssh on all vty
    aux_no_exec: bool | None = None            # 1.2.3  None = no aux port present
    vty_access_class: bool = False             # 1.2.5
    aux_exec_timeout_ok: bool | None = None    # 1.2.6  ≤10 min on aux
    con_exec_timeout_ok: bool | None = None    # 1.2.7  ≤10 min on con 0
    vty_exec_timeout_ok: bool = False          # 1.2.8  ≤10 min on all vty
    http_max_connections_ok: bool | None = None  # 1.2.9  ≤2 when http/s enabled
    http_timeout_policy_ok: bool | None = None   # 1.2.10 ≤600s when http/s enabled

    # ── 1.3  Banners ─────────────────────────────────────────────────────────
    banner_exec: bool = False                  # 1.3.1
    banner_login: bool = False                 # 1.3.2
    banner_motd: bool = False                  # 1.3.3
    banner_webauth: bool | None = None         # 1.3.4  None = http disabled (pass)

    # ── 1.4  Passwords ───────────────────────────────────────────────────────
    enable_secret: bool = False                # 1.4.1  enable secret (type 8 or 9)
    service_password_encryption: bool = False  # 1.4.2
    username_secret: bool | None = None        # 1.4.3  None = no local users defined

    # ── 1.5  SNMP ────────────────────────────────────────────────────────────
    snmp_disabled_or_absent: bool = False      # 1.5.1  pass if no snmp-server lines
    snmp_no_private: bool = False              # 1.5.2
    snmp_no_public: bool = False               # 1.5.3
    snmp_no_rw: bool = False                   # 1.5.4
    snmp_host_defined: bool | None = None      # 1.5.7  None = snmp disabled
    snmp_traps_enabled: bool | None = None     # 1.5.8  None = snmp disabled
    snmp_v3_priv: bool | None = None           # 1.5.9  None = snmpv3 not used

    # ── 2.1  SSH prerequisites ───────────────────────────────────────────────
    ssh_version: str | None = None             # 2.1.1.2 / legacy "ip ssh version"
    ssh_timeout_ok: bool = False               # 2.1.1.1.4  ≤60 s
    ssh_retries_ok: bool = False               # 2.1.1.1.5  ≤3

    # ── 2.1  Global service rules ────────────────────────────────────────────
    no_cdp: bool = False                       # 2.1.2
    no_bootp: bool = False                     # 2.1.3
    no_service_dhcp: bool = False              # 2.1.4
    service_tcp_keepalives_in: bool = False    # 2.1.5
    service_tcp_keepalives_out: bool = False   # 2.1.6
    no_service_pad: bool = False               # 2.1.7

    # ── 2.2  Logging ─────────────────────────────────────────────────────────
    logging_enabled: bool = False              # 2.2.1  archive log config
    logging_buffered: bool = False             # 2.2.2  logging buffered (any size)
    logging_console_critical: bool = False     # 2.2.3
    logging_host: bool = False                 # 2.2.4
    logging_trap_informational: bool = False   # 2.2.5
    service_timestamps_debug: bool = False     # 2.2.6
    logging_source_interface: bool = False     # 2.2.7
    login_on_failure: bool = False             # 2.2.8a
    login_on_success: bool = False             # 2.2.8b

    # ── 2.3  NTP ─────────────────────────────────────────────────────────────
    ntp_authenticate: bool = False             # 2.3.1.1
    ntp_authentication_key: bool = False       # 2.3.1.2
    ntp_trusted_key: bool = False              # 2.3.1.3
    ntp_server: bool = False                   # 2.3.2

    # ── 2.4  Loopback ────────────────────────────────────────────────────────
    loopback_interface: bool = False           # 2.4.1
    ntp_source_loopback: bool = False          # 2.4.3

    # ── 3.1  Routing ─────────────────────────────────────────────────────────
    no_ip_source_route: bool = False           # 3.1.1
    no_service_dhcp_field: bool = False        # alias kept for compat

    # ── Legacy / misc (kept for existing test-config compatibility) ──────────
    telnet_enabled: bool | None = None
    http_enabled: bool | None = None
    admin_timeout_minutes: int | None = None

    # Lines the engine could not match to any known pattern
    unrecognized_lines: list[str] = Field(default_factory=list)
    # Fields populated by user-confirmed learned patterns
    learned_fields: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    cis_id: str                                # e.g. "1.1.1"
    section: str                               # e.g. "1.1 AAA Rules"
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["pass", "fail", "review", "not_applicable"]
    summary: str
    remediation: list[str] = Field(default_factory=list)
    learned: bool = False


class Device(BaseModel):
    id: str
    name: str
    vendor: str
    platform: str
    version: str
    score: int
    status: Literal["compliant", "attention", "critical"]
    findings: list[Finding]
    baseline: BaselineModel
    source_filename: str
    uploaded_at: str


class TrainingItem(BaseModel):
    id: str
    raw_line: str
    suggested_category: str
    suggested_field: str | None = None
    suggested_value: str | None = None
    confidence: float
    status: Literal["pending", "approved", "denied"] = "pending"


class TrainingMapping(BaseModel):
    label: str
    normalized_field: str
    vendor: str = ""
    category: str


class LearnedPattern(BaseModel):
    id: str
    raw_pattern: str
    normalized_field: str
    label: str
    vendor: str = ""
    category: str
    confirmed_at: str
    training_item_id: str
