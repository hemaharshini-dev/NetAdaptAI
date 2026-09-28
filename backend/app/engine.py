"""
CIS Cisco IOS XE 17.x Benchmark v2.2.1 – Level 1 engine.
Covers all automatable checks across Management Plane (§1), Control Plane (§2),
and Data Plane (§3).
"""
from __future__ import annotations

import re
from typing import Literal

from .models import BaselineModel, Finding, LearnedPattern


# ── small helpers ─────────────────────────────────────────────────────────────

def _search(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text, re.I | re.M))


def _find(pattern: str, text: str, cast=str):
    m = re.search(pattern, text, re.I | re.M)
    return cast(m.group(1)) if m else None


def _section(text: str, header: str) -> str:
    """Return the indented block that follows *header* (for sub-section checks)."""
    m = re.search(rf"^{re.escape(header)}\b.*$", text, re.I | re.M)
    if not m:
        return ""
    start = m.end()
    # collect lines until we hit a line at the same or lower indent level
    lines: list[str] = []
    for line in text[start:].splitlines():
        if line and not line[0].isspace() and line.strip():
            break
        lines.append(line)
    return "\n".join(lines)


def _vty_blocks(text: str) -> list[str]:
    """Return each 'line vty …' configuration block as a string."""
    blocks: list[str] = []
    for m in re.finditer(r"^line vty\s+\d+.*$", text, re.I | re.M):
        start = m.end()
        sub: list[str] = []
        for line in text[start:].splitlines():
            if line and not line[0].isspace():
                break
            sub.append(line)
        blocks.append(m.group() + "\n" + "\n".join(sub))
    return blocks


def _timeout_minutes(text: str) -> int | None:
    """Parse the first exec-timeout in *text*, return total minutes or None."""
    m = re.search(r"exec-timeout\s+(\d+)\s+(\d+)", text, re.I)
    if m:
        return int(m.group(1)) + int(m.group(2)) / 60
    m = re.search(r"exec-timeout\s+(\d+)", text, re.I)
    if m:
        return int(m.group(1))
    return None


# ── NORMALISATION ─────────────────────────────────────────────────────────────

def normalize_config(
    text: str,
    learned_patterns: list[LearnedPattern] | None = None,
) -> BaselineModel:
    """Parse raw IOS XE CLI text into a :class:`BaselineModel`."""

    # ── Identity ──────────────────────────────────────────────────────────────
    hostname = _find(r"^hostname\s+(\S+)", text) or "Unknown device"
    vendor = (
        "Cisco"
        if _search(r"Cisco IOS|version\s+\d+\.\d+.*IOS|IOS.XE", text)
        else "Juniper"
        if _search(r"junos|set system host-name", text)
        else "Unclassified"
    )
    platform = (
        "IOS / NX-OS" if vendor == "Cisco"
        else "Junos" if vendor == "Juniper"
        else "Unknown CLI"
    )
    version = _find(r"version\s+([\w.()/-]+)", text) or "Unknown"
    serial = (
        _find(r"(?:serial number|Chassis serial number)\s*[:#]?\s*(\S+)", text)
        or "Not discovered"
    )
    ip_domain_name = _find(r"ip domain-name\s+(\S+)", text)

    # ── 1.1  AAA ──────────────────────────────────────────────────────────────
    aaa_new_model          = _search(r"^aaa new-model\s*$", text)
    aaa_authentication_login  = _search(r"^aaa authentication login\s+\S+", text)
    aaa_authentication_enable = _search(r"^aaa authentication enable default", text)
    aaa_login_vty          = _search(r"login authentication", _section(text, "line vty"))
    aaa_login_http         = _search(r"ip http authentication", text)
    aaa_accounting_commands15 = _search(r"^aaa accounting commands 15", text)
    aaa_accounting_connection = _search(r"^aaa accounting connection", text)
    aaa_accounting_exec    = _search(r"^aaa accounting exec\b", text)
    aaa_accounting_network = _search(r"^aaa accounting network\b", text)
    aaa_accounting_system  = _search(r"^aaa accounting system\b", text)

    # ── 1.2  Access rules ─────────────────────────────────────────────────────
    # 1.2.2  all vty blocks must have transport input ssh
    vty_blocks = _vty_blocks(text)
    if vty_blocks:
        vty_transport_ssh = all(
            _search(r"transport input\s+ssh\b", b) for b in vty_blocks
        )
    else:
        vty_transport_ssh = False

    # 1.2.3  aux port
    aux_block = _section(text, "line aux 0")
    if aux_block.strip():
        aux_no_exec = _search(r"no exec", aux_block)
    else:
        aux_no_exec = None  # no aux port present → treated as N/A (pass)

    # 1.2.5  access-class on vty
    vty_access_class = bool(vty_blocks) and all(
        _search(r"access-class\s+\S+\s+in", b) for b in vty_blocks
    )

    # 1.2.6  exec-timeout ≤10 min on aux
    if aux_block.strip():
        t = _timeout_minutes(aux_block)
        aux_exec_timeout_ok = (t is not None and t <= 10)
    else:
        aux_exec_timeout_ok = None  # no aux → N/A

    # 1.2.7  exec-timeout ≤10 min on console
    con_block = _section(text, "line con 0")
    if con_block.strip():
        t = _timeout_minutes(con_block)
        con_exec_timeout_ok = (t is not None and t <= 10)
    else:
        con_exec_timeout_ok = None

    # 1.2.8  exec-timeout ≤10 min on ALL vty blocks
    if vty_blocks:
        vty_exec_timeout_ok = all(
            (lambda t: t is not None and t <= 10)(_timeout_minutes(b))
            for b in vty_blocks
        )
    else:
        vty_exec_timeout_ok = False

    # 1.2.9  http max-connections ≤2 (only relevant when http/s is on)
    http_on  = _search(r"ip http server\b", text)
    https_on = _search(r"ip http secure-server\b", text)
    if http_on or https_on:
        mc = _find(r"ip http max-connections\s+(\d+)", text, int)
        http_max_connections_ok = (mc is not None and mc <= 2)
    else:
        http_max_connections_ok = None  # N/A

    # 1.2.10 http timeout-policy idle ≤600
    if http_on or https_on:
        idle = _find(r"ip http timeout-policy idle\s+(\d+)", text, int)
        http_timeout_policy_ok = (idle is not None and idle <= 600)
    else:
        http_timeout_policy_ok = None  # N/A

    # ── 1.3  Banners ──────────────────────────────────────────────────────────
    banner_exec   = _search(r"^banner exec\s+", text)
    banner_login  = _search(r"^banner login\s+", text)
    banner_motd   = _search(r"^banner motd\s+", text)
    if http_on or https_on:
        banner_webauth = _search(r"ip admission auth-proxy-banner http", text)
    else:
        banner_webauth = None  # N/A

    # ── 1.4  Passwords ────────────────────────────────────────────────────────
    # 1.4.1  enable secret type 8 or 9 (or at minimum any enable secret)
    enable_secret = _search(r"^enable secret\s+[89]\s+", text) or \
                    _search(r"^enable secret\s+", text)
    service_password_encryption = _search(r"^service password-encryption\b", text)
    # 1.4.3  if local users defined, all must use 'secret' (not 'password')
    local_users = re.findall(r"^username\s+\S+.*$", text, re.I | re.M)
    if local_users:
        username_secret = all(_search(r"\bsecret\b", u) for u in local_users)
    else:
        username_secret = None  # no local users → N/A

    # ── 1.5  SNMP ─────────────────────────────────────────────────────────────
    snmp_lines = [l for l in text.splitlines()
                  if re.match(r"\s*snmp-server\b", l, re.I)]
    if not snmp_lines:
        # SNMP entirely absent → all SNMP checks pass (not used)
        snmp_disabled_or_absent = True
        snmp_no_private = True
        snmp_no_public  = True
        snmp_no_rw      = True
        snmp_host_defined  = None
        snmp_traps_enabled = None
        snmp_v3_priv       = None
    else:
        snmp_disabled_or_absent = _search(r"^no snmp-server\b", text)
        community_lines = [l for l in snmp_lines if "community" in l.lower()]
        snmp_no_private = not any("private" in l.lower() for l in community_lines)
        snmp_no_public  = not any("public"  in l.lower() for l in community_lines)
        snmp_no_rw      = not any(re.search(r"\bRW\b", l, re.I) for l in community_lines)
        snmp_host_defined  = _search(r"^snmp-server host\b", text)
        snmp_traps_enabled = _search(r"^snmp-server enable traps snmp\b", text)
        v3_group_lines = [l for l in snmp_lines if "group" in l.lower() and "v3" in l.lower()]
        if v3_group_lines:
            snmp_v3_priv = all(_search(r"\bpriv\b", l) for l in v3_group_lines)
        else:
            snmp_v3_priv = None  # SNMPv3 not used → N/A

    # ── 2.1  SSH ──────────────────────────────────────────────────────────────
    ssh_version = _find(r"ip ssh version\s+(\d+)", text)
    t_ssh = _find(r"ip ssh time-out\s+(\d+)", text, int) or \
            _find(r"ip ssh timeout\s+(\d+)", text, int)
    ssh_timeout_ok = (t_ssh is not None and t_ssh <= 60)
    r_ssh = _find(r"ip ssh authentication-retries\s+(\d+)", text, int)
    ssh_retries_ok = (r_ssh is not None and r_ssh <= 3)

    # ── 2.1  Global service rules ─────────────────────────────────────────────
    no_cdp             = _search(r"^no cdp run\b", text)
    no_bootp           = not _search(r"^ip bootp server\b", text)   # absent = pass
    no_service_dhcp    = _search(r"^no service dhcp\b", text)
    service_tcp_in     = _search(r"^service tcp-keepalives-in\b", text)
    service_tcp_out    = _search(r"^service tcp-keepalives-out\b", text)
    no_service_pad     = not _search(r"^service pad\b", text)        # absent = pass

    # ── 2.2  Logging ──────────────────────────────────────────────────────────
    logging_enabled          = _search(r"^archive\b", text) and \
                               _search(r"logging enable", text)
    logging_buffered         = _search(r"^logging buffered\b", text)
    logging_console_critical = _search(r"^logging console\s+(critical|alerts|emergencies)\b", text)
    logging_host             = _search(r"^logging host\b", text)
    logging_trap_info        = _search(r"^logging trap\s+(informational|debugging)\b", text)
    service_timestamps_debug = _search(r"^service timestamps debug datetime\b", text)
    logging_source_interface = _search(r"^logging source-interface\b", text)
    login_on_failure         = _search(r"^login on-failure\b", text)
    login_on_success         = _search(r"^login on-success\b", text)

    # ── 2.3  NTP ──────────────────────────────────────────────────────────────
    ntp_authenticate      = _search(r"^ntp authenticate\b", text)
    ntp_authentication_key = _search(r"^ntp authentication-key\b", text)
    ntp_trusted_key       = _search(r"^ntp trusted-key\b", text)
    ntp_server            = _search(r"^ntp server\b", text)

    # ── 2.4  Loopback ─────────────────────────────────────────────────────────
    loopback_interface  = _search(r"^interface [Ll]oopback\d+", text)
    ntp_source_loopback = _search(r"^ntp source\s+[Ll]oopback", text)

    # ── 3.1  Routing ──────────────────────────────────────────────────────────
    # absent of "ip source-route" in modern IOS XE means disabled (safe default)
    # explicit "no ip source-route" is the hardened setting
    no_ip_source_route = _search(r"^no ip source-route\b", text)

    # ── Legacy / misc (kept so existing test configs still score) ─────────────
    telnet_enabled = (
        _search(r"(service telnet|transport input .*telnet)", text)
        and not _search(r"no (feature telnet|service telnet)", text)
    )
    http_enabled = http_on
    timeout_raw = _find(r"exec-timeout\s+(\d+)", text, int)
    admin_timeout_minutes = timeout_raw

    # ── Unrecognized lines (for training queue) ───────────────────────────────
    known_kw = (
        "hostname", "version", "aaa", "username", "enable", "service",
        "ip ", "no ip", "logging", "snmp", "ntp", "banner", "line ",
        "interface", "description", "router ", "access-list", "archive",
        "login", "crypto", "key ", "cdp", "transport", "exec-timeout",
        "shutdown", "boot", "end", "!", "^C",
    )
    lines_clean = [l.strip() for l in text.splitlines() if l.strip() and l.strip() != "!"]
    unrecognized = [
        l for l in lines_clean
        if not any(l.lower().startswith(kw.lower()) for kw in known_kw)
    ]

    # ── Apply learned patterns ────────────────────────────────────────────────
    learned_fields: dict[str, str] = {}
    still_unrecognized: list[str] = []
    for line in unrecognized:
        matched = False
        for pattern in (learned_patterns or []):
            if pattern.vendor and pattern.vendor.lower() not in vendor.lower():
                continue
            if pattern.raw_pattern.lower() in line.lower():
                learned_fields[pattern.normalized_field] = line
                matched = True
                break
        if not matched:
            still_unrecognized.append(line)

    return BaselineModel(
        hostname=hostname, vendor=vendor, platform=platform, version=version,
        serial_number=serial, ip_domain_name=ip_domain_name,
        # 1.1
        aaa_new_model=aaa_new_model,
        aaa_authentication_login=aaa_authentication_login,
        aaa_authentication_enable=aaa_authentication_enable,
        aaa_login_vty=aaa_login_vty,
        aaa_login_http=aaa_login_http,
        aaa_accounting_commands15=aaa_accounting_commands15,
        aaa_accounting_connection=aaa_accounting_connection,
        aaa_accounting_exec=aaa_accounting_exec,
        aaa_accounting_network=aaa_accounting_network,
        aaa_accounting_system=aaa_accounting_system,
        # 1.2
        vty_transport_ssh=vty_transport_ssh,
        aux_no_exec=aux_no_exec,
        vty_access_class=vty_access_class,
        aux_exec_timeout_ok=aux_exec_timeout_ok,
        con_exec_timeout_ok=con_exec_timeout_ok,
        vty_exec_timeout_ok=vty_exec_timeout_ok,
        http_max_connections_ok=http_max_connections_ok,
        http_timeout_policy_ok=http_timeout_policy_ok,
        # 1.3
        banner_exec=banner_exec, banner_login=banner_login,
        banner_motd=banner_motd, banner_webauth=banner_webauth,
        # 1.4
        enable_secret=enable_secret,
        service_password_encryption=service_password_encryption,
        username_secret=username_secret,
        # 1.5
        snmp_disabled_or_absent=snmp_disabled_or_absent,
        snmp_no_private=snmp_no_private, snmp_no_public=snmp_no_public,
        snmp_no_rw=snmp_no_rw,
        snmp_host_defined=snmp_host_defined,
        snmp_traps_enabled=snmp_traps_enabled,
        snmp_v3_priv=snmp_v3_priv,
        # 2.1
        ssh_version=ssh_version,
        ssh_timeout_ok=ssh_timeout_ok, ssh_retries_ok=ssh_retries_ok,
        no_cdp=no_cdp, no_bootp=no_bootp,
        no_service_dhcp=no_service_dhcp,
        service_tcp_keepalives_in=service_tcp_in,
        service_tcp_keepalives_out=service_tcp_out,
        no_service_pad=no_service_pad,
        # 2.2
        logging_enabled=logging_enabled,
        logging_buffered=logging_buffered,
        logging_console_critical=logging_console_critical,
        logging_host=logging_host,
        logging_trap_informational=logging_trap_info,
        service_timestamps_debug=service_timestamps_debug,
        logging_source_interface=logging_source_interface,
        login_on_failure=login_on_failure,
        login_on_success=login_on_success,
        # 2.3
        ntp_authenticate=ntp_authenticate,
        ntp_authentication_key=ntp_authentication_key,
        ntp_trusted_key=ntp_trusted_key,
        ntp_server=ntp_server,
        # 2.4
        loopback_interface=loopback_interface,
        ntp_source_loopback=ntp_source_loopback,
        # 3.1
        no_ip_source_route=no_ip_source_route,
        # legacy
        telnet_enabled=telnet_enabled,
        http_enabled=http_enabled,
        admin_timeout_minutes=admin_timeout_minutes,
        unrecognized_lines=still_unrecognized[:20],
        learned_fields=learned_fields,
    )


# ── RULES TABLE ──────────────────────────────────────────────────────────────
# Each entry: cis_id -> (section, title, severity, summary, remediation, field, pass_condition)
# pass_condition: "true"  → field must be True
#                "false" → field must be False
#                "not_none_true" → field must be not None and True (N/A if None)
#                "ssh2"  → field must == "2"
#                "none_is_na_true" → None → not_applicable; value must be True

_RULES: list[dict] = [
    # ── 1.1  AAA ─────────────────────────────────────────────────────────────
    dict(cis_id="1.1.1", section="1.1 AAA Rules",
         title="Enable 'aaa new-model'", severity="high",
         summary="AAA new-model enables centralised authentication, authorisation and accounting.",
         remediation=["aaa new-model"],
         field="aaa_new_model", mode="true"),
    dict(cis_id="1.1.2", section="1.1 AAA Rules",
         title="Enable 'aaa authentication login'", severity="high",
         summary="Sets AAA authentication at login to enforce centralised credential checking.",
         remediation=["aaa authentication login default local"],
         field="aaa_authentication_login", mode="true"),
    dict(cis_id="1.1.3", section="1.1 AAA Rules",
         title="Enable 'aaa authentication enable default'", severity="high",
         summary="Authenticates users accessing privileged EXEC mode via the enable command.",
         remediation=["aaa authentication enable default enable"],
         field="aaa_authentication_enable", mode="true"),
    dict(cis_id="1.1.4", section="1.1 AAA Rules",
         title="Set 'login authentication' for 'line vty'", severity="high",
         summary="Ensures VTY remote management lines require AAA login authentication.",
         remediation=["line vty 0 15", " login authentication default"],
         field="aaa_login_vty", mode="true"),
    dict(cis_id="1.1.5", section="1.1 AAA Rules",
         title="Set 'login authentication' for 'ip http'", severity="medium",
         summary="Enforces AAA authentication on the HTTP/HTTPS management interface.",
         remediation=["ip http authentication local"],
         field="aaa_login_http", mode="true"),
    dict(cis_id="1.1.6", section="1.1 AAA Rules",
         title="Set 'aaa accounting commands 15'", severity="medium",
         summary="Logs all privilege-level-15 commands for audit trail via TACACS+/RADIUS.",
         remediation=["aaa accounting commands 15 default start-stop group tacacs+"],
         field="aaa_accounting_commands15", mode="true"),
    dict(cis_id="1.1.7", section="1.1 AAA Rules",
         title="Set 'aaa accounting connection'", severity="medium",
         summary="Records outbound connection accounting information for all sessions.",
         remediation=["aaa accounting connection default start-stop group tacacs+"],
         field="aaa_accounting_connection", mode="true"),
    dict(cis_id="1.1.8", section="1.1 AAA Rules",
         title="Set 'aaa accounting exec'", severity="medium",
         summary="Records EXEC terminal session start/stop times for audit purposes.",
         remediation=["aaa accounting exec default start-stop group tacacs+"],
         field="aaa_accounting_exec", mode="true"),
    dict(cis_id="1.1.9", section="1.1 AAA Rules",
         title="Set 'aaa accounting network'", severity="medium",
         summary="Records network service request accounting information.",
         remediation=["aaa accounting network default start-stop group radius"],
         field="aaa_accounting_network", mode="true"),
    dict(cis_id="1.1.10", section="1.1 AAA Rules",
         title="Set 'aaa accounting system'", severity="medium",
         summary="Records all system-level events such as reloads for audit purposes.",
         remediation=["aaa accounting system default start-stop group tacacs+"],
         field="aaa_accounting_system", mode="true"),

    # ── 1.2  Access rules ────────────────────────────────────────────────────
    dict(cis_id="1.2.2", section="1.2 Access Rules",
         title="Set 'transport input ssh' for 'line vty'", severity="critical",
         summary="Restricts VTY management lines to encrypted SSH sessions only.",
         remediation=["line vty 0 15", " transport input ssh"],
         field="vty_transport_ssh", mode="true"),
    dict(cis_id="1.2.3", section="1.2 Access Rules",
         title="Set 'no exec' for 'line aux 0'", severity="high",
         summary="Disables EXEC on the auxiliary port to prevent unauthorised dial-up access.",
         remediation=["line aux 0", " no exec"],
         field="aux_no_exec", mode="none_is_na_true"),
    dict(cis_id="1.2.5", section="1.2 Access Rules",
         title="Set 'access-class' for 'line vty'", severity="high",
         summary="Applies an ACL to VTY lines to restrict management source addresses.",
         remediation=["line vty 0 15", " access-class VTY-ACL in"],
         field="vty_access_class", mode="true"),
    dict(cis_id="1.2.6", section="1.2 Access Rules",
         title="exec-timeout ≤10 min on 'line aux 0'", severity="medium",
         summary="Closes idle auxiliary sessions within 10 minutes to prevent session hijack.",
         remediation=["line aux 0", " exec-timeout 10 0"],
         field="aux_exec_timeout_ok", mode="none_is_na_true"),
    dict(cis_id="1.2.7", section="1.2 Access Rules",
         title="exec-timeout ≤10 min on 'line console 0'", severity="medium",
         summary="Closes idle console sessions within 10 minutes.",
         remediation=["line con 0", " exec-timeout 10 0"],
         field="con_exec_timeout_ok", mode="none_is_na_true"),
    dict(cis_id="1.2.8", section="1.2 Access Rules",
         title="exec-timeout ≤10 min on 'line vty'", severity="high",
         summary="Closes all idle VTY sessions within 10 minutes.",
         remediation=["line vty 0 15", " exec-timeout 10 0"],
         field="vty_exec_timeout_ok", mode="true"),
    dict(cis_id="1.2.9", section="1.2 Access Rules",
         title="Set 'ip http max-connections' ≤2", severity="medium",
         summary="Limits simultaneous HTTP/S management sessions to reduce DoS risk.",
         remediation=["ip http max-connections 2"],
         field="http_max_connections_ok", mode="none_is_na_true"),
    dict(cis_id="1.2.10", section="1.2 Access Rules",
         title="Set 'ip http timeout-policy idle' ≤600 s", severity="medium",
         summary="Times out idle HTTP/S management sessions within 10 minutes.",
         remediation=["ip http timeout-policy idle 600 life 86400 requests 10000"],
         field="http_timeout_policy_ok", mode="none_is_na_true"),

    # ── 1.3  Banners ─────────────────────────────────────────────────────────
    dict(cis_id="1.3.1", section="1.3 Banner Rules",
         title="Set banner-text for 'banner exec'", severity="low",
         summary="Displays a legal notice upon EXEC session establishment.",
         remediation=["banner exec ^", " Authorised access only. All activity logged. ^"],
         field="banner_exec", mode="true"),
    dict(cis_id="1.3.2", section="1.3 Banner Rules",
         title="Set banner-text for 'banner login'", severity="low",
         summary="Displays a legal warning before the login prompt.",
         remediation=["banner login ^", " Unauthorised access is prohibited. ^"],
         field="banner_login", mode="true"),
    dict(cis_id="1.3.3", section="1.3 Banner Rules",
         title="Set banner-text for 'banner motd'", severity="low",
         summary="Displays a message-of-the-day legal notice on every connection.",
         remediation=["banner motd ^", " NOTICE: Authorised users only. ^"],
         field="banner_motd", mode="true"),
    dict(cis_id="1.3.4", section="1.3 Banner Rules",
         title="Set banner-text for 'webauth banner'", severity="low",
         summary="Displays a legal banner on the web authentication page (if HTTP/S is enabled).",
         remediation=["ip admission auth-proxy-banner http banner-text"],
         field="banner_webauth", mode="none_is_na_true"),

    # ── 1.4  Passwords ───────────────────────────────────────────────────────
    dict(cis_id="1.4.1", section="1.4 Password Rules",
         title="Set 'enable secret' (type 8 or 9)", severity="critical",
         summary="Strong hashing (PBKDF2/SCRYPT) protects privileged EXEC passwords.",
         remediation=["enable secret 9 <strong-password>"],
         field="enable_secret", mode="true"),
    dict(cis_id="1.4.2", section="1.4 Password Rules",
         title="Enable 'service password-encryption'", severity="high",
         summary="Encrypts all plaintext passwords in the running configuration.",
         remediation=["service password-encryption"],
         field="service_password_encryption", mode="true"),
    dict(cis_id="1.4.3", section="1.4 Password Rules",
         title="Set 'username secret' for all local users", severity="high",
         summary="Local user passwords must use the secret (hashed) form, not plaintext.",
         remediation=["username <name> secret 9 <password>"],
         field="username_secret", mode="none_is_na_true"),

    # ── 1.5  SNMP ────────────────────────────────────────────────────────────
    dict(cis_id="1.5.1", section="1.5 SNMP Rules",
         title="Disable SNMP when unused ('no snmp-server')", severity="high",
         summary="SNMP exposes management data. Disable entirely if not required.",
         remediation=["no snmp-server"],
         field="snmp_disabled_or_absent", mode="true"),
    dict(cis_id="1.5.2", section="1.5 SNMP Rules",
         title="Unset 'private' SNMP community string", severity="critical",
         summary="Default community 'private' is publicly known; its use allows unauthorised access.",
         remediation=["no snmp-server community private"],
         field="snmp_no_private", mode="true"),
    dict(cis_id="1.5.3", section="1.5 SNMP Rules",
         title="Unset 'public' SNMP community string", severity="critical",
         summary="Default community 'public' is publicly known; remove it to prevent enumeration.",
         remediation=["no snmp-server community public"],
         field="snmp_no_public", mode="true"),
    dict(cis_id="1.5.4", section="1.5 SNMP Rules",
         title="No read-write SNMP community strings", severity="critical",
         summary="RW community strings allow remote device modification. Use SNMPv3 instead.",
         remediation=["no snmp-server community <rw-string> RW"],
         field="snmp_no_rw", mode="true"),
    dict(cis_id="1.5.7", section="1.5 SNMP Rules",
         title="Set 'snmp-server host' when SNMP is used", severity="medium",
         summary="Restricts SNMP trap destinations to authorised management systems only.",
         remediation=["snmp-server host <ip> <community> snmp"],
         field="snmp_host_defined", mode="none_is_na_true"),
    dict(cis_id="1.5.8", section="1.5 SNMP Rules",
         title="Enable 'snmp-server enable traps snmp'", severity="medium",
         summary="Ensures SNMP authentication failure traps are sent for monitoring.",
         remediation=["snmp-server enable traps snmp authentication linkup linkdown coldstart"],
         field="snmp_traps_enabled", mode="none_is_na_true"),
    dict(cis_id="1.5.9", section="1.5 SNMP Rules",
         title="Set 'priv' for SNMPv3 groups", severity="high",
         summary="SNMPv3 groups must use privacy (encryption) to protect management traffic.",
         remediation=["snmp-server group <name> v3 priv"],
         field="snmp_v3_priv", mode="none_is_na_true"),

    # ── 2.1  SSH & global services ───────────────────────────────────────────
    dict(cis_id="2.1.1.2", section="2.1 SSH & Global Services",
         title="Set 'ip ssh version 2'", severity="critical",
         summary="SSHv1 has known vulnerabilities. Only SSHv2 must be permitted.",
         remediation=["ip ssh version 2"],
         field="ssh_version", mode="ssh2"),
    dict(cis_id="2.1.1.1.4", section="2.1 SSH & Global Services",
         title="Set 'ip ssh time-out' ≤60 seconds", severity="medium",
         summary="Short SSH negotiation timeout limits exposure to incomplete login attacks.",
         remediation=["ip ssh time-out 60"],
         field="ssh_timeout_ok", mode="true"),
    dict(cis_id="2.1.1.1.5", section="2.1 SSH & Global Services",
         title="Set 'ip ssh authentication-retries' ≤3", severity="medium",
         summary="Limits brute-force attempts per SSH connection to at most 3.",
         remediation=["ip ssh authentication-retries 3"],
         field="ssh_retries_ok", mode="true"),
    dict(cis_id="2.1.2", section="2.1 SSH & Global Services",
         title="Set 'no cdp run'", severity="medium",
         summary="CDP leaks device type, IOS version and interface details to adjacent devices.",
         remediation=["no cdp run"],
         field="no_cdp", mode="true"),
    dict(cis_id="2.1.3", section="2.1 SSH & Global Services",
         title="Set 'no ip bootp server'", severity="medium",
         summary="BOOTP allows IP address assignment; disable unless explicitly required.",
         remediation=["no ip bootp server"],
         field="no_bootp", mode="true"),
    dict(cis_id="2.1.4", section="2.1 SSH & Global Services",
         title="Set 'no service dhcp'", severity="medium",
         summary="Disable the router DHCP server unless it is the intended DHCP source.",
         remediation=["no service dhcp"],
         field="no_service_dhcp", mode="true"),
    dict(cis_id="2.1.5", section="2.1 SSH & Global Services",
         title="Set 'service tcp-keepalives-in'", severity="medium",
         summary="Detects and clears stale inbound TCP sessions to free resources.",
         remediation=["service tcp-keepalives-in"],
         field="service_tcp_keepalives_in", mode="true"),
    dict(cis_id="2.1.6", section="2.1 SSH & Global Services",
         title="Set 'service tcp-keepalives-out'", severity="medium",
         summary="Detects and clears stale outbound TCP sessions to free resources.",
         remediation=["service tcp-keepalives-out"],
         field="service_tcp_keepalives_out", mode="true"),
    dict(cis_id="2.1.7", section="2.1 SSH & Global Services",
         title="Set 'no service pad'", severity="low",
         summary="Disables the X.25 PAD command set to remove an unnecessary attack surface.",
         remediation=["no service pad"],
         field="no_service_pad", mode="true"),

    # ── 2.2  Logging ─────────────────────────────────────────────────────────
    dict(cis_id="2.2.1", section="2.2 Logging Rules",
         title="Enable 'logging enable' (archive log config)", severity="high",
         summary="Config change logging ensures a durable audit trail of all modifications.",
         remediation=["archive", " log config", "  logging enable"],
         field="logging_enabled", mode="true"),
    dict(cis_id="2.2.2", section="2.2 Logging Rules",
         title="Set 'logging buffered' with buffer size", severity="medium",
         summary="Local buffer logging provides in-device event history for troubleshooting.",
         remediation=["logging buffered 64000"],
         field="logging_buffered", mode="true"),
    dict(cis_id="2.2.3", section="2.2 Logging Rules",
         title="Set 'logging console critical'", severity="medium",
         summary="Limits console log noise to critical messages to prevent performance impact.",
         remediation=["logging console critical"],
         field="logging_console_critical", mode="true"),
    dict(cis_id="2.2.4", section="2.2 Logging Rules",
         title="Set IP address for 'logging host'", severity="high",
         summary="Centralised syslog provides protected, long-term storage of event records.",
         remediation=["logging host <syslog-server-ip>"],
         field="logging_host", mode="true"),
    dict(cis_id="2.2.5", section="2.2 Logging Rules",
         title="Set 'logging trap informational'", severity="medium",
         summary="Sends informational-level messages to the syslog server for full visibility.",
         remediation=["logging trap informational"],
         field="logging_trap_informational", mode="true"),
    dict(cis_id="2.2.6", section="2.2 Logging Rules",
         title="Set 'service timestamps debug datetime'", severity="medium",
         summary="Timestamped logs are essential for accurate incident correlation.",
         remediation=["service timestamps debug datetime msec show-timezone"],
         field="service_timestamps_debug", mode="true"),
    dict(cis_id="2.2.7", section="2.2 Logging Rules",
         title="Set 'logging source-interface'", severity="medium",
         summary="A consistent source IP in syslog messages prevents log fragmentation.",
         remediation=["logging source-interface Loopback0"],
         field="logging_source_interface", mode="true"),
    dict(cis_id="2.2.8a", section="2.2 Logging Rules",
         title="Set 'login on-failure log'", severity="high",
         summary="Failed login attempts must be logged for intrusion detection.",
         remediation=["login on-failure log"],
         field="login_on_failure", mode="true"),
    dict(cis_id="2.2.8b", section="2.2 Logging Rules",
         title="Set 'login on-success log'", severity="medium",
         summary="Successful logins should be logged to provide a complete access audit trail.",
         remediation=["login on-success log"],
         field="login_on_success", mode="true"),

    # ── 2.3  NTP ─────────────────────────────────────────────────────────────
    dict(cis_id="2.3.1.1", section="2.3 NTP Rules",
         title="Set 'ntp authenticate'", severity="medium",
         summary="NTP authentication prevents the device syncing to rogue time sources.",
         remediation=["ntp authenticate"],
         field="ntp_authenticate", mode="true"),
    dict(cis_id="2.3.1.2", section="2.3 NTP Rules",
         title="Set 'ntp authentication-key'", severity="medium",
         summary="Defines the shared key used to authenticate NTP peers.",
         remediation=["ntp authentication-key 1 md5 <key-hash>"],
         field="ntp_authentication_key", mode="true"),
    dict(cis_id="2.3.1.3", section="2.3 NTP Rules",
         title="Set 'ntp trusted-key'", severity="medium",
         summary="Designates which key IDs are trusted for NTP peer authentication.",
         remediation=["ntp trusted-key 1"],
         field="ntp_trusted_key", mode="true"),
    dict(cis_id="2.3.2", section="2.3 NTP Rules",
         title="Set 'ntp server' IP address", severity="medium",
         summary="At least one authenticated NTP server must be configured for time accuracy.",
         remediation=["ntp server <ip-address> key 1"],
         field="ntp_server", mode="true"),

    # ── 2.4  Loopback ────────────────────────────────────────────────────────
    dict(cis_id="2.4.1", section="2.4 Loopback Rules",
         title="Create a single 'interface loopback'", severity="medium",
         summary="A loopback interface provides a stable source address for management services.",
         remediation=["interface Loopback0", " ip address <ip> 255.255.255.255"],
         field="loopback_interface", mode="true"),
    dict(cis_id="2.4.3", section="2.4 Loopback Rules",
         title="Set 'ntp source' to loopback interface", severity="low",
         summary="Binding NTP to the loopback ensures consistent source addressing.",
         remediation=["ntp source Loopback0"],
         field="ntp_source_loopback", mode="true"),

    # ── 3.1  Routing ─────────────────────────────────────────────────────────
    dict(cis_id="3.1.1", section="3.1 Routing Rules",
         title="Set 'no ip source-route'", severity="high",
         summary="Source routing can be exploited to bypass ACLs and should be disabled.",
         remediation=["no ip source-route"],
         field="no_ip_source_route", mode="true"),
]


# ── EVALUATION ────────────────────────────────────────────────────────────────

def evaluate(
    baseline: BaselineModel,
    frameworks: list[str] | None = None,   # kept for API compat, ignored
    learned_patterns: list[LearnedPattern] | None = None,
) -> list[Finding]:
    """Produce one Finding per CIS rule, plus learned-pattern findings."""
    results: list[Finding] = []

    for rule in _RULES:
        field_val = getattr(baseline, rule["field"], None)
        mode: str = rule["mode"]

        if mode == "true":
            if field_val is True:
                status: Literal["pass","fail","review","not_applicable"] = "pass"
            elif field_val is False:
                status = "fail"
            else:
                status = "review"

        elif mode == "false":
            if field_val is False:
                status = "pass"
            elif field_val is True:
                status = "fail"
            else:
                status = "review"

        elif mode == "ssh2":
            if field_val == "2":
                status = "pass"
            elif field_val is None:
                status = "review"
            else:
                status = "fail"

        elif mode == "none_is_na_true":
            if field_val is None:
                status = "not_applicable"
            elif field_val is True:
                status = "pass"
            else:
                status = "fail"

        else:
            status = "review"

        results.append(Finding(
            id=f"cis-{rule['cis_id']}",
            cis_id=rule["cis_id"],
            section=rule["section"],
            title=rule["title"],
            severity=rule["severity"],
            status=status,
            summary=rule["summary"],
            remediation=rule["remediation"],
            learned=False,
        ))

    # ── Learned-pattern findings ───────────────────────────────────────────
    seen: set[str] = set()
    for pattern in (learned_patterns or []):
        if pattern.normalized_field in seen:
            continue
        seen.add(pattern.normalized_field)
        matched = pattern.normalized_field in baseline.learned_fields
        results.append(Finding(
            id=f"learned-{pattern.normalized_field}",
            cis_id="custom",
            section="Learned Patterns",
            title=pattern.label,
            severity="medium",
            status="pass" if matched else "review",
            summary=f"Learned pattern '{pattern.raw_pattern}' → {pattern.normalized_field}",
            remediation=[],
            learned=True,
        ))

    return results
