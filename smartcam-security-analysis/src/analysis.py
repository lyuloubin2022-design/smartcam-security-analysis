from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from statistics import median, pstdev

from src.constants import (
    APP_PROTOCOLS,
    ATTACK_SURFACE_PORTS,
    CONTEXTUAL_HOSTNAME_TERMS,
    DEVICE_PROFILES,
    LEGACY_TLS_VERSIONS,
    SEVERITY_WEIGHTS,
    SUSPICIOUS_PORTS,
)

SENSITIVE_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"\+?\d[\d\s-]{7,}\d"),
    "token": re.compile(r"(?:token|auth_token|session_token)[=:&][A-Za-z0-9_-]{6,}", re.IGNORECASE),
    "device_id": re.compile(r"(?:device_id|serial)[=:&][A-Za-z0-9:-]{4,}", re.IGNORECASE),
}


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _as_bool(value: object) -> bool:
    return bool(value)


def _profile_lookup() -> dict[str, dict[str, object]]:
    return {profile["device_name"]: profile for profile in DEVICE_PROFILES}


def _base_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _is_third_party(row: dict[str, object], profiles: dict[str, dict[str, object]]) -> bool:
    if row["direction"] != "outbound":
        return False
    hostname = str(row["hostname"]).strip().lower()
    if not hostname:
        return False
    approved = profiles[str(row["device_name"])]["approved_domains"]
    return not any(hostname.endswith(str(suffix).lower()) for suffix in approved)


def _snippet(row: dict[str, object], limit: int = 110) -> str:
    for field in ("payload_preview", "url", "hostname"):
        value = str(row.get(field, "")).strip()
        if value:
            return value[:limit]
    return ""


def _alert(
    subject: str,
    category: str,
    severity: str,
    timestamp: str,
    explanation: str,
    value_snippet: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "subject": subject,
        "category": category,
        "severity": severity,
        "timestamp": timestamp,
        "explanation": explanation,
        "value_snippet": value_snippet,
        "recommendation": recommendation,
    }


def _sorted_domains(rows: list[dict[str, object]]) -> list[str]:
    counts = Counter(_base_domain(str(row["hostname"])) for row in rows if str(row["hostname"]).strip())
    return [domain for domain, _ in counts.most_common(3)]


def _count_label(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def detect_alerts(rows: list[dict[str, object]]) -> list[dict[str, str]]:
    profiles = _profile_lookup()
    alerts: list[dict[str, str]] = []

    exposure_groups: dict[tuple[str, str, tuple[str, ...]], list[tuple[dict[str, object], set[str]]]] = defaultdict(list)
    for row in rows:
        if row["direction"] != "outbound" or _as_bool(row["tls_present"]):
            continue
        text = " ".join(str(row[field]) for field in ("hostname", "url", "payload_preview"))
        matches = {label for label, pattern in SENSITIVE_PATTERNS.items() if pattern.search(text)}
        if matches:
            destination = str(row["hostname"] or row["dst_ip"])
            exposure_groups[(str(row["device_name"]), destination, tuple(sorted(matches)))].append((row, matches))

    for (device_name, destination, match_types), grouped_rows in exposure_groups.items():
        first_row = min(grouped_rows, key=lambda item: item[0]["timestamp"])[0]
        severity = "high" if {"email", "phone", "token"} & set(match_types) else "medium"
        record_label = _count_label(len(grouped_rows), "record", "records")
        alerts.append(
            _alert(
                subject=f"{device_name} -> {destination}",
                category="plaintext_identifier_exposure",
                severity=severity,
                timestamp=str(first_row["timestamp"]),
                explanation=(
                    f"Synthetic non-TLS {record_label} encoded {', '.join(match_types)} in the URL or payload sent to {destination}."
                ),
                value_snippet=_snippet(first_row),
                recommendation="Use encrypted transport for diagnostics and remove tokens, contact data, and device IDs from cleartext fields.",
            )
        )

    http_groups: dict[tuple[str, str, int], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row["direction"] == "outbound" and not _as_bool(row["tls_present"]) and str(row["protocol"]) == "HTTP":
            key = (str(row["device_name"]), str(row["hostname"] or row["dst_ip"]), int(row["dst_port"]))
            http_groups[key].append(row)

    for (device_name, destination, dst_port), grouped_rows in http_groups.items():
        first_row = min(grouped_rows, key=lambda row: row["timestamp"])
        severity = "high" if len(grouped_rows) >= 4 else "medium"
        record_label = _count_label(len(grouped_rows), "record", "records")
        alerts.append(
            _alert(
                subject=f"{device_name} -> {destination}:{dst_port}",
                category="plaintext_http_observed",
                severity=severity,
                timestamp=str(first_row["timestamp"]),
                explanation=f"Synthetic HTTP {record_label} used port {dst_port}, leaving URL and payload metadata in cleartext.",
                value_snippet=str(first_row["url"]) or _snippet(first_row),
                recommendation="Retire plaintext HTTP endpoints and require HTTPS or another authenticated encrypted transport.",
            )
        )

    hostname_groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        hostname = str(row["hostname"]).lower()
        if row["direction"] != "outbound" or _as_bool(row["tls_present"]) or not hostname:
            continue
        if any(term in hostname for term in CONTEXTUAL_HOSTNAME_TERMS):
            hostname_groups[(str(row["device_name"]), str(row["hostname"]))].append(row)

    for (device_name, hostname), grouped_rows in hostname_groups.items():
        first_row = min(grouped_rows, key=lambda row: row["timestamp"])
        alerts.append(
            _alert(
                subject=f"{device_name} -> {hostname}",
                category="hostname_exposure",
                severity="medium",
                timestamp=str(first_row["timestamp"]),
                explanation=f"Synthetic non-TLS traffic used contextual hostname '{hostname}', directly exposing location-style naming.",
                value_snippet=hostname,
                recommendation="Avoid embedding contextual identifiers in externally visible hostnames and protect the channel with TLS.",
            )
        )

    suspicious_groups: dict[tuple[str, str, int], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row["direction"] == "outbound" and int(row["dst_port"]) in SUSPICIOUS_PORTS:
            suspicious_groups[(str(row["device_name"]), str(row["hostname"] or row["dst_ip"]), int(row["dst_port"]))].append(row)

    for (device_name, destination, dst_port), grouped_rows in suspicious_groups.items():
        first_row = min(grouped_rows, key=lambda row: row["timestamp"])
        record_label = _count_label(len(grouped_rows), "record", "records")
        alerts.append(
            _alert(
                subject=f"{device_name} -> {destination}:{dst_port}",
                category="suspicious_port",
                severity="high",
                timestamp=str(first_row["timestamp"]),
                explanation=f"Synthetic remote-support style {record_label} used uncommon destination port {dst_port}.",
                value_snippet=_snippet(first_row),
                recommendation="Confirm the business need for this port, close it if unnecessary, and restrict it with allowlisting.",
            )
        )

    weak_groups: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if _as_bool(row["tls_present"]) and str(row["tls_version"]) in LEGACY_TLS_VERSIONS:
            weak_groups[(str(row["device_name"]), str(row["hostname"] or row["dst_ip"]), str(row["tls_version"]))].append(row)

    for (device_name, destination, tls_version), grouped_rows in weak_groups.items():
        first_row = min(grouped_rows, key=lambda row: row["timestamp"])
        record_label = _count_label(len(grouped_rows), "record", "records")
        alerts.append(
            _alert(
                subject=f"{device_name} -> {destination}",
                category="weak_transport",
                severity="high",
                timestamp=str(first_row["timestamp"]),
                explanation=f"Synthetic backup {record_label} used legacy transport version {tls_version} for {destination}.",
                value_snippet=f"{destination} via {tls_version}",
                recommendation="Require TLS 1.2+ across all backup, management, and telemetry paths.",
            )
        )

    app_rows = [row for row in rows if str(row["protocol"]) in APP_PROTOCOLS and row["direction"] == "outbound"]
    device_rows: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in app_rows:
        device_rows[str(row["device_name"])].append(row)

    for device_name, grouped_rows in device_rows.items():
        secure = [row for row in grouped_rows if _as_bool(row["tls_present"])]
        insecure = [row for row in grouped_rows if not _as_bool(row["tls_present"])]
        if secure and insecure:
            insecure_destinations = ", ".join(_sorted_domains(insecure))
            first_row = min(insecure, key=lambda row: row["timestamp"])
            alerts.append(
                _alert(
                    subject=device_name,
                    category="mixed_transport",
                    severity="medium",
                    timestamp=str(first_row["timestamp"]),
                    explanation=f"Synthetic subject mixed encrypted sessions with {len(insecure)} non-TLS application record(s).",
                    value_snippet=f"non_tls_domains={insecure_destinations}",
                    recommendation="Remove plaintext fallbacks so each device profile uses a single encrypted application transport posture.",
                )
            )

    third_party_groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if _is_third_party(row, profiles):
            third_party_groups[(str(row["device_name"]), _base_domain(str(row["hostname"])))].append(row)

    for (device_name, destination_domain), grouped_rows in third_party_groups.items():
        first_row = min(grouped_rows, key=lambda row: row["timestamp"])
        severity = "high" if any(not _as_bool(row["tls_present"]) for row in grouped_rows) else "medium"
        record_label = _count_label(len(grouped_rows), "record", "records")
        alerts.append(
            _alert(
                subject=f"{device_name} -> {destination_domain}",
                category="third_party_destination",
                severity=severity,
                timestamp=str(first_row["timestamp"]),
                explanation=f"Synthetic {record_label} contacted non-approved external domain {destination_domain}.",
                value_snippet=", ".join(sorted({str(row['hostname']) for row in grouped_rows}))[:110],
                recommendation="Review third-party data flows, minimize disclosures, and document whether the destination is operationally necessary.",
            )
        )

    beacon_groups: dict[tuple[str, str, int], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row["direction"] == "outbound" and str(row["hostname"]).strip():
            key = (str(row["device_name"]), str(row["hostname"]), int(row["dst_port"]))
            beacon_groups[key].append(row)

    for (device_name, hostname, dst_port), grouped_rows in beacon_groups.items():
        if len(grouped_rows) < 6:
            continue
        ordered = sorted(grouped_rows, key=lambda row: row["timestamp"])
        intervals = [
            (_parse_timestamp(ordered[index]["timestamp"]) - _parse_timestamp(ordered[index - 1]["timestamp"])).total_seconds()
            for index in range(1, len(ordered))
        ]
        if not intervals:
            continue
        interval_std = pstdev(intervals) if len(intervals) > 1 else 0.0
        interval_med = median(intervals)
        third_party = _is_third_party(ordered[0], profiles)
        insecure = any(not _as_bool(row["tls_present"]) for row in ordered)
        if interval_med < 600 or interval_med > 3600 or interval_std > 180:
            continue
        if not (third_party or insecure):
            continue
        alerts.append(
            _alert(
                subject=f"{device_name} -> {hostname}:{dst_port}",
                category="background_communication",
                severity="high" if third_party and insecure else "medium",
                timestamp=str(ordered[0]["timestamp"]),
                explanation=f"Synthetic beaconing to {hostname}:{dst_port} repeated about every {int(interval_med // 60)} minutes.",
                value_snippet=f"{len(ordered)} records; interval_stdev={int(interval_std)}s",
                recommendation="Investigate recurring telemetry, reduce beacon frequency, and require encrypted transport for any retained background traffic.",
            )
        )

    inbound_groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row["direction"] == "inbound" and int(row["dst_port"]) in ATTACK_SURFACE_PORTS:
            inbound_groups[str(row["device_name"])].append(row)

    for device_name, grouped_rows in inbound_groups.items():
        first_row = min(grouped_rows, key=lambda row: row["timestamp"])
        ports = sorted({int(row["dst_port"]) for row in grouped_rows})
        source_ips = sorted({str(row["src_ip"]) for row in grouped_rows})
        alerts.append(
            _alert(
                subject=device_name,
                category="attack_surface_indicator",
                severity="critical",
                timestamp=str(first_row["timestamp"]),
                explanation=f"Synthetic inbound probe targeted management port(s) {ports} from {', '.join(source_ips)}.",
                value_snippet=_snippet(first_row),
                recommendation="Restrict externally reachable management interfaces, require strong authentication, and block unsolicited inbound access.",
            )
        )

    alerts.sort(
        key=lambda alert: (
            -SEVERITY_WEIGHTS[str(alert["severity"])],
            str(alert["timestamp"]),
            str(alert["category"]),
        )
    )
    return alerts


def build_protocol_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, bool], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["protocol"]), _as_bool(row["tls_present"]))].append(row)

    summary = []
    for (protocol, tls_present), grouped_rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0][0], item[0][1])):
        summary.append(
            {
                "protocol": protocol,
                "tls_present": tls_present,
                "session_count": len(grouped_rows),
                "packet_count_total": sum(int(row["packet_count"]) for row in grouped_rows),
                "byte_count_total": sum(int(row["byte_count"]) for row in grouped_rows),
                "unique_devices": len({str(row["device_name"]) for row in grouped_rows}),
                "top_hostnames": ", ".join([name for name, _ in Counter(str(row["hostname"]) for row in grouped_rows if str(row["hostname"]).strip()).most_common(3)]),
            }
        )
    return summary


def build_port_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[int, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[int(row["dst_port"])].append(row)

    summary = []
    for dst_port, grouped_rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        summary.append(
            {
                "dst_port": dst_port,
                "session_count": len(grouped_rows),
                "byte_count_total": sum(int(row["byte_count"]) for row in grouped_rows),
                "unique_devices": len({str(row["device_name"]) for row in grouped_rows}),
                "protocols": ", ".join([name for name, _ in Counter(str(row["protocol"]) for row in grouped_rows).most_common(3)]),
                "tls_session_count": sum(1 for row in grouped_rows if _as_bool(row["tls_present"])),
                "insecure_session_count": sum(1 for row in grouped_rows if not _as_bool(row["tls_present"])),
                "example_destinations": ", ".join([name for name, _ in Counter(str(row["hostname"] or row["dst_ip"]) for row in grouped_rows).most_common(3)]),
            }
        )
    return summary


def build_destination_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    profiles = _profile_lookup()
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        destination = str(row["hostname"]).strip() or str(row["dst_ip"])
        grouped[destination].append(row)

    summary = []
    for destination, grouped_rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        summary.append(
            {
                "destination": destination,
                "session_count": len(grouped_rows),
                "unique_devices": len({str(row["device_name"]) for row in grouped_rows}),
                "third_party_destination": any(_is_third_party(row, profiles) for row in grouped_rows),
                "non_tls_sessions": sum(1 for row in grouped_rows if not _as_bool(row["tls_present"])),
                "protocols": ", ".join([name for name, _ in Counter(str(row["protocol"]) for row in grouped_rows).most_common(3)]),
                "byte_count_total": sum(int(row["byte_count"]) for row in grouped_rows),
                "first_seen": min(str(row["timestamp"]) for row in grouped_rows),
                "last_seen": max(str(row["timestamp"]) for row in grouped_rows),
            }
        )
    return summary


def build_findings_per_device(rows: list[dict[str, object]], alerts: list[dict[str, str]]) -> list[dict[str, object]]:
    profiles = _profile_lookup()
    alerts_by_device: dict[str, list[dict[str, str]]] = defaultdict(list)
    for alert in alerts:
        subject = str(alert["subject"])
        for device_name in profiles:
            if device_name in subject:
                alerts_by_device[device_name].append(alert)

    session_counts = Counter(str(row["device_name"]) for row in rows)
    byte_counts = Counter()
    protocol_counts: dict[str, Counter[str]] = defaultdict(Counter)
    port_counts: dict[str, Counter[int]] = defaultdict(Counter)
    for row in rows:
        device_name = str(row["device_name"])
        byte_counts[device_name] += int(row["byte_count"])
        protocol_counts[device_name][str(row["protocol"])] += 1
        port_counts[device_name][int(row["dst_port"])] += 1

    findings = []
    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    for profile in DEVICE_PROFILES:
        device_name = str(profile["device_name"])
        device_alerts = alerts_by_device.get(device_name, [])
        category_counts = Counter(str(alert["category"]) for alert in device_alerts)
        highest = "none"
        if device_alerts:
            highest = max(device_alerts, key=lambda alert: severity_rank[str(alert["severity"])])["severity"]
        risk_score = min(
            100,
            category_counts["plaintext_identifier_exposure"] * 14
            + category_counts["attack_surface_indicator"] * 18
            + category_counts["weak_transport"] * 12
            + category_counts["suspicious_port"] * 10
            + category_counts["third_party_destination"] * 8
            + category_counts["background_communication"] * 8
            + category_counts["mixed_transport"] * 6
            + category_counts["plaintext_http_observed"] * 6
            + category_counts["hostname_exposure"] * 4,
        )
        findings.append(
            {
                "device_name": device_name,
                "device_type": profile["device_type"],
                "scenario_role": profile["scenario_role"],
                "session_count": session_counts[device_name],
                "byte_count_total": byte_counts[device_name],
                "alert_count": len(device_alerts),
                "overall_risk_score": risk_score,
                "highest_severity": highest,
                "plaintext_identifier_exposure_count": category_counts["plaintext_identifier_exposure"],
                "plaintext_http_observed_count": category_counts["plaintext_http_observed"],
                "third_party_destination_count": category_counts["third_party_destination"],
                "mixed_transport_observed": "yes" if category_counts["mixed_transport"] else "no",
                "weak_transport_observed": "yes" if category_counts["weak_transport"] else "no",
                "suspicious_port_count": category_counts["suspicious_port"],
                "background_pattern_observed": "yes" if category_counts["background_communication"] else "no",
                "attack_surface_indicator_count": category_counts["attack_surface_indicator"],
                "top_protocols": ", ".join([name for name, _ in protocol_counts[device_name].most_common(3)]),
                "top_dst_ports": ", ".join([str(port) for port, _ in port_counts[device_name].most_common(3)]),
                "notes": str(profile["controlled_focus"]),
            }
        )

    findings.sort(key=lambda row: (-int(row["overall_risk_score"]), str(row["device_name"])))
    return findings


def build_compliance_flags(alerts: list[dict[str, str]]) -> list[dict[str, str]]:
    category_counts = Counter(str(alert["category"]) for alert in alerts)

    def status_row(flag_name: str, status: str, explanation: str) -> dict[str, str]:
        return {"flag_name": flag_name, "status": status, "explanation": explanation}

    rows = []

    if category_counts["plaintext_identifier_exposure"]:
        rows.append(
            status_row(
                "GDPR_Art32a_flag",
                "FAIL",
                "Plaintext identifiers were observed in synthetic traffic, indicating inadequate confidentiality protection for personal data in transit.",
            )
        )
    elif category_counts["mixed_transport"] or category_counts["third_party_destination"]:
        rows.append(
            status_row(
                "GDPR_Art32a_flag",
                "WARN",
                "Mixed or externally shared transport was observed even though direct plaintext personal-data exposure was not detected.",
            )
        )
    else:
        rows.append(status_row("GDPR_Art32a_flag", "PASS", "No plaintext personal-data exposure indicators were observed."))

    if category_counts["plaintext_http_observed"] or category_counts["weak_transport"]:
        rows.append(
            status_row(
                "ENISA_GP_TM_50_flag",
                "FAIL",
                "Application traffic used plaintext HTTP or legacy TLS, indicating weak technical transport protection in this controlled scenario.",
            )
        )
    elif category_counts["mixed_transport"]:
        rows.append(
            status_row(
                "ENISA_GP_TM_50_flag",
                "WARN",
                "Transport protections were inconsistent across application sessions.",
            )
        )
    else:
        rows.append(status_row("ENISA_GP_TM_50_flag", "PASS", "Observed application transport used consistent modern encryption."))

    if category_counts["background_communication"] and category_counts["third_party_destination"]:
        rows.append(
            status_row(
                "ENISA_GP_OP_04_flag",
                "FAIL",
                "Recurring background communications reached non-approved external destinations, suggesting weak control over ongoing outbound operational traffic.",
            )
        )
    elif category_counts["third_party_destination"] or category_counts["mixed_transport"]:
        rows.append(
            status_row(
                "ENISA_GP_OP_04_flag",
                "WARN",
                "External communication patterns indicate operational review is warranted even though a persistent beacon was not dominant.",
            )
        )
    else:
        rows.append(status_row("ENISA_GP_OP_04_flag", "PASS", "No concerning recurring external operational traffic patterns were detected."))

    if category_counts["attack_surface_indicator"] or category_counts["suspicious_port"]:
        rows.append(
            status_row(
                "CRA_attack_surface_flag",
                "FAIL",
                "Inbound management targeting or suspicious service exposure increased the synthetic device attack surface.",
            )
        )
    elif category_counts["third_party_destination"]:
        rows.append(
            status_row(
                "CRA_attack_surface_flag",
                "WARN",
                "Additional external integrations were present and should be reviewed for necessity and hardening.",
            )
        )
    else:
        rows.append(status_row("CRA_attack_surface_flag", "PASS", "No clear attack-surface expansion indicators were observed."))

    return rows


def build_report_context(
    rows: list[dict[str, object]],
    alerts: list[dict[str, str]],
    compliance_flags: list[dict[str, str]],
) -> dict[str, object]:
    profiles = _profile_lookup()
    category_counts = Counter(str(alert["category"]) for alert in alerts)
    status_counts = Counter(str(flag["status"]) for flag in compliance_flags)
    high_or_critical = sum(1 for alert in alerts if str(alert["severity"]) in {"high", "critical"})
    overall_risk_score = min(
        100,
        10 * status_counts["FAIL"]
        + 4 * status_counts["WARN"]
        + 3 * high_or_critical
        + 2 * len(category_counts)
        + (1 if category_counts["plaintext_identifier_exposure"] else 0),
    )

    plaintext_rows = []
    contextual_hosts = set()
    third_party_domains = set()
    suspicious_ports = set()
    weak_tls_targets = set()
    inbound_ports = set()
    insecure_urls = set()
    plaintext_ports = set()

    for row in rows:
        hostname = str(row["hostname"])
        if not _as_bool(row["tls_present"]) and str(row["protocol"]) == "HTTP" and str(row["url"]).strip():
            insecure_urls.add(str(row["url"]))
        if row["direction"] == "outbound" and not _as_bool(row["tls_present"]) and str(row["protocol"]) in APP_PROTOCOLS:
            plaintext_ports.add(int(row["dst_port"]))
        if any(term in hostname.lower() for term in CONTEXTUAL_HOSTNAME_TERMS):
            contextual_hosts.add(hostname)
        if _is_third_party(row, profiles):
            third_party_domains.add(_base_domain(hostname))
        if int(row["dst_port"]) in SUSPICIOUS_PORTS:
            suspicious_ports.add(int(row["dst_port"]))
        if str(row["tls_version"]) in LEGACY_TLS_VERSIONS:
            weak_tls_targets.add(hostname)
        if row["direction"] == "inbound":
            inbound_ports.add(int(row["dst_port"]))
        if row["direction"] == "outbound" and not _as_bool(row["tls_present"]):
            text = " ".join(str(row[field]) for field in ("hostname", "url", "payload_preview"))
            if any(pattern.search(text) for pattern in SENSITIVE_PATTERNS.values()):
                plaintext_rows.append(row)

    plaintext_devices = sorted({str(row["device_name"]) for row in plaintext_rows})
    device_count = len({str(row["device_name"]) for row in rows})

    major_findings = [
        f"{len(alerts)} alert records were generated across {len(category_counts)} categories for {device_count} synthetic device profiles.",
        f"{len(plaintext_rows)} non-TLS sessions carried email, phone, token, or device identifiers.",
        f"{len(third_party_domains)} third-party base domain(s) were contacted outside approved device domains.",
        f"{len(inbound_ports)} inbound management/service port(s) were targeted in the gateway scenario.",
    ]

    return {
        "overall_risk_score": overall_risk_score,
        "major_findings": major_findings,
        "category_counts": dict(category_counts),
        "plaintext_session_count": len(plaintext_rows),
        "plaintext_devices": plaintext_devices,
        "contextual_hosts": sorted(contextual_hosts),
        "third_party_domains": sorted(third_party_domains),
        "suspicious_ports": sorted(suspicious_ports),
        "plaintext_ports": sorted(plaintext_ports),
        "weak_tls_targets": sorted(weak_tls_targets),
        "inbound_ports": sorted(inbound_ports),
        "insecure_urls": sorted(insecure_urls),
    }
