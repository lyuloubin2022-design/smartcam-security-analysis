from __future__ import annotations

import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", str(Path(__file__).resolve().parents[1] / ".mplcache"))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

from src.constants import DEVICE_PROFILES


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _palette(length: int) -> list[str]:
    colors = ["#2f5d62", "#c15b3d", "#5f8d4e", "#9a6fb0", "#d79922", "#4c78a8", "#b23a48", "#7f7f7f"]
    return [colors[index % len(colors)] for index in range(length)]


def save_alert_categories_chart(alerts: list[dict[str, str]], output_path: Path) -> None:
    counts = Counter(str(alert["category"]) for alert in alerts)
    ordered = counts.most_common()
    labels = [label for label, _ in ordered]
    values = [counts[label] for label in labels]

    plt.style.use("seaborn-v0_8-whitegrid")
    fig, ax = plt.subplots(figsize=(10, 5.5))
    bars = ax.bar(labels, values, color=_palette(len(labels)))
    ax.set_title("Synthetic Alert Categories by Count")
    ax.set_ylabel("Generated alert count")
    ax.set_xlabel("Alert category")
    ax.tick_params(axis="x", rotation=30)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 0.05, str(value), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def save_protocol_and_port_chart(rows: list[dict[str, object]], output_path: Path) -> None:
    protocol_bytes: dict[str, int] = defaultdict(int)
    top_ports = Counter()
    for row in rows:
        protocol_label = f"{row['protocol']} ({'TLS' if row['tls_present'] else 'plain'})"
        protocol_bytes[protocol_label] += int(row["byte_count"])
        top_ports[int(row["dst_port"])] += 1

    protocol_items = sorted(protocol_bytes.items(), key=lambda item: item[1], reverse=True)[:6]
    port_items = top_ports.most_common(6)

    plt.style.use("seaborn-v0_8-whitegrid")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5.5))

    ax1.barh([label for label, _ in protocol_items], [value for _, value in protocol_items], color="#4c78a8")
    ax1.set_title("Traffic Volume by Protocol and TLS State")
    ax1.set_xlabel("Total bytes")
    ax1.set_ylabel("Protocol / TLS state")

    ax2.bar([str(port) for port, _ in port_items], [count for _, count in port_items], color="#c15b3d")
    ax2.set_title("Most Active Destination Ports")
    ax2.set_ylabel("Session count")
    ax2.set_xlabel("Destination port")

    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def save_destination_diversity_chart(rows: list[dict[str, object]], output_path: Path) -> None:
    approved_domains = {
        str(profile["device_name"]): [str(domain) for domain in profile["approved_domains"]]
        for profile in DEVICE_PROFILES
    }

    approved_counts: dict[str, set[str]] = defaultdict(set)
    third_party_counts: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        if row["direction"] != "outbound":
            continue
        device_name = str(row["device_name"])
        hostname = str(row["hostname"]).strip()
        if not hostname:
            continue
        if any(hostname.endswith(domain) for domain in approved_domains[device_name]):
            approved_counts[device_name].add(hostname)
        else:
            third_party_counts[device_name].add(hostname)

    devices = [str(profile["device_name"]) for profile in DEVICE_PROFILES]
    approved_values = [len(approved_counts[device]) for device in devices]
    third_party_values = [len(third_party_counts[device]) for device in devices]

    plt.style.use("seaborn-v0_8-whitegrid")
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.bar(devices, approved_values, label="Approved destinations", color="#5f8d4e")
    ax.bar(devices, third_party_values, bottom=approved_values, label="Third-party destinations", color="#d79922")
    ax.set_title("Destination Diversity by Synthetic Subject")
    ax.set_ylabel("Unique destination hostnames")
    ax.set_xlabel("Synthetic subject")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def save_traffic_volume_chart(rows: list[dict[str, object]], output_path: Path) -> None:
    volume_by_hour: dict[str, dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
    insecure_by_hour: dict[datetime, int] = defaultdict(int)

    for row in rows:
        hour_bucket = _parse_timestamp(str(row["timestamp"])).replace(minute=0, second=0, microsecond=0)
        device_name = str(row["device_name"])
        volume_by_hour[device_name][hour_bucket] += int(row["byte_count"])
        if not row["tls_present"]:
            insecure_by_hour[hour_bucket] += int(row["byte_count"])

    all_hours = sorted({hour for device_data in volume_by_hour.values() for hour in device_data})
    devices = [str(profile["device_name"]) for profile in DEVICE_PROFILES]

    plt.style.use("seaborn-v0_8-whitegrid")
    fig, ax = plt.subplots(figsize=(12, 5.5))

    for device_name, color in zip(devices, ["#2f5d62", "#c15b3d", "#4c78a8"]):
        values = [volume_by_hour[device_name].get(hour, 0) for hour in all_hours]
        ax.plot(all_hours, values, marker="o", linewidth=2, markersize=4, label=device_name, color=color)

    insecure_values = [insecure_by_hour.get(hour, 0) for hour in all_hours]
    ax.fill_between(all_hours, insecure_values, color="#d79922", alpha=0.22, label="Non-TLS volume")

    ax.set_title("Traffic Volume Over Time by Synthetic Subject")
    ax.set_ylabel("Byte count per hour")
    ax.set_xlabel("Time bucket (hour)")
    ax.legend(frameon=False, ncol=2)
    fig.autofmt_xdate(rotation=25)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def save_risk_by_subject_chart(findings: list[dict[str, object]], output_path: Path) -> None:
    ordered = sorted(findings, key=lambda row: (-int(row["overall_risk_score"]), str(row["device_name"])))
    subjects = [str(row["device_name"]) for row in ordered]
    scores = [int(row["overall_risk_score"]) for row in ordered]

    def score_color(score: int) -> str:
        if score >= 75:
            return "#b23a48"
        if score >= 50:
            return "#d79922"
        return "#5f8d4e"

    plt.style.use("seaborn-v0_8-whitegrid")
    fig, ax = plt.subplots(figsize=(10, 4.8))
    bars = ax.barh(subjects, scores, color=[score_color(score) for score in scores], height=0.6)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_title("Overall Risk Score by Synthetic Subject")
    ax.set_xlabel("Overall risk score (0-100)")
    ax.set_ylabel("Synthetic subject")

    for bar, score in zip(bars, scores):
        ax.text(min(score + 2, 98), bar.get_y() + bar.get_height() / 2, str(score), va="center", ha="left", fontsize=10)

    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def build_summary_markdown(context: dict[str, object]) -> str:
    overall_risk_score = int(context["overall_risk_score"])
    risk_band = "High" if overall_risk_score >= 75 else "Moderate" if overall_risk_score >= 45 else "Low"
    plaintext_devices = ", ".join(context["plaintext_devices"]) or "none"
    contextual_hosts = ", ".join(context["contextual_hosts"][:3]) or "none observed"
    insecure_urls = ", ".join(context["insecure_urls"][:2]) or "none observed"
    plaintext_ports = ", ".join(str(port) for port in context["plaintext_ports"]) or "none observed"
    suspicious_ports = ", ".join(str(port) for port in context["suspicious_ports"]) or "none observed"
    weak_tls_targets = ", ".join(context["weak_tls_targets"][:2]) or "none observed"
    third_party_domains = ", ".join(context["third_party_domains"][:4]) or "none observed"
    inbound_ports = ", ".join(str(port) for port in context["inbound_ports"]) or "none observed"
    major_findings_lines = "\n".join(f"- {finding}" for finding in context["major_findings"])

    return f"""# Synthetic Security and Privacy Summary

This output is based on synthetic, controlled session records designed to demonstrate detector capability rather than validate live packet captures.

## Overall Risk Score

{overall_risk_score}/100 ({risk_band})

## Major Findings

{major_findings_lines}

## Directly Observed Evidence

- Plaintext PII result: {context['plaintext_session_count']} non-TLS session(s) exposed email, phone, token, or device identifiers across {plaintext_devices}.
- URL / hostname / payload findings: insecure URLs included {insecure_urls}; contextual hostname exposure included {contextual_hosts}.
- Protocol / port findings: plaintext application traffic was observed on port(s) {plaintext_ports}, with suspicious destination port(s) {suspicious_ports}.
- TLS / encryption findings: legacy transport targets included {weak_tls_targets}, and mixed secure/insecure application transport was observed across the synthetic device set.
- Third-party / attack surface findings: third-party destinations included {third_party_domains}; inbound management targeting hit port(s) {inbound_ports}.

## Inferred Risk

- The observed combination of plaintext identifiers, inconsistent transport, recurring background beaconing, and third-party communications would increase privacy leakage risk in a real deployment.
- Legacy TLS and suspicious management exposure suggest weaker resilience against interception, unauthorized access, or remote service misuse.

## Mitigations

- Enforce HTTPS or modern TLS-only application transport for diagnostics, control, and telemetry.
- Remove tokens, contact details, and device identifiers from URLs and plaintext payloads.
- Disable unnecessary support tunnels and restrict management services behind allowlists and strong authentication.
- Review and minimize third-party telemetry destinations, especially recurring background beacons.

## Suggested Report Usage

- CW1 strongest evidence: quote `alerts.csv` rows for plaintext identifier exposure, plaintext HTTP on ports 80 and 8080, and legacy TLS 1.0 backup traffic as controlled attack examples.
- CW2 strongest evidence: use `summary.md`, `compliance_flags.csv`, `findings_per_device.csv`, and `risk_by_subject.png` to show automated assessment, mitigation suggestions, and per-subject risk scoring.
- Scope note: this branch is synthetic and controlled, so it should be presented as detector-capability evidence rather than real packet-capture validation.

## Limitations

- The dataset is synthetic and intentionally controlled; it is not derived from a real packet capture.
- Payloads are preview strings rather than raw packet bodies or reconstructed full sessions.
- Alerting and compliance-style flags are heuristic outputs for reporting and detector demonstrations, not legal, regulatory, or certification determinations.
"""


def build_coursework_mapping_markdown() -> str:
    return """# Coursework Mapping

This branch is a synthetic starter/prototype branch. Use it as controlled detector-capability evidence, not as the real-data validation branch.

| Coursework usage | Strongest starter outputs | Report use |
| --- | --- | --- |
| CW1 Attack 1 | `outputs/tables/alerts.csv`, `outputs/summary.md` | Quote `plaintext_identifier_exposure`, `weak_transport`, and `plaintext_http_observed` alerts as controlled positive attack evidence. |
| CW1 Attack 2 | `outputs/tables/alerts.csv`, `outputs/figures/destination_diversity.png`, `outputs/figures/traffic_volume_over_time.png` | Use `third_party_destination`, `background_communication`, and `attack_surface_indicator` outputs to show external communications and attack-surface indicators. |
| CW2 Defense | `outputs/summary.md`, `outputs/tables/compliance_flags.csv`, `outputs/tables/findings_per_device.csv`, `outputs/figures/risk_by_subject.png` | Use these outputs to show mitigation suggestions, compliance-style assessment, and automated overall risk scoring. |
"""


def build_method_notes_markdown() -> str:
    return """# Method Notes

## Scope

This starter project was built from scratch as a standalone synthetic workflow. It does not rely on prior project folders, hidden assets, or legacy `uk_tot_*.csv` inputs.

## Synthetic Scenario Design

- `cam_livingroom` models a camera-like device with secure heartbeat traffic plus an insecure diagnostic upload and a contextual hostname example.
- `plug_kitchen` models a smart plug / light controller with secure MQTT control plus periodic non-TLS third-party beaconing.
- `hub_gateway` models a gateway/controller with secure orchestration traffic, legacy TLS backup behavior, a suspicious support tunnel, and inbound management probes.

## Data Model

Each synthetic session record includes timestamps, source and destination addressing, protocol labels, ports, URLs, hostnames, payload previews, TLS indicators, packet counts, byte counts, direction, and a `scenario_label` to show which controlled behavior generated the record.

## Detection Approach

- Plaintext identifier exposure is detected by regex matching email, phone, token, and device identifier patterns in non-TLS URLs and payload previews.
- Plaintext HTTP, suspicious ports, weak TLS, and inbound management activity are derived directly from transport and port fields.
- Third-party destinations are identified by comparing observed hostnames against per-device approved domain sets.
- Background communication is flagged when repeated sessions to the same destination occur on a regular cadence and use third-party or insecure transport.
- Mixed transport is flagged when the same device uses both secure and insecure application-layer sessions.

## Compliance-Style Mapping

The generated flags for `GDPR_Art32a_flag`, `ENISA_GP_TM_50_flag`, `ENISA_GP_OP_04_flag`, and `CRA_attack_surface_flag` are internal heuristic mappings intended to support reporting-style discussions. They are not legal advice and do not represent formal conformity assessment.

## Limitations

- No packet reassembly, TLS handshake validation, or deep protocol decoding is performed.
- Session records are generated deterministically for repeatable demonstrations.
- Findings should be interpreted as detector-capability evidence under controlled positive conditions, not as production validation against real traffic.
"""
