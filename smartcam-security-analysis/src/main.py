from __future__ import annotations

import csv
from pathlib import Path

from src.analysis import (
    build_compliance_flags,
    build_destination_summary,
    build_findings_per_device,
    build_port_summary,
    build_protocol_summary,
    build_report_context,
    detect_alerts,
)
from src.constants import DATA_DIR, FIGURES_DIR, OUTPUTS_DIR, ROOT_DIR, TABLES_DIR
from src.reporting import (
    build_coursework_mapping_markdown,
    build_method_notes_markdown,
    build_summary_markdown,
    save_alert_categories_chart,
    save_destination_diversity_chart,
    save_protocol_and_port_chart,
    save_risk_by_subject_chart,
    save_traffic_volume_chart,
)
from src.synthetic_data import generate_synthetic_sessions


def _ensure_directories() -> None:
    for directory in (DATA_DIR, OUTPUTS_DIR, FIGURES_DIR, TABLES_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def _write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    final_fieldnames = fieldnames or list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=final_fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    _ensure_directories()

    sessions, device_profiles = generate_synthetic_sessions()
    alerts = detect_alerts(sessions)
    compliance_flags = build_compliance_flags(alerts)
    findings_per_device = build_findings_per_device(sessions, alerts)
    protocol_summary = build_protocol_summary(sessions)
    port_summary = build_port_summary(sessions)
    destination_summary = build_destination_summary(sessions)
    report_context = build_report_context(sessions, alerts, compliance_flags)

    _write_csv(DATA_DIR / "synthetic_sessions.csv", sessions)
    _write_csv(DATA_DIR / "device_profiles.csv", device_profiles)
    _write_csv(TABLES_DIR / "alerts.csv", alerts)
    _write_csv(TABLES_DIR / "compliance_flags.csv", compliance_flags)
    _write_csv(TABLES_DIR / "findings_per_device.csv", findings_per_device)
    _write_csv(TABLES_DIR / "protocol_summary.csv", protocol_summary)
    _write_csv(TABLES_DIR / "port_summary.csv", port_summary)
    _write_csv(TABLES_DIR / "destination_summary.csv", destination_summary)

    _write_text(OUTPUTS_DIR / "summary.md", build_summary_markdown(report_context))
    _write_text(OUTPUTS_DIR / "coursework_mapping.md", build_coursework_mapping_markdown())
    _write_text(OUTPUTS_DIR / "method_notes.md", build_method_notes_markdown())

    save_alert_categories_chart(alerts, FIGURES_DIR / "alert_categories.png")
    save_protocol_and_port_chart(sessions, FIGURES_DIR / "protocol_and_port_behavior.png")
    save_destination_diversity_chart(sessions, FIGURES_DIR / "destination_diversity.png")
    save_risk_by_subject_chart(findings_per_device, FIGURES_DIR / "risk_by_subject.png")
    save_traffic_volume_chart(sessions, FIGURES_DIR / "traffic_volume_over_time.png")

    generated_paths = [
        DATA_DIR / "synthetic_sessions.csv",
        DATA_DIR / "device_profiles.csv",
        TABLES_DIR / "alerts.csv",
        TABLES_DIR / "compliance_flags.csv",
        TABLES_DIR / "findings_per_device.csv",
        TABLES_DIR / "protocol_summary.csv",
        TABLES_DIR / "port_summary.csv",
        TABLES_DIR / "destination_summary.csv",
        OUTPUTS_DIR / "summary.md",
        OUTPUTS_DIR / "coursework_mapping.md",
        OUTPUTS_DIR / "method_notes.md",
        FIGURES_DIR / "alert_categories.png",
        FIGURES_DIR / "protocol_and_port_behavior.png",
        FIGURES_DIR / "destination_diversity.png",
        FIGURES_DIR / "risk_by_subject.png",
        FIGURES_DIR / "traffic_volume_over_time.png",
    ]

    print("Synthetic security/privacy workflow completed.")
    for path in generated_paths:
        print(f"- {path.relative_to(ROOT_DIR)}")


if __name__ == "__main__":
    main()
