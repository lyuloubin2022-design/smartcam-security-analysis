# Synthetic Security & Privacy Workflow Starter

This project is a standalone, synthetic security-and-privacy analysis workflow built from scratch for controlled detector demonstrations. It does not depend on prior project folders, prior captures, or any legacy `uk_tot_*.csv` files.

The pipeline generates realistic packet/session-style records for three synthetic device profiles, then produces alerting, compliance-style flags, summary tables, charts, and report-ready markdown outputs.

## Branch Role

- This branch is synthetic/starter only.
- It should be used in the report as controlled prototype evidence for detector capability and automated assessment.
- It is not the real-data validation branch.

## Device Profiles

- `cam_livingroom`: camera-like device with secure heartbeat traffic plus controlled plaintext diagnostic leakage.
- `plug_kitchen`: smart plug / light controller with secure MQTT control and periodic third-party background beaconing.
- `hub_gateway`: hub / controller / gateway with legacy backup transport, a suspicious remote-support tunnel, and inbound management probes.

## Project Layout

```text
src/
data/generated/
outputs/figures/
outputs/tables/
README.md
requirements.txt
```

## Run

Install the single dependency and execute the entry point:

```bash
python3 -m pip install -r requirements.txt
python3 -m src.main
```

## Generated Artifacts

The run writes:

- `data/generated/synthetic_sessions.csv`
- `data/generated/device_profiles.csv`
- `outputs/tables/alerts.csv`
- `outputs/tables/compliance_flags.csv`
- `outputs/tables/findings_per_device.csv`
- `outputs/tables/protocol_summary.csv`
- `outputs/tables/port_summary.csv`
- `outputs/tables/destination_summary.csv`
- `outputs/summary.md`
- `outputs/coursework_mapping.md`
- `outputs/method_notes.md`
- `outputs/figures/alert_categories.png`
- `outputs/figures/protocol_and_port_behavior.png`
- `outputs/figures/destination_diversity.png`
- `outputs/figures/risk_by_subject.png`
- `outputs/figures/traffic_volume_over_time.png`

## Notes

- All evidence is synthetic and intentionally controlled.
- The workflow is designed for detector-capability illustration and controlled prototype evidence, not real packet-capture validation.
- Compliance flags are heuristic and report-oriented, not legal or certification determinations.
