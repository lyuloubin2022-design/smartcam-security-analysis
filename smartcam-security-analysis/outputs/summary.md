# Synthetic Security and Privacy Summary

This output is based on synthetic, controlled session records designed to demonstrate detector capability rather than validate live packet captures.

## Overall Risk Score

92/100 (High)

## Major Findings

- 20 alert records were generated across 9 categories for 3 synthetic device profiles.
- 5 non-TLS sessions carried email, phone, token, or device identifiers.
- 4 third-party base domain(s) were contacted outside approved device domains.
- 1 inbound management/service port(s) were targeted in the gateway scenario.

## Directly Observed Evidence

- Plaintext PII result: 5 non-TLS session(s) exposed email, phone, token, or device identifiers across cam_livingroom, hub_gateway, plug_kitchen.
- URL / hostname / payload findings: insecure URLs included http://diag.vendorvideo.example/upload?device_id=CAM-A19F-7781, http://family-room-cam.vendorvideo.example/status?device_id=CAM-A19F-7781; contextual hostname exposure included family-room-cam.vendorvideo.example.
- Protocol / port findings: plaintext application traffic was observed on port(s) 80, 2323, 8080, with suspicious destination port(s) 2323.
- TLS / encryption findings: legacy transport targets included legacy-backup.smarthub.example, and mixed secure/insecure application transport was observed across the synthetic device set.
- Third-party / attack surface findings: third-party destinations included ads-insight.example, analytics-partner.example, partnercloud.example, remoteassist.example; inbound management targeting hit port(s) 8443.

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
