# Method Notes

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
