# Real PCAP Validation Workflow

This folder is a standalone real-data validation branch built around the single capture file:

- `SamsungCamera_00166cab6b88.pcap`

This branch is the real packet-capture validation branch. It complements the synthetic / starter branch rather than replacing it: the synthetic branch remains the stronger place for controlled attack simulation, while this branch is strongest for defensible real-traffic evidence.

The workflow does not start from aggregate CSVs or synthetic starter outputs. It parses the PCAP directly, extracts packet-level and session-level evidence, and then produces alerts, compliance-style flags, report-ready tables, and figures.

## Project Structure

- `src/analyze_pcap.py`: end-to-end extraction and analysis pipeline
- `outputs/intermediate/packets_extracted.csv`: packet-level extracted fields
- `outputs/intermediate/sessions_extracted.csv`: report-ready session / flow windows
- `outputs/tables/alerts.csv`: evidence-backed alerts
- `outputs/tables/compliance_flags.csv`: compliance-style heuristic flags
- `outputs/tables/findings_per_device.csv`: device-level rollup for the observed camera
- `outputs/tables/protocol_summary.csv`: protocol distribution and transport class summary
- `outputs/tables/port_summary.csv`: concrete destination-port summary
- `outputs/tables/destination_summary.csv`: destination diversity and third-party summary
- `outputs/tables/*_top10.csv` and `*_top15.csv`: report-friendly filtered tables
- `outputs/figures/*.png`: report-ready charts
- `outputs/summary.md`: concise report-ready narrative
- `outputs/method_notes.md`: pipeline and evidence-method notes

## Pipeline

The implemented workflow is:

`pcap -> packet-level extraction -> session/flow-level extraction -> evidence detection -> alerts -> compliance-style flags -> report-ready outputs`

The extractor uses Scapy for packet parsing and manual TLS handshake parsing for packet-level certificate / SNI evidence when present inside observed TLS records.

## What Gets Extracted

`packets_extracted.csv` includes packet fields such as:

- frame metadata
- Ethernet and IP endpoints
- TCP / UDP ports
- DNS query / answer data when present
- HTTP / SSDP request metadata when plaintext is visible
- TLS version, SNI, and certificate subject / issuer when directly observable in packet payloads
- a safe truncated plaintext payload preview when the payload is sufficiently readable

`sessions_extracted.csv` includes:

- start and end time
- report-ready client/service endpoint tuple
- dominant application protocol per session window
- packet and byte counts
- observed hostname / domain hints
- secure / insecure / unknown transport class

## Evidence Categories

The workflow analyzes the real capture for:

- plaintext identifier exposure
- URL / hostname / payload visibility
- protocol and destination-port behavior
- TLS / encryption evidence
- third-party communication and attack-surface indicators
- background communication patterns

All findings are evidence-linked. If a field or evidence type is not present in the PCAP, the generated outputs record `not observed` rather than inventing certainty.

## How To Run

Create a virtual environment, install the requirements, and run the analyzer from this folder:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python3 src/analyze_pcap.py
```

Optional fast validation mode:

```bash
PCAP_PACKET_LIMIT=5000 .venv/bin/python3 src/analyze_pcap.py
```

That optional limit is only for local testing. By default, the script processes the full PCAP and overwrites the report artifacts in `outputs/`.

## Notes

- The capture is large, so the full run may take several minutes.
- TLS evidence is packet-level only; the workflow does not decrypt traffic.
- Compliance-style flags in this branch are heuristic reporting aids, not formal legal or certification conclusions.
- This branch is strongest for real protocol, port, transport, hostname / endpoint, and third-party communication evidence.
- It should not be over-claimed as strong personal-PII proof if the PCAP does not directly contain that evidence.
