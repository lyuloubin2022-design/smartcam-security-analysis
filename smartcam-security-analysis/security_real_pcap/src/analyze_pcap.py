from __future__ import annotations

import csv
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from cryptography import x509
from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, PcapReader, Raw, TCP, UDP  # type: ignore

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_PATH = PROJECT_ROOT / "SamsungCamera_00166cab6b88.pcap"
OUTPUTS_DIR = PROJECT_ROOT / os.environ.get("ANALYSIS_OUTPUTS_DIR", "outputs")
INTERMEDIATE_DIR = OUTPUTS_DIR / "intermediate"
FIGURES_DIR = OUTPUTS_DIR / "figures"
TABLES_DIR = OUTPUTS_DIR / "tables"
PACKET_LIMIT = int(os.environ.get("PCAP_PACKET_LIMIT", "0") or "0")

MPLCONFIG_DIR = INTERMEDIATE_DIR / ".mplconfig"
MPLCONFIG_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPLCONFIG_DIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

PACKET_FIELDS = [
    "frame_number",
    "timestamp",
    "frame_len",
    "frame_protocols",
    "eth_src",
    "eth_dst",
    "ip_src",
    "ip_dst",
    "tcp_srcport",
    "tcp_dstport",
    "udp_srcport",
    "udp_dstport",
    "protocol",
    "dns_qry_name",
    "dns_resp_name",
    "dns_a",
    "http_method",
    "http_host",
    "http_request_uri",
    "http_full_url",
    "tls_version",
    "tls_sni",
    "tls_cert_subject",
    "tls_cert_issuer",
    "payload_preview_ascii",
]

SESSION_FIELDS = [
    "start_time",
    "end_time",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_count",
    "byte_count",
    "hostname_or_domain",
    "transport_class",
]

TLS_VERSION_MAP = {
    (3, 0): "SSL 3.0",
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}

HTTP_METHODS = {
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "OPTIONS",
    "PATCH",
    "TRACE",
    "CONNECT",
    "NOTIFY",
    "M-SEARCH",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
}

COMMON_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    161,
    162,
    179,
    389,
    443,
    465,
    587,
    636,
    993,
    995,
    1900,
    3478,
    5222,
}

SEVERITY_SCORES = {"high": 16, "medium": 8, "low": 3, "info": 1}

EMAIL_REGEX = re.compile(
    r"(?i)(?:\b(?:email|e-?mail)\b\s*[:=]\s*|mailto:)"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)
PHONE_REGEX = re.compile(
    r"(?i)\b(?:phone|telephone|tel|mobile|cell)\b\s*[:=]\s*"
    r"(\+?\d[\d ()-]{6,}\d)"
)
MAC_REGEX = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
UUID_REGEX = re.compile(r"\buuid:[A-Za-z0-9._:-]{6,}\b", re.IGNORECASE)
DEVICE_ID_REGEX = re.compile(r"\b[A-Z0-9]{2,}(?:-[A-Z0-9]{2,}){2,}\b")
TOKEN_REGEX = re.compile(
    r"(?i)\b(?:token|access[_-]?token|sessionid|api[_-]?key|apikey)\b\s*[:=]\s*"
    r"([A-Za-z0-9._~+/=-]{8,})(?=$|[&\s])"
)
USERNAME_REGEX = re.compile(
    r"(?i)\b(?:username|login|userid)\b\s*[:=]\s*([A-Za-z0-9._@-]{2,40})(?=$|[&\s])"
)
FIELD_VALUE_REGEXES = [
    re.compile(
        r"(?i)\b(?:friendlyname|usn|udn|serialnumber|deviceid|device_id)\b\s*[:=]\s*"
        r"([A-Za-z0-9._:-]{4,120})"
    ),
    re.compile(
        r"(?i)<(?:friendlyname|udn|serialnumber|deviceid|device_id)>\s*([^<]{4,120})\s*</"
        r"(?:friendlyname|udn|serialnumber|deviceid|device_id)>"
    ),
]


@dataclass
class SessionState:
    start_ts: float
    end_ts: float
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    transport: str
    packet_count: int = 0
    byte_count: int = 0
    protocol_counter: Counter = field(default_factory=Counter)
    hostnames: set[str] = field(default_factory=set)
    transport_classes: Counter = field(default_factory=Counter)
    last_seen: float = 0.0
    seen_fin_or_rst: bool = False


def ensure_directories() -> None:
    for path in [INTERMEDIATE_DIR, FIGURES_DIR, TABLES_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def format_mac(raw: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(cleaned) != 12:
        return raw.lower()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).lower()


def device_mac_from_filename(path: Path) -> str:
    match = re.search(r"([0-9A-Fa-f]{12})", path.stem)
    return format_mac(match.group(1)) if match else ""


def to_iso(ts: float | int | Any) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def safe_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def is_ip_literal(value: str) -> bool:
    if not value:
        return False
    candidate = value.strip().strip("[]")
    try:
        ip_address(candidate)
        return True
    except ValueError:
        return False


def split_host_port(value: str) -> tuple[str, str]:
    cleaned = value.strip()
    if cleaned.startswith("[") and "]:" in cleaned:
        host, _, port = cleaned[1:].partition("]:")
        return host, port if port.isdigit() else ""
    if cleaned.count(":") == 1:
        host, port = cleaned.rsplit(":", 1)
        if port.isdigit():
            return host, port
    return cleaned, ""


def format_endpoint_label(ip_value: str, port_value: str | int | None = None) -> str:
    ip_text = safe_string(ip_value).strip()
    if not ip_text:
        return "not observed"
    label = f"[{ip_text}]" if ":" in ip_text and not ip_text.startswith("[") else ip_text
    if port_value in {None, "", "not observed"}:
        return label
    return f"{label}:{port_value}"


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def is_tls_record(data: bytes) -> bool:
    return len(data) >= 5 and data[0] in {20, 21, 22, 23} and data[1] == 3 and data[2] <= 4


def tls_version_name(major: int, minor: int) -> str:
    return TLS_VERSION_MAP.get((major, minor), f"TLS? {major}.{minor}")


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in {9, 10, 13})
    return printable / len(data)


def safe_payload_preview(data: bytes, limit: int = 160) -> str:
    if not data:
        return ""
    sample = data[:512]
    if printable_ratio(sample) < 0.65:
        return ""
    text = sample.decode("utf-8", errors="ignore")
    text = collapse_ws(text.replace("\x00", " "))
    return text[:limit]


def raw_text_for_detection(data: bytes) -> str:
    if not data:
        return ""
    text = data[:4096].decode("utf-8", errors="ignore").replace("\x00", " ")
    return text


def iter_dns_records(record: Any, expected_cls: type) -> Iterable[Any]:
    current = record
    while current is not None and isinstance(current, expected_cls):
        yield current
        payload = getattr(current, "payload", None)
        current = payload if isinstance(payload, expected_cls) else None


def endpoint_class(ip_value: str) -> str:
    if not ip_value:
        return "unknown"
    try:
        parsed = ip_address(ip_value)
    except ValueError:
        return "unknown"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_private:
        return "private"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    return "public"


def is_public_ip(ip_value: str) -> bool:
    return endpoint_class(ip_value) == "public"


def get_layer_names(packet: Any) -> list[str]:
    names: list[str] = []
    for layer in packet.layers():
        name = getattr(layer, "__name__", safe_string(layer))
        if name not in names:
            names.append(name)
    return names


def get_packet_timestamp(packet: Any) -> float:
    return float(packet.time)


def parse_http_fields(raw_bytes: bytes, src_port: str, dst_port: str) -> dict[str, str]:
    text = raw_text_for_detection(raw_bytes)
    header_block = text.split("\r\n\r\n", 1)[0]
    lines = [line for line in header_block.splitlines() if line.strip()]
    if not lines:
        return {
            "http_method": "",
            "http_host": "",
            "http_request_uri": "",
            "http_full_url": "",
            "http_location": "",
            "http_protocol": "",
            "http_kind": "",
        }

    first_line = lines[0].strip()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    method = ""
    host = headers.get("host", "")
    request_uri = ""
    full_url = ""
    location_url = headers.get("location", "") or headers.get("location".lower(), "")
    protocol = ""
    http_kind = ""

    if first_line.startswith("HTTP/1."):
        protocol = "HTTP"
        http_kind = "response"
    else:
        parts = first_line.split()
        if len(parts) >= 2 and parts[0].upper() in HTTP_METHODS:
            method = parts[0].upper()
            request_uri = parts[1]
            protocol = "HTTP"
            http_kind = "request"
        else:
            return {
                "http_method": "",
                "http_host": "",
                "http_request_uri": "",
                "http_full_url": "",
                "http_location": "",
                "http_protocol": "",
                "http_kind": "",
            }

    if dst_port == "1900" or src_port == "1900" or method in {"NOTIFY", "M-SEARCH"}:
        protocol = "SSDP"

    if host and request_uri and request_uri != "*":
        if request_uri.startswith("http://") or request_uri.startswith("https://"):
            full_url = request_uri
        else:
            scheme = "http"
            full_url = f"{scheme}://{host}{request_uri}"
    elif location_url.startswith("http://") or location_url.startswith("https://"):
        full_url = location_url

    return {
        "http_method": method,
        "http_host": host,
        "http_request_uri": request_uri,
        "http_full_url": full_url,
        "http_location": location_url,
        "http_protocol": protocol,
        "http_kind": http_kind,
    }


def parse_client_hello_sni(body: bytes) -> str:
    if len(body) < 34:
        return ""
    pos = 34
    if pos >= len(body):
        return ""
    session_len = body[pos]
    pos += 1 + session_len
    if pos + 2 > len(body):
        return ""
    cipher_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2 + cipher_len
    if pos >= len(body):
        return ""
    comp_len = body[pos]
    pos += 1 + comp_len
    if pos + 2 > len(body):
        return ""
    ext_total = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    ext_end = min(len(body), pos + ext_total)
    while pos + 4 <= ext_end:
        ext_type = int.from_bytes(body[pos : pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
        ext_body = body[pos + 4 : pos + 4 + ext_len]
        if len(ext_body) < ext_len:
            break
        if ext_type == 0 and len(ext_body) >= 5:
            list_pos = 2
            while list_pos + 3 <= len(ext_body):
                name_type = ext_body[list_pos]
                name_len = int.from_bytes(ext_body[list_pos + 1 : list_pos + 3], "big")
                name_bytes = ext_body[list_pos + 3 : list_pos + 3 + name_len]
                if name_type == 0 and len(name_bytes) == name_len:
                    return safe_string(name_bytes).strip()
                list_pos += 3 + name_len
        pos += 4 + ext_len
    return ""


def parse_certificate_message(body: bytes) -> tuple[str, str, list[str]]:
    if len(body) < 6:
        return "", "", []
    pos = 3
    while pos + 3 <= len(body):
        cert_len = int.from_bytes(body[pos : pos + 3], "big")
        cert_bytes = body[pos + 3 : pos + 3 + cert_len]
        if len(cert_bytes) < cert_len:
            break
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            dns_names: list[str] = []
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                dns_names = san.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                dns_names = []
            return subject, issuer, dns_names
        except Exception:
            pass
        pos += 3 + cert_len
    return "", "", []


def extract_common_name(subject_dn: str) -> str:
    if not subject_dn:
        return ""
    for part in subject_dn.split(","):
        cleaned = part.strip()
        if cleaned.startswith("CN="):
            return cleaned[3:]
    return ""


def extract_tls_metadata(raw_bytes: bytes) -> dict[str, str]:
    result = {
        "tls_version": "",
        "tls_sni": "",
        "tls_cert_subject": "",
        "tls_cert_issuer": "",
        "tls_cert_hostname": "",
    }
    if not is_tls_record(raw_bytes):
        return result

    result["tls_version"] = tls_version_name(raw_bytes[1], raw_bytes[2])
    pos = 0
    while pos + 5 <= len(raw_bytes):
        content_type = raw_bytes[pos]
        major = raw_bytes[pos + 1]
        minor = raw_bytes[pos + 2]
        length = int.from_bytes(raw_bytes[pos + 3 : pos + 5], "big")
        record_end = pos + 5 + length
        if major != 3 or record_end > len(raw_bytes):
            break
        record_body = raw_bytes[pos + 5 : record_end]
        if not result["tls_version"]:
            result["tls_version"] = tls_version_name(major, minor)
        if content_type == 22:
            handoff = 0
            while handoff + 4 <= len(record_body):
                hs_type = record_body[handoff]
                hs_len = int.from_bytes(record_body[handoff + 1 : handoff + 4], "big")
                hs_body = record_body[handoff + 4 : handoff + 4 + hs_len]
                if len(hs_body) < hs_len:
                    break
                if hs_type == 1 and not result["tls_sni"]:
                    result["tls_sni"] = parse_client_hello_sni(hs_body)
                elif hs_type == 11 and not result["tls_cert_subject"]:
                    subject, issuer, dns_names = parse_certificate_message(hs_body)
                    result["tls_cert_subject"] = subject
                    result["tls_cert_issuer"] = issuer
                    result["tls_cert_hostname"] = dns_names[0] if dns_names else extract_common_name(subject)
                handoff += 4 + hs_len
        pos = record_end
    return result


def extract_dns_fields(packet: Any) -> dict[str, str]:
    result = {"dns_qry_name": "", "dns_resp_name": "", "dns_a": ""}
    if DNS not in packet:
        return result
    dns_layer = packet[DNS]

    query_names: list[str] = []
    for qd in iter_dns_records(getattr(dns_layer, "qd", None), type(getattr(dns_layer, "qd", None))):
        qname = safe_string(getattr(qd, "qname", b"")).rstrip(".")
        if qname:
            query_names.append(qname)

    resp_names: list[str] = []
    a_records: list[str] = []
    for ans in iter_dns_records(getattr(dns_layer, "an", None), type(getattr(dns_layer, "an", None))):
        rrname = safe_string(getattr(ans, "rrname", b"")).rstrip(".")
        if rrname:
            resp_names.append(rrname)
        if getattr(ans, "type", None) == 1:
            a_records.append(safe_string(getattr(ans, "rdata", "")))

    result["dns_qry_name"] = ";".join(dict.fromkeys(query_names))
    result["dns_resp_name"] = ";".join(dict.fromkeys(resp_names))
    result["dns_a"] = ";".join(dict.fromkeys(a_records))
    return result


def detect_plaintext_identifiers(text: str) -> list[dict[str, str]]:
    if not text:
        return []

    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        cleaned = collapse_ws(value)
        if not cleaned:
            return
        cleaned = cleaned[:120]
        key = (kind, cleaned)
        if key in seen:
            return
        seen.add(key)
        results.append({"kind": kind, "value": cleaned})

    for match in EMAIL_REGEX.finditer(text):
        add("email", match.group(1))
    for match in PHONE_REGEX.finditer(text):
        digits = re.sub(r"\D", "", match.group(1))
        if len(digits) >= 7:
            add("phone", match.group(1))
    for match in MAC_REGEX.finditer(text):
        add("mac", match.group(0))
    for match in UUID_REGEX.finditer(text):
        add("device_identifier", match.group(0))
    for match in TOKEN_REGEX.finditer(text):
        add("token", match.group(1))
    for match in USERNAME_REGEX.finditer(text):
        add("username", match.group(1))
    for regex in FIELD_VALUE_REGEXES:
        for match in regex.finditer(text):
            add("device_identifier", match.group(1))
    for match in DEVICE_ID_REGEX.finditer(text):
        candidate = match.group(0)
        if len(candidate) >= 12 and any(char.isdigit() for char in candidate):
            add("serial_like_identifier", candidate)

    return results


def choose_protocol(packet: Any, http_info: dict[str, str], tls_info: dict[str, str]) -> str:
    if ARP in packet:
        return "ARP"
    if DNS in packet:
        return "DNS"
    if http_info["http_protocol"]:
        return http_info["http_protocol"]
    if tls_info["tls_version"]:
        return "TLS"
    if IP in packet and int(packet[IP].proto) == 2:
        return "IGMP"
    if ICMP in packet:
        return "ICMP"
    if UDP in packet and (packet[UDP].sport == 123 or packet[UDP].dport == 123):
        return "NTP"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if IP in packet:
        return f"IP_PROTO_{packet[IP].proto}"
    if IPv6 in packet:
        return "IPv6"
    return safe_string(packet.lastlayer().name)


def transport_class_for_packet(protocol: str, tls_version: str) -> str:
    if protocol == "TLS" or tls_version:
        return "secure"
    if protocol in {"HTTP", "SSDP", "DNS", "NTP", "ARP", "IGMP", "ICMP"}:
        return "insecure"
    return "unknown"


def classify_observed_name(value: str) -> str:
    cleaned = value.strip()
    if not cleaned or cleaned == "not observed":
        return "unknown"
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        return "url"
    host, port = split_host_port(cleaned)
    if is_ip_literal(host):
        return "endpoint" if port else "ip"
    if port:
        return "endpoint"
    if "." in host and any(char.isalpha() for char in host):
        return "domain"
    return "other"


def hostname_candidates(
    dns_fields: dict[str, str], http_info: dict[str, str], tls_info: dict[str, str]
) -> set[str]:
    values: set[str] = set()
    for field in [
        dns_fields["dns_qry_name"],
        dns_fields["dns_resp_name"],
        http_info["http_host"],
        tls_info["tls_sni"],
        tls_info["tls_cert_hostname"],
    ]:
        for value in field.split(";"):
            cleaned = value.strip()
            if cleaned:
                values.add(cleaned)
    parsed = urlparse(http_info["http_full_url"]) if http_info["http_full_url"] else None
    if parsed and parsed.netloc:
        values.add(parsed.netloc)
    if http_info["http_location"]:
        parsed_location = urlparse(http_info["http_location"])
        if parsed_location.netloc:
            values.add(parsed_location.netloc)
    return values


def domain_candidates(
    dns_fields: dict[str, str], http_info: dict[str, str], tls_info: dict[str, str]
) -> set[str]:
    return {
        candidate
        for candidate in hostname_candidates(dns_fields, http_info, tls_info)
        if classify_observed_name(candidate) == "domain"
    }


def build_flow_key(packet: Any, ip_src: str, ip_dst: str) -> tuple[str, str, str, str, str]:
    if TCP in packet:
        return (ip_src, ip_dst, safe_string(packet[TCP].sport), safe_string(packet[TCP].dport), "TCP")
    if UDP in packet:
        return (ip_src, ip_dst, safe_string(packet[UDP].sport), safe_string(packet[UDP].dport), "UDP")
    protocol = "IP"
    if ARP in packet:
        protocol = "ARP"
    elif IP in packet and int(packet[IP].proto) == 2:
        protocol = "IGMP"
    elif ICMP in packet:
        protocol = "ICMP"
    return (ip_src, ip_dst, "", "", protocol)


def update_session_state(
    packet: Any,
    packet_time: float,
    frame_len: int,
    protocol: str,
    transport_class: str,
    hostnames: set[str],
    active_sessions: dict[tuple[str, str, str, str, str], SessionState],
    completed_sessions: list[SessionState],
) -> None:
    ip_src = ""
    ip_dst = ""
    if IP in packet:
        ip_src = safe_string(packet[IP].src)
        ip_dst = safe_string(packet[IP].dst)
    elif IPv6 in packet:
        ip_src = safe_string(packet[IPv6].src)
        ip_dst = safe_string(packet[IPv6].dst)
    elif ARP in packet:
        ip_src = safe_string(packet[ARP].psrc)
        ip_dst = safe_string(packet[ARP].pdst)

    flow_key = build_flow_key(packet, ip_src, ip_dst)
    existing = active_sessions.get(flow_key)
    timeout = 300 if flow_key[-1] in {"TCP", "UDP"} else 60
    if existing and packet_time - existing.last_seen > timeout:
        completed_sessions.append(existing)
        active_sessions.pop(flow_key, None)
        existing = None

    if existing is None:
        existing = SessionState(
            start_ts=packet_time,
            end_ts=packet_time,
            src_ip=flow_key[0],
            dst_ip=flow_key[1],
            src_port=flow_key[2],
            dst_port=flow_key[3],
            transport=flow_key[4],
            last_seen=packet_time,
        )
        active_sessions[flow_key] = existing

    existing.end_ts = packet_time
    existing.last_seen = packet_time
    existing.packet_count += 1
    existing.byte_count += frame_len
    existing.protocol_counter[protocol] += 1
    existing.transport_classes[transport_class] += 1
    existing.hostnames.update(hostnames)
    if TCP in packet:
        flags = int(packet[TCP].flags)
        if flags & 0x01 or flags & 0x04:
            existing.seen_fin_or_rst = True
            completed_sessions.append(existing)
            active_sessions.pop(flow_key, None)


def dedupe_join(values: Iterable[str], sep: str = ";") -> str:
    ordered = [value for value in dict.fromkeys(value.strip() for value in values if value and value.strip())]
    return sep.join(ordered)


def top_counter_entries(counter: Counter, limit: int = 8) -> str:
    return ", ".join(f"{key} ({value})" for key, value in counter.most_common(limit)) or "not observed"


def summarize_counter_values(counter: Counter, limit: int = 5) -> str:
    values = [safe_string(key) for key, _value in counter.most_common(limit)]
    if not values:
        return "not observed"
    text = ";".join(values)
    if len(counter) > limit:
        text = f"{text};... (+{len(counter) - limit} more)"
    return text


def select_session_protocol(counter: Counter, fallback: str) -> str:
    priority = ["TLS", "HTTP", "SSDP", "DNS", "NTP", "TCP", "UDP", "ARP", "IGMP", "ICMP", "IPv6"]
    for protocol in priority:
        if counter.get(protocol, 0):
            return protocol
    return counter.most_common(1)[0][0] if counter else fallback


def format_port_list(ports: Iterable[int], limit: int = 15) -> str:
    ordered = sorted(set(ports))
    if not ordered:
        return "not observed"
    if len(ordered) <= limit:
        return ";".join(str(port) for port in ordered)
    visible = ";".join(str(port) for port in ordered[:limit])
    return f"{visible};... (+{len(ordered) - limit} more)"


def add_alert(
    alerts: list[dict[str, str]],
    seen_alerts: set[tuple[str, str, str]],
    *,
    subject: str,
    category: str,
    severity: str,
    timestamp: str,
    explanation: str,
    value_snippet: str,
    recommendation: str,
) -> None:
    key = (category, subject, value_snippet)
    if key in seen_alerts:
        return
    seen_alerts.add(key)
    alerts.append(
        {
            "subject": subject,
            "category": category,
            "severity": severity,
            "timestamp": timestamp,
            "explanation": explanation,
            "value_snippet": value_snippet or "not observed",
            "recommendation": recommendation,
        }
    )


def summarize_top(counter: Counter, limit: int = 5) -> str:
    return ", ".join(f"{key} ({value})" for key, value in counter.most_common(limit))


def choose_service_side(
    src_port: str, dst_port: str, device_service_ports: set[int]
) -> str:
    def rank(port_value: str, prefer_dst: bool) -> tuple[int, int, int]:
        if not port_value.isdigit():
            return (5, 65536, 1 if prefer_dst else 0)
        port = int(port_value)
        if port in device_service_ports:
            return (0, port, 1 if prefer_dst else 0)
        if port in COMMON_PORTS:
            return (1, port, 1 if prefer_dst else 0)
        if port <= 1024:
            return (2, port, 1 if prefer_dst else 0)
        return (3, port, 1 if prefer_dst else 0)

    src_rank = rank(src_port, False)
    dst_rank = rank(dst_port, True)
    if src_port == dst_port and src_port:
        return "dst"
    if src_rank < dst_rank:
        return "src"
    if dst_rank < src_rank:
        return "dst"
    if dst_port.isdigit() and src_port.isdigit():
        return "dst" if int(dst_port) <= int(src_port) else "src"
    return "dst"


def reportable_session_protocol(protocol: str) -> bool:
    if protocol in {"ARP", "IGMP", "IPv6", "EAPOL_KEY", "Raw"}:
        return False
    if protocol.startswith("IP_PROTO_"):
        return False
    return True


def build_report_session_rows(
    sessions: list[SessionState],
    ip_domain_map: dict[str, set[str]],
    device_service_ports: set[int],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for session in sorted(
        sessions,
        key=lambda item: (item.start_ts, item.src_ip, item.dst_ip, item.src_port, item.dst_port),
    ):
        dominant_protocol = select_session_protocol(session.protocol_counter, session.transport)
        if not reportable_session_protocol(dominant_protocol):
            continue

        transport_class = "unknown"
        if session.transport_classes:
            if session.transport_classes.get("secure", 0):
                transport_class = "secure"
            elif session.transport_classes.get("insecure", 0):
                transport_class = "insecure"

        if session.packet_count == 1 and dominant_protocol in {"TCP", "UDP", "ICMP"}:
            continue

        src_ip = session.src_ip or "not observed"
        dst_ip = session.dst_ip or "not observed"
        src_port = session.src_port or "not observed"
        dst_port = session.dst_port or "not observed"

        if src_port != "not observed" or dst_port != "not observed":
            service_side = choose_service_side(
                session.src_port or "",
                session.dst_port or "",
                device_service_ports,
            )
            if service_side == "src":
                client_ip, client_port, service_ip, service_port = dst_ip, dst_port, src_ip, src_port
            else:
                client_ip, client_port, service_ip, service_port = src_ip, src_port, dst_ip, dst_port
        else:
            client_ip, client_port, service_ip, service_port = src_ip, src_port, dst_ip, dst_port

        hostnames: set[str] = set()
        for candidate in session.hostnames:
            if classify_observed_name(candidate) == "domain":
                hostnames.add(candidate)
        for candidate_ip in [session.dst_ip, session.src_ip]:
            for value in ip_domain_map.get(candidate_ip, set()):
                if classify_observed_name(value) == "domain":
                    hostnames.add(value)

        bucket_start = int(session.start_ts // 3600) * 3600
        group_key = (
            bucket_start,
            dominant_protocol,
            transport_class,
            client_ip,
            service_ip,
            service_port,
        )

        existing = grouped.get(group_key)
        if existing is None:
            grouped[group_key] = {
                "start_ts": session.start_ts,
                "end_ts": session.end_ts,
                "src_ip": client_ip,
                "dst_ip": service_ip,
                "src_ports": Counter({client_port: session.packet_count}),
                "dst_ports": Counter({service_port: session.packet_count}),
                "protocol": dominant_protocol,
                "packet_count": session.packet_count,
                "byte_count": session.byte_count,
                "hostnames": set(hostnames),
                "transport_class": transport_class,
            }
            continue

        existing["start_ts"] = min(existing["start_ts"], session.start_ts)
        existing["end_ts"] = max(existing["end_ts"], session.end_ts)
        existing["packet_count"] += session.packet_count
        existing["byte_count"] += session.byte_count
        existing["hostnames"].update(hostnames)
        existing["src_ports"][client_port] += session.packet_count
        existing["dst_ports"][service_port] += session.packet_count

    session_rows = []
    for row in grouped.values():
        top_src_port = row["src_ports"].most_common(1)[0][0] if row["src_ports"] else "not observed"
        top_dst_port = row["dst_ports"].most_common(1)[0][0] if row["dst_ports"] else "not observed"
        session_rows.append(
            {
                "start_time": to_iso(row["start_ts"]),
                "end_time": to_iso(row["end_ts"]),
                "src_ip": row["src_ip"] or "not observed",
                "dst_ip": row["dst_ip"] or "not observed",
                "src_port": top_src_port if len(row["src_ports"]) <= 1 else "multiple",
                "dst_port": top_dst_port if len(row["dst_ports"]) <= 1 else "multiple",
                "protocol": row["protocol"],
                "packet_count": row["packet_count"],
                "byte_count": row["byte_count"],
                "hostname_or_domain": dedupe_join(sorted(row["hostnames"])) or "not observed",
                "transport_class": row["transport_class"],
            }
        )

    return sorted(
        session_rows,
        key=lambda row: (
            row["start_time"],
            row["dst_ip"],
            row["dst_port"],
            row["protocol"],
        ),
    )


def capture_timing_assessment(capture_timing: dict[str, Any]) -> dict[str, Any]:
    active_days = capture_timing.get("active_days", 0)
    forward_gaps_over_60s = capture_timing.get("forward_gaps_over_60s", 0)
    forward_gaps_over_1h = capture_timing.get("forward_gaps_over_1h", 0)
    forward_gaps_over_1d = capture_timing.get("forward_gaps_over_1d", 0)
    negative_jumps = capture_timing.get("negative_timestamp_jumps", 0)
    largest_gap_hours = round(capture_timing.get("largest_gap_seconds", 0) / 3600, 2)
    largest_negative_jump_hours = round(
        capture_timing.get("largest_negative_jump_seconds", 0) / 3600,
        2,
    )
    fragmented = bool(forward_gaps_over_1h or negative_jumps)
    narrative = (
        f"Packet timestamps span {active_days} active day(s) with "
        f"{forward_gaps_over_60s} forward gaps over 60s, "
        f"{forward_gaps_over_1h} forward gaps over 1h, "
        f"{forward_gaps_over_1d} forward gaps over 1 day, and "
        f"{negative_jumps} backward timestamp jump(s)."
    )
    if fragmented:
        narrative += (
            " The file should be treated as fragmented timestamp coverage or merged capture segments, "
            "not a single uninterrupted operating period."
        )
    if largest_gap_hours:
        narrative += f" Largest forward gap observed: {largest_gap_hours}h."
    if largest_negative_jump_hours:
        narrative += f" Largest backward jump observed: {largest_negative_jump_hours}h."
    return {
        "fragmented": fragmented,
        "narrative": narrative,
        "largest_gap_hours": largest_gap_hours,
        "largest_negative_jump_hours": largest_negative_jump_hours,
    }


def generate_report_artifacts(
    analysis: dict[str, Any],
    sessions: list[SessionState],
    packet_count: int,
    total_bytes: int,
    capture_start: float | None,
    capture_end: float | None,
    subject_mac: str,
    subject_ips: set[str],
) -> None:
    session_rows = build_report_session_rows(
        sessions=sessions,
        ip_domain_map=analysis["ip_to_domains"],
        device_service_ports=analysis["device_service_ports"],
    )
    secure_sessions = sum(1 for row in session_rows if row["transport_class"] == "secure")
    insecure_sessions = sum(1 for row in session_rows if row["transport_class"] == "insecure")
    protocol_session_counter = Counter(row["protocol"] for row in session_rows)
    destination_session_counter = Counter(row["dst_ip"] for row in session_rows)

    protocol_summary_rows = []
    for protocol, packets in analysis["protocol_packets"].most_common():
        destination_count = sum(
            1
            for _destination, stats in analysis["destination_stats"].items()
            if stats["protocols"].get(protocol, 0)
        )
        protocol_summary_rows.append(
            {
                "protocol": protocol,
                "packet_count": packets,
                "byte_count": analysis["protocol_bytes"].get(protocol, 0),
                "share_pct": round((packets / packet_count) * 100, 2) if packet_count else 0.0,
                "transport_class": analysis["protocol_transport_class"].get(protocol, "unknown"),
                "session_window_count": protocol_session_counter.get(protocol, 0),
                "destination_count": destination_count,
            }
        )

    port_summary_rows = []
    for port, packets in analysis["port_counter"].most_common():
        stats = analysis["port_stats"][port]
        if port in analysis["device_service_ports"]:
            risk_note = "device service port observed"
        elif port == 1900:
            risk_note = "multicast discovery / SSDP port"
        elif port not in COMMON_PORTS and port >= 49152:
            risk_note = "high-numbered port; review if service exposure is expected"
        elif stats["endpoint_classes"].get("public", 0):
            risk_note = "public / third-party service port observed"
        else:
            risk_note = "observed"
        port_summary_rows.append(
            {
                "destination_port": port,
                "packet_count": packets,
                "byte_count": stats["byte_count"],
                "share_pct": round((packets / packet_count) * 100, 2) if packet_count else 0.0,
                "protocols": top_counter_entries(stats["protocols"], limit=3),
                "endpoint_classes": summarize_counter_values(stats["endpoint_classes"], limit=3),
                "hostname_examples": summarize_counter_values(stats["hostnames"], limit=3),
                "destination_examples": summarize_counter_values(stats["destinations"], limit=3),
                "risk_note": risk_note,
            }
        )

    destination_summary_rows = []
    for destination, stats in sorted(
        analysis["destination_stats"].items(),
        key=lambda item: item[1]["packet_count"],
        reverse=True,
    ):
        destination_summary_rows.append(
            {
                "destination": destination,
                "packet_count": stats["packet_count"],
                "byte_count": stats["byte_count"],
                "share_pct": round((stats["packet_count"] / packet_count) * 100, 2) if packet_count else 0.0,
                "endpoint_class": stats["endpoint_class"],
                "hostname_examples": summarize_counter_values(stats["hostnames"], limit=3),
                "protocols": top_counter_entries(stats["protocols"], limit=3),
                "destination_ports": summarize_counter_values(stats["destination_ports"], limit=5),
                "transport_mix": summarize_counter_values(stats["transport_classes"], limit=3),
                "session_window_count": destination_session_counter.get(destination, 0),
                "third_party_indicator": "yes" if stats["endpoint_class"] == "public" else "no",
                "review_note": (
                    "public / third-party endpoint observed"
                    if stats["endpoint_class"] == "public"
                    else (
                        "multicast discovery endpoint"
                        if stats["endpoint_class"] == "multicast"
                        else (
                            "camera-local endpoint / service"
                            if destination in subject_ips
                            else "private / local endpoint observed"
                        )
                    )
                ),
            }
        )

    alerts = analysis["alerts"]
    compliance_rows = analysis["compliance_flags"]
    timing_note = capture_timing_assessment(analysis["capture_timing"])
    plaintext_identifier_hits = (
        analysis["identifier_hits"].get("device_identifier", [])
        + analysis["identifier_hits"].get("serial_like_identifier", [])
        + analysis["identifier_hits"].get("mac", [])
        + analysis["identifier_hits"].get("email", [])
        + analysis["identifier_hits"].get("phone", [])
        + analysis["identifier_hits"].get("token", [])
        + analysis["identifier_hits"].get("username", [])
    )
    subject_local_ips = sorted(
        ip_value
        for ip_value in subject_ips
        if endpoint_class(ip_value) in {"private", "link_local", "loopback"}
    )

    findings_per_device = [
        {
            "device_label": "SamsungCamera_00166cab6b88",
            "subject_mac": subject_mac or "not observed",
            "observed_local_ips": dedupe_join(subject_local_ips) or "not observed",
            "packet_count": packet_count,
            "reportable_session_count": len(session_rows),
            "active_days": analysis["capture_timing"]["active_days"],
            "timestamp_fragmentation": timing_note["narrative"],
            "public_destination_count": sum(1 for row in destination_summary_rows if row["endpoint_class"] == "public"),
            "public_destination_examples": dedupe_join(
                row["destination"]
                for row in destination_summary_rows[:10]
                if row["endpoint_class"] == "public"
            )
            or "not observed",
            "hostname_domain_count": len(analysis["domain_counter"]),
            "hostname_domain_examples": summarize_counter_values(analysis["domain_counter"], limit=5),
            "url_examples": summarize_counter_values(analysis["url_counter"], limit=5),
            "endpoint_examples": summarize_counter_values(analysis["endpoint_counter"], limit=5),
            "plaintext_identifier_observed": "yes"
            if analysis["identifier_hits"].get("device_identifier") or analysis["identifier_hits"].get("serial_like_identifier")
            else "no",
            "plaintext_identifier_types": dedupe_join(
                kind
                for kind in ["device_identifier", "serial_like_identifier", "mac"]
                if analysis["identifier_hits"].get(kind)
            )
            or "not observed",
            "plaintext_identifier_examples": dedupe_join(
                hit["value"] for hit in plaintext_identifier_hits[:4]
            )
            or "not observed",
            "plaintext_email_observed": "yes" if analysis["identifier_hits"].get("email") else "no",
            "plaintext_phone_observed": "yes" if analysis["identifier_hits"].get("phone") else "no",
            "plaintext_token_observed": "yes" if analysis["identifier_hits"].get("token") else "no",
            "plaintext_username_observed": "yes" if analysis["identifier_hits"].get("username") else "no",
            "plaintext_http_observed": "yes" if analysis["plaintext_http_count"] else "no",
            "tls_observed": "yes" if secure_sessions else "no",
            "mixed_transport_observed": "yes" if secure_sessions and insecure_sessions else "no",
            "secure_session_count": secure_sessions,
            "insecure_session_count": insecure_sessions,
            "device_service_ports": dedupe_join(str(port) for port in sorted(analysis["device_service_ports"])) or "not observed",
            "overall_risk_score": analysis["overall_risk_score"],
        }
    ]

    session_df = pd.DataFrame(session_rows)
    protocol_df = pd.DataFrame(protocol_summary_rows)
    port_df = pd.DataFrame(port_summary_rows)
    destination_df = pd.DataFrame(destination_summary_rows)
    alerts_df = pd.DataFrame(alerts)
    compliance_df = pd.DataFrame(compliance_rows)
    findings_df = pd.DataFrame(findings_per_device)

    session_df.to_csv(INTERMEDIATE_DIR / "sessions_extracted.csv", index=False)
    protocol_df.to_csv(TABLES_DIR / "protocol_summary.csv", index=False)
    port_df.to_csv(TABLES_DIR / "port_summary.csv", index=False)
    destination_df.to_csv(TABLES_DIR / "destination_summary.csv", index=False)
    alerts_df.to_csv(TABLES_DIR / "alerts.csv", index=False)
    compliance_df.to_csv(TABLES_DIR / "compliance_flags.csv", index=False)
    findings_df.to_csv(TABLES_DIR / "findings_per_device.csv", index=False)
    protocol_df.head(10).to_csv(TABLES_DIR / "protocol_summary_top10.csv", index=False)
    port_df.head(15).to_csv(TABLES_DIR / "port_summary_top15.csv", index=False)
    destination_df.head(15).to_csv(TABLES_DIR / "destination_summary_top15.csv", index=False)

    write_method_notes(
        packet_count=packet_count,
        total_bytes=total_bytes,
        capture_start=capture_start,
        capture_end=capture_end,
        capture_timing=analysis["capture_timing"],
        protocol_summary_rows=protocol_summary_rows,
        session_count=len(session_rows),
    )
    write_summary(
        analysis=analysis,
        packet_count=packet_count,
        total_bytes=total_bytes,
        capture_start=capture_start,
        capture_end=capture_end,
        destination_summary_rows=destination_summary_rows,
        protocol_summary_rows=protocol_summary_rows,
        session_rows=session_rows,
        subject_ips=subject_local_ips,
    )
    write_figures(
        analysis=analysis,
        alerts=alerts,
        protocol_summary_rows=protocol_summary_rows,
        port_summary_rows=port_summary_rows,
        destination_summary_rows=destination_summary_rows,
        session_rows=session_rows,
        time_buckets=analysis["time_buckets"],
    )


def write_method_notes(
    *,
    packet_count: int,
    total_bytes: int,
    capture_start: float | None,
    capture_end: float | None,
    capture_timing: dict[str, Any],
    protocol_summary_rows: list[dict[str, Any]],
    session_count: int,
) -> None:
    top_protocol_mix = ", ".join(
        f"{row['protocol']}={row['packet_count']}" for row in protocol_summary_rows[:6]
    ) or "not observed"
    timing_note = capture_timing_assessment(capture_timing)
    lines = [
        "# Method Notes",
        "",
        "Pipeline:",
        "pcap -> packet/session extraction -> evidence classification -> alerts -> compliance flags -> report tables/figures",
        "",
        "1. Packet-level extraction",
        "- The workflow streams the PCAP directly with Scapy rather than starting from any aggregate CSV.",
        "- Each packet is written to `outputs/intermediate/packets_extracted.csv` with Ethernet, IP, TCP/UDP, DNS, HTTP/SSDP, TLS, and safe plaintext-preview fields when they are directly observable.",
        "- Payload previews are truncated and only populated when the bytes look sufficiently plaintext.",
        "",
        "2. Session / flow extraction",
        "- Directional sessions are built from the observed 5-tuple and transport, with timeout-based rollover and TCP FIN/RST closure where present.",
        "- For report use, repeated short-lived flow fragments are consolidated into reportable session windows by client/service tuple, dominant protocol, and hourly time bucket. This reduces socket-level noise in the final session table.",
        "- If multiple ephemeral client ports collapse into one reportable session window, the `src_port` field may show `multiple`. Non-conversational control traffic such as ARP/IGMP remains visible in packet/protocol summaries but is prevented from dominating session counts.",
        "",
        "3. Evidence classification",
        "- Plaintext identifier detection is regex-based and only reports values that appear in visible plaintext payloads or headers.",
        "- DNS hostnames/domains, HTTP URLs, concrete IP:port endpoints, TLS metadata, and safe plaintext payload snippets are tracked separately so the report does not mix hostnames with raw endpoints.",
        "- TLS certificate subject/issuer fields are only filled when the relevant certificate message is directly present inside an observed TLS handshake record.",
        "- Third-party, background-communication, mixed-transport, and attack-surface findings are heuristic summaries built from directly observed endpoints, ports, and services.",
        "",
        "4. Compliance-style flags",
        "- The generated compliance rows are evidence-linked heuristics for reporting support, not a legal certification or full conformance assessment.",
        "- If evidence is incomplete, the explanation explicitly says so.",
        "",
        "Observed capture context:",
        f"- Packet count: {packet_count:,}",
        f"- Total bytes: {total_bytes:,}",
        f"- Capture start (UTC): {to_iso(capture_start) if capture_start else 'not observed'}",
        f"- Capture end (UTC): {to_iso(capture_end) if capture_end else 'not observed'}",
        f"- Reportable session windows: {session_count:,}",
        f"- Timestamp interpretation: {timing_note['narrative']}",
        f"- Top protocol mix: {top_protocol_mix}",
    ]
    (OUTPUTS_DIR / "method_notes.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_summary(
    *,
    analysis: dict[str, Any],
    packet_count: int,
    total_bytes: int,
    capture_start: float | None,
    capture_end: float | None,
    destination_summary_rows: list[dict[str, Any]],
    protocol_summary_rows: list[dict[str, Any]],
    session_rows: list[dict[str, Any]],
    subject_ips: list[str],
) -> None:
    public_destinations = [row for row in destination_summary_rows if row["endpoint_class"] == "public"]
    insecure_sessions = sum(1 for row in session_rows if row["transport_class"] == "insecure")
    secure_sessions = sum(1 for row in session_rows if row["transport_class"] == "secure")
    protocol_findings = ", ".join(
        f"{row['protocol']} ({row['packet_count']})" for row in protocol_summary_rows[:8]
    ) or "not observed"
    hostname_findings = top_counter_entries(analysis["domain_counter"], limit=6)
    url_findings = top_counter_entries(analysis["url_counter"], limit=6)
    endpoint_findings = top_counter_entries(analysis["endpoint_counter"], limit=8)
    payload_findings = top_counter_entries(analysis["payload_counter"], limit=5)
    service_port_summary = format_port_list(analysis["device_service_ports"], limit=20)
    plaintext_identifiers = []
    for key in ["device_identifier", "serial_like_identifier", "mac", "email", "phone", "token", "username"]:
        plaintext_identifiers.extend(analysis["identifier_hits"].get(key, []))
    identifier_text = (
        dedupe_join(hit["value"] for hit in plaintext_identifiers[:4]) if plaintext_identifiers else "not observed"
    )
    email_phone_tokens = []
    for key in ["email", "phone", "token", "username"]:
        email_phone_tokens.extend(analysis["identifier_hits"].get(key, []))
    timing_note = capture_timing_assessment(analysis["capture_timing"])
    if plaintext_identifiers and not email_phone_tokens:
        pii_observed_text = (
            "Plaintext metadata exposed device/service identifiers, but email, phone, token, and username values were not observed. "
            "This supports device/service identifier exposure rather than strong personal-PII leakage."
        )
    elif not plaintext_identifiers:
        pii_observed_text = "Plaintext identifiers were not observed."
    else:
        pii_observed_text = "Multiple plaintext identifiers were observed; stronger personal-PII interpretation should still be made cautiously."

    lines = [
        "# Security and Privacy Summary",
        "",
        f"Overall risk score: **{analysis['overall_risk_score']}/100**",
        "",
        "## Directly Observed Evidence",
        f"- Capture window (UTC): {to_iso(capture_start) if capture_start else 'not observed'} to {to_iso(capture_end) if capture_end else 'not observed'}",
        f"- Capture timing interpretation: {timing_note['narrative']}",
        f"- Packet volume: {packet_count:,} packets / {total_bytes:,} bytes",
        f"- Subject local IPs observed: {dedupe_join(subject_ips) or 'not observed'}",
        f"- Plaintext PII / identifier findings: {pii_observed_text}",
        f"- Plaintext identifier examples: {identifier_text}",
        f"- Hostname / domain findings: {hostname_findings}",
        f"- URL / HTTP findings: {url_findings}",
        f"- Endpoint / IP:port findings: {endpoint_findings}",
        f"- Payload findings: {payload_findings}",
        f"- Protocol findings: {protocol_findings}",
        f"- Destination port findings: {summarize_top(analysis['port_counter'], limit=8) or 'not observed'}",
        f"- TLS / encryption findings: TLS records were observed on cloud-control or public-service flows; reportable secure session windows={secure_sessions}, insecure session windows={insecure_sessions}. Handshake metadata remains partial where SNI/cert packets were not present.",
        f"- Third-party / attack surface findings: {len(public_destinations)} public destination IPs were observed; top examples={dedupe_join(row['destination'] for row in public_destinations[:10]) or 'not observed'}; device service ports seen in traffic={service_port_summary}",
        "",
        "## Inferred Risk",
        "- The strongest direct risk signal in this PCAP is mixed transport: encrypted cloud communications coexist with plaintext LAN discovery and plaintext HTTP device-description exchanges.",
        "- Plaintext exposure appears to center on device/service identifiers and descriptive metadata. That is relevant for privacy-by-design and attack-surface discussion, but it is weaker evidence than direct exposure of strong personal PII.",
        "- Public cloud / third-party communication is directly observed, so dependency inventory, expected-destination allowlisting, and vendor data-flow review are justified follow-up steps.",
        (
            "- Because the timestamp coverage is fragmented and includes backward jumps, this PCAP should not be treated as proof of continuous normal operation across the full calendar span."
            if timing_note["fragmented"]
            else "- The observed time window is still only passive capture evidence; it can describe traffic seen in the file, but it does not by itself prove the device's full operational baseline."
        ),
        "",
        "## Suggested Report Usage",
        "- This branch is strongest for real packet-level protocol and destination-port evidence, TLS / mixed-transport evidence, hostname / endpoint / third-party communication evidence, and attack-surface discussion grounded in directly observed traffic.",
        "- It complements the synthetic branch rather than replacing it. The synthetic branch remains stronger for controlled demonstrations of strong personal-PII leakage or attack scenarios.",
        "",
        "## Mitigations",
        "- Reduce or disable unnecessary UPnP/SSDP exposure where feasible, especially if local discovery is not required.",
        "- Restrict access to plaintext local service ports with network segmentation or local firewall policy.",
        "- Prefer authenticated and encrypted management / metadata endpoints over plaintext HTTP device-description exposure.",
        "- Maintain an allowlist for observed third-party destinations and validate that each cloud dependency is expected and documented.",
        "",
        "## Limitations",
        "- This is passive PCAP analysis only; no traffic decryption, active probing, or firmware validation was performed.",
        (
            "- The packet timestamps span multiple months and include large gaps plus backward jumps, so they are better interpreted as fragmented capture coverage than as one continuous measurement period."
            if timing_note["fragmented"]
            else "- The observed timestamps should be read as capture evidence for this file only; they do not prove complete or exhaustive device behavior outside the captured window."
        ),
        "- TLS certificate fields are only available when the relevant handshake records are present in a packet; fragmented or missing handshakes remain partially unknown.",
        "- Compliance-style flags in this branch are evidence-linked heuristics for reporting support, not a formal audit or legal conclusion.",
    ]
    (OUTPUTS_DIR / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_figures(
    *,
    analysis: dict[str, Any],
    alerts: list[dict[str, str]],
    protocol_summary_rows: list[dict[str, Any]],
    port_summary_rows: list[dict[str, Any]],
    destination_summary_rows: list[dict[str, Any]],
    session_rows: list[dict[str, Any]],
    time_buckets: dict[str, dict[str, int]],
) -> None:
    sns.set_theme(style="whitegrid")

    alert_df = pd.DataFrame(alerts)
    if alert_df.empty:
        alert_df = pd.DataFrame([{"category": "no_alerts", "count": 0}])
    alert_counts = (
        alert_df.groupby("category").size().reset_index(name="count").sort_values("count", ascending=False)
    )
    plt.figure(figsize=(10, 6))
    sns.barplot(data=alert_counts, x="count", y="category", hue="category", legend=False, palette="crest")
    plt.title("Alert Categories")
    plt.xlabel("Alert Count")
    plt.ylabel("Category")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "alert_categories.png", dpi=180)
    plt.close()

    protocol_df = pd.DataFrame(protocol_summary_rows[:10])
    port_df = pd.DataFrame(port_summary_rows[:10])
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    sns.barplot(data=protocol_df, x="packet_count", y="protocol", hue="protocol", legend=False, palette="flare", ax=axes[0])
    axes[0].set_title("Protocol Distribution")
    axes[0].set_xlabel("Packets")
    axes[0].set_ylabel("Protocol")
    sns.barplot(
        data=port_df,
        x="packet_count",
        y="destination_port",
        hue="destination_port",
        legend=False,
        palette="mako",
        ax=axes[1],
    )
    axes[1].set_title("Top Destination Ports")
    axes[1].set_xlabel("Packets")
    axes[1].set_ylabel("Destination Port")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "protocol_and_port_behavior.png", dpi=180)
    plt.close(fig)

    destination_df = pd.DataFrame(destination_summary_rows[:12])
    plt.figure(figsize=(12, 7))
    sns.barplot(data=destination_df, x="packet_count", y="destination", hue="endpoint_class", dodge=False, palette="viridis")
    plt.title("Destination Diversity")
    plt.xlabel("Packets")
    plt.ylabel("Destination")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "destination_diversity.png", dpi=180)
    plt.close()

    traffic_rows = [
        {"time_bucket": bucket, "packets": stats["packets"], "bytes": stats["bytes"]}
        for bucket, stats in sorted(time_buckets.items())
    ]
    traffic_df = pd.DataFrame(traffic_rows)
    if traffic_df.empty:
        traffic_df = pd.DataFrame([{"time_bucket": "not_observed", "packets": 0, "bytes": 0}])
    else:
        traffic_df["time_bucket"] = pd.to_datetime(traffic_df["time_bucket"], utc=True, errors="coerce")
        traffic_df = traffic_df.dropna(subset=["time_bucket"])
        if len(traffic_df) > 2000:
            traffic_df["time_bucket"] = traffic_df["time_bucket"].dt.floor("6h")
        elif len(traffic_df) > 500:
            traffic_df["time_bucket"] = traffic_df["time_bucket"].dt.floor("1h")
        else:
            traffic_df["time_bucket"] = traffic_df["time_bucket"].dt.floor("1min")
        traffic_df = (
            traffic_df.groupby("time_bucket", as_index=False)[["packets", "bytes"]]
            .sum()
            .sort_values("time_bucket")
        )
    fig, ax1 = plt.subplots(figsize=(13, 6))
    ax2 = ax1.twinx()
    ax1.scatter(traffic_df["time_bucket"], traffic_df["packets"], color="#1f77b4", s=14, alpha=0.8, label="Packets")
    ax2.scatter(traffic_df["time_bucket"], traffic_df["bytes"], color="#ff7f0e", s=10, alpha=0.55, label="Bytes")
    ax1.set_title("Traffic Volume Over Time")
    ax1.set_xlabel("Time Bucket (UTC)")
    ax1.set_ylabel("Packets", color="#1f77b4")
    ax2.set_ylabel("Bytes", color="#ff7f0e")
    ax1.tick_params(axis="x", rotation=45)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "traffic_volume_over_time.png", dpi=180)
    plt.close(fig)

    secure_sessions = sum(1 for row in session_rows if row["transport_class"] == "secure")
    insecure_sessions = sum(1 for row in session_rows if row["transport_class"] == "insecure")
    risk_df = pd.DataFrame(
        [
            {"evidence": "Plaintext identifier values", "count": len(analysis["identifier_seen"])},
            {
                "evidence": "Plaintext HTTP / SSDP samples",
                "count": max(len(analysis["http_samples"]), len(analysis["url_counter"])),
            },
            {"evidence": "Mixed transport classes", "count": int(bool(secure_sessions)) + int(bool(insecure_sessions))},
            {
                "evidence": "Public destination IPs",
                "count": sum(1 for row in destination_summary_rows if row["endpoint_class"] == "public"),
            },
            {"evidence": "Exposed device service ports", "count": len(analysis["device_service_ports"])},
        ]
    ).sort_values("count", ascending=False)
    plt.figure(figsize=(11, 6))
    ax = sns.barplot(data=risk_df, x="count", y="evidence", hue="evidence", legend=False, palette="rocket")
    if not risk_df.empty and risk_df["count"].max() >= 50:
        ax.set_xscale("symlog", linthresh=1)
        ax.set_xlabel("Observed Count (symlog scale)")
    else:
        ax.set_xlabel("Observed Count")
    ax.set_title("Risk Evidence Overview")
    ax.set_ylabel("Evidence Category")
    for patch, value in zip(ax.patches, risk_df["count"]):
        ax.text(
            patch.get_width(),
            patch.get_y() + patch.get_height() / 2,
            f" {value}",
            va="center",
            ha="left",
            fontsize=9,
        )
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "risk_evidence_overview.png", dpi=180)
    plt.close()


def analyze_pcap() -> None:
    ensure_directories()
    subject_mac = device_mac_from_filename(PCAP_PATH)

    packets_path = INTERMEDIATE_DIR / "packets_extracted.csv"
    with packets_path.open("w", newline="", encoding="utf-8") as packet_file:
        packet_writer = csv.DictWriter(packet_file, fieldnames=PACKET_FIELDS)
        packet_writer.writeheader()

        analysis: dict[str, Any] = {
            "protocol_packets": Counter(),
            "protocol_bytes": Counter(),
            "protocol_transport_class": {},
            "port_counter": Counter(),
            "port_stats": defaultdict(
                lambda: {
                    "byte_count": 0,
                    "protocols": Counter(),
                    "endpoint_classes": Counter(),
                    "hostnames": Counter(),
                    "destinations": Counter(),
                }
            ),
            "destination_stats": defaultdict(
                lambda: {
                    "packet_count": 0,
                    "byte_count": 0,
                    "endpoint_class": "unknown",
                    "hostnames": Counter(),
                    "protocols": Counter(),
                    "destination_ports": Counter(),
                    "transport_classes": Counter(),
                }
            ),
            "time_buckets": defaultdict(lambda: {"packets": 0, "bytes": 0}),
            "ip_to_domains": defaultdict(set),
            "domain_counter": Counter(),
            "url_counter": Counter(),
            "endpoint_counter": Counter(),
            "payload_counter": Counter(),
            "identifier_hits": defaultdict(list),
            "identifier_seen": set(),
            "plaintext_http_count": 0,
            "http_samples": [],
            "tls_samples": [],
            "device_service_ports": set(),
            "public_endpoint_counter": Counter(),
            "alerts": [],
            "compliance_flags": [],
            "capture_timing": {},
        }
        seen_alerts: set[tuple[str, str, str]] = set()
        active_sessions: dict[tuple[str, str, str, str, str], SessionState] = {}
        completed_sessions: list[SessionState] = []
        subject_ips: set[str] = set()
        capture_start: float | None = None
        capture_end: float | None = None
        packet_count = 0
        total_bytes = 0
        active_days: set[str] = set()
        last_packet_time: float | None = None
        forward_gaps_over_60s = 0
        forward_gaps_over_1h = 0
        forward_gaps_over_1d = 0
        largest_gap_seconds = 0.0
        negative_timestamp_jumps = 0
        largest_negative_jump_seconds = 0.0

        with PcapReader(str(PCAP_PATH)) as reader:
            for packet in reader:
                packet_count += 1
                if PACKET_LIMIT and packet_count > PACKET_LIMIT:
                    break
                packet_time = get_packet_timestamp(packet)
                frame_len = len(bytes(packet))
                total_bytes += frame_len
                capture_start = packet_time if capture_start is None else min(capture_start, packet_time)
                capture_end = packet_time if capture_end is None else max(capture_end, packet_time)

                timestamp = to_iso(packet_time)
                active_days.add(timestamp[:10])
                if last_packet_time is not None:
                    delta = packet_time - last_packet_time
                    if delta < 0:
                        negative_timestamp_jumps += 1
                        largest_negative_jump_seconds = max(largest_negative_jump_seconds, abs(delta))
                    else:
                        if delta > 60:
                            forward_gaps_over_60s += 1
                        if delta > 3600:
                            forward_gaps_over_1h += 1
                        if delta > 86400:
                            forward_gaps_over_1d += 1
                        largest_gap_seconds = max(largest_gap_seconds, delta)
                last_packet_time = packet_time
                eth_src = safe_string(packet[Ether].src) if Ether in packet else ""
                eth_dst = safe_string(packet[Ether].dst) if Ether in packet else ""

                ip_src = ""
                ip_dst = ""
                if IP in packet:
                    ip_src = safe_string(packet[IP].src)
                    ip_dst = safe_string(packet[IP].dst)
                elif IPv6 in packet:
                    ip_src = safe_string(packet[IPv6].src)
                    ip_dst = safe_string(packet[IPv6].dst)
                elif ARP in packet:
                    ip_src = safe_string(packet[ARP].psrc)
                    ip_dst = safe_string(packet[ARP].pdst)

                if subject_mac:
                    if (
                        eth_src.lower() == subject_mac
                        and ip_src
                        and ip_src not in {"0.0.0.0", "::"}
                        and endpoint_class(ip_src) in {"private", "link_local", "loopback"}
                    ):
                        subject_ips.add(ip_src)
                    if (
                        eth_dst.lower() == subject_mac
                        and ip_dst
                        and ip_dst not in {"0.0.0.0", "::"}
                        and endpoint_class(ip_dst) in {"private", "link_local", "loopback"}
                    ):
                        subject_ips.add(ip_dst)

                tcp_srcport = safe_string(packet[TCP].sport) if TCP in packet else ""
                tcp_dstport = safe_string(packet[TCP].dport) if TCP in packet else ""
                udp_srcport = safe_string(packet[UDP].sport) if UDP in packet else ""
                udp_dstport = safe_string(packet[UDP].dport) if UDP in packet else ""

                raw_bytes = bytes(packet[Raw].load) if Raw in packet else b""
                http_info = parse_http_fields(raw_bytes, tcp_srcport or udp_srcport, tcp_dstport or udp_dstport) if raw_bytes else {
                    "http_method": "",
                    "http_host": "",
                    "http_request_uri": "",
                    "http_full_url": "",
                    "http_location": "",
                    "http_protocol": "",
                    "http_kind": "",
                }
                tls_info = extract_tls_metadata(raw_bytes) if raw_bytes else {
                    "tls_version": "",
                    "tls_sni": "",
                    "tls_cert_subject": "",
                    "tls_cert_issuer": "",
                    "tls_cert_hostname": "",
                }
                dns_fields = extract_dns_fields(packet)

                protocol = choose_protocol(packet, http_info, tls_info)
                transport_class = transport_class_for_packet(protocol, tls_info["tls_version"])
                layer_names = get_layer_names(packet)
                if protocol and protocol not in layer_names:
                    layer_names.append(protocol)
                payload_preview = safe_payload_preview(raw_bytes)

                packet_row = {
                    "frame_number": packet_count,
                    "timestamp": timestamp,
                    "frame_len": frame_len,
                    "frame_protocols": ":".join(layer_names),
                    "eth_src": eth_src or "not observed",
                    "eth_dst": eth_dst or "not observed",
                    "ip_src": ip_src or "not observed",
                    "ip_dst": ip_dst or "not observed",
                    "tcp_srcport": tcp_srcport or "not observed",
                    "tcp_dstport": tcp_dstport or "not observed",
                    "udp_srcport": udp_srcport or "not observed",
                    "udp_dstport": udp_dstport or "not observed",
                    "protocol": protocol,
                    "dns_qry_name": dns_fields["dns_qry_name"] or "not observed",
                    "dns_resp_name": dns_fields["dns_resp_name"] or "not observed",
                    "dns_a": dns_fields["dns_a"] or "not observed",
                    "http_method": http_info["http_method"] or "not observed",
                    "http_host": http_info["http_host"] or "not observed",
                    "http_request_uri": http_info["http_request_uri"] or "not observed",
                    "http_full_url": http_info["http_full_url"] or "not observed",
                    "tls_version": tls_info["tls_version"] or "not observed",
                    "tls_sni": tls_info["tls_sni"] or "not observed",
                    "tls_cert_subject": tls_info["tls_cert_subject"] or "not observed",
                    "tls_cert_issuer": tls_info["tls_cert_issuer"] or "not observed",
                    "payload_preview_ascii": payload_preview or "not observed",
                }
                packet_writer.writerow(packet_row)

                analysis["protocol_packets"][protocol] += 1
                analysis["protocol_bytes"][protocol] += frame_len
                existing_transport = analysis["protocol_transport_class"].get(protocol, "unknown")
                transport_rank = {"unknown": 0, "insecure": 1, "secure": 2}
                if transport_rank.get(transport_class, 0) > transport_rank.get(existing_transport, 0):
                    analysis["protocol_transport_class"][protocol] = transport_class

                destination_bucket = timestamp[:16]
                analysis["time_buckets"][destination_bucket]["packets"] += 1
                analysis["time_buckets"][destination_bucket]["bytes"] += frame_len

                hostnames = domain_candidates(dns_fields, http_info, tls_info)
                for hostname in hostnames:
                    analysis["domain_counter"][hostname] += 1

                if http_info["http_full_url"]:
                    analysis["url_counter"][http_info["http_full_url"]] += 1

                destination_port = tcp_dstport or udp_dstport
                if ip_dst and destination_port:
                    analysis["endpoint_counter"][format_endpoint_label(ip_dst, destination_port)] += 1

                lowered_preview = payload_preview.lower()
                if payload_preview and any(
                    keyword in lowered_preview
                    for keyword in ["notify *", "http/1.1", "get /", "post /", "uuid:", "rootdesc.xml", "serial"]
                ):
                    analysis["payload_counter"][payload_preview[:120]] += 1

                if DNS in packet:
                    query_name = dns_fields["dns_qry_name"].split(";")[0] if dns_fields["dns_qry_name"] else ""
                    for answer_ip in [value for value in dns_fields["dns_a"].split(";") if value]:
                        if query_name:
                            analysis["ip_to_domains"][answer_ip].add(query_name)

                tls_hostname = tls_info["tls_cert_hostname"] or tls_info["tls_sni"]
                if tls_hostname and classify_observed_name(tls_hostname) == "domain" and ip_dst:
                    analysis["ip_to_domains"][ip_dst].add(tls_hostname)
                if tls_hostname and classify_observed_name(tls_hostname) == "domain" and ip_src and tls_info["tls_cert_subject"]:
                    analysis["ip_to_domains"][ip_src].add(tls_hostname)

                if ip_dst:
                    dst_class = endpoint_class(ip_dst)
                    dest_stats = analysis["destination_stats"][ip_dst]
                    dest_stats["packet_count"] += 1
                    dest_stats["byte_count"] += frame_len
                    dest_stats["endpoint_class"] = dst_class
                    for hostname in hostnames:
                        dest_stats["hostnames"][hostname] += 1
                    dest_stats["protocols"][protocol] += 1
                    dest_stats["transport_classes"][transport_class] += 1
                    if tcp_dstport:
                        dest_stats["destination_ports"][tcp_dstport] += 1
                    if udp_dstport:
                        dest_stats["destination_ports"][udp_dstport] += 1
                    if dst_class == "public":
                        analysis["public_endpoint_counter"][ip_dst] += 1

                if destination_port:
                    analysis["port_counter"][int(destination_port)] += 1
                    port_stats = analysis["port_stats"][int(destination_port)]
                    port_stats["byte_count"] += frame_len
                    port_stats["protocols"][protocol] += 1
                    if ip_dst:
                        port_stats["endpoint_classes"][endpoint_class(ip_dst)] += 1
                        port_stats["destinations"][ip_dst] += 1
                    for hostname in hostnames:
                        port_stats["hostnames"][hostname] += 1

                if protocol in {"HTTP", "SSDP"}:
                    analysis["plaintext_http_count"] += 1
                    if len(analysis["http_samples"]) < 8:
                        analysis["http_samples"].append(
                            {
                                "timestamp": timestamp,
                                "protocol": protocol,
                                "method": http_info["http_method"] or "response",
                                "host": http_info["http_host"] or http_info["http_full_url"] or ip_dst or ip_src,
                                "uri": http_info["http_request_uri"] or http_info["http_full_url"] or payload_preview,
                                "preview": payload_preview,
                            }
                        )

                if tls_info["tls_version"] and len(analysis["tls_samples"]) < 8:
                    analysis["tls_samples"].append(
                        {
                            "timestamp": timestamp,
                            "dst": ip_dst or ip_src,
                            "tls_version": tls_info["tls_version"],
                            "tls_sni": tls_info["tls_sni"] or "not observed",
                            "tls_cert_subject": tls_info["tls_cert_subject"] or "not observed",
                        }
                    )

                detection_text = raw_text_for_detection(raw_bytes)
                for hit in detect_plaintext_identifiers(detection_text):
                    identifier_key = (hit["kind"], hit["value"])
                    if identifier_key in analysis["identifier_seen"]:
                        continue
                    analysis["identifier_seen"].add(identifier_key)
                    analysis["identifier_hits"][hit["kind"]].append(
                        {
                            "timestamp": timestamp,
                            "value": hit["value"],
                            "protocol": protocol,
                            "src_ip": ip_src,
                            "dst_ip": ip_dst,
                        }
                    )

                subject_as_src = bool(subject_ips and ip_src in subject_ips)
                subject_as_dst = bool(subject_ips and ip_dst in subject_ips)
                if protocol == "HTTP":
                    if subject_as_src and http_info["http_kind"] == "response" and tcp_srcport:
                        analysis["device_service_ports"].add(int(tcp_srcport))
                    elif subject_as_dst and http_info["http_kind"] == "request" and tcp_dstport:
                        analysis["device_service_ports"].add(int(tcp_dstport))
                elif protocol == "SSDP":
                    if subject_as_src and udp_srcport == "1900":
                        analysis["device_service_ports"].add(int(udp_srcport))
                    elif subject_as_dst and udp_dstport == "1900":
                        analysis["device_service_ports"].add(int(udp_dstport))
                elif subject_as_src and TCP in packet and ((int(packet[TCP].flags) & 0x12) == 0x12) and tcp_srcport:
                    analysis["device_service_ports"].add(int(tcp_srcport))

                update_session_state(
                    packet=packet,
                    packet_time=packet_time,
                    frame_len=frame_len,
                    protocol=protocol,
                    transport_class=transport_class,
                    hostnames=hostnames,
                    active_sessions=active_sessions,
                    completed_sessions=completed_sessions,
                )

        completed_sessions.extend(active_sessions.values())

    analysis["capture_timing"] = {
        "active_days": len(active_days),
        "forward_gaps_over_60s": forward_gaps_over_60s,
        "forward_gaps_over_1h": forward_gaps_over_1h,
        "forward_gaps_over_1d": forward_gaps_over_1d,
        "largest_gap_seconds": largest_gap_seconds,
        "negative_timestamp_jumps": negative_timestamp_jumps,
        "largest_negative_jump_seconds": largest_negative_jump_seconds,
    }

    report_session_rows = build_report_session_rows(
        sessions=completed_sessions,
        ip_domain_map=analysis["ip_to_domains"],
        device_service_ports=analysis["device_service_ports"],
    )
    insecure_sessions = sum(1 for row in report_session_rows if row["transport_class"] == "insecure")
    secure_sessions = sum(1 for row in report_session_rows if row["transport_class"] == "secure")

    seen_alerts: set[tuple[str, str, str]] = set()

    identifier_groups = analysis["identifier_hits"]
    observed_identifier_samples = (
        identifier_groups.get("device_identifier", [])
        + identifier_groups.get("serial_like_identifier", [])
        + identifier_groups.get("mac", [])
        + identifier_groups.get("email", [])
        + identifier_groups.get("phone", [])
        + identifier_groups.get("token", [])
        + identifier_groups.get("username", [])
    )
    if observed_identifier_samples:
        sample = observed_identifier_samples[0]
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="plaintext_identifier_exposure",
            severity="medium",
            timestamp=sample["timestamp"],
            explanation="Plaintext payload content exposed an identifier in visible LAN traffic. This is directly observed and not inferred from aggregates.",
            value_snippet=sample["value"],
            recommendation="Reduce plaintext identifier exposure in discovery / metadata services and prefer authenticated encrypted management paths.",
        )

    if analysis["http_samples"]:
        sample = analysis["http_samples"][0]
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="plaintext_http_observed",
            severity="medium",
            timestamp=sample["timestamp"],
            explanation="Plaintext HTTP-like traffic was directly observed. In this capture it includes SSDP/UPnP discovery and local HTTP service interactions.",
            value_snippet=f"{sample['protocol']} {sample['method']} {sample['host']} {sample['uri']}".strip(),
            recommendation="Use encrypted local management interfaces where possible and disable unnecessary plaintext discovery services.",
        )

    if analysis["domain_counter"] or analysis["url_counter"]:
        if analysis["domain_counter"]:
            top_hostname, top_count = analysis["domain_counter"].most_common(1)[0]
        else:
            top_hostname, top_count = analysis["url_counter"].most_common(1)[0]
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="hostname_exposure",
            severity="low",
            timestamp=analysis["http_samples"][0]["timestamp"] if analysis["http_samples"] else "not observed",
            explanation="Domain names or URLs were directly visible in DNS, HTTP headers, or TLS metadata. This alert excludes raw IP:port endpoints so the wording stays consistent with what was observed.",
            value_snippet=f"{top_hostname} ({top_count} packets/samples)",
            recommendation="Inventory exposed service names and reduce unnecessarily descriptive discovery metadata.",
        )

    suspicious_ports = []
    for port, stats in analysis["port_stats"].items():
        endpoint_classes = stats["endpoint_classes"]
        if port not in COMMON_PORTS or (port >= 49152 and "private" in endpoint_classes):
            suspicious_ports.append((port, stats))
    suspicious_ports.sort(key=lambda item: analysis["port_counter"][item[0]], reverse=True)
    if suspicious_ports:
        port, _stats = suspicious_ports[0]
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="suspicious_port",
            severity="low" if port in {5222} else "medium",
            timestamp=analysis["http_samples"][0]["timestamp"] if analysis["http_samples"] else "not observed",
            explanation="A non-default or high-numbered destination/service port was observed and should be reviewed for necessity and exposure scope.",
            value_snippet=str(port),
            recommendation="Confirm the port is expected for this device role and restrict reachability if it is only needed on trusted segments.",
        )

    if analysis["plaintext_http_count"]:
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="weak_transport",
            severity="medium",
            timestamp=analysis["http_samples"][0]["timestamp"],
            explanation="Insecure transport was directly observed for local discovery or service traffic. TLS was not used for those exchanges.",
            value_snippet="HTTP / SSDP / DNS / NTP plaintext traffic",
            recommendation="Limit plaintext services to tightly controlled networks and prefer encrypted management or metadata channels.",
        )

    if secure_sessions and insecure_sessions:
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="mixed_transport",
            severity="medium",
            timestamp=analysis["tls_samples"][0]["timestamp"] if analysis["tls_samples"] else "not observed",
            explanation="Both secure and insecure transports were directly observed in the same capture, indicating uneven protection across device functions.",
            value_snippet=f"secure_sessions={secure_sessions}, insecure_sessions={insecure_sessions}",
            recommendation="Prioritize encrypting the remaining plaintext services or isolate them from less-trusted network segments.",
        )

    if analysis["public_endpoint_counter"]:
        public_ip, public_count = max(
            analysis["public_endpoint_counter"].items(),
            key=lambda item: (bool(analysis["ip_to_domains"].get(item[0], set())), item[1]),
        )
        public_hostnames = dedupe_join(sorted(analysis["ip_to_domains"].get(public_ip, set()))) or "not observed"
        value_snippet = (
            f"{public_ip} ({public_hostnames}; {public_count} packets)"
            if public_hostnames != "not observed"
            else f"{public_ip} ({public_count} packets; hostname not observed)"
        )
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="third_party_destination",
            severity="medium",
            timestamp=analysis["tls_samples"][0]["timestamp"] if analysis["tls_samples"] else "not observed",
            explanation="Communication with public third-party infrastructure was directly observed. This is expected for some IoT devices but expands dependency and privacy surface.",
            value_snippet=value_snippet,
            recommendation="Document expected cloud dependencies and alert on unexpected public endpoints in future captures.",
        )

    if analysis["public_endpoint_counter"]:
        background_candidates = [
            (ip_value, count)
            for ip_value, count in analysis["public_endpoint_counter"].items()
            if count >= 25
        ]
        if background_candidates:
            ip_value, count = sorted(background_candidates, key=lambda item: item[1], reverse=True)[0]
            add_alert(
                analysis["alerts"],
                seen_alerts,
                subject="SamsungCamera_00166cab6b88",
                category="background_communication",
                severity="medium",
                timestamp=analysis["tls_samples"][0]["timestamp"] if analysis["tls_samples"] else "not observed",
                explanation="Repeated communication with the same public endpoint suggests persistent or recurring background activity.",
                value_snippet=f"{ip_value} ({count} packets)",
                recommendation="Validate that the recurring background connection is vendor-expected and covered by the product's data-flow documentation.",
            )

    if analysis["device_service_ports"]:
        add_alert(
            analysis["alerts"],
            seen_alerts,
            subject="SamsungCamera_00166cab6b88",
            category="attack_surface_indicator",
            severity="high",
            timestamp=analysis["http_samples"][0]["timestamp"] if analysis["http_samples"] else "not observed",
            explanation="The device exposed service behavior on identifiable local ports, including plaintext discovery or HTTP service responses.",
            value_snippet=format_port_list(analysis["device_service_ports"], limit=20),
            recommendation="Minimize exposed local services, enforce authentication where supported, and constrain device reachability on the LAN.",
        )

    compliance_rows = []
    insecure_explanation = (
        "Direct evidence: plaintext local discovery / HTTP metadata was observed."
        if analysis["plaintext_http_count"]
        else "Direct evidence: plaintext HTTP metadata was not observed in the extracted plaintext view."
    )
    identifier_explanation = (
        "Direct evidence: plaintext device/service identifiers were observed in LAN-visible metadata."
        if observed_identifier_samples
        else "Direct evidence: plaintext identifiers were not observed in visible payloads."
    )
    compliance_rows.append(
        {
            "flag_name": "GDPR_Art32a_flag",
            "status": "FAIL" if analysis["plaintext_http_count"] and observed_identifier_samples else "WARN",
            "explanation": (
                f"Heuristic evidence flag, not formal compliance proof. {insecure_explanation} {identifier_explanation} "
                "Email, phone, token, and username values were not directly observed here, so this row should be read as a confidentiality-control warning for metadata exposure rather than proof of strong personal-PII leakage."
            ),
        }
    )
    compliance_rows.append(
        {
            "flag_name": "ENISA_GP_TM_50_flag",
            "status": "FAIL" if secure_sessions and insecure_sessions else "WARN",
            "explanation": (
                "Heuristic evidence flag, not formal compliance proof. Direct evidence shows mixed transport: some traffic is TLS-protected while discovery / metadata exchanges remain plaintext. "
                "This supports a transport-hardening concern, but it does not by itself prove full control failure across every device function."
            ),
        }
    )
    compliance_rows.append(
        {
            "flag_name": "ENISA_GP_OP_04_flag",
            "status": "WARN" if analysis["public_endpoint_counter"] else "PASS",
            "explanation": (
                "Heuristic evidence flag, not formal compliance proof. Direct evidence shows communication with public endpoints, so the observed destinations should be checked against approved operational data-flow expectations. "
                "If the device's expected endpoint inventory is incomplete, the capture is insufficient for a stronger conclusion."
            ),
        }
    )
    compliance_rows.append(
        {
            "flag_name": "CRA_attack_surface_flag",
            "status": "FAIL" if analysis["device_service_ports"] else "WARN",
            "explanation": (
                "Heuristic evidence flag, not formal compliance proof. Direct evidence shows local service exposure via SSDP/UPnP and HTTP behavior, indicating reachable attack surface on the observed network segment. "
                "Internet exposure, exploitability, and authentication strength were not directly tested in this passive PCAP."
            ),
        }
    )
    analysis["compliance_flags"] = compliance_rows

    capped_alerts = analysis["alerts"][:25]
    risk_score = min(100, sum(SEVERITY_SCORES.get(alert["severity"], 0) for alert in capped_alerts))
    risk_score = max(risk_score, 20 if analysis["device_service_ports"] else 0)
    analysis["overall_risk_score"] = risk_score

    generate_report_artifacts(
        analysis=analysis,
        sessions=completed_sessions,
        packet_count=packet_count,
        total_bytes=total_bytes,
        capture_start=capture_start,
        capture_end=capture_end,
        subject_mac=subject_mac,
        subject_ips=subject_ips,
    )


if __name__ == "__main__":
    analyze_pcap()
