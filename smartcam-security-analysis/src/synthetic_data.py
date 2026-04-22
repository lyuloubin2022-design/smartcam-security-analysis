from __future__ import annotations

from datetime import datetime, timedelta
from random import Random

from src.constants import DEVICE_PROFILES, SEED


def _ephemeral_port(rng: Random) -> int:
    return rng.randint(32768, 60999)


def _timestamp(base: datetime, offset_minutes: int, rng: Random, jitter_minutes: int = 2) -> str:
    jitter = rng.randint(-jitter_minutes, jitter_minutes)
    return (base + timedelta(minutes=offset_minutes + jitter)).isoformat(timespec="seconds")


def _build_record(
    *,
    timestamp: str,
    device_name: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    transport_class: str,
    hostname: str,
    url: str,
    http_method: str,
    payload_preview: str,
    tls_present: bool,
    tls_version: str,
    packet_length: int,
    packet_count: int,
    direction: str,
    scenario_label: str,
) -> dict[str, object]:
    return {
        "timestamp": timestamp,
        "device_name": device_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "transport_class": transport_class,
        "hostname": hostname,
        "url": url,
        "http_method": http_method,
        "payload_preview": payload_preview,
        "tls_present": tls_present,
        "tls_version": tls_version,
        "packet_length": packet_length,
        "packet_count": packet_count,
        "byte_count": packet_length * packet_count,
        "direction": direction,
        "scenario_label": scenario_label,
    }


def _outbound(
    profile: dict[str, object],
    *,
    timestamp: str,
    rng: Random,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    transport_class: str,
    hostname: str,
    url: str = "",
    http_method: str = "",
    payload_preview: str = "",
    tls_present: bool = False,
    tls_version: str = "",
    packet_length: int = 220,
    packet_count: int = 4,
    scenario_label: str,
) -> dict[str, object]:
    return _build_record(
        timestamp=timestamp,
        device_name=str(profile["device_name"]),
        src_ip=str(profile["src_ip"]),
        dst_ip=dst_ip,
        src_port=_ephemeral_port(rng),
        dst_port=dst_port,
        protocol=protocol,
        transport_class=transport_class,
        hostname=hostname,
        url=url,
        http_method=http_method,
        payload_preview=payload_preview,
        tls_present=tls_present,
        tls_version=tls_version,
        packet_length=packet_length,
        packet_count=packet_count,
        direction="outbound",
        scenario_label=scenario_label,
    )


def _inbound(
    profile: dict[str, object],
    *,
    timestamp: str,
    rng: Random,
    src_ip: str,
    dst_port: int,
    protocol: str,
    transport_class: str,
    hostname: str,
    payload_preview: str,
    scenario_label: str,
    packet_length: int = 96,
    packet_count: int = 3,
) -> dict[str, object]:
    return _build_record(
        timestamp=timestamp,
        device_name=str(profile["device_name"]),
        src_ip=src_ip,
        dst_ip=str(profile["src_ip"]),
        src_port=_ephemeral_port(rng),
        dst_port=dst_port,
        protocol=protocol,
        transport_class=transport_class,
        hostname=hostname,
        url="",
        http_method="",
        payload_preview=payload_preview,
        tls_present=False,
        tls_version="",
        packet_length=packet_length,
        packet_count=packet_count,
        direction="inbound",
        scenario_label=scenario_label,
    )


def _camera_rows(profile: dict[str, object], base: datetime, rng: Random) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for index in range(18):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 40 * index, rng),
                rng=rng,
                dst_ip="198.51.100.20",
                dst_port=443,
                protocol="HTTPS",
                transport_class="TCP",
                hostname="api.vendorvideo.example",
                url="https://api.vendorvideo.example/v1/heartbeat",
                http_method="POST",
                payload_preview="status=ok;fps=15;motion=false;fw=1.4.2",
                tls_present=True,
                tls_version="TLS1.3",
                packet_length=rng.randint(360, 520),
                packet_count=rng.randint(6, 11),
                scenario_label="baseline_secure_heartbeat",
            )
        )

    for index in range(6):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 10 + 80 * index, rng),
                rng=rng,
                dst_ip="198.51.100.24",
                dst_port=443,
                protocol="HTTPS",
                transport_class="TCP",
                hostname="stream.vendorvideo.example",
                url="https://stream.vendorvideo.example/v2/session",
                http_method="POST",
                payload_preview="stream=adaptive;codec=h264;event=healthcheck",
                tls_present=True,
                tls_version="TLS1.3",
                packet_length=rng.randint(420, 640),
                packet_count=rng.randint(7, 12),
                scenario_label="baseline_media_control",
            )
        )

    for index in range(8):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 5 + 90 * index, rng),
                rng=rng,
                dst_ip="192.168.10.1",
                dst_port=53,
                protocol="DNS",
                transport_class="UDP",
                hostname="resolver.home.arpa",
                payload_preview="query=api.vendorvideo.example",
                packet_length=rng.randint(88, 132),
                packet_count=1,
                scenario_label="baseline_name_resolution",
            )
        )

    for index in range(4):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 7 + 360 * index, rng),
                rng=rng,
                dst_ip="198.51.100.5",
                dst_port=123,
                protocol="NTP",
                transport_class="UDP",
                hostname="time.vendorvideo.example",
                payload_preview="clock_sync",
                packet_length=rng.randint(76, 96),
                packet_count=1,
                scenario_label="baseline_time_sync",
            )
        )

    rows.append(
        _outbound(
            profile,
            timestamp=_timestamp(base, 445, rng, 0),
            rng=rng,
            dst_ip="198.51.100.27",
            dst_port=80,
            protocol="HTTP",
            transport_class="TCP",
            hostname="diag.vendorvideo.example",
            url="http://diag.vendorvideo.example/upload?device_id=CAM-A19F-7781",
            http_method="POST",
            payload_preview="owner_email=resident@example.net&phone=+447700900123&auth_token=tok_cam_a19f4411",
            packet_length=388,
            packet_count=6,
            scenario_label="controlled_plaintext_diagnostic_post",
        )
    )

    rows.append(
        _outbound(
            profile,
            timestamp=_timestamp(base, 610, rng, 0),
            rng=rng,
            dst_ip="198.51.100.28",
            dst_port=80,
            protocol="HTTP",
            transport_class="TCP",
            hostname="family-room-cam.vendorvideo.example",
            url="http://family-room-cam.vendorvideo.example/status?device_id=CAM-A19F-7781",
            http_method="GET",
            payload_preview="serial=CAM-A19F-7781;mode=maintenance",
            packet_length=304,
            packet_count=4,
            scenario_label="controlled_contextual_hostname_plaintext",
        )
    )

    rows.append(
        _outbound(
            profile,
            timestamp=_timestamp(base, 675, rng, 0),
            rng=rng,
            dst_ip="203.0.113.41",
            dst_port=443,
            protocol="HTTPS",
            transport_class="TCP",
            hostname="video-metrics.analytics-partner.example",
            url="https://video-metrics.analytics-partner.example/v1/upload",
            http_method="POST",
            payload_preview="clip_len=12;event=occupancy_sample",
            tls_present=True,
            tls_version="TLS1.2",
            packet_length=452,
            packet_count=5,
            scenario_label="controlled_third_party_partner_telemetry",
        )
    )

    return rows


def _plug_rows(profile: dict[str, object], base: datetime, rng: Random) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for index in range(24):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 30 * index, rng),
                rng=rng,
                dst_ip="198.51.100.60",
                dst_port=8883,
                protocol="MQTT",
                transport_class="TCP",
                hostname="broker.iotcontrol.example",
                payload_preview="topic=device/status;power=on;watts=13.2",
                tls_present=True,
                tls_version="TLS1.3",
                packet_length=rng.randint(210, 320),
                packet_count=rng.randint(4, 7),
                scenario_label="baseline_secure_mqtt_control",
            )
        )

    for index in range(6):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 12 + 150 * index, rng),
                rng=rng,
                dst_ip="198.51.100.61",
                dst_port=443,
                protocol="HTTPS",
                transport_class="TCP",
                hostname="api.iotcontrol.example",
                url="https://api.iotcontrol.example/v1/device/sync",
                http_method="POST",
                payload_preview="scene=daytime;fw=2.0.1;relay_state=on",
                tls_present=True,
                tls_version="TLS1.2",
                packet_length=rng.randint(260, 380),
                packet_count=rng.randint(4, 8),
                scenario_label="baseline_secure_api_sync",
            )
        )

    for index in range(6):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 18 + 210 * index, rng),
                rng=rng,
                dst_ip="192.168.10.1",
                dst_port=53,
                protocol="DNS",
                transport_class="UDP",
                hostname="resolver.home.arpa",
                payload_preview="query=broker.iotcontrol.example",
                packet_length=rng.randint(86, 126),
                packet_count=1,
                scenario_label="baseline_name_resolution",
            )
        )

    for index in range(10):
        payload = "watts=13.4;state=standby;beacon=1"
        if index == 3:
            payload = "device_id=PLUG-K-8821&support_phone=+447700900124&state=standby"
        if index == 7:
            payload = "session_token=tok_plug_8821&diagnostic=power_cycle"
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 15 + 45 * index, rng, 1),
                rng=rng,
                dst_ip="203.0.113.80",
                dst_port=8080,
                protocol="HTTP",
                transport_class="TCP",
                hostname="telemetry.ads-insight.example",
                url="http://telemetry.ads-insight.example/beacon",
                http_method="POST",
                payload_preview=payload,
                packet_length=rng.randint(200, 290),
                packet_count=rng.randint(3, 5),
                scenario_label="controlled_background_third_party_beacon",
            )
        )

    return rows


def _hub_rows(profile: dict[str, object], base: datetime, rng: Random) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for index in range(12):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 25 + 60 * index, rng),
                rng=rng,
                dst_ip="198.51.100.90",
                dst_port=443,
                protocol="HTTPS",
                transport_class="TCP",
                hostname="controller.smarthub.example",
                url="https://controller.smarthub.example/v1/poll",
                http_method="POST",
                payload_preview="devices=3;mode=auto;scene=occupied",
                tls_present=True,
                tls_version="TLS1.3",
                packet_length=rng.randint(300, 430),
                packet_count=rng.randint(4, 8),
                scenario_label="baseline_secure_controller_poll",
            )
        )

    for index in range(8):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 40 + 90 * index, rng),
                rng=rng,
                dst_ip="198.51.100.91",
                dst_port=8883,
                protocol="MQTT",
                transport_class="TCP",
                hostname="broker.smarthub.example",
                payload_preview="topic=mesh/status;topology=stable",
                tls_present=True,
                tls_version="TLS1.2",
                packet_length=rng.randint(220, 310),
                packet_count=rng.randint(4, 7),
                scenario_label="baseline_secure_mesh_broker",
            )
        )

    for index in range(6):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 14 + 205 * index, rng),
                rng=rng,
                dst_ip="192.168.10.1",
                dst_port=53,
                protocol="DNS",
                transport_class="UDP",
                hostname="resolver.home.arpa",
                payload_preview="query=controller.smarthub.example",
                packet_length=rng.randint(84, 124),
                packet_count=1,
                scenario_label="baseline_name_resolution",
            )
        )

    for index in range(2):
        rows.append(
            _outbound(
                profile,
                timestamp=_timestamp(base, 220 + 540 * index, rng, 0),
                rng=rng,
                dst_ip="198.51.100.94",
                dst_port=443,
                protocol="HTTPS",
                transport_class="TCP",
                hostname="legacy-backup.smarthub.example",
                url="https://legacy-backup.smarthub.example/archive",
                http_method="POST",
                payload_preview="archive=daily_delta;batch=household-a",
                tls_present=True,
                tls_version="TLS1.0",
                packet_length=498,
                packet_count=6,
                scenario_label="controlled_legacy_backup_tls10",
            )
        )

    rows.append(
        _outbound(
            profile,
            timestamp=_timestamp(base, 795, rng, 0),
            rng=rng,
            dst_ip="203.0.113.110",
            dst_port=2323,
            protocol="TCP",
            transport_class="TCP",
            hostname="support-tunnel.remoteassist.example",
            payload_preview="serial=HUB-99128&auth_token=tok_hub_99128&mode=remote_shell",
            packet_length=336,
            packet_count=5,
            scenario_label="controlled_remote_support_tunnel",
        )
    )

    for minute_offset in (797, 798, 799):
        rows.append(
            _inbound(
                profile,
                timestamp=_timestamp(base, minute_offset, rng, 0),
                rng=rng,
                src_ip="203.0.113.90",
                dst_port=8443,
                protocol="TCP",
                transport_class="TCP",
                hostname="hub-admin.smarthub.example",
                payload_preview="unsolicited SYN to management interface",
                scenario_label="controlled_inbound_admin_probe",
            )
        )

    rows.append(
        _outbound(
            profile,
            timestamp=_timestamp(base, 505, rng, 0),
            rng=rng,
            dst_ip="203.0.113.120",
            dst_port=443,
            protocol="HTTPS",
            transport_class="TCP",
            hostname="backup-storage.partnercloud.example",
            url="https://backup-storage.partnercloud.example/snapshot",
            http_method="POST",
            payload_preview="snapshot=weekly;devices=3",
            tls_present=True,
            tls_version="TLS1.2",
            packet_length=470,
            packet_count=7,
            scenario_label="controlled_third_party_backup_target",
        )
    )

    return rows


def generate_device_profiles() -> list[dict[str, object]]:
    return [
        {
            "device_name": profile["device_name"],
            "device_type": profile["device_type"],
            "src_ip": profile["src_ip"],
            "approved_domains": ",".join(profile["approved_domains"]),
            "scenario_role": profile["scenario_role"],
            "controlled_focus": profile["controlled_focus"],
            "synthetic_controlled": "yes",
        }
        for profile in DEVICE_PROFILES
    ]


def generate_synthetic_sessions(seed: int = SEED) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rng = Random(seed)
    base = datetime(2026, 4, 14, 6, 0, 0)

    profile_lookup = {profile["device_name"]: profile for profile in DEVICE_PROFILES}

    rows = []
    rows.extend(_camera_rows(profile_lookup["cam_livingroom"], base, rng))
    rows.extend(_plug_rows(profile_lookup["plug_kitchen"], base, rng))
    rows.extend(_hub_rows(profile_lookup["hub_gateway"], base, rng))

    rows.sort(key=lambda row: row["timestamp"])
    return rows, generate_device_profiles()
