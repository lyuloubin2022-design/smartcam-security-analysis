from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data" / "generated"
OUTPUTS_DIR = ROOT_DIR / "outputs"
FIGURES_DIR = OUTPUTS_DIR / "figures"
TABLES_DIR = OUTPUTS_DIR / "tables"

SEED = 20260416

DEVICE_PROFILES = [
    {
        "device_name": "cam_livingroom",
        "device_type": "camera_like_device",
        "src_ip": "192.168.10.20",
        "approved_domains": ["vendorvideo.example", "resolver.home.arpa"],
        "scenario_role": "Camera-like device with secure control traffic and insecure diagnostic fallback.",
        "controlled_focus": "Plaintext identifiers, plaintext HTTP, contextual hostname exposure, mixed transport.",
    },
    {
        "device_name": "plug_kitchen",
        "device_type": "smart_plug_light_device",
        "src_ip": "192.168.10.35",
        "approved_domains": ["iotcontrol.example", "resolver.home.arpa"],
        "scenario_role": "Smart plug / light device with secure MQTT control and recurring third-party beaconing.",
        "controlled_focus": "Background communication, third-party destination, mixed transport, plaintext leakage.",
    },
    {
        "device_name": "hub_gateway",
        "device_type": "hub_controller_gateway",
        "src_ip": "192.168.10.10",
        "approved_domains": ["smarthub.example", "resolver.home.arpa"],
        "scenario_role": "Hub / gateway with legacy backup path and externally reachable management surface.",
        "controlled_focus": "Weak TLS, suspicious port, attack surface indicator, third-party destination.",
    },
]

APP_PROTOCOLS = {"HTTP", "HTTPS", "MQTT", "TCP", "RTSP"}
LEGACY_TLS_VERSIONS = {"TLS1.0", "TLS1.1"}
SUSPICIOUS_PORTS = {23, 2323, 31337}
ATTACK_SURFACE_PORTS = {22, 80, 443, 554, 2323, 8443}
CONTEXTUAL_HOSTNAME_TERMS = (
    "family-room",
    "livingroom",
    "kitchen",
    "garage",
    "bedroom",
    "frontdoor",
    "home-",
)
SEVERITY_WEIGHTS = {"low": 2, "medium": 5, "high": 8, "critical": 12}
