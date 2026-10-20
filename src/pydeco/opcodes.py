"""Registry of Deco business v2 opcodes, mapped from a captured live session.

Each entry: human name -> (opcode, category, description, known result keys).
Observed convention: a "base" opcode serves the GET ``{"config_version": ...}``; neighbouring
opcodes serve writes ``{"params": {...}}`` (ADD/SET/MODIFY/REMOVE), the response being
``{"error_code": 0}``. Writes marked (C) are CONFIRMED from capture; the others are inferred from
the pattern and should be confirmed on a real device before use.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Op:
    code: int
    category: str
    description: str
    result_keys: tuple[str, ...] = field(default_factory=tuple)
    writable: bool = False          # a SET/ADD/... exists for this domain
    confirmed_set: bool = False     # a write was observed in capture


# --- Reads (GET) ---------------------------------------------------------------------
# name -> Op
READ: dict[str, Op] = {
    "system_info":       Op(0x4001, "system", "System info: group, mode, components, status",
                            ("group_data", "operation_mode", "component_list", "working_status"), True, True),
    "wan_lan_status":    Op(0x4004, "network", "WAN/LAN status (IP, DNS, MTU, ping)", ("wan", "lan")),
    "ipv6":              Op(0x4006, "network", "IPv6 enable", ("enable_ipv6",)),
    "wifi_bands_info":   Op(0x4009, "wifi", "Radio info (2.4/5/6 GHz)", ("band5_1", "band6", "band2_4")),
    "device_list":       Op(0x400F, "devices", "Deco units in the mesh", ("device_list", "speed_diagnose")),
    "client_list_speed": Op(0x4014, "clients", "Per-client throughput", ("client_list_speed",)),
    "client_list":       Op(0x4018, "clients", "Client list (filterable)", ("client_list", "max_count")),
    "messages":          Op(0x4028, "system", "Notifications / messages", ("message_list",)),
    "iot_scan":          Op(0x4040, "iot", "IoT device scan", ("scan_status", "iot_client_list")),
    "rooms":             Op(0x4050, "home", "Rooms / spaces", ("space_count_max", "space_list")),
    "scenes":            Op(0x4070, "automation", "Scenes", ("scene_list", "action_count_max")),
    "tasks":             Op(0x4080, "automation", "Scheduled tasks / automations", ("task_list",)),
    "operation_mode":    Op(0x40A0, "network", "Router/AP mode", ("mode", "modeList"), True),
    "reservations":      Op(0x40C0, "dhcp", "DHCP address reservations", ("reservation_list",), True),
    "ddns":              Op(0x40D0, "network", "DDNS", ("ddns_enable", "ddns_info")),
    "iptv_vlan":         Op(0x420D, "network", "VLAN / IPTV", ("vlan",)),
    "lan_ip":            Op(0x4211, "network", "LAN IP, mask, DNS", ("lan_ip", "dns_server_ip")),
    "dhcp_server":       Op(0x4213, "dhcp", "DHCP server (range, gateway)", ("start_ip", "end_ip", "gateway")),
    "qos_bandwidth":     Op(0x4219, "network", "Bandwidth / QoS", ("upstream_bandwidth", "downstream_bandwidth")),
    "permissions":       Op(0x4229, "system", "Permission profiles", ("permission_profile", "manager_role_list")),
    "dhcp_leases":       Op(0x423D, "dhcp", "Active DHCP leases", ("client_lease",)),
    "upnp":              Op(0x424A, "network", "UPnP", ("enable",), True, True),
    "homeshield":        Op(0x4267, "security", "HomeShield (IoT/intrusion/web protection)",
                            ("iot_protection", "intrusion_prevention", "web_protection")),
    "parental_controls": Op(0x4270, "security", "Parental controls (owners, lists)",
                            ("owner_list", "black_list_max_count")),
    "timezone":          Op(0x427C, "system", "Time zone", ("tz_region", "time", "timezone")),
    "auto_update":       Op(0x427E, "system", "Automatic firmware update", ("enable_auto_update",)),
    "static_routes":     Op(0x4294, "network", "Static routes", ("route_static_list", "max_count")),
    "reboot_schedule":   Op(0x42E0, "system", "Scheduled reboot", ("enable", "setting")),
    "wifi_bands":        Op(0x42F0, "wifi", "Wi-Fi band settings", ("band5", "band6", "band2_4")),
    "firmware":          Op(0x4301, "system", "Available firmware", ("fw_list",)),
    "wireless_link":     Op(0x4318, "wifi", "Wireless link (backhaul) status", ("band2_4",)),
    "remote_management": Op(0x4370, "network", "Remote management", ("enable", "client_access", "server_setting")),
    "privacy_policy":    Op(0x4385, "system", "Accepted privacy policies", ("accepted_pp_list",)),
    "mlo":               Op(0x43B0, "wifi", "Multi-Link Operation (Wi-Fi 7)", ("mlo", "config_spec")),
    "cameras":           Op(0x43BE, "home", "Cameras (local/home mode)", ("local_only_mode", "home_mode")),
    "doh":               Op(0x43D0, "security", "Secure DNS (DoH)", ("enable", "config"), True, True),
    "network_access":    Op(0x4401, "security", "Network access control, guest, new-device notify",
                            ("access_control_mode", "guest_network_access", "new_device_notify")),
    "blocked_clients":   Op(0x4403, "security", "Blocked clients", ("client_list", "max_count")),
    "port_forwarding":   Op(0x4242, "network", "Port forwarding / port settings",
                            ("port_list", "linked_port", "fixed_wan_port")),
    "acl":               Op(0x4293, "security", "Access control list", ("client_list",)),
    "system_routes":     Op(0x4298, "network", "System routing table", ("route_system_list",)),
    "time_machine":      Op(0x432B, "automation", "Scheduled profiles (time machine)", ("time_machine_list",)),
    "usb_scan":          Op(0x4380, "usb", "USB scan", ("scan_time",)),
    "usb_devices":       Op(0x4381, "usb", "Connected USB devices", ("usb_device_list", "state")),
    "usb_sharing":       Op(0x4383, "usb", "USB sharing servers (media/Samba)", ("authentication", "server_list")),
    "vpn_server":        Op(0x43E0, "network", "VPN server (clients, speed limit)",
                            ("enable", "client_access", "hotspot_list", "speed_limit"), True, True),
    "vpn_discover":      Op(0x43E2, "network", "VPN client discovery", ("hotspot_list", "max_discover_time")),
    "speedtest":         Op(0x4010, "network", "Internet speed test results",
                            ("down_speed", "up_speed", "ping_time", "last_speed_test_time")),
    "led_schedule":      Op(0x401A, "system", "LED schedule / night mode",
                            ("schedule", "enable", "enable_night_mode", "led_individual_control"), True),
    "wps":               Op(0x4215, "wifi", "WPS", ("wps_list", "scanning_time"), True),
    "dns_servers":       Op(0x4228, "network", "DNS server selection",
                            ("type", "is_auto", "multi_server_list", "single_server_list")),
    "parental_pause":    Op(0x4278, "security", "Parental pause / time limit per client",
                            ("end_timestamp", "client_list", "enable", "remaining_time")),
    "family_care":       Op(0x4330, "security", "Family care / HomeShield parental", ("family_care",)),
    "vpn_config":        Op(0x4360, "network", "VPN server configuration", ("vpn_server", "server_config", "server_list")),
    "dpi_qos":           Op(0x4378, "network", "QoS / DPI (per-app bandwidth)",
                            ("most_used_apps", "dpi_qos_mode_info", "upstream_bandwidth")),
    "app_block_list":    Op(0x428B, "security", "App block list (paginated)", ("app_block_list",)),
    "blocked_period":    Op(0x43C4, "security", "Parental blocked time periods", ("blocked_period",)),
    "network_quality":   Op(0x4265, "network", "Network quality scan result", ("network_quality",)),
}

# --- Writes (SET/ADD/MODIFY/REMOVE) --------------------------------------------------
# name -> {opcode, params schema, confirmed?, doc}
WRITE: dict[str, dict] = {
    # CONFIRMED from capture
    "upnp_set":            {"opcode": 0x424B, "params": {"enable": bool}, "confirmed": True,
                            "doc": "Enable/disable UPnP"},
    "doh_set":             {"opcode": 0x43D1, "params": {"enable": bool}, "confirmed": True,
                            "doc": "Enable/disable secure DNS (DoH)"},
    "reservation_modify":  {"opcode": 0x40C2, "confirmed": True,
                            "params": {"ip": str, "mac": str, "original_ip": str, "original_mac": str},
                            "doc": "Modify an existing DHCP reservation"},
    "reservation_add":     {"opcode": 0x40C1, "confirmed": True,
                            "params": {"reservation_list": [{"ip": str, "mac": str}]},
                            "doc": "Add one or more DHCP reservations"},
    "ddns_set":            {"opcode": 0x40D1, "confirmed": True,
                            "params": {"ddns_status": bool, "mode": str, "domain_name": str},
                            "doc": "Configure DDNS (e.g. TP-Link DDNS)"},
    "vpn_server_set":      {"opcode": 0x43E1, "confirmed": True,
                            "params": {"enable": bool, "speed_limit": dict},
                            "doc": "Enable/configure the VPN server and its speed limit"},
    "ipv6_set":            {"opcode": 0x4007, "confirmed": True,
                            "params": {"enable_ipv6": bool, "wan": dict},
                            "doc": "Configure IPv6 / IPv6 WAN"},
    "guest_network_set":   {"opcode": 0x4008, "confirmed": True,
                            "params": {"band2_4": dict, "band5": dict},
                            "doc": "Configure the guest network (per band: SSID, limit, duration)"},
    "led_set":             {"opcode": 0x401B, "confirmed": True,
                            "params": {"enable": bool, "led_individual_control": bool},
                            "doc": "Turn the unit LEDs on/off"},
    "wps_set":             {"opcode": 0x4216, "confirmed": True,
                            "params": {"wps_list": [dict]},
                            "doc": "Start/stop WPS pairing"},
    "manager_roles_set":   {"opcode": 0x422A, "confirmed": True,
                            "params": {"manager_role_list": [dict]},
                            "doc": "Set manager roles (network/iot/client manager)"},
    "homeshield_features_set": {"opcode": 0x43C6, "confirmed": True,
                            "params": {"features": dict},
                            "doc": "Toggle HomeShield features (auc_secure, lib_auc, safe_things)"},
    "dns_servers_set":     {"opcode": 0x4011, "confirmed": True,
                            "params": {"is_auto": bool, "type": str, "select_server_id_list": [str]},
                            "doc": "Select DNS/speed-test servers"},
    # INFERRED from the GET=base / ADD=+1 / MODIFY=+2 / REMOVE=+3 pattern - CONFIRM before real use
    "reservation_remove":  {"opcode": 0x40C3, "params": {"mac": str}, "confirmed": False,
                            "doc": "(inferred) Remove a DHCP reservation"},
    "operation_mode_set":  {"opcode": 0x40A2, "params": {"mode": str}, "confirmed": False,
                            "doc": "(inferred) Switch Router/AP mode"},
}

ALL_BY_CODE = {op.code: name for name, op in READ.items()}
