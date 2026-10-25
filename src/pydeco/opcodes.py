"""Registry of Deco business v2 opcodes, mapped from captured live sessions
and cross-checked against the app's opcode table.

Each entry: human name -> (opcode, category, description, known result keys).
Observed convention: a "base" opcode serves the GET ``{"config_version": ...}``; neighbouring
opcodes serve writes ``{"params": {...}}`` (ADD/SET/MODIFY/REMOVE), the response being
``{"error_code": 0}``. Writes marked confirmed=True were observed in a capture; the others are
inferred from the ADD/SET opcode convention or cross-checked against the app's opcode table,
and should be confirmed on a real device before use.

Reads whose response was observed live (read-only emulator parcours, 25/10) are listed in
LIVE_CONFIRMED_READ; the Deco also pushes unsolicited notifications (PUSH, not requestable).

Opcode names follow the app's own opcode table (e.g. CLIENT_LIST_GET, BLOCKED_LIST_GET).
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
    # 0x4001 is a filtered read (params carry role/username), not a write: no confirmed_set.
    "system_info":       Op(0x4001, "system", "System info: group, mode, components, status (filtered read)",
                             ("group_data", "operation_mode", "component_list", "working_status")),
    "wan_lan_status":    Op(0x4004, "network", "WAN/LAN status (IP, DNS, MTU, ping)", ("wan", "lan")),
    "ipv6":              Op(0x4006, "network", "IPv6 enable", ("enable_ipv6",)),
    "wifi_bands_info":   Op(0x4009, "wifi", "Radio info (2.4/5/6 GHz)", ("band5_1", "band6", "band2_4")),
    "device_list":       Op(0x400F, "devices", "Deco units in the mesh", ("device_list", "speed_diagnose")),
    "speedtest":         Op(0x4010, "network", "Internet speed test results",
                             ("down_speed", "up_speed", "ping_time", "last_speed_test_time")),
    # CLIENT_LIST_GET. Result keys inferred from the app's response convention.
    "client_list":       Op(0x4012, "clients", "Client list (filterable)", ("client_list", "max_count")),
    "client_list_speed": Op(0x4014, "clients", "Per-client throughput", ("client_list_speed",)),
    # BLOCKED_LIST_GET — this opcode is NOT the client list.
    "blocked_list":      Op(0x4018, "clients", "Blocked client list (BLOCKED_LIST_GET)",
                             ("client_list", "max_count")),
    "led_schedule":      Op(0x401A, "system", "LED schedule / night mode",
                             ("schedule", "enable", "enable_night_mode", "led_individual_control"), True),
    "messages":          Op(0x4028, "system", "Notifications / messages", ("message_list",)),
    "iot_scan":          Op(0x4040, "iot", "IoT device scan", ("scan_status", "iot_client_list")),
    "rooms":             Op(0x4050, "home", "Rooms / spaces", ("space_count_max", "space_list")),
    "scenes":            Op(0x4070, "automation", "Scenes", ("scene_list", "action_count_max")),
    "tasks":             Op(0x4080, "automation", "Scheduled tasks / automations", ("task_list",)),
    # OPERATION_MODE_GET (the write is operation_mode_set 0x40A1)
    "operation_mode":    Op(0x40A0, "network", "Router/AP mode", ("mode", "modeList"), True),
    "reservations":      Op(0x40C0, "dhcp", "DHCP address reservations", ("reservation_list",), True),
    "ddns":              Op(0x40D0, "network", "DDNS", ("ddns_enable", "ddns_info")),
    "iptv_vlan":         Op(0x420D, "network", "VLAN / IPTV", ("vlan",)),
    "lan_ip":            Op(0x4211, "network", "LAN IP, mask, DNS", ("lan_ip", "dns_server_ip")),
    "dhcp_server":       Op(0x4213, "dhcp", "DHCP server (range, gateway)", ("start_ip", "end_ip", "gateway")),
    "wps":               Op(0x4215, "wifi", "WPS", ("wps_list", "scanning_time"), True),
    # 11R_GET
    "ieee_802_11r":      Op(0x4208, "wifi", "802.11r fast roaming", ("enable",)),
    "qos_bandwidth":     Op(0x4219, "network", "Bandwidth / QoS", ("upstream_bandwidth", "downstream_bandwidth")),
    # BEAMFORMING_GET / SIP_ALG_GET
    "beamforming":       Op(0x421B, "wifi", "Beamforming", ("enable",)),
    "sip_alg":           Op(0x421D, "network", "SIP ALG helper", ("enable",)),
    # MONTHLY_REPORT_MGR_GET
    "monthly_report":    Op(0x4222, "system", "Monthly report manager", ("enable",)),
    # MAC_CLONE_GET
    "mac_clone":         Op(0x4226, "network", "MAC clone settings", ("clone_mode",)),
    "dns_servers":       Op(0x4228, "network", "DNS server selection",
                             ("type", "is_auto", "multi_server_list", "single_server_list")),
    "permissions":       Op(0x4229, "system", "Permission profiles", ("permission_profile", "manager_role_list")),
    "dhcp_leases":       Op(0x423D, "dhcp", "Active DHCP leases", ("client_lease",)),
    # FIXED_WAN_PORT_GET — NOT port forwarding
    # (port forwarding = 0x40B0..0x40B3, see port_forwarding below).
    "fixed_wan_port":    Op(0x4242, "network", "Fixed WAN port selection (FIXED_WAN_PORT_GET)",
                             ("fixed_wan_port", "linked_port", "port_list")),
    "upnp":              Op(0x424A, "network", "UPnP", ("enable",), True, True),
    # PORT_FORWARDING_LIST_GET
    "port_forwarding":   Op(0x40B0, "network", "Port forwarding rules (PORT_FORWARDING_LIST_GET)",
                             ("port_forwarding_list",)),
    "homeshield":        Op(0x4267, "security", "HomeShield (IoT/intrusion/web protection)",
                             ("iot_protection", "intrusion_prevention", "web_protection")),
    # AVIRA_SCAN_STOP_SET neighbour; 0x4265 returns the scan result.
    "network_quality":   Op(0x4265, "network", "Network quality scan result", ("network_quality",)),
    "parental_controls": Op(0x4270, "security", "Parental controls (owners, lists)",
                             ("owner_list", "black_list_max_count")),
    # FAMILY_TIME_GET (the pause write is family_time_set 0x4279).
    "family_time":       Op(0x4278, "security", "Parental pause / family time state (FAMILY_TIME_GET)",
                             ("end_timestamp", "client_list", "enable", "remaining_time")),
    "timezone":          Op(0x427C, "system", "Time zone", ("tz_region", "time", "timezone")),
    "auto_update":       Op(0x427E, "system", "Automatic firmware update", ("enable_auto_update",)),
    "app_block_list":    Op(0x428B, "security", "App block list (paginated)", ("app_block_list",)),
    # CLOUD_SERVICE_STATE_CHECK: seen in capture as a plain GET (no params write observed).
    "cloud_service_state_check": Op(0x428F, "system", "Cloud service state check", ()),
    # MAC_CLONE_CLIENT_LIST_GET — read-only.
    "mac_clone_client_list": Op(0x4293, "security", "MAC clone client list (MAC_CLONE_CLIENT_LIST_GET)",
                             ("client_list",)),
    "static_routes":     Op(0x4294, "network", "Static routes", ("route_static_list", "max_count")),
    "system_routes":     Op(0x4298, "network", "System routing table", ("route_system_list",)),
    "reboot_schedule":   Op(0x42E0, "system", "Scheduled reboot", ("enable", "setting")),
    "wifi_bands":        Op(0x42F0, "wifi", "Wi-Fi band settings", ("band5", "band6", "band2_4")),
    # DEVICE_LED_CATEGORY_GET
    "device_led_category": Op(0x42F7, "system", "LED category per device", ()),
    "firmware":          Op(0x4301, "system", "Available firmware", ("fw_list",)),
    # CLIENT_ISOLATION_GET
    "client_isolation":  Op(0x4302, "wifi", "Client isolation", ("enable",)),
    "time_machine":      Op(0x432B, "automation", "Scheduled profiles (time machine)", ("time_machine_list",)),
    "wireless_link":     Op(0x4318, "wifi", "Wireless link (backhaul) status", ("band2_4",)),
    # DEVICE_RESOURCE_INFO_GET; filtered read:
    # params {"device_list": [{"device_id": str}]}.
    "device_resource_info": Op(0x4317, "devices", "Per-device resource info (filtered)", ()),
    # DEVICE_LIST_SPEED_GET; filtered read, same params shape as 0x4317.
    "device_list_speed": Op(0x422F, "clients", "Per-device speed query (filtered)", ()),
    "vpn_client_info":   Op(0x4370, "network", "VPN client info (VPN_CLIENT_INFO_GET)",
                             ("enable", "client_access", "server_setting")),
    "dpi_qos":           Op(0x4378, "network", "QoS / DPI (per-app bandwidth)",
                             ("most_used_apps", "dpi_qos_mode_info", "upstream_bandwidth")),
    "privacy_policy":    Op(0x4385, "system", "Accepted privacy policies", ("accepted_pp_list",)),
    "usb_scan":          Op(0x4380, "usb", "USB scan", ("scan_time",)),
    "usb_devices":       Op(0x4381, "usb", "Connected USB devices", ("usb_device_list", "state")),
    "usb_sharing":       Op(0x4383, "usb", "USB sharing servers (media/Samba)", ("authentication", "server_list")),
    # TSS_DEVICE_LIST_GET
    "tss_device_list":   Op(0x43BB, "system", "TSS device list", ()),
    "mlo":               Op(0x43B0, "wifi", "Multi-Link Operation (Wi-Fi 7)", ("mlo", "config_spec")),
    "cameras":           Op(0x43BE, "home", "Cameras (local/home mode)", ("local_only_mode", "home_mode")),
    "doh":               Op(0x43D0, "security", "Secure DNS (DoH)", ("enable", "config"), True, True),
    # DOH_DOT_SERVER_TEST
    "doh_dot_server_test": Op(0x43D3, "security", "DoH/DoT server reachability test", ()),
    "internet_backup":   Op(0x43E0, "network",
                             "Internet backup access (enable, client_access, hotspot_list, speed_limit)",
                             ("enable", "client_access", "hotspot_list", "speed_limit"), True, True),
    "vpn_discover":      Op(0x43E2, "network", "VPN client discovery", ("hotspot_list", "max_discover_time")),
    "vpn_config":        Op(0x4360, "network", "VPN server configuration", ("vpn_server", "server_config", "server_list")),
    "family_care":       Op(0x4330, "security", "Family care / HomeShield parental", ("family_care",)),
    # ACCESS_CONTROL_MODE_GET (the write is access_control_mode_set 0x4402)
    "access_control_mode": Op(0x4401, "security", "Access control mode, guest access, new-device notify",
                             ("access_control_mode", "guest_network_access", "new_device_notify")),
    # ACCESS_CONTROL_WHITE_LIST_GET
    "access_control_white_list": Op(0x4403, "security", "Access control client list (white or block list)",
                             ("client_list", "max_count")),
    # APPLY_LIST_GET (per-client internet on/off state)
    "access_control_apply_list": Op(0x4406, "security", "Per-client internet access state (apply list)",
                             ("client_list", "max_count")),
    # CAMERA_SECURITY_BLOCKED_PERIOD_GET —
    # read-only; the camera write is camera_security_set 0x43BF.
    "blocked_period":    Op(0x43C4, "security", "Camera blocked time periods (read-only)", ("blocked_period",)),
}

# Codes whose response was observed live (read-only emulator session of 25/10: 70 opcodes
# seen, 0 CRC errors, no action button pressed). READ codes absent from this set (never seen
# during that session): speedtest 0x4010, wps 0x4215, dns_servers 0x4228, system_routes 0x4298,
# vpn_config 0x4360, vpn_discover 0x43E2, access_control_apply_list 0x4406.
LIVE_CONFIRMED_READ: frozenset[int] = frozenset({
    0x4001, 0x4004, 0x4006, 0x4009, 0x400F, 0x4012, 0x4014, 0x4018, 0x401A, 0x4028,
    0x4040, 0x4050, 0x4070, 0x4080, 0x40A0, 0x40B0, 0x40C0, 0x40D0, 0x4208, 0x420D,
    0x4211, 0x4213, 0x4219, 0x421B, 0x421D, 0x4222, 0x4226, 0x4229, 0x422F, 0x423D,
    0x4242, 0x424A, 0x4265, 0x4267, 0x4270, 0x4278, 0x427C, 0x427E, 0x428B, 0x428F,
    0x4293, 0x4294, 0x42E0, 0x42F0, 0x42F7, 0x4301, 0x4302, 0x4317, 0x4318, 0x432B,
    0x4330, 0x4370, 0x4378, 0x4380, 0x4381, 0x4383, 0x4385, 0x43B0, 0x43BB, 0x43BE,
    0x43C4, 0x43D0, 0x43D3, 0x43E0, 0x4401, 0x4403,
})

# --- Pushes (notifications sent by the Deco, not requestable) -------------------------
# The Deco pushes these opcodes on its own; the app never sends them (42 client_notify
# pushes received during the 25/10 session, zero requests emitted).
PUSH: dict[str, Op] = {
    "client_notify": Op(0x4015, "clients", "Per-client event pushed by the Deco (join/leave/change)",
                        ("mac",)),
}

# --- Writes (SET/ADD/MODIFY/REMOVE) --------------------------------------------------
# name -> {opcode, params schema, confirmed?, doc}
WRITE: dict[str, dict] = {
    # CONFIRMED from capture (params are the real ones)
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
                            "params": {"ddns_status": bool, "mode": str, "domain_name": str,
                                       "connection_status": str},
                            "doc": "Configure DDNS (e.g. TP-Link DDNS)"},
    "internet_backup_set": {"opcode": 0x43E1, "confirmed": True,
                            "params": {"enable": bool, "speed_limit": dict},
                            "doc": "Enable/configure Internet backup access and its speed limit"},
    "ipv6_set":            {"opcode": 0x4007, "confirmed": True,
                            "params": {"enable_ipv6": bool, "wan": dict, "lan": dict},
                            "doc": "Configure IPv6 / IPv6 WAN and LAN (assigned_type)"},
    "guest_network_set":   {"opcode": 0x4008, "confirmed": True,
                            "params": {"band2_4": dict, "band5_1": dict, "band6": dict},
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
    "dns_servers_set":     {"opcode": 0x4011, "confirmed": True,
                            "params": {"is_auto": bool, "type": str, "select_server_id_list": [str]},
                            "doc": "Select DNS/speed-test servers"},
    # HOMESHIELD_FEATURES_SET — confirmed live (25/10 background sync,
    # features unchanged: auc_secure/lib_auc/safe_things).
    "homeshield_features_set": {"opcode": 0x43C6, "confirmed": True,
                            "params": {"features": dict},
                            "doc": "Toggle HomeShield features (auc_secure, lib_auc, safe_things)"},
    # ACCOUNT_MODIFY. SENSITIVE: the payload carries account credentials — never log it,
    # never store an example payload. Confirmed live (2 background syncs, 25/10, values
    # unchanged).
    "account_modify":      {"opcode": 0x4038, "confirmed": True,
                            "params": {"cloud_account": {"email": str, "password": str}},
                            "doc": "Change the cloud account (sensitive: contains credentials)"},
    # ENV_VAR_SYNC; capture: {"lang": "EN_US"}
    "env_var_sync":        {"opcode": 0x4204, "confirmed": True,
                            "params": {"lang": str},
                            "doc": "Sync environment variables (observed: app language, e.g. \"EN_US\")"},
    # 11R_SET; capture: {"enable": true}
    "ieee_802_11r_set":    {"opcode": 0x4209, "confirmed": True,
                            "params": {"enable": bool},
                            "doc": "Enable/disable 802.11r fast roaming"},
    # AVIRA_SCAN_START_SET / AVIRA_SCAN_STOP_SET;
    # capture 20/10: {"scan_type": ["network_quality"]}, parcours 25/10: ["network_security"] —
    # the same opcode carries both scan types.
    "avira_scan_start":    {"opcode": 0x4263, "confirmed": True,
                            "params": {"scan_type": [str]},
                            "doc": "Start a network scan (scan_type: \"network_quality\" or \"network_security\")"},
    "avira_scan_stop":     {"opcode": 0x4264, "confirmed": True,
                            "params": {"scan_type": [str]},
                            "doc": "Stop a running network scan (same params as start)"},
    # DATA_ANALYSIS_SET; capture: {"enable": false}
    "data_analysis_set":   {"opcode": 0x437E, "confirmed": True,
                            "params": {"enable": bool},
                            "doc": "Enable/disable data analysis (privacy)"},
    # INFERRED from the GET=base / ADD=+1 / MODIFY=+2 / REMOVE=+3 pattern - CONFIRM before real use
    "reservation_remove":  {"opcode": 0x40C3, "params": {"mac": str}, "confirmed": False,
                            "doc": "(inferred) Remove a DHCP reservation"},
    # --- Inferred from the app's opcode table — capture live before real use ---
    # Parental controls "At Home" (owner profiles and family time)
    "parental_owner_add":  {"opcode": 0x4271, "confirmed": False,
                            "params": {"owner_id": str, "internet_blocked": bool, "app_block": dict,
                                       "dpi_app_limit": dict, "bed_time": dict, "off_time": dict,
                                       "time_limits": dict, "website_list": [str],
                                       "youtube_restricted": bool, "safe_search": bool},
                            "doc": "Create a parental profile"},
    "parental_owner_remove": {"opcode": 0x4272, "confirmed": False,
                            "params": {"owner_list": [str]},
                            "doc": "Remove parental profile(s) by owner id"},
    "parental_owner_modify": {"opcode": 0x4273, "confirmed": False,
                            "params": {"owner_id": str, "internet_blocked": bool, "app_block": dict,
                                       "dpi_app_limit": dict, "bed_time": dict, "off_time": dict,
                                       "time_limits": dict, "website_list": [str],
                                       "youtube_restricted": bool, "safe_search": bool},
                            "doc": "Edit a parental profile"},
    "parental_owner_bonus_add": {"opcode": 0x4274, "confirmed": False,
                            "params": {"owner_id": str, "bypass_time": int},
                            "doc": "Grant bonus time to a parental profile"},
    "parental_ignore_owner_request": {"opcode": 0x4277, "confirmed": False,
                            "params": {"owner_id": str, "type": str},
                            "doc": "Dismiss a child access request"},
    "family_time_set":     {"opcode": 0x4279, "confirmed": False,
                            "params": {"client_list": [str], "enable": bool, "time": int,
                                       "end_timestamp": int, "remaining_time": int},
                            "doc": "Pause/resume internet for parental profiles"},
    "family_whitelist_add": {"opcode": 0x427A, "confirmed": False,
                            "params": {"owner_id": str},
                            "doc": "Always-allowed sites: add owner"},
    "family_whitelist_remove": {"opcode": 0x427B, "confirmed": False,
                            "params": {"owner_id": str},
                            "doc": "Always-allowed sites: remove owner"},
    "dpi_app_limit_add":   {"opcode": 0x428D, "confirmed": False,
                            "params": {"owner_id": str, "dpi_app_limit": {"limit_list": [dict]}},
                            "doc": "Add per-app time limits to a parental profile"},
    "dpi_app_limit_modify": {"opcode": 0x429D, "confirmed": False,
                            "params": {"owner_id": str, "dpi_app_limit": {"limit_list": [dict]}},
                            "doc": "Edit per-app time limits"},
    "dpi_app_limit_remove": {"opcode": 0x429F, "confirmed": False,
                            "params": {"owner_id": str, "dpi_app_limit_id_list": [int]},
                            "doc": "Remove per-app time limits"},
    # QoS bandwidth
    "qos_bandwidth_set":   {"opcode": 0x421A, "confirmed": False,
                            "params": {"bandwidth_mode": str, "downstream_bandwidth": int,
                                       "upstream_bandwidth": int, "network_services": [str]},
                            "doc": "Set QoS bandwidth mode and up/down rates"},
    # DPI QoS per app
    "dpi_qos_info_set":    {"opcode": 0x4379, "confirmed": False,
                            "params": {"dpi_qos_mode_info": [dict], "downstream_bandwidth": int,
                                       "upstream_bandwidth": int},
                            "doc": "Set per-app DPI QoS modes and bandwidth"},
    "dpi_qos_mode_item_remove": {"opcode": 0x437A, "confirmed": False,
                            "params": {"dpi_qos_mode_id_list": [str]},
                            "doc": "Remove DPI QoS mode items"},
    # Port forwarding
    "port_forwarding_add": {"opcode": 0x40B1, "confirmed": False,
                            "params": {"port_forwarding_id": str, "external_ip": str,
                                       "external_port": str, "external_subnet": str,
                                       "internal_ip": str, "internal_port": str, "protocol": str,
                                       "service_name": str, "service_type": str},
                            "doc": "Add a port forwarding rule"},
    "port_forwarding_modify": {"opcode": 0x40B2, "confirmed": False,
                            "params": {"port_forwarding_id": str, "external_ip": str,
                                       "external_port": str, "external_subnet": str,
                                       "internal_ip": str, "internal_port": str, "protocol": str,
                                       "service_name": str, "service_type": str},
                            "doc": "Modify a port forwarding rule"},
    "port_forwarding_delete": {"opcode": 0x40B3, "confirmed": False,
                            "params": {"port_forwarding_id": str},
                            "doc": "Delete a port forwarding rule"},
    # Fixed WAN port — touches the WAN
    "fixed_wan_port_set":  {"opcode": 0x4243, "confirmed": False,
                            "params": {"fixed_wan_port": int, "linked_port": int, "port_list": [dict],
                                       "type": str, "is_iptv": bool, "ethernet_physical_speed": int},
                            "doc": "Select the fixed WAN port (be careful)"},
    # Access control
    "access_control_mode_set": {"opcode": 0x4402, "confirmed": False,
                            "params": {"access_control_mode": str, "guest_network_access": bool,
                                       "new_device_notify": bool},
                            "doc": "Set access control mode (\"block_list\"|\"white_list\"), guest access, notify"},
    "access_control_white_list_add": {"opcode": 0x4404, "confirmed": False,
                            "params": {"client_list": [dict]},
                            "doc": "Add clients to the access-control list ({mac, name, client_type})"},
    "access_control_white_list_remove": {"opcode": 0x4405, "confirmed": False,
                            "params": {"client_list": [str]},
                            "doc": "Remove clients (MACs) from the access-control list"},
    "access_control_apply_list_set": {"opcode": 0x4407, "confirmed": False,
                            "params": {"client_list": [str], "enable": bool},
                            "doc": "Per-client internet on/off (apply list)"},
    # Camera security
    # Opcode corrected on 25/10: the app's opcode table gives CAMERA_SECURITY_SET = 0x43BF
    # (0x4347 is HY_BAND_SEARCH_STOP).
    "camera_security_set": {"opcode": 0x43BF, "confirmed": False,
                            "params": {"home_mode": dict, "local_only_mode": dict},
                            "doc": "Camera security: block cameras by mode/schedule"},
    # MAC clone
    "mac_clone_set":       {"opcode": 0x4227, "confirmed": False,
                            "params": {"clone_mode": str},
                            "doc": "Set MAC clone mode"},
    # CRITICAL: switching the operation mode can cut access to the Deco (AP = no more
    # router/DHCP). 0x40A1 is OPERATION_MODE_SET (0x40A2 is OPERATION_MODE_BACKUP_SET,
    # not mapped here).
    "operation_mode_set":  {"opcode": 0x40A1, "confirmed": False,
                            "params": {"mode": str},
                            "doc": "(critical) Switch operation mode — mode: \"Router\"|\"AP\"|\"LTE\"|"
                                   "\"Repeater\"|\"DSL_Modem\"|\"3G4G_Router\"|\"Mobile_5G\"|"
                                   "\"DSL_Bridge\"|\"EWAN_Bridge\"|\"Mobile_Bridge\""},
}

# opcode -> registry name, covering reads, writes and pushes (no duplicates, see tests).
ALL_BY_CODE: dict[int, str] = {op.code: name for name, op in READ.items()}
ALL_BY_CODE.update({w["opcode"]: name for name, w in WRITE.items()})
ALL_BY_CODE.update({op.code: name for name, op in PUSH.items()})