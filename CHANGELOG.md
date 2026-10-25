# Changelog

## 0.2.0

Opcode names and codes corrected after cross-checking the app's opcode table and a new
read-only live session (25/10). Read this before upgrading: several registry names changed
meaning.

### Breaking changes

- `client_list`: 0x4018 → 0x4012. 0x4018 is in fact `blocked_list` (blocked client list).
  `DecoClient.get_clients()` follows: it now reads 0x4012 and returns the real client list.
- `port_forwarding`: 0x4242 → 0x40B0. 0x4242 is `fixed_wan_port` (fixed WAN port selection),
  not port forwarding.
- Removed names: `acl`, `network_access`, `blocked_clients`, `parental_pause` (superseded by
  the entries above and by `access_control_*` / `family_time`).

### Renames (same codes, honest names)

- `vpn_server` (0x43E0) → `internet_backup`: this domain is the Internet backup access
  (enable, client_access, hotspot_list, speed_limit). The write was confirmed in capture;
  only the name was wrong.
- `vpn_server_set` (0x43E1) → `internet_backup_set`.
- `remote_management` (0x4370) → `vpn_client_info` (the app's table says VPN_CLIENT_INFO_GET).

### Corrections

- `operation_mode_set`: 0x40A2 → 0x40A1 (0x40A2 is OPERATION_MODE_BACKUP_SET).
- `camera_security_set`: 0x43BF.

### Newly confirmed writes

Observed in live captures, params documented in `pydeco.opcodes.WRITE`:
0x4038 `account_modify`, 0x4204 `env_var_sync`, 0x4209 `ieee_802_11r_set`,
0x4263 `avira_scan_start`, 0x4264 `avira_scan_stop`, 0x437E `data_analysis_set`.

### Live-confirmed reads and push

- 66 of the 73 read domains were confirmed live during the read-only emulator session of
  25/10 (0 CRC errors); the codes are listed in `LIVE_CONFIRMED_READ`.
- New push 0x4015 `client_notify`: per-client event (join/leave/change) sent by the Deco on
  its own, not requestable.

## 0.1.0

Initial release.