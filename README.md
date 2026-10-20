# pydeco-tmp

Control a **TP-Link Deco** mesh router **locally, without the app**, over its native TMP
protocol — the same channel the official app uses. Reverse-engineered from the Deco app
(`com.tplink.tpm5`) and verified against a captured live session.

> ⚠️ Unofficial. No affiliation with TP-Link. Use on your own network, at your own risk.
> Reads are safe; writes change your router and require explicit confirmation.

## How it works

The Deco app talks to the router over an SSH tunnel (dropbear on port **20001**) to a local
TMP daemon (`127.0.0.1:20002`). Authentication is your TP-Link account:
`username = hex(SHA-1(email))`, `password = account password`. Requests are small JSON documents
wrapped in a binary framing (TMP type-5 + a "business v2" header), addressed by numeric opcodes.

Key finding that makes this work: on the SSH transport there is **no application-level handshake** —
opening the channel *is* the connection. (The app's TCP/TDP transport sends a `[1,1,1,0]` CONNECT;
sending that over SSH corrupts the session.) After a one-shot `ALLOC` that returns a session token,
every setting is a `opcode + JSON` round-trip. See `RAPPORT-TMP.md` for the full protocol write-up.

## Install

```bash
pip install paramiko          # the only runtime dependency
pip install -e .              # from this repo
```

## Usage

```python
from pydeco import DecoClient, keychain

with DecoClient(host="192.168.0.1",
                email="me@example.com",
                password=keychain("deco"),          # or a plain string
                host_key_sha256="<sha256 of your router key>") as deco:  # optional pin
    print(deco.get_devices())                              # the Deco units
    print(deco.get("dhcp_leases"))                         # current leases
    print(deco.snapshot(categories=["network", "dhcp"]))   # bulk read

    # Writes need explicit confirmation:
    deco.set("upnp_set", {"enable": False}, confirm=True)
```

- `deco.get(name)` / `deco.snapshot()` — reads (see `pydeco.opcodes.READ`).
- `deco.set(name, params, confirm=True)` — writes (see `pydeco.opcodes.WRITE`). Opcodes only
  *inferred* from the GET/SET pattern (not yet observed in a capture) additionally require
  `allow_unconfirmed=True`.
- `deco.raw(opcode, params=None)` — escape hatch for any opcode.

## Status

v0.1 — 58 read domains mapped; 13 writes confirmed from capture (UPnP, DoH, DHCP reservation
add/modify, DDNS, VPN server, IPv6, guest network, LED, WPS, manager roles, HomeShield features,
DNS servers), more inferred. The capture holds ~91 opcodes total; contributions welcome — capture
a setting change and add its opcode/params.

## License

MIT
