"""High-level client to drive a Deco router locally, outside the official app.

Example::

    from pydeco import DecoClient, keychain

    with DecoClient(host="192.168.0.1", email="me@example.com",
                    password=keychain("deco")) as deco:
        print(deco.get("device_list"))
        print(deco.get_clients())
        # write (explicit confirmation required):
        deco.set("upnp_set", {"enable": False}, confirm=True)

Reads are safe. Writes require ``confirm=True`` and, for opcodes that are only INFERRED (not seen
in a capture), ``allow_unconfirmed=True`` as well - a guard against sending a command whose format
has not been verified on a real device.
"""
from __future__ import annotations

import subprocess
from typing import Any

from .opcodes import READ, WRITE
from .transport import DecoError, DecoTransport


def keychain(service: str) -> str:
    """Read a secret from the macOS keychain (``security find-generic-password``).

    The secret travels via the subprocess pipe, never as a shell argument.
    """
    out = subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


class DecoClient:
    def __init__(self, host: str, email: str, password: str,
                 host_key_sha256: str | None = None, timeout: int = 10):
        self._tr = DecoTransport(host, email, password, host_key_sha256, timeout)

    def __enter__(self) -> "DecoClient":
        self._tr.connect()
        return self

    def __exit__(self, *exc) -> None:
        self._tr.close()

    def connect(self) -> None:
        self._tr.connect()

    def close(self) -> None:
        self._tr.close()

    @property
    def token(self) -> str | None:
        return self._tr.token

    # -- reads -----------------------------------------------------------------------
    def get(self, name: str, params: dict | None = None) -> Any:
        """Read a domain by name (key of ``opcodes.READ``). Optional ``params`` (filter)."""
        if name not in READ:
            raise KeyError(f"unknown read: {name!r} (see pydeco.opcodes.READ)")
        return self._tr.call(READ[name].code, params)

    def raw(self, opcode: int, params: dict | None = None) -> Any:
        """Escape hatch: call an arbitrary opcode. ``params`` => write."""
        return self._tr.call(opcode, params)

    # a few common shortcuts
    def get_devices(self) -> Any:
        return self.get("device_list")

    def get_clients(self) -> Any:
        return self.get("client_list")

    def get_reservations(self) -> Any:
        return self.get("reservations")

    def get_dhcp_leases(self) -> Any:
        return self.get("dhcp_leases")

    def get_system_info(self) -> Any:
        return self.get("system_info")

    def snapshot(self, categories: list[str] | None = None) -> dict[str, Any]:
        """Read every domain (or those in the given categories) as a name->result dict.

        Domains that fail are returned as ``{"__error__": "..."}`` without interrupting the sweep.
        """
        out: dict[str, Any] = {}
        for name, op in READ.items():
            if categories and op.category not in categories:
                continue
            try:
                out[name] = self._tr.call(op.code)
            except DecoError as exc:
                out[name] = {"__error__": str(exc)}
        return out

    # -- writes (guarded) ------------------------------------------------------------
    def set(self, name: str, params: dict, *, confirm: bool = False,
            allow_unconfirmed: bool = False) -> Any:
        """Run a write declared in ``opcodes.WRITE``.

        ``confirm=True`` is mandatory (a write changes the real router). For an opcode that is only
        INFERRED (``confirmed=False``), ``allow_unconfirmed=True`` is required as well.
        """
        if name not in WRITE:
            raise KeyError(f"unknown write: {name!r} (see pydeco.opcodes.WRITE)")
        spec = WRITE[name]
        if not confirm:
            raise DecoError(f"write {name!r} refused: pass confirm=True (it changes the router).")
        if not spec.get("confirmed", False) and not allow_unconfirmed:
            raise DecoError(f"write {name!r} not confirmed by capture: "
                            "pass allow_unconfirmed=True to force (format unverified).")
        return self._tr.call(spec["opcode"], params)
