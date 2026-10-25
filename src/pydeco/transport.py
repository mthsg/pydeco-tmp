"""Deco TMP transport layer: SSH (dropbear) + TMP type-5 / business v2 framing.

Protocol reverse-engineered from the TP-Link Deco app and verified against a captured live
session. Key points:

* SSH dropbear on port 20001. Password auth:
  username = hex(SHA-1(TP-Link account email)), password = the account password.
* A ``direct-tcpip`` channel to ``127.0.0.1:20002`` (the local TMP daemon behind dropbear).
  **No application handshake**: opening the channel *is* the connection. Sending a type-1 CONNECT
  ``[1,1,1,0]`` corrupts the session and causes an EOF on the next packet.
* TMP type-5 framing (16-byte header, big-endian):
  ``[1][1][5][0][len u16][0][0][seq u32][crc u32]`` + payload. The CRC field is first set to
  ``0x5A6B7C8D``; CRC32 is computed over the whole packet, then the result is written back at
  offset 12. ``seq`` starts at 1.
* business v2 framing (20-byte header):
  ``[1][ver=2][opcode u16][ptype][err][txid u16][crc u32][total u32][offset u32]`` + body.
  ``ptype``: 2 = request (PUSH), 5 = response, 4 = PULL (next fragment). ``crc`` = CRC32 of the
  body (0 if empty). ``txid`` starts at 0 and increments per request.
* Sequence: ALLOC (opcode 1, empty body) -> 32-hex token (kept, never resent); then every request
  ``opcode / ptype 2 / JSON body`` gets its ``ptype 5`` response matched by ``txid``. No VERIFY
  (opcode 2) on a fresh token.

This module performs NO writes of its own; it exposes ``request()``. Write policy is handled by
the client layer.
"""
from __future__ import annotations

import hashlib
import json
import socket
import struct
import time
import zlib
from typing import Any

try:
    import paramiko
except ImportError:  # import paresseux : l'échec survient à la connexion, pas à l'import
    paramiko = None  # type: ignore[assignment]

TMP_PORT = 20001
TMP_LOCAL = ("127.0.0.1", 20002)
TMP_ORIGIN = ("127.0.0.1", 54321)
CRC_PLACEHOLDER = 0x5A6B7C8D
VER_BIZ = 2
PT_PUSH, PT_RESP, PT_PULL = 2, 5, 4
OP_ALLOC = 0x0001


class DecoError(Exception):
    """Application error returned by the Deco (non-zero ``error_code`` or business ``err``)."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class DecoTransport:
    """A TMP/SSH session to a Deco router. Usable as a context manager."""

    def __init__(self, host: str, email: str, password: str,
                 host_key_sha256: str | None = None, timeout: int = 10):
        self.host = host
        self.email = email
        self._password = password
        self.host_key_sha256 = host_key_sha256
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._tr: paramiko.Transport | None = None
        self._chan: Any = None
        self._seq = 1          # TMP sequence (M()), starts at 1
        self._txid = 0         # business txid (h()), starts at 0
        self.token: str | None = None

    # -- lifecycle -------------------------------------------------------------------
    def __enter__(self) -> DecoTransport:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        """Open SSH, authenticate (ONE attempt) and allocate the session token."""
        if paramiko is None:
            raise DecoError("pydeco requires paramiko (`pip install paramiko`)")
        self._sock = socket.create_connection((self.host, TMP_PORT), timeout=self.timeout)
        self._tr = paramiko.Transport(self._sock)
        self._tr.start_client(timeout=self.timeout)
        if self.host_key_sha256:
            got = hashlib.sha256(self._tr.get_remote_server_key().asbytes()).hexdigest()
            if got != self.host_key_sha256.lower():
                self.close()
                raise DecoError(f"unexpected host key: {got}")
        user = hashlib.sha1(self.email.encode()).hexdigest()
        self._tr.auth_password(user, self._password)   # single attempt (lockout otherwise)
        self._chan = self._tr.open_channel("direct-tcpip", TMP_LOCAL, TMP_ORIGIN,
                                            timeout=self.timeout)
        self._chan.settimeout(self.timeout)
        self.token = self.request(OP_ALLOC).decode("ascii", "replace")

    def close(self) -> None:
        for obj in (self._chan, self._tr, self._sock):
            try:
                if obj is not None:
                    obj.close()
            except Exception:  # noqa: BLE001, S110 — fermeture au mieux, session déjà perdue
                pass
        self._chan = self._tr = self._sock = None
        self.token = None

    # -- framing ---------------------------------------------------------------------
    def _next_seq(self) -> int:
        v = self._seq
        self._seq += 1
        return v

    def _next_txid(self) -> int:
        v = self._txid
        self._txid = (self._txid + 1) & 0xFFFF
        return v

    @staticmethod
    def _tmp5(payload: bytes, seq: int) -> bytes:
        base = struct.pack(">BBBBHBBI", 1, 1, 5, 0, len(payload), 0, 0, seq)
        crc = zlib.crc32(base + struct.pack(">I", CRC_PLACEHOLDER) + payload) & 0xFFFFFFFF
        return base + struct.pack(">I", crc) + payload

    @staticmethod
    def _biz(opcode: int, ptype: int, body: bytes, txid: int, offset: int = 0) -> bytes:
        crc = zlib.crc32(body) & 0xFFFFFFFF if body else 0
        return struct.pack(">BBHBBHIII", 1, VER_BIZ, opcode, ptype, 0, txid,
                           crc, len(body), offset) + body

    def _recvn(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._chan.recv(n - len(buf))
            if not chunk:
                raise DecoError(f"channel closed (received {len(buf)}/{n} bytes)")
            buf += chunk
        return buf

    def _read_tmp5(self) -> bytes:
        """Read the next TMP packet; answer keep-alives (type 4), return the type-5 payload."""
        while True:
            head = self._recvn(4)
            typ = head[2]
            if typ == 4:                       # keep-alive: echo it back
                self._chan.sendall(bytes([1, 1, 4, 0]))
                continue
            if typ == 2:                       # stray connection ACK: ignore
                continue
            if typ == 5:
                rest = self._recvn(12)
                length = struct.unpack(">H", (head + rest)[4:6])[0]
                return self._recvn(length)
            raise DecoError(f"unexpected TMP type {typ}")

    @staticmethod
    def _parse_biz(payload: bytes) -> dict:
        (_, _ver, opcode, ptype, err, txid, _crc, total, offset) = struct.unpack_from(
            ">BBHBBHIII", payload, 0)
        return {"opcode": opcode, "ptype": ptype, "err": err, "txid": txid,
                "total": total, "offset": offset, "body": payload[20:]}

    # -- low-level API ---------------------------------------------------------------
    def request(self, opcode: int, params: dict | None = None) -> bytes:
        """Send a request (PUSH) and return the raw response body (bytes).

        ``opcode``: business code. ``params``: if given, this is a write - inserted under
        ``params`` in the JSON body ``{"config_version": <ms>, "params": {...}}``. Otherwise a
        plain read. ALLOC (opcode 1) is sent with an empty body.
        """
        if self._chan is None:
            raise DecoError("not connected")
        tx = self._next_txid()
        body = b""
        if opcode != OP_ALLOC:
            payload = {"config_version": int(time.time() * 1000)}
            if params is not None:
                payload["params"] = params
            body = json.dumps(payload, separators=(",", ":")).encode()
        self._chan.sendall(self._tmp5(self._biz(opcode, PT_PUSH, body, tx), self._next_seq()))
        data = bytearray()
        total = None
        while True:
            p = self._parse_biz(self._read_tmp5())
            if p["txid"] != tx:                # response for another (async) transaction: skip
                continue
            if p["err"] != 0:
                raise DecoError(f"business error {p['err']} (opcode 0x{opcode:04x})", p["err"])
            if p["ptype"] != PT_RESP:
                raise DecoError(f"unexpected ptype {p['ptype']} (opcode 0x{opcode:04x})")
            data += p["body"]
            total = p["total"]
            if total == 0 or len(data) >= total:
                break
            self._chan.sendall(self._tmp5(
                self._biz(opcode, PT_PULL, b"", tx, offset=len(data)), self._next_seq()))
        return bytes(data)

    def call(self, opcode: int, params: dict | None = None) -> Any:
        """Like ``request`` but decodes JSON and unwraps/validates ``result`` / ``error_code``."""
        raw = self.request(opcode, params)
        if not raw:
            return None
        doc = json.loads(raw.decode("utf-8", "replace"))
        ec = doc.get("error_code")
        if ec not in (None, 0):
            raise DecoError(f"error_code {ec} (opcode 0x{opcode:04x})", ec)
        return doc.get("result", doc)
