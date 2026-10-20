"""Framing tests (offline): the bytes we produce must match the real captured session."""
import struct

from pydeco.transport import DecoTransport


def test_alloc_byte_identical_to_app():
    """The ALLOC packet must be identical to the one captured from the app (CRC 0x50384E94)."""
    biz = DecoTransport._biz(0x0001, 2, b"", 0)          # op=ALLOC, PUSH, empty body, txid 0
    pkt = DecoTransport._tmp5(biz, 1)                     # seq 1
    captured = bytes([1, 1, 5, 0, 0, 20, 0, 0, 0, 0, 0, 1, 0x50, 0x38, 0x4E, 0x94,
                      1, 2, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    assert pkt == captured


def test_biz_header_layout():
    body = b'{"enable":false}'
    biz = DecoTransport._biz(0x424B, 2, body, 5)
    t, ver, op, pt, err, txid, crc, total, off = struct.unpack_from(">BBHBBHIII", biz, 0)
    assert (t, ver, op, pt, err, txid, total, off) == (1, 2, 0x424B, 2, 0, 5, len(body), 0)
    assert biz[20:] == body


def test_parse_roundtrip():
    body = b'{"result":{"enable":true},"error_code":0}'
    biz = DecoTransport._biz(0x424A, 5, body, 7)
    p = DecoTransport._parse_biz(biz)
    assert p["opcode"] == 0x424A and p["ptype"] == 5 and p["txid"] == 7
    assert p["body"] == body


def test_tmp5_crc_depends_on_payload():
    a = DecoTransport._tmp5(b"\x01\x02", 1)
    b = DecoTransport._tmp5(b"\x01\x03", 1)
    assert a[12:16] != b[12:16]        # CRC changes with the payload
