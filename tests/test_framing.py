"""Framing tests (offline): the bytes we produce must match the real captured session."""
import struct
import unittest

from pydeco.transport import DecoTransport


class FramingTest(unittest.TestCase):
    def test_alloc_byte_identical_to_app(self):
        """The ALLOC packet must be identical to the one captured from the app (CRC 0x50384E94)."""
        biz = DecoTransport._biz(0x0001, 2, b"", 0)          # op=ALLOC, PUSH, empty body, txid 0
        pkt = DecoTransport._tmp5(biz, 1)                     # seq 1
        captured = bytes([1, 1, 5, 0, 0, 20, 0, 0, 0, 0, 0, 1, 0x50, 0x38, 0x4E, 0x94,
                          1, 2, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(pkt, captured)

    def test_biz_header_layout(self):
        body = b'{"enable":false}'
        biz = DecoTransport._biz(0x424B, 2, body, 5)
        t, ver, op, pt, err, txid, _crc, total, off = struct.unpack_from(">BBHBBHIII", biz, 0)
        self.assertEqual(
            (t, ver, op, pt, err, txid, total, off),
            (1, 2, 0x424B, 2, 0, 5, len(body), 0))
        self.assertEqual(biz[20:], body)

    def test_parse_roundtrip(self):
        body = b'{"result":{"enable":true},"error_code":0}'
        biz = DecoTransport._biz(0x424A, 5, body, 7)
        p = DecoTransport._parse_biz(biz)
        self.assertEqual(p["opcode"], 0x424A)
        self.assertEqual(p["ptype"], 5)
        self.assertEqual(p["txid"], 7)
        self.assertEqual(p["body"], body)

    def test_tmp5_crc_depends_on_payload(self):
        a = DecoTransport._tmp5(b"\x01\x02", 1)
        b = DecoTransport._tmp5(b"\x01\x03", 1)
        self.assertNotEqual(a[12:16], b[12:16])        # CRC changes with the payload


if __name__ == "__main__":
    unittest.main()