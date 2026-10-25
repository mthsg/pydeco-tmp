"""Registry consistency tests (offline): opcodes.py must stay self-consistent."""
import unittest

from pydeco.opcodes import ALL_BY_CODE, LIVE_CONFIRMED_READ, PUSH, READ, WRITE


class RegistryConsistencyTest(unittest.TestCase):
    def test_read_codes_unique(self):
        codes = [op.code for op in READ.values()]
        self.assertEqual(len(codes), len(set(codes)), "duplicate opcode in READ")

    def test_write_codes_unique(self):
        codes = [w["opcode"] for w in WRITE.values()]
        self.assertEqual(len(codes), len(set(codes)), "duplicate opcode in WRITE")

    def test_push_codes_unique_and_disjoint(self):
        codes = [op.code for op in PUSH.values()]
        self.assertEqual(len(codes), len(set(codes)), "duplicate opcode in PUSH")
        read_codes = {op.code for op in READ.values()}
        write_codes = {w["opcode"] for w in WRITE.values()}
        self.assertFalse(set(codes) & read_codes, "push opcode also in READ")
        self.assertFalse(set(codes) & write_codes, "push opcode also in WRITE")

    def test_no_code_shared_between_read_and_write(self):
        read_codes = {op.code for op in READ.values()}
        write_codes = {w["opcode"] for w in WRITE.values()}
        overlap = read_codes & write_codes
        self.assertFalse(overlap,
                         f"opcodes present in both READ and WRITE: {sorted(hex(c) for c in overlap)}")

    def test_all_by_code_covers_read_write_push(self):
        read_codes = {op.code for op in READ.values()}
        write_codes = {w["opcode"] for w in WRITE.values()}
        push_codes = {op.code for op in PUSH.values()}
        self.assertEqual(read_codes | write_codes | push_codes, set(ALL_BY_CODE))

    def test_confirmed_writes_have_opcode_and_params(self):
        for name, w in WRITE.items():
            self.assertIsInstance(w["opcode"], int, name)
            if w["confirmed"]:
                self.assertIn("params", w, f"confirmed write without params schema: {name}")

    def test_live_confirmed_reads_exist(self):
        """Every live-confirmed code (25/10 session) must be a known READ."""
        read_codes = {op.code for op in READ.values()}
        self.assertTrue(LIVE_CONFIRMED_READ <= read_codes,
                        f"codes live inconnus: {sorted(hex(c) for c in LIVE_CONFIRMED_READ - read_codes)}")

    def test_client_notify_push(self):
        """0x4015 = per-client push from the Deco (42 pushes, 25/10 session)."""
        self.assertEqual(PUSH["client_notify"].code, 0x4015)
        self.assertEqual(ALL_BY_CODE[0x4015], "client_notify")

    def test_known_corrections(self):
        """Proven corrections (per the app's opcode table) stay in place."""
        self.assertEqual(READ["fixed_wan_port"].code, 0x4242)          # FIXED_WAN_PORT_GET
        self.assertEqual(READ["port_forwarding"].code, 0x40B0)         # PORT_FORWARDING_LIST_GET
        self.assertEqual(READ["access_control_white_list"].code, 0x4403)
        self.assertEqual(READ["family_time"].code, 0x4278)             # FAMILY_TIME_GET
        self.assertEqual(WRITE["family_time_set"]["opcode"], 0x4279)   # the pause
        self.assertEqual(WRITE["operation_mode_set"]["opcode"], 0x40A1)  # OPERATION_MODE_SET
        self.assertFalse(READ["system_info"].confirmed_set)            # filtered read
        self.assertEqual(READ["mac_clone_client_list"].code, 0x4293)   # lecture seule
        self.assertEqual(READ["blocked_list"].code, 0x4018)            # BLOCKED_LIST_GET
        self.assertEqual(READ["client_list"].code, 0x4012)             # CLIENT_LIST_GET


if __name__ == "__main__":
    unittest.main()