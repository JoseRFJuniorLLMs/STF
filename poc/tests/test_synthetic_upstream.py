import hashlib
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from synthetic_upstream import SyntheticUpstream


class SyntheticUpstreamTests(unittest.TestCase):
    def test_effect_receipt_records_exact_action_and_parameters_digest(self):
        upstream = SyntheticUpstream()
        params = {"format": "pdf", "document": "DOC-001"}
        effect = upstream.execute(
            "export_restricted", "service-account-17",
            "document://SYNTHETIC/DOC-001", params,
        )
        expected_digest = hashlib.sha256(json.dumps(
            params, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()

        self.assertEqual(effect["status"], "EXECUTED")
        self.assertEqual(effect["action"], "export_restricted")
        self.assertEqual(effect["principal"], "service-account-17")
        self.assertEqual(effect["parameters_digest"], expected_digest)
        self.assertEqual(upstream.hits, 1)
        self.assertEqual(upstream.effects, [effect])

        effect["action"] = "case_write"
        self.assertEqual(upstream.effects[0]["action"], "export_restricted")

    def test_invalid_action_has_no_effect(self):
        upstream = SyntheticUpstream()
        with self.assertRaises(ValueError):
            upstream.execute("unknown", "p", "t", {})
        self.assertEqual(upstream.hits, 0)
        self.assertEqual(upstream.effects, [])

    def test_reset_clears_receipts_and_count(self):
        upstream = SyntheticUpstream()
        upstream.execute("case_write", "p", "case://SYNTHETIC/RE-000001", {})
        self.assertEqual(upstream.hits, 1)
        upstream.reset()
        self.assertEqual(upstream.hits, 0)
        self.assertEqual(upstream.effects, [])


if __name__ == "__main__":
    unittest.main()
