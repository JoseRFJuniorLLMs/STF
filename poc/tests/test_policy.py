import pathlib,sys,unittest,hashlib,json
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
from policy import decide

def digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
INC={"state":"OPEN","severity":"HIGH","principal":"service-account-17"}
APR={"approval_id":"APR-001","state":"APPROVED","principal":"service-account-17","target":"document://SYNTHETIC/DOC-001","parameters_digest":digest({"document":"DOC-001","format":"pdf"})}

class PolicyTests(unittest.TestCase):
    def test_compromised_principal_write_is_denied(self):
        d=decide(action="case_write",incident=INC,principal="service-account-17",target="case://SYNTHETIC/RE-000001")
        self.assertEqual(d.outcome,"DENY");self.assertFalse(d.effect_allowed)
    def test_export_requires_human_without_approval(self):
        d=decide(action="export_restricted",incident=INC,principal="service-account-17",target=APR["target"],parameters_digest=APR["parameters_digest"])
        self.assertEqual(d.outcome,"REQUIRE_HITL");self.assertTrue(d.requires_human)
    def test_valid_bound_approval_allows_exactly_that_request(self):
        d=decide(action="export_restricted",incident=INC,principal="service-account-17",target=APR["target"],parameters_digest=APR["parameters_digest"],approval=APR)
        self.assertEqual(d.outcome,"ALLOW");self.assertTrue(d.effect_allowed)
    def test_replay_is_denied(self):
        d=decide(action="export_restricted",incident=INC,principal="service-account-17",target=APR["target"],parameters_digest=APR["parameters_digest"],approval=APR,consumed={"APR-001"})
        self.assertEqual(d.reason_code,"REPLAY_DETECTED")
    def test_identity_swap_is_denied_before_replay_reason(self):
        d=decide(action="export_restricted",incident=INC,principal="agent:other",target=APR["target"],parameters_digest=APR["parameters_digest"],approval=APR,consumed={"APR-001"})
        self.assertEqual(d.reason_code,"IDENTITY_BINDING_MISMATCH")
    def test_parameter_swap_is_denied_before_replay_reason(self):
        d=decide(action="export_restricted",incident=INC,principal="service-account-17",target="document://SYNTHETIC/DOC-999",parameters_digest=digest({"document":"DOC-999","format":"pdf"}),approval=APR,consumed={"APR-001"})
        self.assertEqual(d.reason_code,"PARAMETERS_DIGEST_MISMATCH")
    def test_unknown_action_fails_closed(self):
        d=decide(action="something_new",incident=None,principal="x",target="y")
        self.assertEqual(d.reason_code,"UNKNOWN_ACTION_FAIL_CLOSED");self.assertEqual(d.outcome,"DENY")


    def test_expired_approval_is_denied(self):
        expired=dict(APR); expired["expires_at_epoch"]=10
        d=decide(action="export_restricted",incident=INC,principal="service-account-17",
                 target=APR["target"],parameters_digest=APR["parameters_digest"],
                 approval=expired,now=20)
        self.assertEqual(d.reason_code,"APPROVAL_EXPIRED")
        self.assertEqual(d.outcome,"DENY")


    def test_case_write_can_execute_after_valid_human_approval_when_principal_not_compromised(self):
        approval=dict(APR)
        approval["target"]="case://SYNTHETIC/RE-000001"
        approval["parameters_digest"]=digest({"field":"metadata"})
        d=decide(action="case_write",incident=INC,principal="safe-operator",
                 target=approval["target"],parameters_digest=approval["parameters_digest"],
                 approval={**approval,"principal":"safe-operator"})
        self.assertEqual(d.outcome,"ALLOW")
        self.assertTrue(d.effect_allowed)

if __name__=="__main__": unittest.main()
