import importlib.util
import json
import pathlib
import unittest
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("stf_poc_server", HERE / "server.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class PocEngineTests(unittest.TestCase):
    def setUp(self): self.e = mod.PocEngine()
    def test_phase1_opens_incident(self):
        for _ in range(7): self.e.step()
        self.assertIsNotNone(self.e.incident); self.assertEqual(self.e.incident["state"], "OPEN")
        self.assertGreaterEqual(len(self.e.signals), 5); self.assertEqual(self.e.incident["principal"], mod.COMPROMISED_PRINCIPAL)
    def test_denied_write_has_zero_upstream_delta(self):
        for _ in range(8): self.e.step()
        ev=self.e.events[-1]; self.assertEqual(ev.event_type,"app.case_update_requested"); self.assertEqual(ev.outcome,"DENY")
        self.assertEqual(ev.upstream_delta,0); self.assertEqual(self.e.upstream_hits,0)
    def test_human_approval_executes_once_and_replay_denied(self):
        for _ in range(12): self.e.step()
        self.assertEqual(self.e.upstream_hits,1); replay=self.e.events[-1]
        self.assertEqual(replay.event_type,"approval.replay"); self.assertEqual(replay.outcome,"DENY"); self.assertEqual(replay.upstream_delta,0)
        self.assertIn("APR-001",self.e.approvals_consumed)
    def test_identity_and_parameter_binding(self):
        for _ in range(14): self.e.step()
        identity=self.e.events[-2]; params=self.e.events[-1]
        self.assertEqual(identity.reason_code,"IDENTITY_BINDING_MISMATCH"); self.assertEqual(params.reason_code,"PARAMETERS_DIGEST_MISMATCH")
        self.assertEqual(identity.upstream_delta,0); self.assertEqual(params.upstream_delta,0)
    def test_evidence_bundle_verifies_and_tamper_fails(self):
        self.e.run_all(); bundle=self.e.evidence_bundle()
        self.assertEqual(self.e.verify_bundle(bundle)["overall"],"PASS")
        tampered=json.loads(json.dumps(bundle)); tampered["events"][0]["summary"]="ADULTERADO"
        self.assertEqual(self.e.verify_bundle(tampered)["overall"],"FAIL")
    def test_full_qualification(self):
        self.e.run_all(); self.assertEqual([x for x in self.e.qualification() if not x["ok"]],[])
        self.assertEqual(self.e.tamper_status,"DETECTED"); self.assertEqual(self.e.offline_verify,"PASS")
    def test_hash_chain_is_deterministic(self):
        a=mod.PocEngine();a.run_all();b=mod.PocEngine();b.run_all()
        self.assertEqual([e.event_hash for e in a.events],[e.event_hash for e in b.events])
        self.assertEqual(a.evidence_bundle()["merkle_root"],b.evidence_bundle()["merkle_root"])
    def test_loopback_adapter_rejects_remote(self):
        sys.path.insert(0,str(HERE)); from heraclitus_adapter import HeraclitusAdapter
        with self.assertRaises(ValueError): HeraclitusAdapter("https://example.com")
    def test_offline_verifier_module(self):
        self.e.run_all(); sys.path.insert(0,str(HERE)); import verify
        self.assertEqual(verify.verify(self.e.evidence_bundle())["overall"],"PASS")


    def test_source_health_activates_as_events_arrive(self):
        self.assertTrue(all(x["status"]=="WAITING" for x in self.e.source_health()))
        for _ in range(7): self.e.step()
        active={x["source"] for x in self.e.source_health() if x["status"]=="ACTIVE"}
        self.assertTrue({"Firewall/WAF","IAM","Host","Network","DB Audit","Application"}.issubset(active))

    def test_why_incident_returns_evidence_chain(self):
        for _ in range(7): self.e.step()
        why=self.e.why_incident()
        self.assertEqual(why["status"],"OPEN")
        self.assertGreaterEqual(len(why["reasons"]),5)
        self.assertEqual(why["principal"],mod.COMPROMISED_PRINCIPAL)
        self.assertTrue(all("evidence_hash" in x for x in why["reasons"]))

    def test_as_of_reconstructs_pre_and_post_incident_state(self):
        self.e.run_all()
        before=self.e.as_of(3)
        after=self.e.as_of(8)
        self.assertIsNone(before["incident"])
        self.assertIsNotNone(after["incident"])
        self.assertEqual(before["upstream_hits"],0)
        self.assertEqual(after["upstream_hits"],0)
        executed=self.e.as_of(11)
        self.assertEqual(executed["upstream_hits"],1)
        self.assertEqual(executed["approval_state"],"CONSUMED")

    def test_evidence_object_exposes_chain_link(self):
        self.e.run_all()
        obj=self.e.evidence_object(5)
        self.assertEqual(obj["status"],"PASS")
        self.assertTrue(obj["provenance"]["chain_link_valid"])
        self.assertEqual(obj["provenance"]["previous_lsn"],4)
        self.assertEqual(obj["provenance"]["next_lsn"],6)

    def test_all_tamper_variants_are_detected(self):
        self.e.run_all()
        for kind in ("modify","delete","reorder","truncate"):
            with self.subTest(kind=kind):
                result=self.e.tamper_variant(kind)
                self.assertEqual(result["status"],"DETECTED")
                self.assertEqual(result["verification"]["overall"],"FAIL")

    def test_incident_report_is_explainable(self):
        self.e.run_all()
        report=self.e.incident_report()
        self.assertEqual(report["incident_id"],mod.INCIDENT_ID)
        self.assertEqual(report["controls"]["policy_enforcement"],"PASS")
        self.assertEqual(report["controls"]["hitl"],"PASS")
        self.assertEqual(report["controls"]["anti_replay"],"PASS")
        self.assertGreaterEqual(len(report["why"]["reasons"]),5)


    def test_compare_as_of_shows_security_state_transition(self):
        self.e.run_all()
        cmp=self.e.compare_as_of(3,15)
        self.assertEqual(cmp["from"]["incident"],None)
        self.assertIsNotNone(cmp["to"]["incident"])
        self.assertGreater(cmp["delta"]["risk"],0)
        self.assertIn("OPEN",cmp["delta"]["incident"])
        self.assertIn("DETECTED",cmp["delta"]["tamper"])


    def test_bundle_manifest_detects_non_event_tampering(self):
        self.e.run_all()
        bundle=self.e.evidence_bundle()
        self.assertEqual(self.e.verify_bundle(bundle)["overall"],"PASS")
        tampered=json.loads(json.dumps(bundle))
        tampered["qualification"][0]["expected"]="HACKED"
        result=self.e.verify_bundle(tampered)
        self.assertEqual(result["manifest"],"FAIL")
        self.assertEqual(result["overall"],"FAIL")

    def test_bundle_manifest_detects_trust_tampering(self):
        self.e.run_all()
        tampered=json.loads(json.dumps(self.e.evidence_bundle()))
        tampered["trust"]["institutional_signature"]="PASS"
        result=self.e.verify_bundle(tampered)
        self.assertEqual(result["manifest"],"FAIL")
        self.assertEqual(result["overall"],"FAIL")


    def test_signal_provenance_matches_final_event_hash_on_incident_open(self):
        for _ in range(5): self.e.step()
        self.assertIsNotNone(self.e.incident)
        event_by_lsn={e.lsn:e for e in self.e.events}
        for signal in self.e.signals:
            self.assertEqual(signal["evidence_hash"],event_by_lsn[signal["lsn"]].event_hash)

    def test_metadata_tampering_fails_semantic_verification(self):
        self.e.run_all()
        bundle=json.loads(json.dumps(self.e.evidence_bundle()))
        bundle["campaign_id"]="OTHER"
        result=self.e.verify_bundle(bundle)
        self.assertEqual(result["semantic"],"FAIL")
        self.assertEqual(result["overall"],"FAIL")

    def test_invalid_hex_hash_fails_without_exception(self):
        self.e.run_all()
        bundle=json.loads(json.dumps(self.e.evidence_bundle()))
        bundle["events"][0]["event_hash"]="z"*64
        result=self.e.verify_bundle(bundle)
        self.assertEqual(result["overall"],"FAIL")

    def test_as_of_matches_external_runtime_correlation(self):
        import telemetry
        e=mod.PocEngine()
        for kind,raw in telemetry.sample_campaign():
            e.ingest_telemetry(kind,raw)
        live=e.snapshot()
        historic=e.as_of(len(e.events))
        self.assertEqual(bool(live["incident"]),bool(historic["incident"]))
        self.assertEqual(live["risk"],historic["risk"])
        self.assertEqual(live["incident"]["principal"],historic["incident"]["principal"])


    def test_concurrent_snapshot_never_emits_invalid_bundle(self):
        import telemetry
        e=mod.PocEngine()
        errors=[]
        def writer():
            try:
                for kind,raw in telemetry.sample_campaign():
                    e.ingest_telemetry(kind,raw)
                    time.sleep(0.002)
            except Exception as exc:
                errors.append(exc)
        t=threading.Thread(target=writer)
        t.start()
        while t.is_alive():
            try:
                bundle=e.evidence_bundle()
                result=e.verify_bundle(bundle)
                if bundle["events"] and result["overall"]!="PASS":
                    errors.append(AssertionError(result))
            except Exception as exc:
                errors.append(exc)
            time.sleep(0.001)
        t.join()
        self.assertEqual(errors,[])

    def test_offline_verifier_invalid_hex_returns_fail_not_exception(self):
        self.e.run_all()
        import verify
        bundle=json.loads(json.dumps(self.e.evidence_bundle()))
        bundle["events"][0]["event_hash"]="z"*64
        result=verify.verify(bundle)
        self.assertEqual(result["overall"],"FAIL")

    def test_execution_modes_do_not_mix_without_reset(self):
        import telemetry
        e=mod.PocEngine()
        kind,raw=telemetry.sample_campaign()[0]
        e.ingest_telemetry(kind,raw)
        before=len(e.events)
        state=e.step()
        self.assertEqual(len(e.events),before)
        self.assertEqual(state["execution_mode"],"API_LAB")

    def test_certidoes_emitir_e_listar(self):
        cert = self.e.emit_certidao("Teste de indisponibilidade programada", 184)
        self.assertTrue(cert["id"].startswith("CERT-2026-"))
        self.assertIn("hash", cert)
        self.assertIn("lsn", cert)
        self.assertEqual(cert["duracao"], "3m 04s")
        certs = self.e.list_certidoes()
        self.assertTrue(any(c["id"] == cert["id"] for c in certs))
        # Verifica se o evento está gravado na cadeia de evidências
        ev = self.e.events[-1]
        self.assertEqual(ev.event_type, "stf.resilience.certidao_indisponibilidade")
        self.assertEqual(ev.event_hash, cert["hash"])

    def test_interop_reconciliar_e_duplicata(self):
        mock_ledger = type("MockLedger", (), {"listar": lambda self: {"processos": []}})()
        reconcil = self.e.interop_reconciliar(mock_ledger)
        self.assertEqual(reconcil["status"], "RECONCILIADO")
        self.assertGreaterEqual(reconcil["total_monitoradas"], 3)
        dup = self.e.interop_testar_duplicata(mock_ledger)
        self.assertTrue(dup["deduplicated"])
        self.assertEqual(dup["status"], "DUPLICATA_DETECTADA")

class DesfechoUnicoTests(unittest.TestCase):
    """A mesma regra no grafo (contadores) e nos gráficos (classifyDecision)."""
    def test_eventos_de_controlo_nao_contam_como_tentativa(self):
        e=mod.PocEngine(); e.run_all()
        controlo=[ev for ev in e.events if ev.details.get("attack") is False]
        self.assertTrue(controlo)
        total=sum(c["attempts"] for c in e.equipment_counters.values())
        self.assertEqual(total,len(e.events)-len(controlo))
    def test_hitl_retido_conta_como_bloqueado(self):
        self.assertTrue(mod.is_blocked({"outcome":"REQUIRE_HITL"}))
        self.assertTrue(mod.is_blocked({"outcome":"deny"}))
        self.assertFalse(mod.is_blocked({"outcome":"OBSERVED"}))
        self.assertFalse(mod.is_attack({"attack":False}))
        self.assertTrue(mod.is_attack({}))

    def test_simulacao_grava_perfil_por_componente_sem_efeito_real(self):
        class Adapter:
            def __init__(self): self.events = []
            def record_red_team_event(self, payload):
                self.events.append(payload)
                return {"accepted": True, "lsn": len(self.events)}

        engine = mod.PocEngine()
        adapter = Adapter()
        engine.adapter = adapter
        for attack_id in ("NET_WAF_01", "DB_ORA_01", "H01"):
            results = [engine.simulate_attack(attack_id) for _ in range(10)]
            eq_id = results[0]["attack"]["equipment_id"]
            self.assertEqual(sum(engine.demo_counts[eq_id].values()), 10)
            self.assertTrue(all(result["event"]["upstream_delta"] == 0 for result in results))
        self.assertEqual(engine.upstream_hits, 0)
        self.assertEqual(len(adapter.events), 30)
        self.assertTrue(all(event["campaign_id"] == mod.DEMO_CAMPAIGN_ID for event in adapter.events))
        self.assertEqual({event["reason_code"] for event in adapter.events}, {
            "DEMO_DEFENDED", "DEMO_BLOCKED", "DEMO_TARGET_REACHED"
        })

    def test_simulacao_recusa_disparo_sem_banco(self):
        engine = mod.PocEngine()
        engine.adapter = None
        with self.assertRaisesRegex(RuntimeError, "HeraclitusDB indisponível"):
            engine.simulate_attack("NET_WAF_01")
        self.assertEqual(sum(sum(counts.values()) for counts in engine.demo_counts.values()), 0)

if __name__=="__main__": unittest.main()
