# -*- coding: utf-8 -*-
import pathlib
import sys
import unittest
import hashlib

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from zanin_defense import (
    PUBLIC_INCIDENT_FACTS,
    SYNTHETIC_SCENARIOS,
    TextSpan,
    Finding,
    DocumentParser,
    ForensicDetector,
    DocumentSanitizer,
    DefensePipelineSimulator,
    EvidenceBundleManager,
    TechnicalReportGenerator
)

class ComprehensiveZaninDefenseTests(unittest.TestCase):

    def test_facts_and_disclaimer_integrity(self):
        """Verifica que os fatos públicos e as distinções de simulação estão explícitos."""
        self.assertIn("fatos_confirmados", PUBLIC_INCIDENT_FACTS)
        self.assertIn("o_que_nao_e_fato_publico", PUBLIC_INCIDENT_FACTS)
        self.assertTrue(len(PUBLIC_INCIDENT_FACTS["fatos_confirmados"]) >= 5)

    def test_benign_document_passes_without_false_positive(self):
        """Um texto acadêmico que cita termos de prompt injection não deve ser bloqueado."""
        doc = DocumentParser.parse_from_scenario("scenario_academic_benign")
        det = ForensicDetector.inspect(doc)
        self.assertEqual(det["verdict"], "ALLOWED")
        self.assertFalse(det["quarantine_recommended"])
        self.assertEqual(len(det["findings"]), 0)

    def test_steganographic_prompt_injection_is_quarantined(self):
        """Documento com esteganografia visual e instruções de coerção deve ser colocado em quarentena."""
        doc = DocumentParser.parse_from_scenario("scenario_zanin_stego")
        det = ForensicDetector.inspect(doc)
        self.assertEqual(det["verdict"], "QUARANTINED")
        self.assertTrue(det["quarantine_recommended"])

        # Deve conter findings explicáveis estruturados
        rule_ids = [f["regra_disparada"] for f in det["findings"]]
        self.assertIn("DOC-STEG-001", rule_ids)
        self.assertIn("DOC-STEG-002", rule_ids)
        self.assertIn("DOC-AI-001", rule_ids)

        for finding in det["findings"]:
            self.assertTrue(finding["finding_id"].startswith("PI-"))
            self.assertTrue(finding["explicacao"])
            self.assertIn(finding["severidade"], ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_original_document_bytes_immutable_during_sanitization(self):
        """A sanitização deve gerar cópia limpa SEM alterar os bytes do documento original."""
        doc = DocumentParser.parse_from_scenario("scenario_zanin_stego")
        orig_hash_before = doc["hashes"]["sha256_original_bytes"]

        det = ForensicDetector.inspect(doc)
        san = DocumentSanitizer.sanitize(doc, det["findings"])

        self.assertTrue(san["forensic_integrity"]["bytes_originais_preservados"])
        self.assertFalse(san["forensic_integrity"]["documento_original_alterado"])
        self.assertTrue(san["forensic_integrity"]["copia_sanitizada_criada"])
        self.assertEqual(san["original_sha256"], orig_hash_before)

        # O texto sanitizado não deve conter os spans ocultos
        self.assertNotIn("[SYSTEM_OVERRIDE]", san["sanitized_text"])
        self.assertGreater(san["removed_spans_count"], 0)

    def test_detector_miss_scenario_b_policy_gateway_denies_with_zero_upstream(self):
        """TESTE FUNDAMENTAL: Mesmo quando o detector falha (MISS), o Policy Gateway barra a ação."""
        result = DefensePipelineSimulator.run_pipeline("scenario_b_miss")

        # 1. Detector teve MISS
        self.assertEqual(result["detection"]["verdict"], "ALLOWED")
        self.assertEqual(len(result["detection"]["findings"]), 0)

        # 2. O LLM foi exposto e tentou executar ação protegida
        self.assertTrue(result["llm"]["exposed"])
        self.assertEqual(result["llm"]["requested_action"], "judicial_case_write")

        # 3. Barreira 2 (Policy Gateway) interceptou e negou
        pol = result["policy_decision"]
        self.assertEqual(pol["decision"], "DENY")
        self.assertEqual(pol["reason_code"], "UNAUTHORIZED_DOCUMENT_ORIGIN_ACTION")
        self.assertEqual(pol["upstream_delta"], 0)
        self.assertEqual(pol["executed_count"], 0)
        self.assertEqual(pol["real_effect"], "NENHUM")

    def test_legitimate_scenario_c_executes_with_upstream_one(self):
        """Cenário C: Ação autorizada com HITL aprovação vinculada executa com upstream_delta=1."""
        result = DefensePipelineSimulator.run_pipeline("scenario_c_legit")

        pol = result["policy_decision"]
        self.assertEqual(pol["decision"], "ALLOW")
        self.assertEqual(pol["reason_code"], "AUTHORIZED_BY_BOUND_HITL_APPROVAL")
        self.assertEqual(pol["upstream_delta"], 1)
        self.assertEqual(pol["executed_count"], 1)

    def test_evidence_bundle_and_offline_verifier(self):
        """Gera o Evidence Bundle e valida com o verificador offline."""
        result = DefensePipelineSimulator.run_pipeline("scenario_zanin_stego")
        bundle = EvidenceBundleManager.build_bundle(result)

        self.assertIn("manifest", bundle)
        self.assertIn("original", bundle)
        self.assertIn("extracted", bundle)
        self.assertIn("sanitized", bundle)
        self.assertIn("proofs", bundle)

        # Verificação offline
        verification = EvidenceBundleManager.verify_bundle(bundle)
        self.assertEqual(verification["overall_status"], "PASS")

        # Verifica se checagens sem integração externa permanecem estritamente UNVERIFIED
        check_map = {c["check"]: c["status"] for c in verification["checks"]}
        self.assertEqual(check_map["PACKAGE_STRUCTURE"], "PASS")
        self.assertEqual(check_map["ORIGINAL_FILE_HASH"], "PASS")
        self.assertEqual(check_map["POLICY_AND_UPSTREAM_ENFORCEMENT"], "PASS")
        self.assertEqual(check_map["EXTERNAL_TIMESTAMP"], "UNVERIFIED")
        self.assertEqual(check_map["INSTITUTIONAL_SIGNATURE"], "UNVERIFIED")

    def test_technical_report_disclaimer_header(self):
        """O relatório técnico gerado deve ter cabeçalho explícito de não emissão pelo STF."""
        result = DefensePipelineSimulator.run_pipeline("scenario_zanin_stego")
        report = TechnicalReportGenerator.generate(result)

        cab = report["cabecalho"]
        self.assertEqual(cab["titulo"], "RELATÓRIO TÉCNICO SINTÉTICO DA POC")
        self.assertIn("ARTEFATO SINTÉTICO DE DEMONSTRAÇÃO", cab["subtitulo"])
        self.assertEqual(cab["aviso_legal"], "NÃO EMITIDO PELO SUPREMO TRIBUNAL FEDERAL")
        self.assertEqual(report["enforcement_politica"]["upstream_delta"], 0)

    def test_vitoria_data_exfiltration_blocked_with_zero_upstream(self):
        """Cenário VitórIA: Tentativa de exfiltração de minutas sigilosas é barrada com upstream_delta=0."""
        result = DefensePipelineSimulator.run_pipeline("scenario_vitoria_exfiltration")

        # 1. Detector identifica esteganografia e tentativa de tool abuse / exfiltração
        det = result["detection"]
        self.assertEqual(det["verdict"], "QUARANTINED")
        rules = [f["regra_disparada"] for f in det["findings"]]
        self.assertIn("DOC-STEG-001", rules)
        self.assertIn("DOC-TOOL-001", rules)

        # 2. Policy Gateway barra com upstream_delta=0
        pol = result["policy_decision"]
        self.assertEqual(pol["decision"], "QUARANTINED_PRE_LLM")
        self.assertEqual(pol["policy_rule"], "POLICY-HERACLITUS-SIGILO-V1")
        self.assertEqual(pol["upstream_delta"], 0)
        self.assertEqual(pol["real_effect"], "NENHUM (ACESSO A SEGREDO DE JUSTIÇA NEGADO)")
        self.assertIn("Heraclitus", pol["heraclitus_role"])

        # 3. Incident Graph contém os nós do Heraclitus
        node_labels = [n["label"] for n in result["incident_graph"]["nodes"]]
        self.assertIn("Heraclitus Policy Gateway", node_labels)
        self.assertIn("Heraclitus LSN Ledger", node_labels)

if __name__ == '__main__':
    unittest.main()

