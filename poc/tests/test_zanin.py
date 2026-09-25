# -*- coding: utf-8 -*-
import pathlib, sys, unittest
HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from zanin_defense import (
    CASE_ZANIN_METADATA,
    CASE_ZANIN_VISIBLE_TEXT,
    CASE_ZANIN_INJECTED_PROMPT,
    PromptInjectionSanitizer,
    generate_certidao_pericial
)

class ZaninDefenseTests(unittest.TestCase):
    def test_clean_document_passes(self):
        result = PromptInjectionSanitizer.inspect(
            visible_text="Texto limpo e legítimo de um recurso ordinário.",
            hidden_payload="",
            font_color="#000000",
            font_size_pt=12.0
        )
        self.assertFalse(result["blocked"])
        self.assertEqual(result["verdict"], "ALLOWED")
        self.assertEqual(result["threat_score"], 0)

    def test_case_zanin_steganographic_injection_is_blocked(self):
        result = PromptInjectionSanitizer.inspect(
            visible_text=CASE_ZANIN_VISIBLE_TEXT,
            hidden_payload=CASE_ZANIN_INJECTED_PROMPT,
            font_color="#ffffff",
            font_size_pt=0.5
        )
        self.assertTrue(result["blocked"])
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertTrue(result["is_steganographic"])
        self.assertTrue(result["is_injection"])
        self.assertGreaterEqual(result["threat_score"], 80)
        self.assertEqual(result["reason_code"], "DEMO_BLOCKED_PROMPT_INJECTION")
        # Confere se os hashes existem
        self.assertTrue(result["evidence"]["sha256_full_document"])
        self.assertTrue(result["evidence"]["sha256_visible"])
        self.assertTrue(result["evidence"]["sha256_hidden"])

    def test_certidao_generation(self):
        inspection = PromptInjectionSanitizer.inspect(
            visible_text=CASE_ZANIN_VISIBLE_TEXT,
            hidden_payload=CASE_ZANIN_INJECTED_PROMPT,
            font_color="#ffffff",
            font_size_pt=0.5
        )
        certidao = generate_certidao_pericial("ARE-1488204-MG", inspection, lsn=10555)
        self.assertEqual(certidao["numero_processo"], "ARE-1488204-MG")
        self.assertEqual(certidao["lsn_heraclitusdb"], 10555)
        self.assertTrue(certidao["hash_certidao_pericial"])
        self.assertEqual(len(certidao["destinatarios"]), 2)

if __name__ == '__main__':
    unittest.main()
