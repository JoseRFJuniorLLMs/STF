import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
DASH=ROOT/"poc"/"dashboard"

class RepositoryContracts(unittest.TestCase):
    def test_every_main_tab_has_matching_view(self):
        html=(DASH/"index.html").read_text(encoding="utf-8")
        pairs=re.findall(r'<button[^>]+class="main-tab[^"]*"[^>]+aria-controls="([^"]+)"[^>]+data-view="([^"]+)"',html)
        self.assertGreaterEqual(len(pairs),8)
        for view_id,_ in pairs:
            self.assertIn(f'id="{view_id}"',html)

    def test_forense_ia_contract_is_present(self):
        html=(DASH/"index.html").read_text(encoding="utf-8")
        js=(DASH/"zanin.js").read_text(encoding="utf-8")
        self.assertIn("Forense de IA",html)
        for token in ("Modo Executivo","Modo Pericial","O humano vê uma coisa. A máquina pode receber outra.","btnReplayIncident","evidenceGraph","execTrustChecklist"):
            self.assertIn(token,js)

    def test_no_inline_dynamic_attack_navigation_handlers(self):
        for name in ("processos.js","incidente.js","auditoria.js"):
            text=(DASH/name).read_text(encoding="utf-8")
            self.assertNotRegex(text,r'onclick="[^"]*goToAttack\(')

    def test_prohibited_overclaims_are_absent_from_runtime_ui(self):
        banned=["Ninguém — nem os técnicos do tribunal — consegue alterar","Garantia de Não-Repúdio","100% PARIDADE","Certidão Oficial de Indisponibilidade","RPO Comprovado","EFEITO REAL: NENHUM"]
        runtime="\n".join(x.read_text(encoding="utf-8",errors="ignore") for x in DASH.glob("*") if x.suffix in {".js",".html"})
        for phrase in banned:
            self.assertNotIn(phrase,runtime)

    def test_destructive_reset_never_uses_shell_true(self):
        text=(ROOT/"zera.py").read_text(encoding="utf-8")
        self.assertNotIn("shell=True",text)
        self.assertIn('parser.add_argument("--yes"',text)
        self.assertIn("validated_data_dir",text)

    def test_deploy_is_sha_based_not_manual_scp_manifest(self):
        text=(ROOT/"deploy.md").read_text(encoding="utf-8")
        self.assertIn("git checkout --detach",text)
        self.assertIn("DEPLOYED_SHA",text)
        self.assertNotIn("compute scp",text)

if __name__=="__main__": unittest.main()
