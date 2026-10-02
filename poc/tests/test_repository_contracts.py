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

    def test_fallback_is_visible_and_explicitly_volatile_in_ui(self):
        proc=(DASH/"processos.js").read_text(encoding="utf-8")
        visual=(DASH/"log-visual.js").read_text(encoding="utf-8")
        self.assertIn("FALLBACK VOLÁTIL",proc)
        self.assertIn("MEMORY FALLBACK · VOLATILE",visual)
        self.assertIn("somente leitura",proc)

    def test_all_technical_table_headers_have_context_help(self):
        files=[DASH/"index.html",*sorted(DASH.glob("*.js"))]
        for path in files:
            name=path.name
            text=path.read_text(encoding="utf-8")
            for tag in re.findall(r"<th\\b[^>]*>",text):
                self.assertRegex(tag,r"(?:data-help|title|aria-describedby)=",msg=f"{name}: technical <th> without help: {tag}")

    def test_context_help_engine_supports_mouse_keyboard_touch_and_escape(self):
        app=(DASH/"app.js").read_text(encoding="utf-8")
        for token in ("data-help","aria-describedby","pointerover","focusin","pointerType === 'touch'","Escape","MutationObserver"):
            self.assertIn(token,app)
        css=(DASH/"styles.css").read_text(encoding="utf-8")
        self.assertIn(".context-help-popover",css)
        self.assertIn(".has-context-help:focus-visible",css)

    def test_p0_terms_have_contextual_explanations(self):
        runtime={name:(DASH/name).read_text(encoding="utf-8") for name in (
            "index.html","processos.js","zanin.js","auditoria.js","resiliencia.js","interoperabilidade.js"
        )}
        checks={
            "index.html":("UPSTREAM","risco calculada","integração observada"),
            "processos.js":("AS OF LSN","MEMORY_FALLBACK","HITL"),
            "zanin.js":("UNTRUSTED_DOCUMENT","DATA_ONLY","NO TOOL AUTHORITY","Evidence Bundle","TSA","HSM/KMS","WORM"),
            "auditoria.js":("Merkle","Manifesto","Raiz do pacote","AS OF LSN"),
            "resiliencia.js":("RPO","RTO","Checkpoint / Backup"),
            "interoperabilidade.js":("MNI","Idempotência","Chave de Idempotência"),
        }
        for name,tokens in checks.items():
            text=runtime[name]
            self.assertIn("data-help=",text,msg=f"{name} has no contextual help")
            for token in tokens:
                self.assertIn(token,text,msg=f"{name}: missing explained critical term {token}")

    def test_graph_nodes_have_keyboard_equivalent_to_hover_and_click(self):
        app=(DASH/"app.js").read_text(encoding="utf-8")
        for token in ('role="button" tabindex="0"',"onfocus=","onblur=","onkeydown=","event.key==='Enter'","aria-label="):
            self.assertIn(token,app)

    def test_chart_tooltips_have_roving_keyboard_and_touch_access(self):
        app=(DASH/"app.js").read_text(encoding="utf-8")
        for token in ("decorateTips","tabindex', index === 0 ? '0' : '-1'","ArrowRight","ArrowLeft","focusTip","pointerup","plainTip"):
            self.assertIn(token,app)

    def test_context_help_is_materially_present_across_views(self):
        expected={
            "index.html":12,
            "processos.js":3,
            "log-visual.js":5,
            "zanin.js":15,
            "incidente.js":8,
            "auditoria.js":7,
            "resiliencia.js":8,
            "interoperabilidade.js":8,
        }
        for name,minimum in expected.items():
            text=(DASH/name).read_text(encoding="utf-8")
            self.assertGreaterEqual(text.count("data-help="),minimum,msg=f"{name}: contextual help coverage regressed")

    def test_main_tabs_are_self_describing(self):
        html=(DASH/"index.html").read_text(encoding="utf-8")
        tabs=re.findall(r'<button[^>]+class="main-tab[^"]*"[^>]+>',html)
        self.assertGreaterEqual(len(tabs),8)
        for tab in tabs:
            self.assertIn("data-help=",tab)

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
