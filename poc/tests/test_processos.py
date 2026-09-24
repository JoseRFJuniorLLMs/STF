import json,os,pathlib,re,sys,tempfile,unittest
from datetime import datetime
HERE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
from heraclitus_core import CoreUnavailable,HeraclitusCore,_fields,decode_append_response,decode_query_response,encode_append_request,encode_query_request,resolve_token
from processos import BRT,CATALOGO,TPU,ProcessLedger,_passos,numero_unico,numero_unico_valido,verificar_cadeia

class FakeCore:
    """Núcleo em memória com a semântica que o ledger usa: idempotência por
    chave, `parents`, e `AS OF LSN n` exclusivo (só o que existia antes de n)."""
    addr="127.0.0.1:0"
    def __init__(self):
        self.rows=[]; self.by_key={}
    def append(self,*,agent_id,session_id,kind,content,attrs,parents,idempotency_key):
        payload=json.dumps([kind,content,attrs,parents],sort_keys=True)
        if idempotency_key in self.by_key:
            row,prev=self.by_key[idempotency_key]
            if prev!=payload: raise RuntimeError("idempotency key reused with a different payload")
            return {"lsn":row["lsn"],"deduplicated":True,"event_id":row["id"]}
        lsn=len(self.rows)+100
        row={"lsn":lsn,"id":f"01EV{lsn:06d}","kind":kind,"content":json.dumps(content),"parents":list(parents),
             "attrs":{**attrs,"__heraclitus_idempotency_key":idempotency_key},"ts_hlc":(1_790_000_000_000+lsn)<<16}
        self.rows.append(row); self.by_key[idempotency_key]=(row,payload)
        return {"lsn":lsn,"deduplicated":False,"event_id":row["id"]}
    def query(self,gql):
        conds=dict(re.findall(r'n\.(\w+) = "([^"]*)"',gql))
        m=re.search(r"AS OF LSN (\d+)",gql); limit=int(m.group(1)) if m else None
        return [r for r in self.rows if all(r["attrs"].get(k)==v for k,v in conds.items()) and (limit is None or r["lsn"]<limit)]

class NumeroUnicoTests(unittest.TestCase):
    def test_catalogo_tem_numero_unico_cnj_valido(self):
        for proc in CATALOGO:
            numero=numero_unico(proc["sequencial"],proc["ano"])
            self.assertTrue(numero_unico_valido(numero),numero)
            self.assertTrue(numero.endswith(".1.00.0000"))
    def test_dv_adulterado_e_rejeitado(self):
        numero=numero_unico(1,2026); dv=int(numero[8:10])
        self.assertFalse(numero_unico_valido(f"{numero[:8]}{(dv+1)%100:02d}{numero[10:]}"))
    def test_roteiros_so_usam_codigos_tpu_catalogados(self):
        for proc in CATALOGO:
            for passo in proc["roteiro"]:
                if passo["tipo"]=="andamento": self.assertIn(passo["codigo"],TPU,proc["id"])
            self.assertLessEqual(proc["inicial"],len(_passos(proc)))

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.core=FakeCore(); self.ledger=ProcessLedger(self.core)
    def test_protocolar_e_idempotente(self):
        primeiro=self.ledger.protocolar()
        self.assertEqual(primeiro["gravados"],sum(p["inicial"] for p in CATALOGO))
        segundo=self.ledger.protocolar()
        self.assertEqual(segundo,{"gravados":0,"ja_existentes":primeiro["gravados"]})
        self.assertEqual(len(self.core.rows),primeiro["gravados"])
    def test_lista_resume_cada_processo_a_partir_do_banco(self):
        self.ledger.protocolar()
        lista=self.ledger.listar()
        self.assertEqual(len(lista["processos"]),len(CATALOGO))
        re1=next(p for p in lista["processos"] if p["id"]=="RE-000001")
        self.assertEqual(re1["eventos"],CATALOGO[0]["inicial"])
        self.assertEqual(re1["situacao"],"EM_TRAMITACAO")
        self.assertEqual(re1["capa"]["numero"],"RE 000001")
    def test_tramitar_encadeia_no_evento_anterior(self):
        self.ledger.protocolar()
        antes=self.ledger.detalhe("HC-000003")["eventos"]
        res=self.ledger.tramitar("HC-000003",agora=datetime(2026,9,24,10,0,tzinfo=BRT))
        self.assertEqual(res["seq"],len(antes)+1)
        depois=self.ledger.detalhe("HC-000003")
        self.assertEqual(depois["eventos"][-1]["parents"],[antes[-1]["id"]])
        self.assertTrue(depois["integridade"]["integra"])
        self.assertEqual(depois["eventos"][-1]["conteudo"]["dataHora"],"2026-09-24T10:00:00-03:00")
    def test_tramitar_ate_ao_fim_leva_a_baixa(self):
        self.ledger.protocolar()
        proc=next(p for p in CATALOGO if p["id"]=="ARE-000006")
        for _ in range(len(_passos(proc))-proc["inicial"]): self.ledger.tramitar("ARE-000006")
        self.assertEqual(self.ledger.detalhe("ARE-000006")["processo"]["situacao"],"BAIXADO")
        with self.assertRaises(LookupError): self.ledger.tramitar("ARE-000006")
    def test_tramitar_sem_protocolo_ou_processo_desconhecido(self):
        with self.assertRaises(LookupError): self.ledger.tramitar("RE-000001")
        with self.assertRaises(KeyError): self.ledger.tramitar("RE-999999")
        with self.assertRaises(LookupError): self.ledger.tramitar()
    def test_as_of_reconstroi_o_processo_incluindo_o_lsn_pedido(self):
        self.ledger.protocolar()
        eventos=self.ledger.detalhe("ADI-000002")["eventos"]
        corte=eventos[3]["lsn"]
        passado=self.ledger.detalhe("ADI-000002",as_of=corte)
        self.assertEqual([e["lsn"] for e in passado["eventos"]],[e["lsn"] for e in eventos[:4]])
        self.assertEqual(passado["lsns"],[e["lsn"] for e in eventos])
        self.assertTrue(passado["integridade"]["integra"])
    def test_id_invalido_nao_chega_ao_gql(self):
        with self.assertRaises(ValueError): self.ledger._eventos('RE-000001" OR n.x = "y')

class CadeiaTests(unittest.TestCase):
    def _cadeia(self):
        ledger=ProcessLedger(FakeCore()); ledger.protocolar()
        return ledger.detalhe("RE-000001")["eventos"]
    def test_cadeia_integra(self):
        self.assertTrue(verificar_cadeia(self._cadeia())["integra"])
    def test_elo_cortado_e_detectado(self):
        eventos=self._cadeia(); eventos[4]["parents"]=["01FORJADO"]
        res=verificar_cadeia(eventos)
        self.assertFalse(res["integra"]); self.assertEqual(res["elos"],4)
    def test_evento_apagado_e_detectado(self):
        eventos=self._cadeia(); del eventos[2]
        self.assertFalse(verificar_cadeia(eventos)["integra"])

class CoreCodecTests(unittest.TestCase):
    def test_append_request_codifica_todos_os_campos(self):
        raw=encode_append_request("ag","sess","Kind",b"{}",{"b":"2","a":"1"},["P1","P2"],"k1")
        campos=list(_fields(raw))
        self.assertEqual([n for n,_ in campos],[1,2,3,4,8,8,9,9,10])
        self.assertEqual(dict(_fields(campos[4][1])),{1:b"a",2:b"1"})
        self.assertEqual(campos[-1][1],b"k1")
    def test_append_response_e_query(self):
        self.assertEqual(decode_append_response(b"\x08\xa0\x35\x10\x01\x1a\x03ULI"),{"lsn":6816,"deduplicated":True,"event_id":"ULI"})
        self.assertEqual(decode_query_response(encode_query_request('[{"lsn":1}]')),'[{"lsn":1}]')
    def test_nucleo_so_aceita_loopback(self):
        HeraclitusCore("127.0.0.1:17474")
        with self.assertRaises(ValueError): HeraclitusCore("10.0.0.5:17474")

class TokenTests(unittest.TestCase):
    def setUp(self):
        self.saved={k:os.environ.pop(k,None) for k in ("STF_HERACLITUS_CORE_TOKEN","STF_HERACLITUS_CORE_TOKEN_FILE","HERACLITUS_TOKEN","HERACLITUS_TOKEN_FILE")}
    def tearDown(self):
        for k,v in self.saved.items():
            os.environ.pop(k,None)
            if v is not None: os.environ[k]=v
    def test_credencial_de_outra_instancia_nao_e_usada(self):
        os.environ["HERACLITUS_TOKEN"]="token-da-memoria"
        self.assertIsNone(resolve_token())
    def test_token_do_stf_por_variavel_e_por_ficheiro(self):
        os.environ["STF_HERACLITUS_CORE_TOKEN"]=" abc "
        self.assertEqual(resolve_token(),"abc")
        del os.environ["STF_HERACLITUS_CORE_TOKEN"]
        with tempfile.NamedTemporaryFile("w",suffix=".token",delete=False) as fh: fh.write("xyz\n")
        try:
            os.environ["STF_HERACLITUS_CORE_TOKEN_FILE"]=fh.name
            self.assertEqual(resolve_token(),"xyz")
        finally: os.unlink(fh.name)
    def test_ficheiro_ilegivel_vira_estado_e_nao_derruba_o_painel(self):
        os.environ["STF_HERACLITUS_CORE_TOKEN_FILE"]=str(HERE/"nao-existe.token")
        core=HeraclitusCore("127.0.0.1:17474")
        with self.assertRaises(CoreUnavailable): core.query("MATCH (n) RETURN n")

if __name__=="__main__": unittest.main()
