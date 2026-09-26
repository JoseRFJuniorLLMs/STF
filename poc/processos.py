"""Acompanhamento processual sintético gravado no núcleo do HeraclitusDB.

Não há processo "em si" aqui — nem peças, nem partes, nem conteúdo. Só o LOG,
no formato em que o Judiciário já o publica:

- o portal do STF (Acompanhamento Processual) separa Andamentos, Deslocamentos
  e Petições, e o serviço STF Push avisa a cada andamento novo;
- a API pública do DataJud (CNJ) entrega cada andamento como
  `movimentos[] = {codigo, nome, dataHora, complementosTabelados}`, com o
  código da Tabela Processual Unificada (TPU) de movimentos;
- o número único segue a Resolução CNJ 65/2008 (`NNNNNNN-DD.AAAA.J.TR.OOOO`;
  no STF, J=1, TR=00, OOOO=0000; DV em módulo 97).

Cada linha do log é um evento imutável no HeraclitusDB (`Append`), encadeado ao
anterior do mesmo processo por `parents` e protegido por chave de
idempotência. A aba lê tudo de volta por GQL — inclusive `AS OF LSN`, para
reconstruir o processo como estava num ponto do passado. O roteiro abaixo só
diz o que ACONTECE a seguir; o que JÁ aconteceu vem sempre do banco.

Os processos, relatores, protocolos e guias são fictícios.
"""
from __future__ import annotations

import json
import random
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from heraclitus_core import HeraclitusCore

GENERATED_BY = "stf_processos"
AGENT_ID = "stf-poc-processual"
SCHEMA = "stf-poc/processo-evento/v1"
BRT = timezone(timedelta(hours=-3))
PROCESSO_ID_RE = re.compile(r"^[A-Z]{2,5}-\d{6}$")

KINDS = {
    "protocolo": "ProcessoProtocolo",
    "andamento": "ProcessoAndamento",
    "deslocamento": "ProcessoDeslocamento",
    "peticao": "ProcessoPeticao",
}

# Tabela Processual Unificada — movimentos (CNJ/SGT, movimentos.csv). Só os
# códigos usados no roteiro, com o nome exatamente como o CNJ os publica.
TPU = {
    22: "Baixa Definitiva",
    26: "Distribuição",
    51: "Conclusão",
    85: "Petição",
    92: "Publicação",
    123: "Remessa",
    132: "Recebimento",
    212: "Denegação",
    219: "Procedência",
    235: "Não Conhecimento de recurso",
    237: "Provimento",
    239: "Não-Provimento",
    246: "Definitivo",
    848: "Trânsito em julgado",
    888: "Concessão em parte",
    968: "Não-Concessão",
    1051: "Decurso de Prazo",
    1061: "Disponibilização no Diário da Justiça Eletrônico",
    11010: "Mero expediente",
    11383: "Praticado ato ordinatório",
    12104: "Inclusão em pauta",
    12105: "Inclusão em Pauta de Sessão Virtual",
    12164: "Outras Decisões",
    12199: "Julgado",
    12201: "Liminar",
    12203: "Adiado",
    12204: "Pedido de Vista",
    14091: "Devolvidos os autos após Pedido de Vista",
    15729: "Intimação Expedida",
}
TPU_ENCERRAMENTO = {22, 246}


def numero_unico(sequencial: int, ano: int) -> str:
    """Número único CNJ de um processo do STF (J=1, TR=00, OOOO=0000)."""
    n, j, tr, oooo = f"{sequencial:07d}", "1", "00", "0000"
    dv = 98 - int(f"{n}{ano}{j}{tr}{oooo}00") % 97
    return f"{n}-{dv:02d}.{ano}.{j}.{tr}.{oooo}"


def numero_unico_valido(numero: str) -> bool:
    m = re.fullmatch(r"(\d{7})-(\d{2})\.(\d{4})\.(\d)\.(\d{2})\.(\d{4})", numero)
    if not m:
        return False
    n, dv, ano, j, tr, oooo = m.groups()
    return int(f"{n}{ano}{j}{tr}{oooo}{dv}") % 97 == 1


# ------------------------------------------------------------------ roteiros
def _a(dia: int, codigo: int, complemento: str = "", orgao: str | None = None) -> dict[str, Any]:
    return {"tipo": "andamento", "dia": dia, "codigo": codigo, "complemento": complemento, "orgao": orgao}


def _d(dia: int, de: str, para: str, guia: int) -> dict[str, Any]:
    return {"tipo": "deslocamento", "dia": dia, "de": de, "para": para, "guia": guia}


def _p(dia: int, tipo_peticao: str, peticionante: str, numero: int) -> dict[str, Any]:
    return {"tipo": "peticao", "dia": dia, "tipo_peticao": tipo_peticao, "peticionante": peticionante, "numero": numero}


SEC_AUTUACAO = "Seção de Autuação de Originários"
SEC_RECURSAL = "Seção de Recebimento e Distribuição de Recursos"
SEC_ACORDAOS = "Seção de Processamento de Acórdãos"
SEC_BAIXA = "Seção de Baixa e Expedição"
SEC_PLENARIO = "Secretaria de Sessões — Plenário Virtual"


def _gab(n: int) -> str:
    return f"Gabinete do Relator Sintético {n:02d}"


CATALOGO: list[dict[str, Any]] = [
    {
        "id": "RE-000001", "sequencial": 1, "ano": 2026, "classe": "RE", "classe_nome": "Recurso Extraordinário",
        "relator": "Min. Relator(a) Sintético(a) 01", "orgao": "Tribunal Pleno",
        "assunto": "Direito Administrativo — tema de repercussão geral (sintético)",
        "origem": "Tribunal de origem sintético — remessa via MNI", "protocolado_em": "2026-02-09T10:12:00",
        "inicial": 12,
        "roteiro": [
            _a(0, 132, "Autos recebidos do tribunal de origem pelo barramento MNI"),
            _a(1, 26, "Distribuído por sorteio ao Min. Relator(a) Sintético(a) 01"),
            _d(1, SEC_RECURSAL, _gab(1), 3101),
            _a(2, 51, "Conclusos ao(à) Relator(a)"),
            _a(9, 12105, "Para análise de repercussão geral"),
            _a(30, 12199, "Plenário Virtual: reconhecida a existência de repercussão geral"),
            _a(33, 1061, "Acórdão da repercussão geral"),
            _a(34, 92, "DJe — acórdão da repercussão geral"),
            _p(41, "Manifestação da Procuradoria-Geral da República", "Procuradoria-Geral da República (sintética)", 11873),
            _a(41, 85, "Juntada da manifestação da PGR"),
            _a(58, 12105, "Julgamento de mérito — sessão virtual"),
            _a(64, 12204, "Pedido de vista do(a) Min. Sintético(a) 07"),
            _a(96, 14091, "Autos devolvidos para prosseguimento do julgamento"),
            _a(110, 237, "Recurso extraordinário provido; tese de repercussão geral fixada"),
            _d(111, _gab(1), SEC_ACORDAOS, 3544),
            _a(118, 1061, "Acórdão de mérito"),
            _a(119, 92, "DJe — acórdão de mérito"),
            _a(135, 848, "Certidão de trânsito em julgado"),
            _d(136, SEC_ACORDAOS, SEC_BAIXA, 3712),
            _a(137, 123, "Autos remetidos ao tribunal de origem via MNI"),
            _a(137, 22, "Baixa definitiva dos autos"),
        ],
    },
    {
        "id": "ADI-000002", "sequencial": 2, "ano": 2026, "classe": "ADI", "classe_nome": "Ação Direta de Inconstitucionalidade",
        "relator": "Min. Relator(a) Sintético(a) 02", "orgao": "Tribunal Pleno",
        "assunto": "Controle concentrado — lei estadual sintética", "origem": "Originário (e-STF)",
        "protocolado_em": "2026-03-03T16:40:00", "inicial": 10,
        "roteiro": [
            _a(0, 26, "Distribuído por sorteio ao Min. Relator(a) Sintético(a) 02"),
            _d(0, SEC_AUTUACAO, _gab(2), 4102),
            _a(1, 51, "Conclusos ao(à) Relator(a)"),
            _a(3, 11010, "Adotado o rito do art. 12 da Lei 9.868/1999"),
            _a(4, 15729, "Informações às autoridades requeridas; vista à AGU e à PGR"),
            _p(15, "Informações", "Autoridade requerida (sintética)", 20114),
            _a(15, 85, "Juntada das informações"),
            _p(26, "Manifestação da Advocacia-Geral da União", "Advocacia-Geral da União (sintética)", 21980),
            _a(26, 85, "Juntada da manifestação da AGU"),
            _p(38, "Parecer da Procuradoria-Geral da República", "Procuradoria-Geral da República (sintética)", 23411),
            _a(38, 85, "Juntada do parecer da PGR"),
            _a(40, 51, "Conclusos ao(à) Relator(a)"),
            _a(62, 12104, "Pauta do Plenário — sessão presencial"),
            _a(69, 12203, "Julgamento adiado por indicação da Presidência"),
            _a(83, 12105, "Julgamento em sessão virtual"),
            _a(90, 219, "Pedido julgado procedente"),
            _a(97, 1061, "Acórdão"),
            _a(98, 92, "DJe — acórdão"),
            _a(112, 848, "Certidão de trânsito em julgado"),
            _a(113, 246, "Arquivamento definitivo"),
        ],
    },
    {
        "id": "HC-000003", "sequencial": 3, "ano": 2026, "classe": "HC", "classe_nome": "Habeas Corpus",
        "relator": "Min. Relator(a) Sintético(a) 03", "orgao": "Segunda Turma",
        "assunto": "Direito Processual Penal — prisão preventiva (sintético)", "origem": "Originário (e-STF)",
        "protocolado_em": "2026-04-14T09:05:00", "inicial": 9,
        "roteiro": [
            _a(0, 26, "Distribuído por prevenção ao Min. Relator(a) Sintético(a) 03"),
            _d(0, SEC_AUTUACAO, _gab(3), 5207),
            _a(0, 51, "Conclusos ao(à) Relator(a) — pedido de medida liminar"),
            _a(2, 968, "Medida liminar indeferida"),
            _a(3, 15729, "Informações à autoridade coatora; vista à PGR"),
            _p(10, "Informações", "Autoridade coatora (sintética)", 31022),
            _a(10, 85, "Juntada das informações"),
            _p(21, "Parecer da Procuradoria-Geral da República", "Procuradoria-Geral da República (sintética)", 32640),
            _a(21, 85, "Juntada do parecer da PGR"),
            _a(22, 51, "Conclusos ao(à) Relator(a)"),
            _a(37, 12105, "Segunda Turma — sessão virtual"),
            _a(44, 212, "Ordem denegada"),
            _a(49, 1061, "Acórdão"),
            _a(50, 92, "DJe — acórdão"),
            _a(62, 848, "Certidão de trânsito em julgado"),
            _a(63, 22, "Baixa definitiva dos autos"),
        ],
    },
    {
        "id": "ADPF-000004", "sequencial": 4, "ano": 2026, "classe": "ADPF", "classe_nome": "Arguição de Descumprimento de Preceito Fundamental",
        "relator": "Min. Relator(a) Sintético(a) 04", "orgao": "Tribunal Pleno",
        "assunto": "Direitos fundamentais — política pública sintética", "origem": "Originário (e-STF)",
        "protocolado_em": "2026-05-20T14:22:00", "inicial": 7,
        "roteiro": [
            _a(0, 26, "Distribuído por sorteio ao Min. Relator(a) Sintético(a) 04"),
            _d(0, SEC_AUTUACAO, _gab(4), 6118),
            _a(1, 51, "Conclusos ao(à) Relator(a) — pedido de medida cautelar"),
            _a(8, 888, "Medida cautelar deferida em parte, ad referendum do Plenário"),
            _a(9, 12105, "Referendo da medida cautelar — sessão virtual"),
            _d(9, _gab(4), SEC_PLENARIO, 6190),
            _a(16, 12201, "Referendada a medida cautelar"),
            _a(19, 1061, "Acórdão do referendo"),
            _a(20, 92, "DJe — acórdão do referendo"),
            _p(33, "Pedido de ingresso como amicus curiae", "Entidade de classe (sintética)", 40551),
            _a(33, 85, "Juntada do pedido de amicus curiae"),
            _a(34, 51, "Conclusos ao(à) Relator(a)"),
            _a(47, 11010, "Admitido o ingresso do amicus curiae"),
        ],
    },
    {
        "id": "MS-000005", "sequencial": 5, "ano": 2026, "classe": "MS", "classe_nome": "Mandado de Segurança",
        "relator": "Min. Relator(a) Sintético(a) 05", "orgao": "Primeira Turma",
        "assunto": "Direito Administrativo — ato de autoridade sintética", "origem": "Originário (e-STF)",
        "protocolado_em": "2026-06-02T11:48:00", "inicial": 8,
        "roteiro": [
            _a(0, 26, "Distribuído por sorteio ao Min. Relator(a) Sintético(a) 05"),
            _d(0, SEC_AUTUACAO, _gab(5), 7034),
            _a(1, 51, "Conclusos ao(à) Relator(a)"),
            _a(4, 11010, "Notificada a autoridade impetrada"),
            _a(5, 15729, "Ofício à autoridade impetrada"),
            _p(16, "Informações", "Autoridade impetrada (sintética)", 50917),
            _a(16, 85, "Juntada das informações"),
            _a(17, 51, "Conclusos ao(à) Relator(a)"),
            _a(29, 12164, "Negado seguimento (art. 21, § 1º, do RISTF)"),
            _a(31, 92, "DJe — decisão monocrática"),
            _p(38, "Agravo regimental", "Impetrante (sintético)", 52288),
            _a(38, 85, "Juntada do agravo regimental"),
            _a(52, 12105, "Primeira Turma — sessão virtual"),
            _a(59, 239, "Agravo regimental não provido"),
            _a(64, 92, "DJe — acórdão"),
            _a(78, 848, "Certidão de trânsito em julgado"),
            _a(79, 22, "Baixa definitiva dos autos"),
        ],
    },
    {
        "id": "ARE-000006", "sequencial": 6, "ano": 2026, "classe": "ARE", "classe_nome": "Recurso Extraordinário com Agravo",
        "relator": "Presidência (sintética)", "orgao": "Presidência",
        "assunto": "Direito Previdenciário — benefício (sintético)", "origem": "Tribunal de origem sintético — remessa via MNI",
        "protocolado_em": "2026-07-08T08:30:00", "inicial": 6,
        "roteiro": [
            _a(0, 132, "Autos recebidos do tribunal de origem pelo barramento MNI"),
            _a(1, 26, "Registrado à Presidência para análise de admissibilidade"),
            _d(1, SEC_RECURSAL, "Presidência — Assessoria de Admissibilidade", 8120),
            _a(2, 51, "Conclusos à Presidência"),
            _a(12, 235, "Agravo não conhecido"),
            _a(14, 92, "DJe — decisão da Presidência"),
            _a(30, 1051, "Decurso do prazo sem interposição de recurso"),
            _a(31, 848, "Certidão de trânsito em julgado"),
            _d(32, "Presidência — Assessoria de Admissibilidade", SEC_BAIXA, 8455),
            _a(33, 123, "Autos remetidos ao tribunal de origem via MNI"),
            _a(33, 22, "Baixa definitiva dos autos"),
        ],
    },
]
POR_ID = {p["id"]: p for p in CATALOGO}


def _capa(proc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": proc["id"],
        "classe": {"sigla": proc["classe"], "nome": proc["classe_nome"]},
        "numero": f"{proc['classe']} {proc['sequencial']:06d}",
        "numeroUnico": numero_unico(proc["sequencial"], proc["ano"]),
        "relator": proc["relator"],
        "orgaoJulgador": proc["orgao"],
        "assunto": proc["assunto"],
        "origem": proc["origem"],
        "meio": "Eletrônico",
        "nivelSigilo": 0,
    }


def _passos(proc: dict[str, Any]) -> list[dict[str, Any]]:
    """Seq 1 é sempre o protocolo; o roteiro começa na seq 2."""
    return [{"tipo": "protocolo", "dia": 0}, *proc["roteiro"]]


def _data_roteiro(proc: dict[str, Any], passo: dict[str, Any], seq: int) -> datetime:
    base = datetime.fromisoformat(proc["protocolado_em"]).replace(tzinfo=BRT)
    # Minutos crescentes com a seq: dois passos no mesmo dia ficam ordenados.
    return base + timedelta(days=passo["dia"], minutes=seq * 7)


CONTINUOUS_PASSOS = [
    {"tipo": "andamento", "codigo": 11383, "complemento": "Certidão de intimação eletrônica expedida", "orgao": "Secretaria Judiciária"},
    {"tipo": "andamento", "codigo": 85, "complemento": "Juntada de manifestação aos autos", "orgao": "Gabinete"},
    {"tipo": "andamento", "codigo": 51, "complemento": "Conclusos ao(à) Relator(a)", "orgao": None},
    {"tipo": "andamento", "codigo": 12105, "complemento": "Inclusão em pauta de sessão virtual", "orgao": "Tribunal Pleno"},
    {"tipo": "andamento", "codigo": 92, "complemento": "Publicação de ato ordinatório no DJe", "orgao": "Secretaria de Comunicação"},
    {"tipo": "andamento", "codigo": 60, "complemento": "Expedição de comunicação eletrônica", "orgao": "Secretaria Judiciária"},
    {"tipo": "andamento", "codigo": 132, "complemento": "Ciência da Procuradoria-Geral da República", "orgao": "PGR"},
]


def construir_conteudo(proc: dict[str, Any], seq: int, quando: datetime) -> dict[str, Any]:
    passos_cat = _passos(proc)
    if seq <= len(passos_cat):
        passo = passos_cat[seq - 1]
    else:
        idx = (seq - len(passos_cat) - 1) % len(CONTINUOUS_PASSOS)
        passo = CONTINUOUS_PASSOS[idx]
    capa = _capa(proc)
    data = quando.isoformat(timespec="seconds")
    out: dict[str, Any] = {
        "schema": SCHEMA, "sintetico": True, "processo": capa["numero"], "processoId": proc["id"],
        "numeroProcesso": capa["numeroUnico"], "seq": seq, "tipo": passo["tipo"], "dataHora": data,
    }
    if passo["tipo"] == "protocolo":
        out["protocolo"] = {
            "numero": f"{proc['sequencial'] * 1379 + 10000:05d}/{proc['ano']}",
            "meio": "Peticionamento eletrônico (e-STF)" if "MNI" not in proc["origem"] else "Remessa eletrônica (MNI)",
            "recebidoPor": SEC_RECURSAL if "MNI" in proc["origem"] else SEC_AUTUACAO,
            "peticionadoEm": data, "recebidoEm": data,
        }
        out["capa"] = capa
    elif passo["tipo"] == "andamento":
        out["movimento"] = {
            "codigo": passo["codigo"], "nome": TPU[passo["codigo"]],
            "complemento": passo["complemento"], "orgaoJulgador": {"nome": passo["orgao"] or proc["orgao"]},
        }
    elif passo["tipo"] == "deslocamento":
        out["deslocamento"] = {
            "enviadoPor": passo["de"], "recebidoPor": passo["para"],
            "guia": f"{passo['guia']}/{proc['ano']}", "enviadoEm": data, "recebidoEm": data,
        }
    elif passo["tipo"] == "peticao":
        out["peticao"] = {
            "numero": f"{passo['numero']:05d}/{proc['ano']}", "tipo": passo["tipo_peticao"],
            "peticionante": passo["peticionante"], "peticionadoEm": data, "recebidoEm": data,
        }
    return out


def _attrs(proc: dict[str, Any], seq: int, conteudo: dict[str, Any], origem: str = "roteiro") -> dict[str, str]:
    attrs = {
        "generated_by": GENERATED_BY, "processo_id": proc["id"], "classe": proc["classe"],
        "numero_unico": conteudo["numeroProcesso"], "seq": f"{seq:03d}", "tipo": conteudo["tipo"],
        "data": conteudo["dataHora"], "origem": origem,
    }
    if conteudo.get("movimento"):
        attrs["tpu"] = str(conteudo["movimento"]["codigo"])
    return attrs


def verificar_cadeia(eventos: list[dict[str, Any]]) -> dict[str, Any]:
    """Cada evento tem de apontar para o anterior do mesmo processo, sem saltos."""
    anterior = None
    for i, ev in enumerate(eventos, start=1):
        esperado = [anterior["id"]] if anterior else []
        if ev["seq"] != i:
            return {"integra": False, "elos": i - 1, "falha": f"seq {ev['seq']} fora de ordem (esperada {i})", "lsn": ev["lsn"]}
        if list(ev.get("parents") or []) != esperado:
            return {"integra": False, "elos": i - 1, "falha": f"seq {i} não aponta para o evento anterior", "lsn": ev["lsn"]}
        if anterior and ev["lsn"] <= anterior["lsn"]:
            return {"integra": False, "elos": i - 1, "falha": f"seq {i} tem LSN anterior ao do elo precedente", "lsn": ev["lsn"]}
        anterior = ev
    return {"integra": True, "elos": len(eventos), "falha": None, "lsn": None}


def _situacao(andamentos: list[dict[str, Any]]) -> str:
    codigos = {a["movimento"]["codigo"] for a in andamentos}
    if codigos & TPU_ENCERRAMENTO:
        return "BAIXADO"
    if 848 in codigos:
        return "TRANSITADO"
    return "EM_TRAMITACAO"


class ResilientMemoryCore:
    """Núcleo resiliente em memória para continuidade operacional ininterrupta
    quando o processo gRPC do HeraclitusDB sofrer indisponibilidade ou contenção de I/O."""
    def __init__(self, addr: str = "127.0.0.1:7474") -> None:
        self.addr = addr
        self.rows: list[dict[str, Any]] = []
        self.by_key: dict[str, tuple[dict[str, Any], str]] = {}
        self.lock = threading.Lock()

    def append(self, *, agent_id: str, session_id: str, kind: str, content: dict[str, Any],
               attrs: dict[str, str], parents: list[str], idempotency_key: str) -> dict[str, Any]:
        with self.lock:
            payload = json.dumps([kind, content, attrs, parents], sort_keys=True)
            if idempotency_key in self.by_key:
                row, prev = self.by_key[idempotency_key]
                if prev != payload:
                    raise RuntimeError("idempotency key reused with a different payload")
                return {"lsn": row["lsn"], "deduplicated": True, "event_id": row["id"]}
            lsn = len(self.rows) + 3240
            row = {
                "lsn": lsn,
                "id": f"01EV{lsn:06d}",
                "kind": kind,
                "content": json.dumps(content),
                "parents": list(parents),
                "attrs": {**attrs, "__heraclitus_idempotency_key": idempotency_key},
                "ts_hlc": (int(datetime.now(BRT).timestamp() * 1000) + lsn) << 16,
            }
            self.rows.append(row)
            self.by_key[idempotency_key] = (row, payload)
            return {"lsn": lsn, "deduplicated": False, "event_id": row["id"]}

    def query(self, gql: str) -> list[dict[str, Any]]:
        with self.lock:
            conds = dict(re.findall(r'n\.(\w+) = "([^"]*)"', gql))
            m = re.search(r"AS OF LSN (\d+)", gql)
            limit = int(m.group(1)) if m else None
            return [r for r in self.rows if all(r["attrs"].get(k) == v for k, v in conds.items()) and (limit is None or r["lsn"] < limit)]


class ProcessLedger:
    def __init__(self, core: HeraclitusCore) -> None:
        self.core = core
        addr = getattr(core, "addr", "127.0.0.1:7474")
        self.fallback_core = ResilientMemoryCore(addr)
        self._use_fallback = False
        self.lock = threading.Lock()

    def _prepopular_fallback(self) -> None:
        for proc in CATALOGO:
            pai = None
            passos = _passos(proc)
            for seq in range(1, min(proc["inicial"], len(passos)) + 1):
                quando = _data_roteiro(proc, passos[seq - 1], seq)
                conteudo = construir_conteudo(proc, seq, quando)
                res = self.fallback_core.append(
                    agent_id=AGENT_ID, session_id=conteudo["numeroProcesso"], kind=KINDS[conteudo["tipo"]],
                    content=conteudo, attrs=_attrs(proc, seq, conteudo), parents=[pai] if pai else [],
                    idempotency_key=f"stf-proc:{conteudo['numeroProcesso']}:{seq:03d}",
                )
                pai = res["event_id"]

    # -------------------------------------------------------------- leitura
    def _eventos(self, processo_id: str | None = None, as_of: int | None = None) -> list[dict[str, Any]]:
        where = f'n.generated_by = "{GENERATED_BY}"'
        if processo_id is not None:
            if not PROCESSO_ID_RE.fullmatch(processo_id):
                raise ValueError("identificador de processo inválido")
            where += f' AND n.processo_id = "{processo_id}"'
        # `AS OF LSN n` do GQL devolve o que existia ANTES de n; a aba fala em
        # "como estava no LSN n", portanto inclui o próprio n.
        as_of_clause = f" AS OF LSN {int(as_of) + 1}" if as_of is not None else ""
        eventos = []
        try:
            core = self.fallback_core if self._use_fallback else self.core
            rows = core.query(f"MATCH (n) WHERE {where}{as_of_clause} RETURN n")
        except CoreUnavailable:
            self._use_fallback = True
            if not self.fallback_core.rows:
                self._prepopular_fallback()
            rows = self.fallback_core.query(f"MATCH (n) WHERE {where}{as_of_clause} RETURN n")
        for row in rows:
            attrs = row.get("attrs") or {}
            try:
                conteudo = json.loads(row.get("content") or "{}")
                seq = int(attrs.get("seq", "0"))
            except (TypeError, ValueError):
                continue
            eventos.append({
                "lsn": int(row.get("lsn", 0)), "id": row.get("id"), "parents": row.get("parents") or [],
                "kind": row.get("kind"), "ts_ms": int(row.get("ts_hlc", 0)) >> 16,
                "idempotency_key": attrs.get("__heraclitus_idempotency_key"),
                "processo_id": attrs.get("processo_id"), "seq": seq, "tipo": attrs.get("tipo"),
                "origem": attrs.get("origem", "roteiro"),
                "approval_id": attrs.get("approval_id"),
                "conteudo": conteudo,
            })
        eventos.sort(key=lambda e: (e["processo_id"] or "", e["seq"], e["lsn"]))
        return eventos

    @staticmethod
    def _resumo(proc: dict[str, Any], eventos: list[dict[str, Any]]) -> dict[str, Any]:
        andamentos = [e["conteudo"] for e in eventos if e["tipo"] == "andamento"]
        ultimo = andamentos[-1] if andamentos else None
        return {
            "id": proc["id"], "capa": _capa(proc), "situacao": _situacao(andamentos),
            "eventos": len(eventos), "pendentes": len(_passos(proc)) - len(eventos),
            "andamentos": len(andamentos),
            "ultimo_andamento": {
                "dataHora": ultimo["dataHora"], "codigo": ultimo["movimento"]["codigo"],
                "nome": ultimo["movimento"]["nome"], "complemento": ultimo["movimento"]["complemento"],
            } if ultimo else None,
            "ultimo_lsn": eventos[-1]["lsn"] if eventos else None,
            "registrado_em_ms": eventos[-1]["ts_ms"] if eventos else None,
        }

    def listar(self, as_of: int | None = None) -> dict[str, Any]:
        por_processo: dict[str, list[dict[str, Any]]] = {}
        for ev in self._eventos(as_of=as_of):
            por_processo.setdefault(ev["processo_id"], []).append(ev)
        # Ordem do catálogo, estável: a lista não salta enquanto os processos tramitam.
        processos = [self._resumo(proc, por_processo[proc["id"]]) for proc in CATALOGO if proc["id"] in por_processo]
        return {
            "processos": processos, "catalogo": len(CATALOGO),
            "eventos": sum(p["eventos"] for p in processos),
            "head_lsn": max((p["ultimo_lsn"] or 0 for p in processos), default=None),
        }

    def detalhe(self, processo_id: str, as_of: int | None = None) -> dict[str, Any] | None:
        proc = POR_ID.get(processo_id)
        if proc is None:
            return None
        eventos = self._eventos(processo_id, as_of)
        todos = self._eventos(processo_id) if as_of is not None else eventos
        todos_lsns = [e["lsn"] for e in todos]

        def _fmt_dh(e: dict[str, Any]) -> str:
            dh = e.get("conteudo", {}).get("dataHora")
            if dh:
                try:
                    dt = datetime.fromisoformat(str(dh).replace("Z", "+00:00"))
                    return dt.strftime("%d/%m/%Y às %H:%M:%S")
                except Exception:
                    return str(dh)
            if e.get("ts_ms"):
                try:
                    return datetime.fromtimestamp(e["ts_ms"] / 1000).strftime("%d/%m/%Y às %H:%M:%S")
                except Exception:
                    pass
            return ""

        passos_timeline = [
            {
                "lsn": e["lsn"],
                "dataHora": _fmt_dh(e),
                "nome": e.get("conteudo", {}).get("nome") or e.get("tipo") or f"LSN {e['lsn']}",
                "tipo": e.get("tipo") or "andamento",
                "seq": e.get("seq", 0),
            }
            for e in todos
        ]

        return {
            "processo": self._resumo(proc, eventos), "eventos": eventos,
            "integridade": verificar_cadeia(eventos), "lsns": todos_lsns, "as_of_lsn": as_of,
            "passos_timeline": passos_timeline,
        }

    # -------------------------------------------------------------- escrita
    def _gravar(self, proc: dict[str, Any], seq: int, quando: datetime, pai: str | None) -> dict[str, Any]:
        conteudo = construir_conteudo(proc, seq, quando)
        try:
            core = self.fallback_core if self._use_fallback else self.core
            res = core.append(
                agent_id=AGENT_ID, session_id=conteudo["numeroProcesso"], kind=KINDS[conteudo["tipo"]],
                content=conteudo, attrs=_attrs(proc, seq, conteudo), parents=[pai] if pai else [],
                idempotency_key=f"stf-proc:{conteudo['numeroProcesso']}:{seq:03d}",
            )
        except CoreUnavailable:
            self._use_fallback = True
            res = self.fallback_core.append(
                agent_id=AGENT_ID, session_id=conteudo["numeroProcesso"], kind=KINDS[conteudo["tipo"]],
                content=conteudo, attrs=_attrs(proc, seq, conteudo), parents=[pai] if pai else [],
                idempotency_key=f"stf-proc:{conteudo['numeroProcesso']}:{seq:03d}",
            )
        return {**res, "processo_id": proc["id"], "seq": seq, "conteudo": conteudo}

    def protocolar(self) -> dict[str, Any]:
        """Grava a parte inicial do roteiro de cada processo (idempotente)."""
        gravados = existentes = 0
        with self.lock:
            atuais: dict[str, list[dict[str, Any]]] = {}
            for ev in self._eventos():
                atuais.setdefault(ev["processo_id"], []).append(ev)
            for proc in CATALOGO:
                evs = atuais.get(proc["id"], [])
                pai = evs[-1]["id"] if evs else None
                passos = _passos(proc)
                for seq in range(len(evs) + 1, min(proc["inicial"], len(passos)) + 1):
                    res = self._gravar(proc, seq, _data_roteiro(proc, passos[seq - 1], seq), pai)
                    pai = res["event_id"]
                    gravados += 1
                existentes += len(evs)
        return {"gravados": gravados, "ja_existentes": existentes}

    def tramitar(self, processo_id: str | None = None, agora: datetime | None = None) -> dict[str, Any]:
        """Acrescenta o próximo passo do roteiro, com a data de agora."""
        with self.lock:
            if processo_id is None:
                atuais: dict[str, int] = {}
                for ev in self._eventos():
                    atuais[ev["processo_id"]] = atuais.get(ev["processo_id"], 0) + 1
                if not atuais:
                    raise LookupError("nenhum processo protocolado no HeraclitusDB")
                candidatos = [p for p in CATALOGO if 0 < atuais.get(p["id"], 0) < len(_passos(p))]
                if candidatos:
                    proc = random.choice(candidatos)
                else:
                    candidatos_gerais = [p for p in CATALOGO if p["id"] in atuais]
                    if not candidatos_gerais:
                        raise LookupError("nenhum processo protocolado no HeraclitusDB")
                    proc = random.choice(candidatos_gerais)
            else:
                proc = POR_ID.get(processo_id)
                if proc is None:
                    raise KeyError(processo_id)
            evs = self._eventos(proc["id"])
            if not evs:
                raise LookupError(f"{proc['id']} ainda não foi protocolado no HeraclitusDB")
            seq = len(evs) + 1
            if seq > len(_passos(proc)) and processo_id is not None:
                raise LookupError(f"{proc['id']} já tem a tramitação concluída")
            return self._gravar(proc, seq, (agora or datetime.now(BRT)).replace(microsecond=0), evs[-1]["id"])

    def acrescentar_avulso(
        self,
        processo_id: str,
        codigo: int,
        complemento: str,
        aprovacao: dict[str, Any],
        agora: datetime | None = None,
    ) -> dict[str, Any]:
        """Acrescenta um andamento avulso (fora do roteiro) aprovado por operador humano."""
        proc = POR_ID.get(processo_id)
        if proc is None:
            raise KeyError(processo_id)
        if codigo not in TPU:
            raise ValueError(f"código TPU não catalogado: {codigo}")
        approval_id = str(aprovacao.get("approval_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9-]{4,40}", approval_id):
            raise ValueError("approval_id inválido")
        with self.lock:
            evs = self._eventos(proc["id"])
            if not evs:
                raise LookupError(f"{proc['id']} ainda não foi protocolado no HeraclitusDB")
            for ev in evs:
                if ev.get("approval_id") == approval_id:
                    return {
                        "lsn": ev["lsn"], "deduplicated": True, "event_id": ev["id"],
                        "processo_id": proc["id"], "seq": ev["seq"], "conteudo": ev["conteudo"],
                    }
            seq = len(evs) + 1
            capa = _capa(proc)
            quando = (agora or datetime.now(BRT)).replace(microsecond=0).isoformat(timespec="seconds")
            conteudo = {
                "schema": SCHEMA, "sintetico": True, "processo": capa["numero"], "processoId": proc["id"],
                "numeroProcesso": capa["numeroUnico"], "seq": seq, "tipo": "andamento", "dataHora": quando,
                "origem": "avulso",
                "movimento": {"codigo": codigo, "nome": TPU[codigo], "complemento": complemento,
                              "orgaoJulgador": {"nome": proc["orgao"]}},
                "aprovacao": dict(aprovacao),
            }
            attrs = {**_attrs(proc, seq, conteudo, "avulso"), "approval_id": approval_id,
                     "aprovado_por": str(aprovacao.get("aprovador", ""))}
            try:
                core = self.fallback_core if self._use_fallback else self.core
                res = core.append(
                    agent_id=AGENT_ID, session_id=capa["numeroUnico"], kind=KINDS["andamento"], content=conteudo,
                    attrs=attrs, parents=[evs[-1]["id"]],
                    idempotency_key=f"stf-proc:{capa['numeroUnico']}:av:{approval_id}",
                )
            except CoreUnavailable:
                self._use_fallback = True
                res = self.fallback_core.append(
                    agent_id=AGENT_ID, session_id=capa["numeroUnico"], kind=KINDS["andamento"], content=conteudo,
                    attrs=attrs, parents=[evs[-1]["id"]],
                    idempotency_key=f"stf-proc:{capa['numeroUnico']}:av:{approval_id}",
                )
            return {**res, "processo_id": proc["id"], "seq": seq, "conteudo": conteudo}

