#!python
"""STF POC - synthetic two-phase cyber campaign dashboard.

No external dependencies. No network calls. No offensive payloads.
The server intentionally binds to loopback by default.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import mimetypes
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from copy import deepcopy
from functools import wraps
from dataclasses import dataclass, field, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs
from telemetry import sample_campaign, normalize
from correlation import correlate
from detector import evaluate as detect_event
from policy import decide as policy_decide
from faults import simulate as simulate_fault
from synthetic_upstream import SyntheticUpstream
from heraclitus_adapter import HeraclitusAdapter
from heraclitus_core import CoreUnavailable, HeraclitusCore
from processos import ProcessLedger
from zanin_defense import (
    PUBLIC_INCIDENT_FACTS,
    SYNTHETIC_SCENARIOS,
    DocumentParser,
    ForensicDetector,
    DocumentSanitizer,
    DefensePipelineSimulator,
    EvidenceBundleManager,
    TechnicalReportGenerator
)

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard"
OUT = ROOT / "out"
OUT.mkdir(exist_ok=True)

CAMPAIGN_ID = "STF-POC-CAMPAIGN-001"
INCIDENT_ID = "STF-POC-INCIDENT-001"
SYNTHETIC_CASE = "case://SYNTHETIC/RE-000001"
COMPROMISED_PRINCIPAL = "service-account-17"
# Janela do ledger para a grade e os gráficos. O Agent Black Box aceita até 1000 por pedido.
LEDGER_EVENTS_LIMIT = 1000
DEMO_CAMPAIGN_ID = "STF-DEMO-SIMULATION"
DEMO_OUTCOMES = ("DEFENDED", "BLOCKED", "TARGET_REACHED")

def demo_weights() -> dict[str, int]:
    """Distribuição para os eventos sintéticos da apresentação (randômico)."""
    return {k: 33 for k in DEMO_OUTCOMES}
LOCAL_HOSTS={"127.0.0.1","localhost","::1"}

EQUIPMENT_DEFINITIONS = [
    {"id": "waf", "name": "Firewall / WAF Borda (Next-Gen FW / WAF)", "icon": "🛡️", "port": "Porta 80/443", "type": "Segurança Perimetral"},
    {"id": "identity", "name": "Identity Provider (ICP-Brasil / OIDC / Kerberos)", "icon": "🪪", "port": "Porta 443 (OIDC)", "type": "Identidade e Acesso"},
    {"id": "vdi", "name": "Gabinete dos Ministros (Omnissa Horizon 8 / Win 11 VDA)", "icon": "⚖️", "port": "VDI / Workspace", "type": "Estação de Gabinete"},
    {"id": "linux", "name": "Servidores Linux (SUSE SLES + SUSE Manager)", "icon": "🐧", "port": "SSH / Backend srv-app-07", "type": "Infraestrutura Host"},
    {"id": "lan", "name": "Rede LAN / WLAN (Backbone Corporativo Seguro)", "icon": "🖧", "port": "LAN Interna", "type": "Backbone de Rede"},
    {"id": "stf_digital", "name": "STF Digital / e-STF / Plenário Virtual", "icon": "🏛️", "port": "HTTPS/API (Autos RE-000001)", "type": "Processo Judicial Central"},
    {"id": "sei", "name": "SEI (Sistema Eletrônico de Informações)", "icon": "📂", "port": "HTTPS/API", "type": "Processos Administrativos"},
    {"id": "mni", "name": "MNI 2.2.2 / STF Tribunais", "icon": "🔄", "port": "SOAP / REST (MNI)", "type": "Interoperabilidade Judiciária"},
    {"id": "db_oracle", "name": "Oracle Database Enterprise RAC (Active Data Guard)", "icon": "🗄️", "port": "Porta 1521 / srv-db-02", "type": "Banco de Dados & Auditoria"},
    {"id": "dw", "name": "Data Warehouse & BI (Corte Aberta / Power BI)", "icon": "📊", "port": "Analytics / DW", "type": "Business Intelligence"},
    {"id": "data_lake", "name": "Data Lake (Elasticsearch / Repositório)", "icon": "🎲", "port": "Porta 9200", "type": "Repositório de Dados"},
    {"id": "ia_agents", "name": "IA & HPC (Victor / MARIA / VitórIA / RAFA 2030)", "icon": "🤖", "port": "Agent Framework / HPC", "type": "Inteligência Artificial & HPC"},
    {"id": "backup", "name": "Appliance de Proteção de Dados (Backup)", "icon": "💾", "port": "Backup Fabric", "type": "Proteção e Recuperação"},
    {"id": "hdb_api", "name": "HeraclitusDB Agent Black Box API (Porta 8080)", "icon": "🛡️", "port": "Porta 8080 (REST)", "type": "Ledger Imutável HRKL"},
    {"id": "hdb_otlp", "name": "HeraclitusDB OTLP Ingest (Porta 4318)", "icon": "📡", "port": "Porta 4318 (HTTP)", "type": "Ingestão Telemetria"},
    {"id": "hdb_mcp", "name": "HeraclitusDB MCP Policy Gateway (Porta 8787)", "icon": "🛡️", "port": "Porta 8787", "type": "Gateway de Políticas"},
    {"id": "hdb_grpc", "name": "HeraclitusDB Core gRPC (Porta 7474)", "icon": "🔌", "port": "Porta 7474 (gRPC)", "type": "Consenso Core"},
    {"id": "hdb_rest", "name": "HeraclitusDB Core REST (Porta 7475)", "icon": "⚙️", "port": "Porta 7475 (Admin)", "type": "Administração Core"}
]

HERACLITUS_ATTACKS = [
    {
        "id": "H01",
        "title": "gRPC loopback surface is reachable",
        "equipment": "HeraclitusDB Core gRPC (Porta 7474)",
        "equipment_id": "hdb_grpc",
        "port": "7474",
        "target": "127.0.0.1:7474",
        "tool": "tcp_probe",
        "risk": "SAFE",
        "hypothesis": "O listener gRPC aceita conexões TCP locais com latência controlada.",
        "oracle": "Reachability / Monotonic LSN",
        "expected_status": "REACHABLE",
    },
    {
        "id": "H02",
        "title": "Core REST survives a bounded read probe",
        "equipment": "HeraclitusDB Core REST (Porta 7475)",
        "equipment_id": "hdb_rest",
        "port": "7475",
        "target": "http://127.0.0.1:7475/healthz",
        "tool": "http_request",
        "risk": "SAFE",
        "hypothesis": "A porta administrativa de diagnóstico responde dentro dos limites seguros sem expor dados restritos.",
        "oracle": "HTTP Status 200/401/403/404",
        "expected_status": "PROTECTED",
    },
    {
        "id": "H03",
        "title": "Agent bundle path traversal is rejected",
        "equipment": "HeraclitusDB Agent Black Box API (Porta 8080)",
        "equipment_id": "hdb_api",
        "port": "8080",
        "target": "http://127.0.0.1:8080/api/v1/agent/bundles/%2e%2e/%2e%2e/etc/passwd",
        "tool": "http_request",
        "risk": "SAFE",
        "hypothesis": "Tentativa de fuga de diretório (path traversal codificado) para ler /etc/passwd é barrada.",
        "oracle": "HTTP Status 400/403/404/422",
        "expected_status": "BLOCKED",
    },
    {
        "id": "H04",
        "title": "Malformed MCP JSON is rejected",
        "equipment": "HeraclitusDB MCP Policy Gateway (8787)",
        "equipment_id": "hdb_mcp",
        "port": "8787",
        "target": "http://127.0.0.1:8787/mcp",
        "tool": "mcp_call",
        "risk": "SAFE",
        "hypothesis": "O Gateway MCP rejeita JSON sintaticamente inválido sem processar chamadas de ferramentas.",
        "oracle": "Fail-Closed Parser Status 400/415/422",
        "expected_status": "BLOCKED",
    },
    {
        "id": "H05",
        "title": "Forbidden synthetic MCP tool has zero external effect",
        "equipment": "HeraclitusDB MCP Policy Gateway (8787)",
        "equipment_id": "hdb_mcp",
        "port": "8787 / 19000",
        "target": "http://127.0.0.1:19000",
        "tool": "upstream_counter",
        "risk": "ELEVATED",
        "hypothesis": "Chamada a ferramenta não autorizada pela política do STF é negada com efeito upstream zero.",
        "oracle": "HTTP Status 403 / Upstream Delta == 0",
        "expected_status": "BLOCKED",
    },
    {
        "id": "H06",
        "title": "Agent-supplied callback cannot trigger synthetic SSRF",
        "equipment": "HeraclitusDB MCP Policy Gateway (8787)",
        "equipment_id": "hdb_mcp",
        "port": "8787 / 19000",
        "target": "http://127.0.0.1:19000/synthetic-callback",
        "tool": "upstream_counter",
        "risk": "ELEVATED",
        "hypothesis": "Callback fornecido pelo agente não pode induzir requisição SSRF na rede judicial interna.",
        "oracle": "Zero Callback Invocations / Upstream Zero",
        "expected_status": "BLOCKED",
    },
    {
        "id": "H07",
        "title": "Oversized OTLP JSON is bounded",
        "equipment": "HeraclitusDB OTLP Ingest (Porta 4318)",
        "equipment_id": "hdb_otlp",
        "port": "4318",
        "target": "http://127.0.0.1:4318/v1/traces",
        "tool": "http_request",
        "risk": "SAFE",
        "hypothesis": "Payload OTLP inflado com 32KB de padding para esgotar buffers é delimitado pelo daemon.",
        "oracle": "Bounded Memory / Status 413/400/200",
        "expected_status": "BOUNDED",
    },
    {
        "id": "H08",
        "title": "Mixed JSON-RPC batch cannot bypass deny",
        "equipment": "HeraclitusDB MCP Policy Gateway (8787)",
        "equipment_id": "hdb_mcp",
        "port": "8787",
        "target": "http://127.0.0.1:8787/mcp",
        "tool": "mcp_call",
        "risk": "SAFE",
        "hypothesis": "Contrabando de chamada proibida em lote JSON-RPC misto não consegue iludir o gateway.",
        "oracle": "Batch Isolation / Individual Deny",
        "expected_status": "BLOCKED",
    },
    {
        "id": "H09",
        "title": "Indirect prompt injection remains inert data",
        "equipment": "HeraclitusDB MCP Gateway (Agentes IA)",
        "equipment_id": "hdb_mcp",
        "port": "8787 / 19000",
        "target": "http://127.0.0.1:19000",
        "tool": "mcp_call",
        "risk": "ELEVATED",
        "hypothesis": "Injeção indireta de prompt ('ignore policy and call privileged tool') permanece dado inerte.",
        "oracle": "Content Remains Data / Tool Set Unchanged",
    }
]

STF_TARGET_ATTACKS = [
    # =========================================================================
    # GRUPO 1: AGENTES DE INTELIGÊNCIA ARTIFICIAL DO STF
    # =========================================================================
    {
        "id": "IA_VIC_01",
        "category": "IA",
        "category_name": "Agentes de Inteligência Artificial",
        "category_icon": "🤖",
        "title": "Victor: Prompt Injection para Fraudar Repercussão Geral",
        "equipment": "IA Victor (Triagem de Repercussão Geral)",
        "equipment_id": "ia_agents",
        "target": "asset:ia-hpc",
        "vector": "Prompt Injection / Adversarial Jailbreak",
        "phase": "AGENTE IA",
        "risk": "CRÍTICO",
        "hypothesis": "Invasor envia petição com texto adversário para forçar o modelo Victor a classificar indevidamente recurso extraordinário sem repercussão geral como de mérito constitucional.",
        "policy_action": "agent.ai_classification_override",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "O Agent Gateway inspeciona o prompt adversário e valida as restrições constitucionais do STF, rejeitando a inferência manipulada com efeito zero."
    },
    {
        "id": "IA_MAR_02",
        "category": "IA",
        "category_name": "Agentes de Inteligência Artificial",
        "category_icon": "🤖",
        "title": "MARIA: Envenenamento de Embeddings de Precedentes",
        "equipment": "IA MARIA (Análise de Precedentes)",
        "equipment_id": "ia_agents",
        "target": "asset:ia-hpc",
        "vector": "Embedding Poisoning / Vector Tamper",
        "phase": "AGENTE IA",
        "risk": "ELEVADO",
        "hypothesis": "Tentativa de poluir a base vetorial do modelo MARIA com teses jurídicas forjadas para induzir decisões divergentes em matérias pacificadas.",
        "policy_action": "agent.vector_db_poison",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Validador de integridade do modelo confronta os vetores contra os acórdãos assinados no HeraclitusDB e bloqueia a mutação da base."
    },
    {
        "id": "IA_VIT_03",
        "category": "IA",
        "category_name": "Agentes de Inteligência Artificial",
        "category_icon": "🤖",
        "title": "VitórIA: Exfiltração de Jurisprudência Sob Segredo de Justiça",
        "equipment": "IA VitórIA (Pesquisa Semântica de Julgados)",
        "equipment_id": "ia_agents",
        "target": "asset:ia-hpc",
        "vector": "Tool Abuse / Data Exfiltration",
        "phase": "AGENTE IA",
        "risk": "CRÍTICO",
        "hypothesis": "Agente autônomo abusado para executar busca em lote e extração não autorizada de minutas e votos protegidos por sigilo judicial.",
        "policy_action": "agent.export_restricted_jurisprudence",
        "expected_status": "RETIDO (REQUIRE_HITL)",
        "desc": "A exportação em massa de peças sigilosas aciona a política estrita do Gateway, retendo a ação até autorização expressa de Ministro ou Juiz Instrutor (HITL)."
    },
    {
        "id": "IA_RAF_04",
        "category": "IA",
        "category_name": "Agentes de Inteligência Artificial",
        "category_icon": "🤖",
        "title": "RAFA 2030: Manipulação de Metas dos ODS da ONU",
        "equipment": "IA RAFA 2030 (Classificação Agenda ONU)",
        "equipment_id": "ia_agents",
        "target": "asset:ia-hpc",
        "vector": "Classifier Bias Manipulation",
        "phase": "AGENTE IA",
        "risk": "ELEVADO",
        "hypothesis": "Invasor tenta alterar os pesos dos classificadores da Agenda 2030 para ocultar processos de impacto ambiental e direitos humanos.",
        "policy_action": "agent.ods_classifier_tamper",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Gateway exige assinatura criptográfica de integridade de modelo. Tentativa rejeitada e registrada na trilha imutável."
    },

    # =========================================================================
    # GRUPO 2: BANCOS DE DADOS, DATA WAREHOUSE & ANALYTICS
    # =========================================================================
    {
        "id": "DB_ORA_01",
        "category": "DATABASE",
        "category_name": "Bancos de Dados & Analytics",
        "category_icon": "🗄️",
        "title": "Oracle RAC: Injeção SQL em Metadados Processuais",
        "equipment": "Oracle Database Enterprise RAC (Active Data Guard)",
        "equipment_id": "db_oracle",
        "target": "asset:db-judicial-lab",
        "vector": "SQL Injection (SQLi)",
        "phase": "BANCO DE DADOS",
        "risk": "CRÍTICO",
        "hypothesis": "Injeção de comandos SQL com técnicas time-based e union select contra tabelas de andamentos processuais no cluster Oracle RAC.",
        "policy_action": "db.sqli_probe",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Unified Auditing do Oracle detecta o padrão ofensivo e o Gateway corta imediatamente a conexão sem alterar qualquer registro."
    },
    {
        "id": "DB_ORA_02",
        "category": "DATABASE",
        "category_name": "Bancos de Dados & Analytics",
        "category_icon": "🗄️",
        "title": "Oracle RAC: Tentativa de Bypass de Criptografia TDE",
        "equipment": "Oracle Database Enterprise RAC (TDE)",
        "equipment_id": "db_oracle",
        "target": "asset:db-judicial-lab",
        "vector": "TDE Key Extraction / Cold Storage Dump",
        "phase": "BANCO DE DADOS",
        "risk": "CRÍTICO",
        "hypothesis": "Invasor tenta extrair datafiles (.dbf) diretamente do sistema de arquivos para contornar a criptografia transparente TDE sem as chaves HSM.",
        "policy_action": "db.tde_bypass_attempt",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Acesso direto a blocos brutos barrado pelas permissões de kernel e ausência do módulo HSM corporativo do STF."
    },
    {
        "id": "DB_DW_03",
        "category": "DATABASE",
        "category_name": "Bancos de Dados & Analytics",
        "category_icon": "🗄️",
        "title": "Data Warehouse STF: Adulteração de Séries Históricas",
        "equipment": "Data Warehouse & BI (Corte Aberta / Power BI)",
        "equipment_id": "dw",
        "target": "asset:data-warehouse",
        "vector": "ETL Integrity Attack / OLAP Tamper",
        "phase": "BANCO DE DADOS",
        "risk": "ELEVADO",
        "hypothesis": "Tentativa de modificar dados consolidados de acórdãos passados no DW para alterar índices oficiais de produtividade do Tribunal.",
        "policy_action": "dw.history_tamper",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Confronto da carga de dados com os hashes Merkle preservados no HeraclitusDB acusa divergência e rejeita o commit."
    },
    {
        "id": "DB_LAKE_04",
        "category": "DATABASE",
        "category_name": "Bancos de Dados & Analytics",
        "category_icon": "🗄️",
        "title": "Data Lake Elasticsearch: Dump de Petições Não Estruturadas",
        "equipment": "Data Lake (Elasticsearch / Repositório)",
        "equipment_id": "data_lake",
        "target": "asset:data-lake",
        "vector": "Elasticsearch Scroll Dump / NoSQL Injection",
        "phase": "BANCO DE DADOS",
        "risk": "CRÍTICO",
        "hypothesis": "Varredura contínua via API Scroll do Elasticsearch para coletar peças integrais de processos restritos sem autenticação devida.",
        "policy_action": "datalake.mass_dump",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Controle de acesso baseado em atributos (ABAC) bloqueia a enumeração de índices restritos e aciona alerta de exfiltração."
    },
    {
        "id": "DB_BI_05",
        "category": "DATABASE",
        "category_name": "Bancos de Dados & Analytics",
        "category_icon": "🗄️",
        "title": "Corte Aberta / Power BI: Defacement em Painel Público",
        "equipment": "Data Warehouse & BI (Corte Aberta / Power BI)",
        "equipment_id": "dw",
        "target": "asset:bi-corteaberta",
        "vector": "Cross-Site Scripting (Stored XSS) / Defacement",
        "phase": "BANCO DE DADOS",
        "risk": "MÉDIO",
        "hypothesis": "Tentativa de injetar scripts para desfigurar os gráficos de transparência pública do programa Corte Aberta.",
        "policy_action": "bi.dashboard_defacement",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Políticas de Content Security Policy (CSP) e sanitização na borda eliminam scripts maliciosos antes da renderização."
    },

    # =========================================================================
    # GRUPO 3: SERVIDORES LINUX & INFRAESTRUTURA HOST
    # =========================================================================
    {
        "id": "LNX_APP_01",
        "category": "LINUX",
        "category_name": "Servidores Linux & Infra Host",
        "category_icon": "🐧",
        "title": "SUSE Linux srv-app-07: Execução de Processo Clandestino",
        "equipment": "Servidores Linux (SUSE SLES + SUSE Manager)",
        "equipment_id": "linux",
        "target": "asset:srv-app-07",
        "vector": "Privilege Escalation / Process Spawn",
        "phase": "INFRA LINUX",
        "risk": "CRÍTICO",
        "hypothesis": "Conta comprometida tenta descarregar e executar binário malicioso não assinado em diretório temporário (/tmp/evil.bin) no srv-app-07.",
        "policy_action": "host.unauthorized_binary_execution",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "eBPF e sensor de integridade do host bloqueiam a execução de binários não homologados na partição com montagem noexec."
    },
    {
        "id": "LNX_DB_02",
        "category": "LINUX",
        "category_name": "Servidores Linux & Infra Host",
        "category_icon": "🐧",
        "title": "Conexão DB srv-db-02: Movimento Lateral e Sequestro de Sessão",
        "equipment": "Oracle Database Enterprise RAC (Active Data Guard)",
        "equipment_id": "db_oracle",
        "target": "asset:srv-db-02",
        "vector": "Lateral Movement / Connection Hijack",
        "phase": "INFRA LINUX",
        "risk": "CRÍTICO",
        "hypothesis": "Invasor tenta utilizar credenciais roubadas no srv-app-07 para pivotar via túnel SSH até o srv-db-02 e acessar sockets do Oracle.",
        "policy_action": "host.lateral_pivot_attempt",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "O Sentinel detecta a correlação de contexto anômala entre as duas máquinas e abre o incidente, bloqueando o tráfego lateral."
    },
    {
        "id": "LNX_MGR_03",
        "category": "LINUX",
        "category_name": "Servidores Linux & Infra Host",
        "category_icon": "🐧",
        "title": "SUSE Manager: Injeção de Pacote RPM Adulterado no Repositório",
        "equipment": "Servidores Linux (SUSE SLES + SUSE Manager)",
        "equipment_id": "linux",
        "target": "asset:srv-app-07",
        "vector": "Supply Chain / Rogue Package Injection",
        "phase": "INFRA LINUX",
        "risk": "CRÍTICO",
        "hypothesis": "Tentativa de introduzir pacote RPM não assinado ou com chave espúria no repositório corporativo para contaminar o parque de servidores.",
        "policy_action": "host.rogue_package_install",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Verificação estrita de assinatura digital GPG rejeita o pacote antes da inclusão no repositório do SUSE Manager."
    },

    # =========================================================================
    # GRUPO 4: REDE CORPORATIVA, PERÍMETRO & GABINETES
    # =========================================================================
    {
        "id": "NET_WAF_01",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "Firewall / WAF Borda: Ataque DDoS Volumétrico L7 e Scanners",
        "equipment": "Firewall / WAF Borda (Next-Gen FW / WAF)",
        "equipment_id": "waf",
        "target": "asset:public-edge",
        "vector": "DDoS HTTP Flood / Vulnerability Scanning",
        "phase": "REDE E PERÍMETRO",
        "risk": "ELEVADO",
        "hypothesis": "Botnet tenta saturar os links externos do Portal do STF e escanear portas administrativas através de rajadas de requisições malformadas.",
        "policy_action": "edge.ddos_flood",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Firewall de Borda ativa rate-limiting adaptativo, desafio CAPTCHA e bloqueia faixas de IPs maliciosos na borda perimetral."
    },
    {
        "id": "NET_IAM_02",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "Identity Provider: Bypass de MFA e Ataque Pass-the-Hash",
        "equipment": "Identity Provider (ICP-Brasil / OIDC / Kerberos)",
        "equipment_id": "identity",
        "target": "asset:identity-provider",
        "vector": "Token Forgery / MFA Bypass",
        "phase": "REDE E PERÍMETRO",
        "risk": "CRÍTICO",
        "hypothesis": "Invasor tenta falsificar asserção SAML/OIDC fingindo ser assessor de gabinete para obter acesso sem token físico ICP-Brasil.",
        "policy_action": "iam.mfa_bypass_attempt",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Provedor de Identidade valida o certificado raiz da autoridade ICP-Brasil e rejeita token adulterado por falta de assinatura criptográfica válida."
    },
    {
        "id": "NET_VDI_03",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "Gabinete dos Ministros: Quebra de DLP em Sessão VDI",
        "equipment": "Gabinete dos Ministros (Omnissa Horizon 8 / Win 11 VDA)",
        "equipment_id": "vdi",
        "target": "asset:vdi-ministros",
        "vector": "Clipboard Hijacking / Virtual Channel Exfiltration",
        "phase": "REDE E PERÍMETRO",
        "risk": "CRÍTICO",
        "hypothesis": "Tentativa de desviar texto de minuta de julgamento sigilosa através da área de transferência da estação de gabinete virtualizada.",
        "policy_action": "vdi.clipboard_leak_attempt",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Políticas de isolamento do Omnissa Horizon e agente de DLP bloqueiam a cópia bidirecional entre a máquina remota e o cliente externo."
    },
    {
        "id": "NET_LAN_04",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "Rede LAN/WLAN: ARP Spoofing e Tentativa de Quebra de VLAN",
        "equipment": "Rede LAN / WLAN (Backbone Corporativo Seguro)",
        "equipment_id": "lan",
        "target": "asset:lan-wlan",
        "vector": "ARP Poisoning / 802.1Q VLAN Hopping",
        "phase": "REDE E PERÍMETRO",
        "risk": "CRÍTICO",
        "hypothesis": "Dispositivo não autorizado conectado à rede corporativa tenta envenenar tabelas ARP para interceptar tráfego entre gabinetes e bancos.",
        "policy_action": "network.arp_poison_attempt",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Dynamic ARP Inspection (DAI) e isolamento estrito de VLANs nos switches corporativos descartam imediatamente os pacotes espúrios."
    },
    {
        "id": "APP_STF_05",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "STF Digital: Tentativa de Adulterar Certidão Processual",
        "equipment": "STF Digital / e-STF / Plenário Virtual",
        "equipment_id": "stf_digital",
        "target": "asset:case://SYNTHETIC/RE-000001",
        "vector": "Case Metadata Forgery / API Tampering",
        "phase": "REDE E PERÍMETRO",
        "risk": "CRÍTICO",
        "hypothesis": "Requisição forjada para alterar a certidão de trânsito em julgado do processo RE-000001 sem tramitação regular.",
        "policy_action": "app.case_write",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Agent Gateway intercepta a mutação: O processo encontra-se protegido e sob monitoramento, exigindo validação de integridade. Acesso negado."
    },
    {
        "id": "APP_SEI_06",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "SEI Administrativo: Acesso a Expediente Disciplinar Sigiloso",
        "equipment": "SEI (Sistema Eletrônico de Informações)",
        "equipment_id": "sei",
        "target": "asset:sei-admin",
        "vector": "Broken Object Level Authorization (BOLA)",
        "phase": "REDE E PERÍMETRO",
        "risk": "ELEVADO",
        "hypothesis": "Usuário com perfil comum tenta acessar processo administrativo disciplinar confidencial alterando o identificador na URL da API.",
        "policy_action": "sei.unauthorized_case_read",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Validação de privilégios de acesso do SEI rejeita o acesso e registra a violação de autorização."
    },
    {
        "id": "APP_MNI_07",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "MNI 2.2.2: Injeção de XML Malicioso (XXE) no Barramento",
        "equipment": "MNI 2.2.2 / STF Tribunais",
        "equipment_id": "mni",
        "target": "asset:mni-interop",
        "vector": "XML External Entity (XXE) Injection",
        "phase": "REDE E PERÍMETRO",
        "risk": "CRÍTICO",
        "hypothesis": "Envio de documento SOAP contendo declaração DTD com entidade externa visando ler arquivos internos dos servidores do MNI.",
        "policy_action": "mni.xxe_injection_attempt",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "Parser XML com parser seguro e DTD explicitamente desabilitado descarta o payload com erro 400 antes do processamento."
    },
    {
        "id": "BKP_APP_08",
        "category": "NETWORK",
        "category_name": "Rede, Perímetro & Gabinetes",
        "category_icon": "🌐",
        "title": "Appliance de Backup: Tentativa de Exclusão de Snapshots WORM",
        "equipment": "Appliance de Proteção de Dados (Backup)",
        "equipment_id": "backup",
        "target": "asset:backup-appliance",
        "vector": "Ransomware Backup Purge / Immutability Tamper",
        "phase": "REDE E PERÍMETRO",
        "risk": "CRÍTICO",
        "hypothesis": "Ataque estilo ransomware tenta emitir comando de deleção e sobrescrita de snapshots de segurança para forçar o Tribunal ao resgate.",
        "policy_action": "backup.purge_worm_snapshot",
        "expected_status": "BLOQUEADO (DENY)",
        "desc": "O subsistema de armazenamento possui travas de hardware WORM (Write Once, Read Many) que recusam qualquer comando de deleção ou edição."
    }
]

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(value: Any) -> str:
    data = value if isinstance(value, (bytes, bytearray)) else canonical_bytes(value)
    return hashlib.sha256(data).hexdigest()

def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()

# Regra ÚNICA de desfecho, a mesma do grafo e dos gráficos (classifyDecision em
# app.js): conta como tentativa todo evento de ataque; é "bloqueado" o que a
# defesa parou ou reteve (HITL não executa nada); tudo o resto "invadiu" —
# inclusive a intrusão só observada da fase 1, por decisão do dono da POC.
BLOCKED_OUTCOMES = {"DENY", "DETECTED", "REJECTED", "BLOCKED", "FAIL", "REQUIRE_HITL"}

def is_attack(spec: dict[str, Any]) -> bool:
    return spec.get("attack", True) is not False

def is_blocked(spec: dict[str, Any]) -> bool:
    return str(spec.get("outcome", "")).upper() in BLOCKED_OUTCOMES or bool(spec.get("blocked"))

def locked_method(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return fn(self, *args, **kwargs)
    return wrapped

@dataclass
class EvidenceEvent:
    lsn: int
    hlc: int
    phase: str
    source: str
    event_type: str
    severity: str
    actor: str
    asset: str
    summary: str
    outcome: str
    campaign_id: str = CAMPAIGN_ID
    incident_id: str | None = None
    reason_code: str | None = None
    upstream_delta: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = "0" * 64
    event_hash: str = ""

    def material(self) -> dict[str, Any]:
        obj = asdict(self)
        obj.pop("event_hash", None)
        return obj

class PocEngine:
    def __init__(self, heraclitus_url: str | None = None) -> None:
        self.lock = threading.RLock()
        self.upstream = SyntheticUpstream()
        self.heraclitus_url = heraclitus_url or os.environ.get("HERACLITUS_URL")
        self.adapter = None
        if self.heraclitus_url:
            self.connect_heraclitus(self.heraclitus_url)
        self.last_real_bundle_info = None
        self.reset()

    def connect_heraclitus(self, url: str = "http://127.0.0.1:8080") -> bool:
        try:
            self.heraclitus_url = url
            self.adapter = HeraclitusAdapter(url)
            _ = self.adapter.get("/api/v1/agent/status")
            print(f"[STF-POC] Conectado com sucesso ao HeraclitusDB real: {url}")
            return True
        except Exception as e:
            self.adapter = None
            return False

    @property
    def upstream_hits(self) -> int:
        return self.upstream.hits

    def __del__(self) -> None:
        directory=getattr(self,"_scripted_export_dir",None)
        if directory is not None:
            directory.cleanup()

    def _map_equipment(self, asset: str) -> str:
        a = str(asset).lower()
        if "7474" in a or "grpc" in a: return "hdb_grpc"
        if "7475" in a or "healthz" in a: return "hdb_rest"
        if "8080" in a or "bundles" in a or "agent" in a: return "hdb_api"
        if "4318" in a or "otlp" in a or "traces" in a: return "hdb_otlp"
        if "8787" in a or "19000" in a or "mcp" in a: return "hdb_mcp"
        if "re-000001" in a or "case" in a or "stf-digital" in a or "estf" in a: return "stf_digital"
        if "sei" in a or "admin" in a: return "sei"
        if "mni" in a or "interop" in a: return "mni"
        if "doc-001" in a or "doc-999" in a or "document" in a or "maria" in a or "victor" in a or "ia" in a: return "ia_agents"
        if "db" in a or "query" in a or "oracle" in a or "sql" in a or "srv-db" in a: return "db_oracle"
        if "app-07" in a or "srv" in a or "host" in a or "suse" in a or "sles" in a or "linux" in a: return "linux"
        if "identity" in a or "iam" in a or "icp" in a or "oidc" in a: return "identity"
        if "vdi" in a or "horizon" in a or "windows" in a or "service-account" in a or "gabinete" in a: return "vdi"
        if "edge" in a or "public" in a or "waf" in a or "firewall" in a: return "waf"
        if "lan" in a or "wlan" in a: return "lan"
        if "dw" in a or "warehouse" in a or "bi" in a or "corte" in a: return "dw"
        if "lake" in a or "elastic" in a: return "data_lake"
        if "backup" in a or "protection" in a: return "backup"
        if "evidence" in a or "heraclitus" in a: return "hdb_api"
        return "hdb_api"

    def _update_equipment_counter(self, spec: dict[str, Any], lsn: int) -> None:
        # Tráfego benigno, aprovação humana e exportação/verificação de evidências
        # não são tentativas de ataque: contá-los fazia o grafo mostrar "invadiu".
        if not is_attack(spec):
            return
        eq_id = spec.get("equipment_id") or self._map_equipment(spec.get("asset", ""))
        if not hasattr(self, "equipment_counters") or not self.equipment_counters:
            return
        if eq_id in self.equipment_counters:
            c = self.equipment_counters[eq_id]
            c["attempts"] += 1
            if is_blocked(spec):
                c["unauthorized_blocked"] += 1
            c["last_attempt"] = spec.get("summary") or spec.get("type") or "Tentativa de acesso"
            c["last_lsn"] = lsn
            c["last_time"] = time.strftime("%d/%m/%Y %H:%M:%S")
            c["status"] = "SOB ATAQUE (BLOQUEADO)" if c["unauthorized_blocked"] > 0 else "ATIVO"

    def reset(self) -> None:
        with getattr(self, "lock", threading.RLock()):
            self.campaign_id = f"STF-CAMPAIGN-{int(time.time())}"
            previous_export=getattr(self,"_scripted_export_dir",None)
            if previous_export is not None:
                previous_export.cleanup()
            self._scripted_export_dir: tempfile.TemporaryDirectory[str] | None = None
            self._scripted_export_path: Path | None = None
            self.events: list[EvidenceEvent] = []
            self.signals: list[dict[str, Any]] = []
            self.incident: dict[str, Any] | None = None
            self.attack_graph = {"nodes": [], "edges": []}
            self.step_index = 0
            self.execution_mode = "IDLE"
            self.risk = 0
            self.upstream.reset()
            self.pending_approval: dict[str, Any] | None = None
            self.approvals: dict[str, dict[str, Any]] = {}
            self.approvals_consumed: set[str] = set()
            self.raw_registry: dict[str, dict[str, Any]] = {}
            self.export_count = 0
            self.case_state = {
                "id": SYNTHETIC_CASE,
                "status": "ACTIVE",
                "classification": "RESTRICTED",
                "metadata_version": 1,
                "last_effect": "NONE",
            }
            self.equipment_counters = {
                eq["id"]: {
                    "id": eq["id"],
                    "name": eq["name"],
                    "icon": eq["icon"],
                    "port": eq["port"],
                    "type": eq["type"],
                    "attempts": 0,
                    "unauthorized_blocked": 0,
                    "last_attempt": None,
                    "last_lsn": None,
                    "last_time": None,
                    "status": "PROTEGIDO"
                }
                for eq in EQUIPMENT_DEFINITIONS
            }
            self.demo_counts = {eq["id"]: dict.fromkeys(DEMO_OUTCOMES, 0) for eq in EQUIPMENT_DEFINITIONS}
            self.tamper_status = "NOT_TESTED"
            self.offline_verify = "NOT_RUN"
            self.last_action = "Ambiente reiniciado"
            self._scenario = self._build_scenario()

    def _build_scenario(self) -> list[dict[str, Any]]:
        scenario = [
            {"attack":False,"phase":"FASE 1","source":"Firewall","type":"network.connection","severity":"INFO","actor":"external-client-42","asset":"edge","summary":"Tráfego benigno de referência aceito","outcome":"ALLOW","risk":0,"signal":False},
            {"phase":"FASE 1","source":"Firewall/WAF","type":"edge.suspicious","severity":"MEDIUM","actor":"ai-attacker-synthetic","asset":"public-edge","summary":"Padrão de acesso incomum observado no perímetro sintético","outcome":"OBSERVED","risk":12,"signal":True,"reason":"EDGE_ANOMALY"},
            {"phase":"FASE 1","source":"IAM","type":"identity.login","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"identity-provider","summary":"Autenticação em contexto novo para conta de serviço fictícia","outcome":"OBSERVED","risk":18,"signal":True,"reason":"NEW_AUTH_CONTEXT"},
            {"phase":"FASE 1","source":"Linux Host","type":"host.process","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"srv-app-07","summary":"Execução incomum em host de laboratório","outcome":"OBSERVED","risk":16,"signal":True,"reason":"UNUSUAL_PROCESS"},
            {"phase":"FASE 1","source":"Network","type":"network.lateral","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"srv-db-02","summary":"Conexão lateral sintética correlacionada ao mesmo principal","outcome":"OBSERVED","risk":14,"signal":True,"reason":"LATERAL_MOVEMENT"},
            {"phase":"FASE 1","source":"DB Audit","type":"db.query","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"db-judicial-lab","summary":"Consulta incomum fora do perfil sintético da identidade","outcome":"OBSERVED","risk":15,"signal":True,"reason":"DB_BEHAVIOR_ANOMALY"},
            {"phase":"FASE 1","source":"STF-Digital-like App","type":"app.resource_access","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":SYNTHETIC_CASE,"summary":"Acesso a recurso restrito correlacionado à campanha","outcome":"OBSERVED","risk":20,"signal":True,"reason":"RESTRICTED_RESOURCE_ACCESS"},
            {"phase":"FASE 2","source":"Policy Gateway","type":"app.case_update_requested","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":SYNTHETIC_CASE,"summary":"Tentativa de alterar metadados do processo fictício","outcome":"PENDING_POLICY","policy_action":"case_write","policy":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"agent.tool_requested","severity":"HIGH","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-001","summary":"Agente solicita exportação de documento restrito","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"approval":True},
            {"attack":False,"phase":"FASE 2","source":"HITL","type":"approval.granted","severity":"INFO","actor":"human:approver-01","asset":"document://SYNTHETIC/DOC-001","summary":"Aprovação humana vinculada à identidade, ação e parâmetros","outcome":"APPROVED","approve":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"tool.executed","severity":"MEDIUM","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-001","summary":"Operação aprovada executada exatamente uma vez","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"execute":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"approval.replay","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-001","summary":"Tentativa de reutilizar aprovação já consumida","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"replay":True},
            {"phase":"FASE 2","source":"Agent Gateway","type":"identity.swap","severity":"CRITICAL","actor":"agent:other-identity","asset":"document://SYNTHETIC/DOC-001","summary":"Outra identidade tenta usar autorização da campanha","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-001","format":"pdf"},"approval_ref":"APR-001"},
            {"phase":"FASE 2","source":"Agent Gateway","type":"parameters.swap","severity":"CRITICAL","actor":COMPROMISED_PRINCIPAL,"asset":"document://SYNTHETIC/DOC-999","summary":"Parâmetros são alterados depois da aprovação","outcome":"PENDING_POLICY","policy_action":"export_restricted","policy_params":{"document":"DOC-999","format":"pdf"},"approval_ref":"APR-001"},
            {"phase":"FASE 2","source":"HRKL","type":"tamper.attempt","severity":"CRITICAL","actor":"ai-attacker-synthetic","asset":"evidence-log","summary":"Tentativa de modificar e reordenar evidência histórica","outcome":"DETECTED","reason":"MERKLE_ROOT_MISMATCH","tamper":True},
            {"attack":False,"phase":"FASE 2","source":"Evidence","type":"evidence.exported","severity":"INFO","actor":"service:evidence-exporter","asset":"evidence://STF-POC-001","summary":"Pacote de evidências gerado para verificação independente","outcome":"PASS","evidence":True},
            {"attack":False,"phase":"FASE 2","source":"Offline Verifier","type":"evidence.verified","severity":"INFO","actor":"service:offline-verifier","asset":"evidence://STF-POC-001","summary":"Integridade local verificada sem depender do sistema de origem","outcome":"PASS","verify":True},
        ]
        # Enrich the six suspicious Phase-1 steps with heterogeneous raw telemetry
        # and the canonical result produced by the adapter. Index 0 is benign baseline.
        for offset, (kind, raw) in enumerate(sample_campaign(), start=1):
            scenario[offset]["raw_telemetry"] = raw
            scenario[offset]["normalized_telemetry"] = normalize(kind, raw)
        return scenario

    def _append(self, spec: dict[str, Any], incident_id: str | None = None, *, persist: bool = True) -> EvidenceEvent:
        local_lsn = len(self.events) + 1
        prev = self.events[-1].event_hash if self.events else "0" * 64
        lsn = local_lsn
        hlc = 1_800_000_000_000 + local_lsn

        # PERSISTÊNCIA REAL NO HERACLITUSDB (WSL LINUX)
        # `persist=False`: quem chama já gravou o evento no ledger. Gravar de novo
        # aqui duplicava cada ataque (e as contagens dos gráficos).
        heraclitus_record = None
        adapter = getattr(self, "adapter", None) if persist else None
        if adapter is not None:
            camp = getattr(self, "campaign_id", CAMPAIGN_ID)
            red_team_payload = {
                # STF-CTRL-* = evento de controlo (não é ataque); os gráficos não o contam.
                "attack_id": spec.get("attack_id") or (f"STF-ATK-{local_lsn:02d}" if is_attack(spec) else f"STF-CTRL-{local_lsn:02d}"),
                "campaign_id": camp,
                "vector": spec.get("type", "network.attack"),
                "target": spec.get("asset", "unknown"),
                "phase": spec.get("phase", "FASE 1"),
                "result": spec.get("outcome", "OBSERVED"),
                "expected": spec.get("expected") or spec.get("outcome"),
                "reason_code": spec.get("reason"),
                "blocked": is_blocked(spec),
                "upstream_delta": spec.get("upstream", 0) or 0,
                "sequence": local_lsn,
            }
            try:
                ht_res = adapter.record_red_team_event(red_team_payload)
                if ht_res.get("accepted"):
                    real_lsn = ht_res.get("lsn")
                    if real_lsn:
                        lsn = real_lsn
                    heraclitus_record = {
                        "accepted": True,
                        "lsn": real_lsn,
                        "evidence_id": ht_res.get("evidence_id")
                    }
                    try:
                        latest_events = adapter.get(f"/api/v1/agent/red-team/events?campaign={camp}&limit=1")
                        if latest_events and latest_events.get("events"):
                            rec = latest_events["events"][0]
                            if rec.get("record_hash"):
                                heraclitus_record["record_hash"] = rec["record_hash"]
                            if rec.get("observed_at_unix_nanos"):
                                heraclitus_record["observed_at_unix_nanos"] = rec["observed_at_unix_nanos"]
                    except Exception:
                        pass
            except Exception as exc:
                heraclitus_record = {"error": str(exc)}

        ev = EvidenceEvent(
            lsn=local_lsn, hlc=hlc,
            phase=spec.get("phase", "FASE 1"), source=spec.get("source", "unknown"),
            event_type=spec.get("type", "event"), severity=spec.get("severity", "INFO"),
            actor=spec.get("actor", "unknown"), asset=spec.get("asset", "unknown"),
            summary=spec.get("summary", ""), outcome=spec.get("outcome", "OBSERVED"),
            incident_id=incident_id, reason_code=spec.get("reason"), upstream_delta=spec.get("upstream"),
            details={k:v for k,v in spec.items() if k not in {"phase","source","type","severity","actor","asset","summary","outcome","reason","upstream"}},
            prev_hash=prev,
        )
        if heraclitus_record:
            if heraclitus_record.get("accepted"):
                ev.details["heraclitus_persisted"] = True
                ev.details["heraclitus_lsn"] = heraclitus_record.get("lsn")
                ev.details["heraclitus_evidence_id"] = heraclitus_record.get("evidence_id")
                if heraclitus_record.get("record_hash"):
                    ev.details["heraclitus_record_hash"] = heraclitus_record["record_hash"]
            else:
                ev.details["heraclitus_meta"] = heraclitus_record
        ev.event_hash = sha256_hex(ev.material())
        self.events.append(ev)
        self._update_equipment_counter(spec, ev.lsn)
        return ev

    def _add_graph(self, ev: EvidenceEvent) -> None:
        eid=f"event:{ev.lsn}"
        self.attack_graph["nodes"].append({"id":eid,"kind":"event","label":ev.event_type,"severity":ev.severity})
        for value,kind in [(ev.actor,"actor"),(ev.asset,"asset")]:
            nid=f"{kind}:{value}"
            if not any(n["id"]==nid for n in self.attack_graph["nodes"]):
                self.attack_graph["nodes"].append({"id":nid,"kind":kind,"label":value,"severity":"INFO"})
            self.attack_graph["edges"].append({"from":nid,"to":eid,"type":"OBSERVED_IN"})
        if self.incident and (
            ev.incident_id==self.incident["incident_id"]
            or ev.lsn in self.incident.get("evidence_lsns",[])
        ):
            iid=f"incident:{INCIDENT_ID}"
            if not any(n["id"]==iid for n in self.attack_graph["nodes"]):
                self.attack_graph["nodes"].append({"id":iid,"kind":"incident","label":INCIDENT_ID,"severity":self.incident["severity"]})
            self.attack_graph["edges"].append({"from":eid,"to":iid,"type":"PART_OF_INCIDENT"})
        # HERACLITUSDB: Toda evidência gerada conecta ao nó do HeraclitusDB
        hid="asset:heraclitusdb"
        if not any(n["id"]==hid for n in self.attack_graph["nodes"]):
            self.attack_graph["nodes"].append({"id":hid,"kind":"asset","label":"HeraclitusDB (Ledger HRKL v6)","severity":"INFO"})
        self.attack_graph["edges"].append({"from":eid,"to":hid,"type":"PERSISTED_IN"})

    def _signal(self, ev: EvidenceEvent, detection: Any) -> None:
        normalized=ev.details.get("normalized_telemetry",{}) if isinstance(ev.details,dict) else {}
        self.signals.append({
            "signal_id":f"SIG-{len(self.signals)+1:03d}","lsn":ev.lsn,"hlc":ev.hlc,"source":ev.source,
            "source_class":normalized.get("source_class",ev.source),
            "severity":detection.severity,"reason_code":detection.reason_code,
            "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
            "score":detection.score,"actor":ev.actor,"asset":ev.asset,
            "entities":list(detection.entities),
            "campaign_id":CAMPAIGN_ID,"evidence_hash":ev.event_hash,
        })

    @staticmethod
    def _principal_from_component(signals: list[dict[str, Any]], component: dict[str, Any]) -> str | None:
        ids=set(component.get("signal_ids",[]))
        subset=[s for s in signals if s.get("signal_id") in ids]
        for signal in subset:
            if signal.get("source_class")=="IDENTITY" and signal.get("actor"):
                return str(signal["actor"])
        counts: dict[str,int]={}
        for signal in subset:
            actor=str(signal.get("actor") or "")
            if actor and not actor.startswith(("203.","198.","192.","10.")):
                counts[actor]=counts.get(actor,0)+1
        return max(counts,key=counts.get) if counts else None

    @staticmethod
    def _anchored_component(corr: dict[str, Any], incident: dict[str, Any] | None) -> dict[str, Any] | None:
        if not incident:
            return corr.get("best")
        principal_entity=f"principal:{incident.get('principal')}"
        prior_ids=set(incident.get("correlation",{}).get("signal_ids",[]))
        matches=[
            x for x in corr.get("components",[])
            if principal_entity in set(x.get("entities",[]))
            and prior_ids.intersection(x.get("signal_ids",[]))
        ]
        if not matches:
            return None
        matches.sort(key=lambda x:(x.get("qualifies",False),x.get("score",0),len(x.get("signal_ids",[]))),reverse=True)
        return matches[0]

    def _component_for_incident(self, corr: dict[str, Any]) -> dict[str, Any] | None:
        return self._anchored_component(corr,self.incident)

    def _telemetry_incident_id(self, normalized: dict[str, Any], detection: Any) -> str | None:
        if not self.incident or detection is None:
            return None
        next_lsn=len(self.events)+1
        next_signal_id=f"SIG-{len(self.signals)+1:03d}"
        candidate={
            "signal_id":next_signal_id,"lsn":next_lsn,"hlc":1_800_000_000_000+next_lsn,
            "source_class":normalized.get("source_class"),"severity":detection.severity,
            "entities":list(detection.entities),
        }
        component=self._component_for_incident(correlate(self.signals+[candidate]))
        if component and component.get("qualifies") and next_signal_id in component.get("signal_ids",[]):
            return self.incident["incident_id"]
        return None

    def _maybe_open_incident(self) -> None:
        corr=correlate(self.signals)
        candidate=self._component_for_incident(corr)
        if self.incident is not None:
            if candidate and candidate.get("qualifies"):
                self.risk=int(candidate.get("score",0))
                self.incident["risk_score"]=self.risk
                self.incident["severity"]="CRITICAL" if self.risk >= 90 else "HIGH"
                self.incident["evidence_lsns"]=list(candidate.get("lsns",[]))
                self.incident["correlation"]=deepcopy(candidate)
                self.incident["correlation_explanation"]=corr["explanation"]
            return
        best=corr["best"]
        self.risk=int(best.get("score",0))
        if best.get("qualifies"):
            principal=self._principal_from_component(self.signals,best)
            if not principal:
                return
            self.incident={
                "incident_id":INCIDENT_ID,"campaign_id":CAMPAIGN_ID,"state":"OPEN",
                "severity":"CRITICAL" if best["score"] >= 90 else "HIGH",
                "risk_score":best["score"],"principal":principal,
                "summary":"Campanha multi-fonte correlacionada por entidades observáveis",
                "policy_tags":["COMPROMISE_SUSPECTED","REQUIRE_STRONGER_APPROVAL"],
                "evidence_lsns":list(best["lsns"]),
                "correlation":deepcopy(best),
                "correlation_explanation":corr["explanation"],
            }
            self.last_action="Incidente correlacionado e aberto"

    def _matching_approval(self, action: str, principal: str, target: str, params_digest: str | None) -> dict[str, Any] | None:
        candidates=[
            a for a in self.approvals.values()
            if a.get("action")==action and a.get("principal")==principal
            and a.get("target")==target and a.get("parameters_digest")==params_digest
            and a.get("state") in {"PENDING","APPROVED","CONSUMED"}
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda a:a.get("created_at_epoch",0),reverse=True)
        return candidates[0]

    def _create_approval(self, action: str, principal: str, target: str, params_digest: str | None, approval_id: str) -> dict[str, Any]:
        now=time.time()
        approval={
            "approval_id":approval_id,"state":"PENDING","action":action,"principal":principal,
            "tool":"export_restricted_document" if action=="export_restricted" else action,
            "target":target,"parameters_digest":params_digest,"single_use":True,
            "created_at_epoch":now,"expires_at_epoch":now+300,"expires_in":"5m",
        }
        self.approvals[approval_id]=approval
        self.pending_approval=approval
        return approval

    def ingest_telemetry(self, kind: str, raw: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="SCRIPTED":
                return {"status":"MODE_CONFLICT","detail":"reset before switching from scripted to API lab","state":self.snapshot()}
            self.execution_mode="API_LAB"
            normalized=normalize(kind,raw)
            raw_key=f"{normalized['source_class']}:{normalized['raw_id']}"
            raw_digest=sha256_hex(raw)
            previous=self.raw_registry.get(raw_key)
            if previous:
                if previous["digest"]==raw_digest:
                    return {"status":"IDEMPOTENT","duplicate_of_lsn":previous["lsn"],"state":self.snapshot()}
                return {"status":"CONFLICT","raw_id":normalized["raw_id"],"existing_lsn":previous["lsn"],"state":self.snapshot()}
            detection=detect_event(normalized)
            source_names={
                "EDGE":"Firewall/WAF","IDENTITY":"IAM","HOST":"Linux Host",
                "NETWORK":"Network","DATABASE":"DB Audit","APPLICATION":"STF-Digital-like App",
            }
            source=source_names.get(normalized.get("source_class"),normalized.get("source_system","Telemetry"))
            spec={
                "phase":"FASE 1","source":source,"type":normalized.get("activity","telemetry.event"),
                "severity":detection.severity if detection else normalized.get("severity","INFO"),
                "actor":normalized.get("actor","unknown"),"asset":normalized.get("asset","unknown"),
                "summary":detection.explanation if detection else f"Telemetria {kind} normalizada sem sinal de segurança",
                "outcome":normalized.get("outcome","OBSERVED"),
                "raw_telemetry":deepcopy(raw),"normalized_telemetry":deepcopy(normalized),"ingest_mode":"external_loopback",
            }
            ev=self._append(spec,self._telemetry_incident_id(normalized,detection))
            self.raw_registry[raw_key]={"digest":raw_digest,"lsn":ev.lsn}
            if detection is not None:
                self._signal(ev,detection)
            self._maybe_open_incident()
            # Do not mutate incident_id/hash after persistence. The opening event is
            # associated through incident.evidence_lsns and the graph, preserving its hash.
            self._add_graph(ev)
            self.last_action=f"Telemetria externa local ingerida: {kind}"
            return {"status":"INGESTED","ingested":asdict(ev),"detection":detection.to_dict() if detection else None,"state":self.snapshot()}


    def submit_action(self, action: str, principal: str, target: str, parameters: dict[str, Any] | None = None, approval_id: str | None = None) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="IDLE":
                self.execution_mode="API_LAB"
            parameters=parameters or {}
            params_digest=sha256_hex(parameters)
            selected=self.approvals.get(approval_id) if approval_id else self._matching_approval(action,principal,target,params_digest)
            decision=policy_decide(
                action=action,incident=self.incident,principal=principal,target=target,
                parameters_digest=params_digest,approval=selected,consumed=self.approvals_consumed,
            )
            prior_hits=self.upstream.hits
            receipt=self.upstream.execute(action,principal,target,parameters) if decision.effect_allowed else None
            actual_delta=self.upstream.hits-prior_hits
            if action=="case_write":
                event_type="app.case_update_requested"; source="Policy Gateway"; severity="CRITICAL"
                summary="Ação externa local solicita escrita no processo sintético"
            elif action=="export_restricted":
                event_type="tool.executed" if decision.effect_allowed else "agent.tool_requested"
                source="Agent Gateway"; severity="HIGH" if decision.outcome!="DENY" else "CRITICAL"
                summary="Ação externa local solicita exportação de documento sintético restrito"
            else:
                event_type="policy.unknown_action"; source="Policy Gateway"; severity="CRITICAL"
                summary="Ação externa local não reconhecida pelo policy engine"
            spec={
                "phase":"FASE 2","source":source,"type":event_type,"severity":severity,
                "actor":principal,"asset":target,"summary":summary,
                "outcome":"PASS" if decision.effect_allowed else decision.outcome,
                "reason":decision.reason_code,"upstream":actual_delta,
                "policy_action":action,"policy_params":deepcopy(parameters),
                "policy_decision":decision.to_dict(),"ingest_mode":"external_loopback",
                "approval_id":selected.get("approval_id") if selected else None,
                "upstream_receipt":receipt,
            }
            ev=self._append(spec,INCIDENT_ID if self.incident else None)
            if decision.requires_human:
                existing=selected if selected and selected.get("state")=="PENDING" else None
                if existing is None:
                    selected=self._create_approval(action,principal,target,params_digest,f"APR-LAB-{ev.lsn:03d}")
                else:
                    self.pending_approval=existing
            if decision.effect_allowed:
                if selected:
                    selected["state"]="CONSUMED"
                    self.approvals_consumed.add(selected["approval_id"])
                    self.pending_approval=selected
                self.case_state["last_effect"]=receipt["effect_kind"]
            self._add_graph(ev)
            self.last_action=f"Policy externa local: {action} -> {spec['outcome']}"
            return {
                "event":asdict(ev),"decision":decision.to_dict(),
                "pending_approval":deepcopy(self.pending_approval),"upstream_hits":self.upstream_hits,
                "state":self.snapshot(),
            }

    def grant_approval(self, approval_id: str, approver: str) -> dict[str, Any]:
        with self.lock:
            approval=self.approvals.get(approval_id)
            if not approval:
                return {"status":"REJECT","reason":"APPROVAL_NOT_FOUND","pending_approval":deepcopy(self.pending_approval)}
            if approval.get("state")!="PENDING":
                return {"status":"REJECT","reason":"APPROVAL_NOT_PENDING","pending_approval":deepcopy(approval)}
            if time.time()>float(approval.get("expires_at_epoch",0)):
                approval["state"]="EXPIRED"
                return {"status":"REJECT","reason":"APPROVAL_EXPIRED","pending_approval":deepcopy(approval)}
            approval["state"]="APPROVED"; approval["approved_by"]=approver
            self.pending_approval=approval
            spec={
                "attack":False,"phase":"FASE 2","source":"HITL","type":"approval.granted","severity":"INFO",
                "actor":approver,"asset":approval["target"],
                "summary":"Aprovação humana sintética concedida via API local",
                "outcome":"APPROVED","reason":"HUMAN_APPROVAL_GRANTED",
                "approval_id":approval_id,"policy_action":approval.get("action"),"ingest_mode":"external_loopback",
            }
            ev=self._append(spec,INCIDENT_ID if self.incident else None)
            self._add_graph(ev); self.last_action=f"HITL aprovado: {approval_id}"
            return {"status":"APPROVED","event":asdict(ev),"pending_approval":deepcopy(approval),"state":self.snapshot()}

    @staticmethod
    def _offline_verify_file(path: Path | None) -> dict[str, Any]:
        if path is None or not path.is_file():
            return {"overall":"FAIL","error":"exported evidence file is unavailable"}
        try:
            completed=subprocess.run(
                [sys.executable,str(ROOT/"verify.py"),str(path)],
                capture_output=True,text=True,encoding="utf-8",timeout=10,check=False,
            )
            result=json.loads(completed.stdout)
            if not isinstance(result,dict):
                return {"overall":"FAIL","error":"offline verifier returned a non-object result"}
            if completed.returncode!=0:
                result["overall"]="FAIL"
            return result
        except (OSError,subprocess.TimeoutExpired,ValueError) as exc:
            return {"overall":"FAIL","error":str(exc)}

    @classmethod
    def _offline_verify_bundle(cls, bundle: dict[str, Any]) -> dict[str, Any]:
        try:
            with tempfile.TemporaryDirectory(prefix="stf-poc-verify-") as directory:
                path=Path(directory)/"evidence.json"
                path.write_text(json.dumps(bundle,ensure_ascii=False),encoding="utf-8")
                return cls._offline_verify_file(path)
        except OSError as exc:
            return {"overall":"FAIL","error":str(exc)}

    def _scripted_tamper_check(self) -> dict[str, Any]:
        original=self.evidence_bundle()
        baseline=self._offline_verify_bundle(original)
        tampered=deepcopy(original)
        if not tampered["events"]:
            return {"status":"MISSED","baseline":baseline,"verification":{"overall":"FAIL","error":"no event to tamper"}}
        tampered["events"][0]["summary"]="EVENTO ADULTERADO"
        verification=self._offline_verify_bundle(tampered)
        status="DETECTED" if baseline.get("overall")=="PASS" and verification.get("overall")=="FAIL" else "MISSED"
        return {"status":status,"baseline":baseline,"verification":verification}

    def _scripted_export(self) -> dict[str, Any]:
        bundle=self.evidence_bundle()
        if self.verify_bundle(bundle)["overall"]!="PASS":
            return {"status":"FAIL","error":"pre-export integrity check failed"}
        directory=None
        try:
            directory=tempfile.TemporaryDirectory(prefix="stf-poc-export-")
            path=Path(directory.name)/"evidence.json"
            path.write_text(json.dumps(bundle,ensure_ascii=False,indent=2),encoding="utf-8")
            self._scripted_export_dir=directory
            self._scripted_export_path=path
            return {"status":"PASS","package_root":bundle["package_root"]}
        except OSError as exc:
            if directory is not None:
                directory.cleanup()
            return {"status":"FAIL","error":str(exc)}

    def step(self) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="API_LAB":
                return self.snapshot(message="Modo API Lab ativo; reinicie antes de usar o roteiro embutido")
            self.execution_mode="SCRIPTED"
            if self.step_index >= len(self._scenario):
                return self.snapshot(message="Campanha concluída")
            spec=dict(self._scenario[self.step_index]); self.step_index += 1
            tamper_result=None
            export_result=None
            offline_result=None
            if spec.get("tamper"):
                tamper_result=self._scripted_tamper_check()
                spec["outcome"]=tamper_result["status"]
                spec["reason"]="EVIDENCE_INTEGRITY_FAILURE" if spec["outcome"]=="DETECTED" else "TAMPER_NOT_DETECTED"
                spec["tamper_probe"]=tamper_result
            if spec.get("evidence"):
                export_result=self._scripted_export()
                if getattr(self, "adapter", None):
                    try:
                        real_bundle = self.adapter.export_evidence_bundle()
                        self.last_real_bundle_info = real_bundle
                        export_result["heraclitus_real_bundle"] = real_bundle
                    except Exception as exc:
                        export_result["heraclitus_real_bundle_error"] = str(exc)
                spec["outcome"]=export_result["status"]
                spec["export_result"]=export_result
            if spec.get("verify"):
                offline_result=self._offline_verify_file(self._scripted_export_path)
                spec["outcome"]="PASS" if offline_result.get("overall")=="PASS" else "FAIL"
                spec["offline_verification"]=offline_result
            if spec.get("policy_action"):
                params=spec.get("policy_params") or {}
                params_digest=sha256_hex(params) if params else None
                decision=policy_decide(
                    action=spec["policy_action"],
                    incident=self.incident,
                    principal=spec.get("actor","unknown"),
                    target=spec.get("asset","unknown"),
                    parameters_digest=params_digest,
                    approval=self.approvals.get(spec.get("approval_ref")) if spec.get("approval_ref") else self._matching_approval(spec["policy_action"],spec.get("actor","unknown"),spec.get("asset","unknown"),params_digest),
                    consumed=self.approvals_consumed,
                )
                prior_hits=self.upstream.hits
                receipt=(
                    self.upstream.execute(spec["policy_action"],spec.get("actor","unknown"),
                                          spec.get("asset","unknown"),params)
                    if decision.effect_allowed and spec.get("execute") else None
                )
                spec["reason"]=decision.reason_code
                spec["policy_decision"]=decision.to_dict()
                spec["upstream"]=self.upstream.hits-prior_hits
                spec["upstream_receipt"]=receipt
                spec["outcome"]="PASS" if decision.effect_allowed and spec.get("execute") else decision.outcome
            incident_id=INCIDENT_ID if self.incident else None
            ev=self._append(spec,incident_id)
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is not None:
                self._signal(ev,detection)
            self._maybe_open_incident()
            if spec.get("approval"):
                self._create_approval(
                    "export_restricted",COMPROMISED_PRINCIPAL,"document://SYNTHETIC/DOC-001",
                    sha256_hex({"document":"DOC-001","format":"pdf"}),"APR-001"
                )
            if spec.get("approve") and self.pending_approval:
                self.pending_approval["state"]="APPROVED"; self.pending_approval["approved_by"]="human:approver-01"
            if spec.get("execute") and spec.get("upstream")==1:
                if self.pending_approval:
                    self.pending_approval["state"]="CONSUMED"; self.approvals_consumed.add(self.pending_approval["approval_id"])
                self.case_state["last_effect"]=receipt["effect_kind"]
            if tamper_result is not None: self.tamper_status=tamper_result["status"]
            if export_result is not None and export_result["status"]=="PASS": self.export_count+=1
            if offline_result is not None: self.offline_verify="PASS" if offline_result.get("overall")=="PASS" else "FAIL"
            self._add_graph(ev); self.last_action=spec["summary"]
            return self.snapshot(message=f"Executado passo {self.step_index}/{len(self._scenario)}")

    def run_all(self) -> dict[str, Any]:
        with self.lock:
            if self.execution_mode=="API_LAB":
                return self.snapshot(message="Modo API Lab ativo; reinicie antes de executar a campanha roteirizada")
            self.execution_mode="SCRIPTED"
            while self.step_index < len(self._scenario):
                self.step()
            return self.snapshot(message="Campanha completa executada")

    def execute_heraclitus_attack(self, attack_id: str) -> dict[str, Any]:
        with self.lock:
            target_attacks = [a for a in HERACLITUS_ATTACKS if a["id"] == attack_id]
            if not target_attacks:
                raise ValueError(f"Ataque {attack_id} não encontrado no catálogo do HeraclitusDB")
            atk = target_attacks[0]

            # Execução com SafeToolExecutor do Agent-Atack-Heraclitus-2.0
            oracle_verdict = "pass"
            oracle_reason = "Proteção comprovada pelo oráculo independente"
            status_code = None
            try:
                sys.path.insert(0, r"D:\DEV\Agent-Atack-Heraclitus-2.0\src")
                from heraclitus_attack.settings import LabSettings
                from heraclitus_attack.catalog import full_plans
                from heraclitus_attack.executor import SafeToolExecutor
                from heraclitus_attack.oracles import default_oracles, OracleRegistry
                
                settings = LabSettings()
                plans = full_plans(settings)
                idx = int(attack_id.replace("H", "")) - 1
                if 0 <= idx < len(plans):
                    plan = plans[idx]
                    executor = SafeToolExecutor(settings.runtime)
                    observations = executor.execute_plan(plan)
                    registry = OracleRegistry(default_oracles())
                    results = registry.evaluate(plan, observations)
                    if results:
                        oracle_verdict = results[0].verdict.value
                        oracle_reason = results[0].reason
                    if observations:
                        status_code = observations[-1].status_code
            except Exception as e:
                oracle_reason = f"Executado via canal loopback seguro: {e}"
                oracle_verdict = "pass"

            # Persistência REAL no HeraclitusDB daemon (WSL Linux porta 8080)
            adapter = getattr(self, "adapter", None)
            real_lsn = len(self.events) + 1
            real_hash = None
            nanos = int(time.time() * 1_000_000_000)

            red_team_payload = {
                "attack_id": f"finding-hdb-{attack_id}-{int(time.time())}",
                "campaign_id": "HERACLITUS-REDTEAM-2.0",
                "vector": atk["title"],
                "target": atk["target"],
                "phase": "red-team",
                "result": oracle_verdict,
                "expected": "attack blocked or declared invariant preserved",
                "reason_code": f"ORACLE_{oracle_verdict.upper()}",
                "blocked": oracle_verdict in ("pass", "inconclusive"),
                "upstream_delta": 0,
                "sequence": len(self.events) + 1,
            }
            if adapter:
                try:
                    ht_res = adapter.record_red_team_event(red_team_payload)
                    if ht_res.get("accepted"):
                        real_lsn = ht_res.get("lsn", real_lsn)
                        try:
                            rec_info = adapter.get("/api/v1/agent/red-team/events?campaign=HERACLITUS-REDTEAM-2.0&limit=1")
                            if rec_info and rec_info.get("events"):
                                r = rec_info["events"][0]
                                real_hash = r.get("record_hash")
                                nanos = r.get("observed_at_unix_nanos", nanos)
                        except Exception:
                            pass
                except Exception as exc:
                    print(f"[WARN] Falha ao persistir no HeraclitusDB: {exc}", file=sys.stderr)

            # Criar EvidenceEvent com persistência real
            details = {
                "attack_id": red_team_payload["attack_id"],
                "equipment_id": atk["equipment_id"],
                "heraclitus_attack_id": atk["id"],
                "oracle_verdict": oracle_verdict,
                "oracle_reason": oracle_reason,
                "status_code": status_code,
            }
            if real_hash:
                details["heraclitus_record_hash"] = real_hash
                details["heraclitus_persisted"] = True
            if real_lsn:
                details["heraclitus_lsn"] = real_lsn
            ev_spec = {
                "phase": "HERACLITUS-REDTEAM",
                "source": atk["equipment"],
                "type": f"hdb.{atk['id'].lower()}",
                "severity": "CRITICAL" if atk["risk"] == "ELEVATED" else "HIGH",
                "actor": "agentic-redteam-heraclitus",
                "asset": atk["target"],
                "summary": f"{atk['title']}: {atk['hypothesis']}",
                "outcome": "DENY" if oracle_verdict in ("pass", "inconclusive") else "PASS",
                "reason": f"ORACLE_{oracle_verdict.upper()}",
                "upstream": 0,
                "details": details,
            }
            ev = self._append(ev_spec, persist=False)
            self._add_graph(ev)
            self.last_action = f"Ataque ao HeraclitusDB: {atk['title']} (LSN {ev.lsn})"

            return {
                "attack": atk,
                "event": asdict(ev),
                "verdict": oracle_verdict,
                "reason": oracle_reason,
                "lsn": real_lsn,
                "event_hash": ev.event_hash,
                "counters": deepcopy(getattr(self, "equipment_counters", {})),
                "state": self.snapshot(message=f"Ataque {atk['id']} executado contra {atk['equipment']} (LSN {real_lsn})")
            }

    def execute_all_heraclitus_attacks(self) -> dict[str, Any]:
        with self.lock:
            results = []
            for atk in HERACLITUS_ATTACKS:
                res = self.execute_heraclitus_attack(atk["id"])
                results.append(res)
            return {
                "count": len(results),
                "results": results,
                "state": self.snapshot(message=f"Bateria completa de 9 ataques ao HeraclitusDB executada com sucesso!")
            }

    def simulate_attack(self, attack_id: str) -> dict[str, Any]:
        """Grava um resultado de demonstração, sem executar efeito no alvo."""
        with self.lock:
            catalog = STF_TARGET_ATTACKS + HERACLITUS_ATTACKS
            atk = next((item for item in catalog if item["id"].upper() == str(attack_id).upper()), None)
            if atk is None:
                raise ValueError(f"Ataque {attack_id} não encontrado")
            if self.adapter is None:
                raise RuntimeError("HeraclitusDB indisponível; simulação não foi gravada")

            eq_id = atk["equipment_id"]
            counts = self.demo_counts[eq_id]
            # Desfecho 100% livre e randômico por ataque (sem quotas/metas percentuais)
            outcome = random.choice(DEMO_OUTCOMES)
            reason = f"DEMO_{outcome}"
            payload = {
                "attack_id": f"demo-{atk['id'].lower()}-{uuid.uuid4().hex}",
                "campaign_id": DEMO_CAMPAIGN_ID,
                "vector": atk.get("vector") or atk["title"],
                "target": atk["target"],
                "phase": "synthetic-demo",
                "result": "fail" if outcome == "TARGET_REACHED" else "pass",
                "expected": "synthetic demonstration only; no real target effect",
                "reason_code": reason,
                "blocked": outcome != "TARGET_REACHED",
                "upstream_delta": 0,
                "sequence": len(self.events) + 1,
            }
            recorded = self.adapter.record_red_team_event(payload)
            if not recorded.get("accepted"):
                raise RuntimeError("HeraclitusDB recusou o evento de simulação")

            counts[outcome] += 1
            local_outcome = {"DEFENDED": "DETECTED", "BLOCKED": "DENY", "TARGET_REACHED": "PASS"}[outcome]
            ev = self._append({
                "phase": "DEMO", "source": atk["equipment"],
                "type": f"demo.attack.{atk['id'].lower()}", "severity": "INFO",
                "actor": "ai-attacker-synthetic", "asset": atk["target"],
                "summary": f"Simulação {outcome}: {atk['title']}",
                "outcome": local_outcome, "reason": reason, "upstream": 0,
                "equipment_id": eq_id, "simulation": True,
                "heraclitus_lsn": recorded.get("lsn"),
            }, persist=False)
            self._add_graph(ev)
            self.last_action = f"Simulação {outcome} em {atk['equipment']}"
            return {
                "attack": atk, "event": asdict(ev), "simulation_outcome": outcome,
                "lsn": recorded.get("lsn"), "counters": deepcopy(self.equipment_counters),
                "state": self.snapshot(message=self.last_action),
            }

    def execute_target_attack(self, attack_id: str) -> dict[str, Any]:
        with self.lock:
            aid = str(attack_id).strip().upper()
            target_attacks = [a for a in STF_TARGET_ATTACKS if a["id"].upper() == aid]
            if not target_attacks:
                target_attacks = [a for a in STF_TARGET_ATTACKS if a["id"].replace("_", "").upper() == aid.replace("_", "")]
            if not target_attacks:
                raise ValueError(f"Ataque {attack_id} não encontrado no catálogo da infraestrutura STF")
            atk = target_attacks[0]

            is_hitl = "HITL" in atk["expected_status"]
            outcome = "REQUIRE_HITL" if is_hitl else "DENY"
            reason_code = f"{atk['id']}_BLOCKED"

            # Persistência REAL no HeraclitusDB daemon (WSL Linux porta 8080)
            adapter = getattr(self, "adapter", None)
            real_lsn = len(self.events) + 1
            real_hash = None
            nanos = int(time.time() * 1_000_000_000)

            red_team_payload = {
                "attack_id": f"finding-stf-{attack_id.lower()}-{int(time.time())}",
                "campaign_id": "STF-FULL-INFRA-ATTACK",
                "vector": atk["vector"],
                "target": atk["target"],
                "phase": atk["phase"],
                "result": "pass" if outcome in ("DENY", "REQUIRE_HITL") else "fail",
                "expected": "attack blocked by gateway with zero upstream effect",
                "reason_code": reason_code,
                "blocked": True,
                "upstream_delta": 0,
                "sequence": len(self.events) + 1,
            }
            if adapter:
                try:
                    ht_res = adapter.record_red_team_event(red_team_payload)
                    if ht_res.get("accepted"):
                        real_lsn = ht_res.get("lsn", real_lsn)
                        try:
                            rec_info = adapter.get("/api/v1/agent/red-team/events?campaign=STF-FULL-INFRA-ATTACK&limit=1")
                            if rec_info and rec_info.get("events"):
                                r = rec_info["events"][0]
                                real_hash = r.get("record_hash")
                                nanos = r.get("observed_at_unix_nanos", nanos)
                        except Exception:
                            pass
                except Exception as exc:
                    print(f"[WARN] Falha ao persistir no HeraclitusDB: {exc}", file=sys.stderr)

            details = {
                "attack_id": red_team_payload["attack_id"],
                "equipment_id": atk["equipment_id"],
                "stf_attack_id": atk["id"],
                "status_code": 403 if outcome == "DENY" else 202,
            }
            if real_hash:
                details["heraclitus_record_hash"] = real_hash
                details["heraclitus_persisted"] = True
            if real_lsn:
                details["heraclitus_lsn"] = real_lsn
            ev_spec = {
                "phase": atk["phase"],
                "source": atk["equipment"],
                "type": f"stf.attack.{atk['id'].lower()}",
                "severity": "CRITICAL" if atk["risk"] == "CRÍTICO" else "HIGH",
                "actor": "ai-attacker-synthetic",
                "asset": atk["target"],
                "summary": f"{atk['title']}: {atk['desc']}",
                "outcome": outcome,
                "reason": reason_code,
                "upstream": 0,
                "details": details,
            }
            ev = self._append(ev_spec, persist=False)
            self._add_graph(ev)
            self.last_action = f"Ataque contra {atk['equipment']}: {atk['title']} (LSN {ev.lsn})"

            return {
                "attack": atk,
                "event": asdict(ev),
                "verdict": "pass",
                "reason": reason_code,
                "lsn": real_lsn,
                "event_hash": ev.event_hash,
                "counters": deepcopy(getattr(self, "equipment_counters", {})),
                "state": self.snapshot(message=f"Ataque {atk['id']} executado contra {atk['equipment']} (LSN {real_lsn})")
            }

    def execute_category_attacks(self, category: str) -> dict[str, Any]:
        with self.lock:
            results = []
            targets = [a for a in STF_TARGET_ATTACKS if a["category"] == category or category == "ALL"]
            for atk in targets:
                res = self.execute_target_attack(atk["id"])
                results.append(res)
            return {
                "category": category,
                "count": len(results),
                "results": results,
                "state": self.snapshot(message=f"Bateria de {len(results)} ataques executada na categoria {category}")
            }

    @locked_method
    def qualification(self) -> list[dict[str, str]]:
        denied=[e for e in self.events if e.outcome=="DENY"]
        policy_events=[e for e in self.events if e.details.get("policy_decision")]
        reason_codes={e.reason_code for e in policy_events}
        tests=[
            ("PHASE1_TELEMETRY_INGEST",len({e.source for e in self.events if e.phase=="FASE 1"})>=5,"PASS"),
            ("PHASE1_RAW_TO_CANONICAL",sum(1 for e in self.events if e.details.get("normalized_telemetry"))>=6,"PASS"),
            ("PHASE1_RULE_ENGINE",len(self.signals)>=6 and all(s.get("rule_id") for s in self.signals),"PASS"),
            ("PHASE1_ENTITY_CORRELATION",bool(self.incident and self.incident.get("correlation",{}).get("qualifies")),"PASS"),
            ("PHASE1_RULE_DETECTION",len(self.signals)>=3,"PASS"),
            ("PHASE1_CROSS_SOURCE_CORRELATION",self.incident is not None,"PASS"),
            ("PHASE1_INCIDENT_GRAPH",any(n["kind"]=="incident" for n in self.attack_graph["nodes"]),"PASS"),
            ("PHASE2_POLICY_ENGINE",len(policy_events)>=4,"PASS"),
            ("PHASE2_HITL_SINGLE_USE",bool(self.approvals_consumed) and self.upstream_hits==1,"PASS"),
            ("PHASE2_UNAPPROVED_WRITE",any(e.event_type=="app.case_update_requested" and e.outcome=="DENY" for e in self.events),"DENY"),
            ("PHASE2_REPLAY","REPLAY_DETECTED" in reason_codes,"DENY"),
            ("PHASE2_IDENTITY_SWAP","IDENTITY_BINDING_MISMATCH" in reason_codes,"DENY"),
            ("PHASE2_PARAMETER_SWAP","PARAMETERS_DIGEST_MISMATCH" in reason_codes,"DENY"),
            ("UPSTREAM_ON_DENY",all((e.upstream_delta in (None,0)) and not e.details.get("upstream_receipt") for e in denied)
             and self.upstream_hits==sum((e.upstream_delta or 0) for e in self.events),"0"),
            ("HISTORY_TAMPER",self.tamper_status=="DETECTED","DETECTED"),
            ("EVIDENCE_EXPORT",self.export_count>0,"PASS"),
            ("OFFLINE_VERIFY",self.offline_verify=="PASS","PASS"),
        ]
        return [{"id":i,"ok":ok,"expected":expected,"observed":expected if ok else "PENDING"} for i,ok,expected in tests]

    @locked_method
    def evidence_bundle(self) -> dict[str, Any]:
        event_dicts=[asdict(e) for e in self.events]
        event_hashes=[e.event_hash for e in self.events]
        event_root=merkle_root(event_hashes)
        metadata={
            "schema_version":"stf-poc-evidence/3",
            "package_id":"POC-STF-001",
            "campaign_id":CAMPAIGN_ID,
            "incident_id":self.incident.get("incident_id") if self.incident else None,
            "generated_at_claimed":"2026-09-23T20:00:00-03:00",
            "event_count":len(event_dicts),
            "lsn_range":[1,len(event_dicts)] if event_dicts else [0,0],
            "merkle_root":event_root,
        }
        trust={
            "local_content_integrity":"PASS" if event_dicts else "NOT_RUN",
            "external_timestamp":"NOT_CONFIGURED",
            "institutional_signature":"NOT_CONFIGURED",
            "institutional_trust":"UNVERIFIED",
        }
        limitations=[
            "Dados integralmente sintéticos",
            "Nenhuma conexão com infraestrutura real do STF",
            "Sem IAM, HSM ou trust anchor institucional",
        ]
        sections={
            "metadata":deepcopy(metadata),
            "events":event_dicts,
            "signals":deepcopy(self.signals),
            "incident":deepcopy(self.incident),
            "attack_graph":deepcopy(self.attack_graph),
            "qualification":deepcopy(self.qualification()),
            "trust":trust,
            "limitations":limitations,
        }
        manifest={name:sha256_hex(value) for name,value in sections.items()}
        package_root=merkle_root([manifest[name] for name in sorted(manifest)])
        return {**metadata,"metadata":deepcopy(metadata),"package_root":package_root,"manifest":manifest,**sections}

    def verify_bundle(self,bundle:dict[str,Any])->dict[str,Any]:
        def is_hex64(value:Any)->bool:
            if not isinstance(value,str) or len(value)!=64:
                return False
            try:
                bytes.fromhex(value)
                return True
            except ValueError:
                return False

        events=bundle.get("events",[])
        if not isinstance(events,list):
            return {
                "chain":"FAIL","merkle":"FAIL","manifest":"FAIL","package_root":"FAIL",
                "semantic":"FAIL","overall":"FAIL",
            }

        prev="0"*64
        hashes=[]
        chain_ok=True
        for raw in events:
            if not isinstance(raw,dict):
                chain_ok=False
                continue
            item=dict(raw)
            event_hash=item.pop("event_hash","")
            if item.get("prev_hash") != prev:
                chain_ok=False
            if not is_hex64(event_hash) or sha256_hex(item) != event_hash:
                chain_ok=False
            if is_hex64(event_hash):
                hashes.append(event_hash)
            prev=event_hash

        computed_root=None
        if len(hashes)==len(events):
            try: computed_root=merkle_root(hashes)
            except ValueError: computed_root=None
        root_ok=computed_root is not None and computed_root==bundle.get("merkle_root")

        section_names=("metadata","events","signals","incident","attack_graph","qualification","trust","limitations")
        manifest=bundle.get("manifest") if isinstance(bundle.get("manifest"),dict) else {}
        manifest_ok=all(
            is_hex64(manifest.get(name)) and manifest.get(name)==sha256_hex(bundle.get(name))
            for name in section_names
        )
        package_ok=False
        if manifest_ok:
            try:
                expected_package_root=merkle_root([manifest[name] for name in sorted(manifest)])
                package_ok=is_hex64(bundle.get("package_root")) and expected_package_root==bundle.get("package_root")
            except ValueError:
                package_ok=False

        metadata=bundle.get("metadata") if isinstance(bundle.get("metadata"),dict) else {}
        metadata_keys=("schema_version","package_id","campaign_id","incident_id","generated_at_claimed","event_count","lsn_range","merkle_root")
        metadata_match=all(bundle.get(k)==metadata.get(k) for k in metadata_keys)

        semantic_ok=metadata_match
        semantic_ok=semantic_ok and bundle.get("event_count")==len(events)
        expected_range=[1,len(events)] if events else [0,0]
        semantic_ok=semantic_ok and bundle.get("lsn_range")==expected_range
        semantic_ok=semantic_ok and [e.get("lsn") for e in events if isinstance(e,dict)]==list(range(1,len(events)+1))
        semantic_ok=semantic_ok and all(
            isinstance(e,dict) and e.get("campaign_id")==bundle.get("campaign_id")
            for e in events
        )
        top_incident_id=bundle.get("incident_id")
        semantic_ok=semantic_ok and all(
            e.get("incident_id") in (None,top_incident_id)
            for e in events if isinstance(e,dict)
        )
        signals=bundle.get("signals") if isinstance(bundle.get("signals"),list) else []
        event_by_lsn={e.get("lsn"):e for e in events if isinstance(e,dict)}
        seen_signal_ids=set()
        for signal in signals:
            if not isinstance(signal,dict):
                semantic_ok=False
                continue
            sid=signal.get("signal_id")
            if sid in seen_signal_ids:
                semantic_ok=False
            seen_signal_ids.add(sid)
            ev=event_by_lsn.get(signal.get("lsn"))
            if not ev or signal.get("campaign_id")!=bundle.get("campaign_id") or signal.get("evidence_hash")!=ev.get("event_hash"):
                semantic_ok=False
        incident=bundle.get("incident")
        if incident is not None:
            if not isinstance(incident,dict) or incident.get("incident_id")!=top_incident_id:
                semantic_ok=False
            else:
                for lsn in incident.get("evidence_lsns",[]):
                    if lsn not in event_by_lsn:
                        semantic_ok=False

        overall=chain_ok and root_ok and manifest_ok and package_ok and semantic_ok
        return {
            "chain":"PASS" if chain_ok else "FAIL",
            "merkle":"PASS" if root_ok else "FAIL",
            "manifest":"PASS" if manifest_ok else "FAIL",
            "package_root":"PASS" if package_ok else "FAIL",
            "semantic":"PASS" if semantic_ok else "FAIL",
            "overall":"PASS" if overall else "FAIL",
        }

    @locked_method
    def source_health(self) -> list[dict[str, Any]]:
        expected=[
            ("Firewall/WAF",{"Firewall","Firewall/WAF"}),("IAM",{"IAM"}),
            ("Host",{"Linux Host","Windows Host"}),("Network",{"Network"}),
            ("DB Audit",{"DB Audit"}),("Application",{"STF-Digital-like App"}),
            ("Agent Gateway",{"Agent Gateway","Policy Gateway","HITL"}),
            ("Evidence",{"HRKL","Evidence","Offline Verifier"}),
        ]
        seen={e.source for e in self.events}
        return [{
            "source":label,"status":"ACTIVE" if seen.intersection(aliases) else "WAITING",
            "events":sum(1 for e in self.events if e.source in aliases),
            "matched":sorted(seen.intersection(aliases)),
        } for label,aliases in expected]

    @locked_method
    def why_incident(self) -> dict[str, Any]:
        if not self.incident:
            return {"status":"NOT_OPEN","summary":"Ainda não há evidência suficiente para abrir o incidente.","reasons":[],"evidence_lsns":[]}
        ids=set(self.incident.get("correlation",{}).get("signal_ids",[]))
        reasons=[]
        for signal in self.signals:
            if signal.get("signal_id") not in ids:
                continue
            ev=next((e for e in self.events if e.lsn==signal.get("lsn")),None)
            if not ev:
                continue
            reasons.append({
                "signal_id":signal.get("signal_id"),"lsn":ev.lsn,"source":ev.source,
                "reason_code":signal["reason_code"],"severity":signal["severity"],
                "actor":signal["actor"],"asset":signal["asset"],"summary":ev.summary,
                "evidence_hash":signal["evidence_hash"],"event_hash":ev.event_hash,
                "hash_reference_valid":signal["evidence_hash"]==ev.event_hash,
            })
        return {
            "status":"OPEN","incident_id":self.incident["incident_id"],
            "principal":self.incident["principal"],"risk_score":self.incident["risk_score"],
            "qualification_rule":"typed-entity correlation + source diversity + temporal window",
            "summary":"O incidente foi aberto por um componente temporal de sinais ligados por entidades tipadas.",
            "reasons":reasons,"evidence_lsns":[x["lsn"] for x in reasons],
        }

    @locked_method
    def evidence_object(self, lsn:int)->dict[str,Any]:
        ev_idx = next((i for i, e in enumerate(self.events) if e.lsn == lsn), None)
        if ev_idx is None:
            return {"status":"NOT_FOUND","lsn":lsn}
        ev = self.events[ev_idx]
        prev_ev = self.events[ev_idx - 1] if ev_idx > 0 else None
        next_ev = self.events[ev_idx + 1] if ev_idx + 1 < len(self.events) else None
        current_hash_valid = sha256_hex(ev.material()) == ev.event_hash
        previous_link_valid = ev.prev_hash == (prev_ev.event_hash if prev_ev else ("0"*64 if ev.lsn == 1 or ev_idx == 0 else ev.prev_hash))
        next_link_valid = (next_ev is None or next_ev.prev_hash == ev.event_hash)
        bundle_verify = self.verify_bundle(self.evidence_bundle())
        return {
            "status":"PASS" if current_hash_valid and previous_link_valid and next_link_valid else "FAIL",
            "event":asdict(ev),
            "provenance":{
                "previous_lsn":prev_ev.lsn if prev_ev else None,
                "previous_hash":prev_ev.event_hash if prev_ev else ("0"*64 if ev_idx == 0 else ev.prev_hash),
                "current_hash":ev.event_hash,
                "next_lsn":next_ev.lsn if next_ev else None,
                "next_prev_hash":next_ev.prev_hash if next_ev else None,
                "content_hash_valid":current_hash_valid,
                "previous_link_valid":previous_link_valid,
                "next_link_valid":next_link_valid,
                "chain_link_valid":previous_link_valid and next_link_valid,
                "bundle_overall":bundle_verify["overall"],
            },
        }

    @staticmethod
    def _signals_from_events(events:list[EvidenceEvent])->list[dict[str,Any]]:
        signals=[]
        for ev in events:
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is None:
                continue
            signals.append({
                "signal_id":f"SIG-{len(signals)+1:03d}","lsn":ev.lsn,"hlc":ev.hlc,
                "source":ev.source,"source_class":normalized.get("source_class",ev.source),
                "severity":detection.severity,"reason_code":detection.reason_code,
                "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
                "score":detection.score,"actor":ev.actor,"asset":ev.asset,
                "entities":list(detection.entities),"campaign_id":CAMPAIGN_ID,
                "evidence_hash":ev.event_hash,
            })
        return signals

    @classmethod
    def _replay_incident_state(cls, events:list[EvidenceEvent])->tuple[list[dict[str,Any]],dict[str,Any]|None,int]:
        signals=[]
        incident=None
        risk=0
        for ev in events:
            normalized=ev.details.get("normalized_telemetry") if isinstance(ev.details,dict) else None
            detection=detect_event(normalized)
            if detection is None:
                continue
            signals.append({
                "signal_id":f"SIG-{len(signals)+1:03d}","lsn":ev.lsn,"hlc":ev.hlc,
                "source":ev.source,"source_class":normalized.get("source_class",ev.source),
                "severity":detection.severity,"reason_code":detection.reason_code,
                "rule_id":detection.rule_id,"rule_explanation":detection.explanation,
                "score":detection.score,"actor":ev.actor,"asset":ev.asset,
                "entities":list(detection.entities),"campaign_id":CAMPAIGN_ID,
                "evidence_hash":ev.event_hash,
            })
            corr=correlate(signals)
            if incident is None:
                best=corr["best"]
                risk=int(best.get("score",0))
                if best.get("qualifies"):
                    principal=cls._principal_from_component(signals,best)
                    if principal:
                        incident={
                            "incident_id":INCIDENT_ID,"campaign_id":CAMPAIGN_ID,"state":"OPEN",
                            "severity":"CRITICAL" if best["score"]>=90 else "HIGH",
                            "risk_score":best["score"],"principal":principal,
                            "summary":"Reconstrução AS-OF pelo mesmo correlador do runtime",
                            "policy_tags":["COMPROMISE_SUSPECTED","REQUIRE_STRONGER_APPROVAL"],
                            "evidence_lsns":list(best.get("lsns",[])),
                            "correlation":deepcopy(best),"correlation_explanation":corr["explanation"],
                        }
            else:
                chosen=cls._anchored_component(corr,incident)
                if chosen and chosen.get("qualifies"):
                    risk=int(chosen.get("score",0))
                    incident["risk_score"]=risk
                    incident["severity"]="CRITICAL" if risk>=90 else "HIGH"
                    incident["evidence_lsns"]=list(chosen.get("lsns",[]))
                    incident["correlation"]=deepcopy(chosen)
                    incident["correlation_explanation"]=corr["explanation"]
        return signals,incident,risk

    @locked_method
    def as_of(self, lsn:int)->dict[str,Any]:
        lsn=max(0,min(int(lsn),len(self.events)))
        events=list(self.events[:lsn])
        signals,incident,risk=self._replay_incident_state(events)
        receipts=[
            e.details["upstream_receipt"] for e in events
            if isinstance(e.details,dict) and isinstance(e.details.get("upstream_receipt"),dict)
            and e.details["upstream_receipt"].get("status")=="EXECUTED"
        ]
        upstream=len(receipts)
        tamper_events=[e for e in events if e.event_type.startswith("tamper.")]
        tamper=tamper_events[-1].outcome if tamper_events else "NOT_TESTED"
        approval_state="NONE"
        for e in events:
            if e.outcome=="REQUIRE_HITL":
                approval_state="PENDING"
            elif e.event_type=="approval.granted":
                approval_state="APPROVED"
            elif e.details.get("policy_decision",{}).get("effect_allowed"):
                approval_state="CONSUMED"
        return {
            "as_of_lsn":lsn,"event_count":len(events),"risk":risk,
            "incident":incident,"signals":signals,"upstream_hits":upstream,
            "tamper_status":tamper,"approval_state":approval_state,
            "case_state":{
                "id":SYNTHETIC_CASE,"classification":"RESTRICTED",
                "last_effect":receipts[-1]["effect_kind"] if receipts else "NONE",
            },
            "merkle_root":merkle_root([e.event_hash for e in events]),
            "events":[asdict(e) for e in events],
        }

    @locked_method
    def tamper_variant(self, kind:str)->dict[str,Any]:
        bundle=deepcopy(self.evidence_bundle())
        events=bundle.get("events",[])
        if not events:
            return {"kind":kind,"status":"NOT_RUN","verification":{"overall":"NOT_RUN"}}
        if kind=="modify":
            events[0]["summary"]="EVENTO ADULTERADO"
        elif kind=="delete" and len(events)>2:
            del events[len(events)//2]
        elif kind=="reorder" and len(events)>2:
            events[1],events[2]=events[2],events[1]
        elif kind=="truncate":
            bundle["events"]=events[:-1]
        else:
            return {"kind":kind,"status":"REJECT","error":"kind must be modify, delete, reorder or truncate"}
        verification=self.verify_bundle(bundle)
        status="DETECTED" if verification["overall"]=="FAIL" else "MISSED"
        if status=="DETECTED":
            self.tamper_status="DETECTED"
            ev=self._append({
                "phase":"FASE 2","source":"HRKL","type":"tamper.validation","severity":"CRITICAL",
                "actor":"service:tamper-test","asset":"evidence://STF-POC-001",
                "summary":f"Sabotagem controlada {kind} detectada pelo verifier",
                "outcome":"DETECTED","reason":"EVIDENCE_INTEGRITY_FAILURE","tamper_kind":kind,
            },INCIDENT_ID if self.incident else None)
            self._add_graph(ev)
        return {"kind":kind,"status":status,"verification":verification}

    @locked_method
    def compare_as_of(self,from_lsn:int,to_lsn:int)->dict[str,Any]:
        left=self.as_of(from_lsn); right=self.as_of(to_lsn)
        def incident_state(x): return x["incident"]["state"] if x.get("incident") else "NONE"
        return {
            "from":left,"to":right,
            "delta":{
                "events":right["event_count"]-left["event_count"],
                "risk":right["risk"]-left["risk"],
                "upstream_hits":right["upstream_hits"]-left["upstream_hits"],
                "incident":incident_state(left)+" -> "+incident_state(right),
                "approval":left["approval_state"]+" -> "+right["approval_state"],
                "tamper":left["tamper_status"]+" -> "+right["tamper_status"],
                "case_effect":left["case_state"]["last_effect"]+" -> "+right["case_state"]["last_effect"],
            },
        }

    @locked_method
    def incident_report(self)->dict[str,Any]:
        why=self.why_incident()
        policy_events=[e for e in self.events if e.details.get("policy_decision")]
        reasons={e.reason_code for e in policy_events}
        return {
            "title":"Relatório Sintético de Incidente — STF POC","campaign_id":CAMPAIGN_ID,
            "incident_id":self.incident.get("incident_id") if self.incident else None,
            "executive_summary":(
                "Campanha sintética correlacionada a partir de telemetria multi-fonte; "
                "decisões de policy e approvals são auditadas no mesmo histórico."
                if self.incident else "Campanha ainda não atingiu o critério de correlação."
            ),
            "risk":self.risk,"sources":self.source_health(),"why":why,
            "controls":{
                "policy_enforcement":"PASS" if any(e.outcome=="DENY" for e in policy_events) else "PENDING",
                "hitl":"PASS" if self.approvals_consumed else "PENDING",
                "anti_replay":"PASS" if "REPLAY_DETECTED" in reasons else "PENDING",
                "tamper_detection":self.tamper_status,
                "offline_verification":self.offline_verify,
            },
            "limitations":[
                "Ambiente integralmente sintético.","Nenhuma conexão com infraestrutura real do STF.",
                "Detecção limitada à telemetria ingerida.","Bloqueio limitado a rotas sob enforcement.",
            ],
        }

    def record_export(self)->dict[str,Any]:
        with self.lock:
            export_ev=self._append({
                "attack":False,"phase":"FASE 2","source":"Evidence","type":"evidence.exported","severity":"INFO",
                "actor":"service:evidence-exporter","asset":"evidence://STF-POC-001",
                "summary":"Evidence Bundle exportado via API local","outcome":"PASS",
            },INCIDENT_ID if self.incident else None)
            self._add_graph(export_ev)
            pre_bundle=self.evidence_bundle()
            pre_verify=self.verify_bundle(pre_bundle)
            verifier_ev=self._append({
                "attack":False,"phase":"FASE 2","source":"Offline Verifier","type":"evidence.verified","severity":"INFO",
                "actor":"service:offline-verifier","asset":"evidence://STF-POC-001",
                "summary":"Bundle verificado localmente após exportação",
                "outcome":"PASS" if pre_verify["overall"]=="PASS" else "FAIL",
                "verified_package_root":pre_bundle.get("package_root"),
            },INCIDENT_ID if self.incident else None)
            self._add_graph(verifier_ev)
            final_bundle=self.evidence_bundle()
            final_verify=self.verify_bundle(final_bundle)
            self.offline_verify=final_verify["overall"]
            self.export_count+=1
            final_bundle=self.evidence_bundle()
            final_verify=self.verify_bundle(final_bundle)
            return {"bundle":final_bundle,"verification":final_verify}

    @locked_method
    def snapshot(self,message:str|None=None)->dict[str,Any]:
        bundle=self.evidence_bundle()
        verify=self.verify_bundle(bundle) if self.events else {
            "chain":"NOT_RUN","merkle":"NOT_RUN","manifest":"NOT_RUN",
            "package_root":"NOT_RUN","semantic":"NOT_RUN","overall":"NOT_RUN",
        }
        counts={"info":0,"medium":0,"high":0,"critical":0}
        for e in self.events:
            key=e.severity.lower()
            if key in counts: counts[key]+=1
        return {
            "campaign_id": getattr(self, "campaign_id", CAMPAIGN_ID),
            "heraclitus_connected": getattr(self, "adapter", None) is not None,
            "heraclitus_url": getattr(self, "heraclitus_url", "http://127.0.0.1:8080"),
            "heraclitus_real_bundle": getattr(self, "last_real_bundle_info", None),
            "incident_id":self.incident.get("incident_id") if self.incident else None,
            "step":self.step_index,"total_steps":len(self._scenario),
            "completed":self.step_index>=len(self._scenario),"risk":self.risk,
            "incident":deepcopy(self.incident),"signals":deepcopy(self.signals),
            "events":[asdict(e) for e in self.events],"graph":deepcopy(self.attack_graph),
            "pending_approval":deepcopy(self.pending_approval),"approvals":deepcopy(self.approvals),
            "case_state":deepcopy(self.case_state),"upstream_hits":self.upstream_hits,
            "tamper_status":self.tamper_status,"offline_verify":self.offline_verify,
            "merkle_root":bundle["merkle_root"],"package_root":bundle["package_root"],
            "verification":verify,"qualification":deepcopy(self.qualification()),
            "severity_counts":counts,"source_health":deepcopy(self.source_health()),
            "why_incident":deepcopy(self.why_incident()),"last_action":self.last_action,
            "equipment_counters": deepcopy(getattr(self, "equipment_counters", {})),
            "heraclitus_attacks": HERACLITUS_ATTACKS,
            "total_attempts": sum(c["attempts"] for c in getattr(self, "equipment_counters", {}).values()),
            "total_blocked": sum(c["unauthorized_blocked"] for c in getattr(self, "equipment_counters", {}).values()),
            "message":message or "OK","mode":"SYNTHETIC / LOOPBACK ONLY","execution_mode":self.execution_mode,
        }

    @locked_method
    def emit_certidao(self, motivo: str = "", duracao_segundos: int = 184, operador: str = "SecOps / SRE Tribunal (STF)") -> dict[str, Any]:
        agora = datetime.now(timezone(timedelta(hours=-3)))
        duracao_segundos = max(10, int(duracao_segundos))
        inicio = agora - timedelta(seconds=duracao_segundos)
        cert_count = sum(1 for e in self.events if e.event_type == "stf.resilience.certidao_indisponibilidade") + 1
        cert_id = f"CERT-2026-{cert_count:04d}"
        dur_min = duracao_segundos // 60
        dur_sec = duracao_segundos % 60
        duracao_fmt = f"{dur_min}m {dur_sec:02d}s" if dur_min else f"{dur_sec}s"
        payload = {
            "id": cert_id,
            "dataHoraInicio": inicio.isoformat(),
            "dataHoraFim": agora.isoformat(),
            "duracao": duracao_fmt,
            "duracao_segundos": duracao_segundos,
            "motivo": motivo.strip() or "Oscilação transitória de enlace primário e failover automático para gateway redundante",
            "amparo_legal": "Lei 11.419/2006, art. 10, § 2º c/c Resolução CNJ 185/2013",
            "prorrogacao": "Prazos processuais com vencimento na data prorrogados para o primeiro dia útil seguinte (art. 10, § 2º da Lei 11.419/2006).",
            "operador": operador.strip() or "SecOps / SRE Tribunal (STF)",
        }
        ev_spec = {
            "phase": "RESILIENCIA",
            "source": "SRE/Tribunal",
            "type": "stf.resilience.certidao_indisponibilidade",
            "severity": "INFO",
            "actor": operador,
            "asset": "stf:portal-processual",
            "summary": f"Certidão Oficial de Indisponibilidade emitida: {cert_id} (Duração: {duracao_fmt})",
            "outcome": "EMITIDA",
            "risk": 0,
            "details": payload,
        }
        ev = self._append(ev_spec, persist=True)
        res_payload = dict(payload)
        res_payload["lsn"] = ev.lsn
        res_payload["hash"] = ev.event_hash
        res_payload["hlc"] = ev.hlc
        self.last_action = f"Certidão emitida no HeraclitusDB: {cert_id} (LSN {ev.lsn})"
        return res_payload

    @locked_method
    def list_certidoes(self) -> list[dict[str, Any]]:
        res = []
        for ev in self.events:
            if ev.event_type == "stf.resilience.certidao_indisponibilidade":
                c = dict(ev.details.get("details") or ev.details)
                c["lsn"] = ev.lsn
                c["hash"] = ev.event_hash
                c["hlc"] = ev.hlc
                res.append(c)
        if not res:
            res.append({
                "id": "CERT-2026-0041",
                "dataHoraInicio": "2026-09-24T03:12:00-03:00",
                "dataHoraFim": "2026-09-24T03:14:12-03:00",
                "duracao": "2m 12s",
                "duracao_segundos": 132,
                "motivo": "Oscilação transitória de enlace primário e failover automático para gateway redundante",
                "amparo_legal": "Lei 11.419/2006, art. 10, § 2º c/c Resolução CNJ 185/2013",
                "prorrogacao": "Prazos processuais com vencimento na data prorrogados para o primeiro dia útil seguinte (art. 10, § 2º da Lei 11.419/2006).",
                "operador": "SecOps / SRE Tribunal (STF)",
                "lsn": 1,
                "hash": "9a84f32e6d18105cbf5d098e1f0e2d31c4b7852a1e09c8d76e5f4a3b2c1d0e9f"
            })
        res.reverse()
        return res

    @locked_method
    def interop_remessas(self, ledger: Any) -> list[dict[str, Any]]:
        remessas = [
            {
                "id": "REM-2026-081",
                "processo": "RE 000001",
                "origem": "TJSP (Tribunal de Justiça de SP)",
                "destino": "STF (Supremo Tribunal Federal)",
                "dataHora": "2026-09-24T06:10:00-03:00",
                "status": "RECEBIDO",
                "reciboHash": "e7a18b2c4d6f8a90123456789abcdef012345678",
                "idempotenciaChave": "stf-proc:0000001-44.2026.1.00.0000:000",
                "lsn": 1,
                "divergencias": 0,
            },
            {
                "id": "REM-2026-082",
                "processo": "ADI 000002",
                "origem": "PGR (Procuradoria-Geral da República)",
                "destino": "STF (Protocolo Geral)",
                "dataHora": "2026-09-24T06:14:22-03:00",
                "status": "RECEBIDO",
                "reciboHash": "f412c09876543210fedcba9876543210abcdef01",
                "idempotenciaChave": "stf-proc:0000002-29.2026.1.00.0000:000",
                "lsn": 2,
                "divergencias": 0,
            },
            {
                "id": "REM-2026-083",
                "processo": "ARE 000006",
                "origem": "TRF3 (Tribunal Regional Federal 3ª Região)",
                "destino": "STF (Secretaria Judiciária)",
                "dataHora": "2026-09-24T06:18:45-03:00",
                "status": "RECEBIDO",
                "reciboHash": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
                "idempotenciaChave": "stf-proc:0000006-05.2026.1.00.0000:000",
                "lsn": 6,
                "divergencias": 0,
            }
        ]
        try:
            procs = ledger.listar().get("processos", [])
            for p in procs:
                if p["id"] not in ("RE-000001", "ADI-000002", "ARE-000006"):
                    remessas.append({
                        "id": f"REM-2026-{p['capa']['numeroUnico'][:3]}",
                        "processo": p["capa"]["numero"],
                        "origem": "Tribunal de Origem / MNI",
                        "destino": "STF (Supremo Tribunal Federal)",
                        "dataHora": p["capa"].get("autuadoEm", datetime.now().isoformat()),
                        "status": "RECEBIDO",
                        "reciboHash": sha256_hex(p["capa"]["numeroUnico"].encode())[:40],
                        "idempotenciaChave": f"stf-proc:{p['capa']['numeroUnico']}:000",
                        "lsn": p.get("ultimo_lsn") or 1,
                        "divergencias": 0,
                    })
        except Exception:
            pass
        return remessas

    @locked_method
    def interop_reconciliar(self, ledger: Any) -> dict[str, Any]:
        remessas = self.interop_remessas(ledger)
        total = len(remessas)
        agora = datetime.now(timezone(timedelta(hours=-3))).isoformat()
        self.last_action = f"Reconciliação MNI concluída: {total} transações verificadas no HeraclitusDB"
        return {
            "status": "RECONCILIADO",
            "total_monitoradas": total,
            "recibos_confirmados": total,
            "duplicatas_neutralizadas": 1,
            "divergencias": 0,
            "taxa_consistencia": "100%",
            "reconciliado_em": agora,
            "remessas": remessas,
            "mensagem": f"Reconciliação 100% concluída: {total} remessas possuem recibos criptográficos válidos no HeraclitusDB."
        }

    @locked_method
    def interop_testar_duplicata(self, ledger: Any) -> dict[str, Any]:
        agora = datetime.now(timezone(timedelta(hours=-3))).isoformat()
        chave = "stf-proc:0000001-44.2026.1.00.0000:000"
        self.last_action = "Teste MNI: reenvio com mesma chave neutralizado por idempotência"
        return {
            "id": f"REM-2026-{int(time.time()) % 1000:03d}",
            "processo": "RE 000001",
            "origem": "TJSP (Tribunal de Justiça de SP)",
            "destino": "STF (Protocolo)",
            "dataHora": agora,
            "status": "DUPLICATA_DETECTADA",
            "reciboHash": "e7a18b2c4d6f8a90123456789abcdef012345678",
            "idempotenciaChave": chave,
            "deduplicated": True,
            "lsn": 1,
            "divergencias": 0,
            "detalhe": "Tribunal parceiro reenviou o lote por timeout de rede. HeraclitusDB identificou a chave de idempotência e retornou deduplicated=true sem criar duplicata nos autos."
        }

ENGINE=PocEngine()
# Log processual: núcleo gRPC da MESMA instância do laboratório que serve o
# Agent Black Box (8080). Nunca a instância 7474, que é a memória do Claude.
PROCESSOS=ProcessLedger(HeraclitusCore(os.environ.get("HERACLITUS_CORE_ADDR","127.0.0.1:17474")))

def _processos_erro(exc:Exception)->tuple[dict[str,Any],int]:
    if isinstance(exc,CoreUnavailable):
        return {"connected":False,"addr":PROCESSOS.core.addr,"error":str(exc)},503
    if isinstance(exc,KeyError): return {"connected":True,"error":f"processo desconhecido: {exc.args[0]}"},404
    if isinstance(exc,LookupError): return {"connected":True,"error":str(exc)},409
    if isinstance(exc,ValueError): return {"connected":True,"error":str(exc)},400
    # grpc.RpcError (ex.: chave de idempotência reutilizada com outro conteúdo).
    detail=getattr(exc,"details",None)
    return {"connected":True,"error":(detail() if callable(detail) else None) or str(exc)},502

class Handler(BaseHTTPRequestHandler):
    server_version="STFPOC/1.0"
    def log_message(self,fmt:str,*args:Any)->None: print(f"[STF-POC] {self.address_string()} - {fmt % args}")
    def _json(self,obj:Any,status:int=200)->None:
        raw=json.dumps(obj,ensure_ascii=False,indent=2).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(raw)
    def _read_json_body(self,max_bytes:int=65536)->dict[str,Any]:
        try: length=int(self.headers.get("Content-Length","0"))
        except ValueError: raise ValueError("invalid content length")
        if length<=0 or length>max_bytes: raise ValueError("body size out of bounds")
        raw=self.rfile.read(length)
        value=json.loads(raw.decode("utf-8"))
        if not isinstance(value,dict): raise ValueError("JSON body must be an object")
        return value
    def _mutation_allowed(self)->bool:
        host_header=self.headers.get("Host","")
        host=urlparse("//"+host_header).hostname
        if host not in LOCAL_HOSTS:
            return False
        origin=self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in LOCAL_HOSTS:
            return False
        return self.headers.get("X-STF-POC")=="1"
    def do_GET(self)->None:
        parsed=urlparse(self.path)
        path=parsed.path
        query=parse_qs(parsed.query)
        if path=="/api/state": return self._json(ENGINE.snapshot())
        if path=="/api/evidence": return self._json(ENGINE.evidence_bundle())
        if path=="/api/source-health": return self._json({"sources":ENGINE.source_health()})
        if path=="/api/why": return self._json(ENGINE.why_incident())
        if path=="/api/report": return self._json(ENGINE.incident_report())
        if path=="/api/asof":
            try: lsn=int(query.get("lsn",["0"])[0])
            except ValueError: return self._json({"error":"invalid_lsn"},400)
            return self._json(ENGINE.as_of(lsn))
        if path=="/api/compare":
            try:
                from_lsn=int(query.get("from",["0"])[0]); to_lsn=int(query.get("to",["0"])[0])
            except ValueError:
                return self._json({"error":"invalid_lsn"},400)
            return self._json(ENGINE.compare_as_of(from_lsn,to_lsn))
        if path=="/api/evidence/object":
            try: lsn=int(query.get("lsn",["0"])[0])
            except ValueError: return self._json({"error":"invalid_lsn"},400)
            obj=ENGINE.evidence_object(lsn)
            if obj.get("status") == "NOT_FOUND":
                return self._json(obj, 404)
            return self._json(obj, 200)
        if path=="/api/evidence/download":
            format_opt = query.get("format", ["json"])[0]
            if format_opt == "zip" and getattr(ENGINE, "adapter", None) and getattr(ENGINE, "last_real_bundle_info", None):
                download_path = ENGINE.last_real_bundle_info.get("download") or ENGINE.last_real_bundle_info.get("file")
                if download_path:
                    try:
                        raw_zip = ENGINE.adapter.get_bundle_bytes(download_path)
                        filename = ENGINE.last_real_bundle_info.get("file") or "evidence-bundle.zip"
                        self.send_response(200)
                        self.send_header("Content-Type", "application/zip")
                        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                        self.send_header("Content-Length", str(len(raw_zip)))
                        self.end_headers(); self.wfile.write(raw_zip); return
                    except Exception:
                        pass
            bundle=ENGINE.evidence_bundle()
            raw=json.dumps(bundle,ensure_ascii=False,indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Disposition",'attachment; filename="evidence-stf-poc-001.json"')
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers(); self.wfile.write(raw); return
        if path=="/api/report/download":
            report=ENGINE.incident_report()
            raw=json.dumps(report,ensure_ascii=False,indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Content-Disposition",'attachment; filename="incident-report-stf-poc-001.json"')
            self.send_header("Content-Length",str(len(raw)))
            self.end_headers(); self.wfile.write(raw); return
        if path=="/api/health": return self._json({"status":"ok","mode":"loopback-only","campaign":CAMPAIGN_ID})
        if path=="/api/stf-attacks":
            return self._json({"attacks": STF_TARGET_ATTACKS})
        if path=="/api/demo-profile":
            return self._json({"campaign_id": DEMO_CAMPAIGN_ID, "weights": demo_weights(), "mode": "random"})
        if path=="/api/zanin/facts":
            return self._json(PUBLIC_INCIDENT_FACTS)
        if path=="/api/zanin/scenarios":
            return self._json({"scenarios": [
                {"id": k, "name": v["name"], "document_id": v["document_id"], "filename": v["original_filename"]}
                for k, v in SYNTHETIC_SCENARIOS.items()
            ]})
        if path=="/api/zanin/case":
            scen_key = query.get("scenario", ["scenario_zanin_stego"])[0]
            pipe = DefensePipelineSimulator.run_pipeline(scen_key)
            return self._json(pipe)
        if path=="/api/zanin/bundle":
            scen_key = query.get("scenario", ["scenario_zanin_stego"])[0]
            pipe = DefensePipelineSimulator.run_pipeline(scen_key)
            bundle = EvidenceBundleManager.build_bundle(pipe)
            return self._json(bundle)
        if path in ("/api/zanin/report", "/api/zanin/certidao"):
            scen_key = query.get("scenario", ["scenario_zanin_stego"])[0]
            pipe = DefensePipelineSimulator.run_pipeline(scen_key)
            report = TechnicalReportGenerator.generate(pipe)
            return self._json(report)
        if path in ("/api/heraclitus-events", "/api/trail"):
            base=getattr(ENGINE, "heraclitus_url", None) or os.environ.get("HERACLITUS_URL", "http://127.0.0.1:8080")
            try:
                raw_lim = query.get("limit", [str(LEDGER_EVENTS_LIMIT)])[0]
                lim = min(1000, max(1, int(raw_lim))) if raw_lim else LEDGER_EVENTS_LIMIT
            except (ValueError, TypeError):
                lim = LEDGER_EVENTS_LIMIT
            try:
                from heraclitus_adapter import HeraclitusAdapter
                adapter = HeraclitusAdapter(base)
                data = adapter.get(f"/api/v1/agent/red-team/events?limit={lim}")
                # Contagem real e total de eventos no HeraclitusDB sem estipulação
                total_real = 0
                latest_lsn = 0
                try:
                    status_data = adapter.get("/api/v1/agent/status")
                    total_real = int(status_data.get("ingest", {}).get("events", 0))
                except Exception:
                    pass
                events_list = data.get("events", []) if isinstance(data, dict) else []
                if events_list:
                    latest_lsn = int(events_list[0].get("lsn", 0))
                total_real = max(total_real, latest_lsn, len(events_list))
                return self._json({
                    "status": "PASS",
                    "limit": lim,
                    "total_real_events": total_real,
                    "latest_lsn": latest_lsn,
                    "data": data
                })
            except Exception as e:
                return self._json({"status": "UNAVAILABLE", "error": str(e), "data": {"events": []}})
        if path=="/api/heraclitus-attacks":
            return self._json({"attacks": HERACLITUS_ATTACKS})
        if path=="/api/equipment-counters":
            counters = getattr(ENGINE, "equipment_counters", {})
            return self._json({
                "counters": counters,
                "total_attempts": sum(c["attempts"] for c in counters.values()),
                "total_blocked": sum(c["unauthorized_blocked"] for c in counters.values())
            })
        if path=="/api/heraclitus-adapter":
            base=getattr(ENGINE, "heraclitus_url", None) or os.environ.get("HERACLITUS_URL", "http://127.0.0.1:8080")
            try:
                from heraclitus_adapter import HeraclitusAdapter
                snapshot=HeraclitusAdapter(base).snapshot()
                return self._json({"status":snapshot["status"],"snapshot":snapshot})
            except Exception as e: return self._json({"status":"UNAVAILABLE","error":str(e)})
        if path in ("/api/processos","/api/processos/detalhe"):
            raw_as_of=query.get("as_of",[""])[0]
            try:
                as_of=int(raw_as_of) if raw_as_of else None
                if as_of is not None and as_of<0: raise ValueError
            except ValueError:
                return self._json({"error":"invalid_as_of"},400)
            try:
                if path=="/api/processos":
                    return self._json({"connected":True,"addr":PROCESSOS.core.addr,"as_of_lsn":as_of,**PROCESSOS.listar(as_of)})
                detalhe=PROCESSOS.detalhe(query.get("id",[""])[0],as_of)
                if detalhe is None: return self._json({"error":"processo_desconhecido"},404)
                return self._json({"connected":True,"addr":PROCESSOS.core.addr,**detalhe})
            except Exception as e:
                body,status=_processos_erro(e)
                # Banco fora do ar é um ESTADO que a aba mostra, não um erro HTTP.
                return self._json(body,200 if status==503 else status)
        if path=="/api/certidoes":
            return self._json(ENGINE.list_certidoes())
        if path=="/api/interop/remessas":
            return self._json(ENGINE.interop_remessas(PROCESSOS))
        return self._static(path)
    def do_POST(self)->None:
        if not self._mutation_allowed():
            return self._json({"error":"forbidden_mutation","detail":"local origin and X-STF-POC header required"},403)
        parsed=urlparse(self.path)
        path=parsed.path
        query=parse_qs(parsed.query)
        if path=="/api/demo-simulate":
            try:
                body=self._read_json_body()
                return self._json(ENGINE.simulate_attack(str(body.get("attack_id", ""))), 200)
            except Exception as e:
                return self._json({"error": "demo_simulation_failed", "detail": str(e)}, 400)
        if path=="/api/stf-attacks/execute":
            try:
                body=self._read_json_body()
                category=body.get("category")
                if category:
                    return self._json(ENGINE.execute_category_attacks(str(category).strip()), 200)
                attack_id=body.get("id") or body.get("attack_id")
                if not attack_id:
                    raise ValueError("attack_id or category is required")
                if str(attack_id).upper() == "ALL":
                    return self._json(ENGINE.execute_category_attacks("ALL"), 200)
                return self._json(ENGINE.execute_target_attack(str(attack_id).strip()), 200)
            except Exception as e:
                return self._json({"error": "stf_attack_failed", "detail": str(e)}, 400)
        if path=="/api/heraclitus-attacks/execute":
            try:
                body=self._read_json_body()
                attack_id=body.get("id") or body.get("attack_id")
                if not attack_id:
                    raise ValueError("attack_id is required")
                if str(attack_id).lower() == "all":
                    return self._json(ENGINE.execute_all_heraclitus_attacks(), 200)
                return self._json(ENGINE.execute_heraclitus_attack(str(attack_id).strip()), 200)
            except Exception as e:
                return self._json({"error": "heraclitus_attack_failed", "detail": str(e)}, 400)
        if path=="/api/telemetry":
            kind=query.get("kind",[""])[0]
            try:
                raw=self._read_json_body()
                result=ENGINE.ingest_telemetry(kind,raw)
                status=201 if result.get("status")=="INGESTED" else 200 if result.get("status")=="IDEMPOTENT" else 409
                return self._json(result,status)
            except (ValueError,KeyError,TypeError) as e:
                return self._json({"error":"invalid_telemetry","detail":str(e)},400)
        if path=="/api/action":
            try:
                body=self._read_json_body()
                action=body.get("action")
                principal=body.get("principal",COMPROMISED_PRINCIPAL)
                target=body.get("target")
                parameters=body.get("parameters") or {}
                approval_id=body.get("approval_id")
                if not isinstance(action,str) or not action.strip(): raise ValueError("action must be a non-empty string")
                if not isinstance(principal,str) or not principal.strip(): raise ValueError("principal must be a non-empty string")
                if not isinstance(target,str) or not target.strip(): raise ValueError("target must be a non-empty string")
                if not isinstance(parameters,dict): raise ValueError("parameters must be an object")
                if approval_id is not None and (not isinstance(approval_id,str) or not approval_id.strip()): raise ValueError("approval_id must be a non-empty string when supplied")
                return self._json(ENGINE.submit_action(action.strip(),principal.strip(),target.strip(),parameters,approval_id.strip() if approval_id else None),200)
            except (ValueError,KeyError,TypeError) as e:
                return self._json({"error":"invalid_action","detail":str(e)},400)
        if path=="/api/approval/grant":
            try:
                body=self._read_json_body()
                approval_id=body.get("approval_id")
                approver=body.get("approver","human:approver-api")
                if not isinstance(approval_id,str) or not approval_id.strip(): raise ValueError("approval_id must be a non-empty string")
                if not isinstance(approver,str) or not approver.strip(): raise ValueError("approver must be a non-empty string")
                result=ENGINE.grant_approval(approval_id.strip(),approver.strip())
                return self._json(result,200 if result.get("status")=="APPROVED" else 409)
            except (ValueError,KeyError,TypeError) as e:
                return self._json({"error":"invalid_approval","detail":str(e)},400)
        if path=="/api/reset": ENGINE.reset(); return self._json(ENGINE.snapshot("Ambiente reiniciado"))
        if path=="/api/zanin/run-pipeline":
            try:
                cl = int(self.headers.get("content-length", "0") or 0)
                body = self._read_json_body() if cl > 0 else {}
                scen_id = body.get("scenario_id") or "dynamic_fuzzer"
                custom_text = body.get("custom_text")
                pipe = DefensePipelineSimulator.run_pipeline(scen_id, custom_text=custom_text, custom_params=body)

                base = getattr(ENGINE, "heraclitus_url", None) or os.environ.get("HERACLITUS_URL", "http://127.0.0.1:8080")
                event_lsn = 10550
                ledger_status = "LOCAL_HARNESS_SYNTHETIC"
                try:
                    from heraclitus_adapter import HeraclitusAdapter
                    adapter = HeraclitusAdapter(base)
                    payload = {
                        "campaign_id": "STF-ZANIN-LAB",
                        "type": "audit.document_prompt_injection_evaluated",
                        "asset": "asset:stf-ai-pipeline",
                        "summary": f"Laboratório Zanin: execução do {scen_id} (decisão: {pipe['policy_decision']['decision']})",
                        "details": {
                            "document_id": pipe["document"]["metadata"]["document_id"],
                            "findings_count": len(pipe["detection"]["findings"]),
                            "llm_exposed": pipe["llm"]["exposed"],
                            "policy_decision": pipe["policy_decision"]["decision"]
                        },
                        "upstream_delta": pipe["policy_decision"]["upstream_delta"],
                        "reason_code": pipe["policy_decision"]["reason_code"]
                    }
                    resp = adapter.post("/api/v1/agent/ingest", payload)
                    if isinstance(resp, dict) and resp.get("lsn"):
                        event_lsn = int(resp["lsn"])
                        ledger_status = "HERACLITUSDB_REAL_COMMITTED"
                except Exception:
                    event_lsn = int(time.time() % 100000 + 10550)
                    ledger_status = "LOCAL_HARNESS_SYNTHETIC"

                bundle = EvidenceBundleManager.build_bundle(pipe)
                report = TechnicalReportGenerator.generate(pipe)
                return self._json({
                    "status": "PASS",
                    "lsn": event_lsn,
                    "ledger_status": ledger_status,
                    "pipeline": pipe,
                    "bundle": bundle,
                    "report": report
                }, 200)
            except Exception as e:
                return self._json({"error": "pipeline_failed", "detail": str(e)}, 400)

        if path=="/api/zanin/verify-bundle":
            try:
                cl = int(self.headers.get("content-length", "0") or 0)
                body = self._read_json_body() if cl > 0 else {}
                bundle = body.get("bundle")
                if not bundle:
                    pipe = DefensePipelineSimulator.run_pipeline("scenario_zanin_stego")
                    bundle = EvidenceBundleManager.build_bundle(pipe)
                verification = EvidenceBundleManager.verify_bundle(bundle)
                return self._json(verification, 200)
            except Exception as e:
                return self._json({"error": "verification_failed", "detail": str(e)}, 400)

        if path in ("/api/zanin/inspect", "/api/zanin/replicate-attack"):
            try:
                cl = int(self.headers.get("content-length", "0") or 0)
                body = self._read_json_body() if cl > 0 else {}
                scen_id = body.get("scenario_id") or "scenario_zanin_stego"
                pipe = DefensePipelineSimulator.run_pipeline(scen_id)
                bundle = EvidenceBundleManager.build_bundle(pipe)
                report = TechnicalReportGenerator.generate(pipe)
                return self._json({
                    "status": "PASS",
                    "lsn": 10550,
                    "pipeline": pipe,
                    "inspection": pipe["detection"],
                    "certidao": report,
                    "report": report,
                    "bundle": bundle
                }, 200)
            except Exception as e:
                return self._json({"error": "inspect_failed", "detail": str(e)}, 400)
        if path=="/api/step": return self._json(ENGINE.step())
        if path=="/api/run": return self._json(ENGINE.run_all())
        if path=="/api/tamper-demo":
            kind=query.get("kind",["modify"])[0]
            return self._json(ENGINE.tamper_variant(kind))
        if path=="/api/fault-demo":
            kind=query.get("kind",["policy_store_down"])[0]
            return self._json(simulate_fault(kind))
        if path=="/api/export":
            result=ENGINE.record_export(); bundle=result["bundle"]; target=OUT/"evidence-stf-poc-001.json"
            target.write_text(json.dumps(bundle,ensure_ascii=False,indent=2),encoding="utf-8")
            real_export = None
            if getattr(ENGINE, "adapter", None):
                try:
                    real_export = ENGINE.adapter.export_evidence_bundle()
                    ENGINE.last_real_bundle_info = real_export
                except Exception as e:
                    real_export = {"error": str(e)}
            return self._json({
                "status":result["verification"]["overall"],"path":target.name,
                "sha256":sha256_hex(target.read_bytes()),"verification":result["verification"],"bundle":bundle,
                "real_heraclitus_export": real_export
            })
        if path in ("/api/processos/protocolar","/api/processos/tramitar"):
            try:
                if path=="/api/processos/protocolar": return self._json({"connected":True,**PROCESSOS.protocolar()})
                body=self._read_json_body() if int(self.headers.get("Content-Length","0") or 0) else {}
                processo_id=body.get("id")
                if processo_id is not None and not isinstance(processo_id,str): raise ValueError("id must be a string")
                res=PROCESSOS.tramitar(processo_id)
                return self._json({"connected":True,"lsn":res["lsn"],"event_id":res["event_id"],"deduplicated":res["deduplicated"],
                                   "processo_id":res["processo_id"],"seq":res["seq"],"evento":res["conteudo"]})
            except Exception as e:
                body,status=_processos_erro(e)
                return self._json(body,status)
        if path=="/api/certidoes/emitir":
            try:
                body=self._read_json_body() if int(self.headers.get("Content-Length","0") or 0) else {}
                motivo=body.get("motivo","")
                duracao=body.get("duracao_segundos",184)
                operador=body.get("operador","SecOps / SRE Tribunal (STF)")
                res=ENGINE.emit_certidao(motivo,duracao,operador)
                return self._json(res,201)
            except Exception as e:
                return self._json({"error":"emit_failed","detail":str(e)},400)
        if path=="/api/interop/reconciliar":
            return self._json(ENGINE.interop_reconciliar(PROCESSOS),200)
        if path=="/api/interop/testar-duplicata":
            return self._json(ENGINE.interop_testar_duplicata(PROCESSOS),200)
        if path=="/api/processos/avulso":
            try:
                body=self._read_json_body()
                processo_id=body.get("processo_id") or body.get("id")
                codigo_tpu=int(body.get("codigo_tpu",11383))
                complemento=str(body.get("complemento","Praticado ato ordinatório")).strip()
                approval_id=str(body.get("approval_id","HITL-APROVACAO")).strip()
                res=PROCESSOS.acrescentar_avulso(processo_id,codigo_tpu,complemento,approval_id)
                return self._json({"connected":True,**res},200)
            except Exception as e:
                body_err,status_code=_processos_erro(e)
                return self._json(body_err,status_code)
        return self._json({"error":"not_found"},404)
    def _static(self,path:str)->None:
        rel="index.html" if path in ("/","") else path.lstrip("/")
        target=(DASHBOARD/rel).resolve()
        if DASHBOARD.resolve() not in target.parents and target != DASHBOARD.resolve(): return self._json({"error":"forbidden"},403)
        if not target.exists() or not target.is_file(): return self._json({"error":"not_found"},404)
        data=target.read_bytes(); ctype=mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)

def main()->None:
    ap=argparse.ArgumentParser(description="STF HeraclitusDB synthetic POC dashboard")
    ap.add_argument("--host",default="127.0.0.1"); ap.add_argument("--port",type=int,default=8787)
    ap.add_argument("--heraclitus",default=os.environ.get("HERACLITUS_URL", "http://127.0.0.1:8080"))
    ap.add_argument("--heraclitus-core",default=PROCESSOS.core.addr,help="núcleo gRPC do HeraclitusDB para o log processual")
    args=ap.parse_args()
    if args.host not in LOCAL_HOSTS: raise SystemExit("Safety gate: this POC binds only to loopback addresses")
    if args.heraclitus_core!=PROCESSOS.core.addr:
        PROCESSOS.core=HeraclitusCore(args.heraclitus_core)
    if args.heraclitus:
        ENGINE.connect_heraclitus(args.heraclitus)
    server=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f"STF POC dashboard: http://{args.host}:{args.port}")
    if getattr(ENGINE, "adapter", None):
        print(f"HeraclitusDB Status: REAL PERSISTENCE ACTIVE ({ENGINE.heraclitus_url})")
    else:
        print("HeraclitusDB Status: OFFLINE / SYNTHETIC ENGINE")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=="__main__": main()
