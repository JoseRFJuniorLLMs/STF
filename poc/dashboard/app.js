const $ = s => document.querySelector(s);
let state = null;
let running = false;
let selectedNode = null;
let isFullscreen = false;

// ========================================================
// CATÁLOGO DOS 17 ATAQUES MAPEADOS À INFRAESTRUTURA DO STF
// ========================================================
const ATTACKS = [
  { step: 1, title: '01. Calibração e Tráfego Benigno', infra: 'Firewall / WAF Borda', target: 'public-edge', type: 'network.connection', phase: 'FASE 1', desc: 'Tráfego legítimo de calibração para estabelecer a linha de base no perímetro do STF.' },
  { step: 2, title: '02. Sondagem no Perímetro (WAF)', infra: 'Firewall / WAF Borda', target: 'public-edge', type: 'edge.suspicious', phase: 'FASE 1', desc: 'Padrão incomum de requisições no perímetro de borda do Portal do STF.' },
  { step: 3, title: '03. Invasão de Sessão (IAM)', infra: 'Gabinete Ministros (Horizon VDI)', target: 'identity-provider', type: 'identity.login', phase: 'FASE 1', desc: 'Novo contexto de autenticação suspeito em estação de trabalho de gabinete (service-account-17).' },
  { step: 4, title: '04. Execução de Processo Atípico', infra: 'SUSE Linux Enterprise', target: 'srv-app-07', type: 'host.process', phase: 'FASE 1', desc: 'Processo incomum executado no servidor Linux SUSE do backend da aplicação judicial.' },
  { step: 5, title: '05. Movimento Lateral Interno', infra: 'SUSE Linux Enterprise', target: 'srv-db-02', type: 'network.lateral', phase: 'FASE 1', desc: 'Conexão lateral correlacionada entre o servidor de aplicação e o nó de dados srv-db-02.' },
  { step: 6, title: '06. Consulta Anômala a Metadados', infra: 'Oracle Database RAC', target: 'db-judicial-lab', type: 'db.query', phase: 'FASE 1', desc: 'Query fora do padrão da identidade em metadados processuais no cluster Oracle Database RAC.' },
  { step: 7, title: '07. Acesso a Autos no STF Digital', infra: 'STF Digital / e-STF', target: 'case://SYNTHETIC/RE-000001', type: 'app.resource_access', phase: 'FASE 1', desc: 'Acesso a processo restrito no STF Digital. O Sentinel correlaciona os sinais e ABRE O INCIDENTE!' },
  { step: 8, title: '08. Tentativa de Alterar Processo', infra: 'STF Digital / e-STF', target: 'case://SYNTHETIC/RE-000001', type: 'app.case_update_requested', phase: 'FASE 2', desc: 'Tentativa de alteração no processo RE-000001. Bloqueio automático pelo Gateway: DENY.' },
  { step: 9, title: '09. Tentativa de Exportar Acórdão Sigiloso', infra: 'IA & HPC (Victor / MARIA)', target: 'document://SYNTHETIC/DOC-001', type: 'agent.tool_requested', phase: 'FASE 2', desc: 'Agente solicita exportação de documento restrito. O Gateway exige aprovação humana: REQUIRE_HITL.' },
  { step: 10, title: '10. Aprovação Humana de Operador', infra: 'Aprovador de Gabinete (HITL)', target: 'document://SYNTHETIC/DOC-001', type: 'approval.granted', phase: 'FASE 2', desc: 'Operador humano concede autorização vinculada estritamente à identidade, ação e parâmetros.' },
  { step: 11, title: '11. Execução Única da Exportação', infra: 'STF Digital / Gateway', target: 'document://SYNTHETIC/DOC-001', type: 'tool.executed', phase: 'FASE 2', desc: 'Ação autorizada executa exatamente uma vez. Oráculo upstream emite recibo e soma 1.' },
  { step: 12, title: '12. Tentativa de Replay de Autorização', infra: 'IA & HPC (Victor / MARIA)', target: 'document://SYNTHETIC/DOC-001', type: 'approval.replay', phase: 'FASE 2', desc: 'Invasor tenta reaproveitar a autorização consumida: Bloqueio estrito (REPLAY_DETECTED).' },
  { step: 13, title: '13. Tentativa de Troca de Identidade', infra: 'Gabinete Ministros (Horizon VDI)', target: 'document://SYNTHETIC/DOC-001', type: 'identity.swap', phase: 'FASE 2', desc: 'Outro agente tenta usar a autorização concedida: Bloqueio (IDENTITY_BINDING_MISMATCH).' },
  { step: 14, title: '14. Tentativa de Troca de Parâmetros', infra: 'STF Digital / e-STF', target: 'document://SYNTHETIC/DOC-999', type: 'parameters.swap', phase: 'FASE 2', desc: 'Documento-alvo alterado após aprovação: Bloqueio (PARAMETERS_DIGEST_MISMATCH).' },
  { step: 15, title: '15. Tentativa de Sabotar Trilha Criptográfica', infra: 'HeraclitusDB (Ledger HRKL v6)', target: 'evidence-log', type: 'tamper.attempt', phase: 'FASE 2', desc: 'Invasor tenta sabotar histórico. Árvore Merkle e Hash-chain acusam quebra: DETECTED.' },
  { step: 16, title: '16. Geração do Evidence Bundle', infra: 'HeraclitusDB (Ledger HRKL v6)', target: 'evidence://STF-POC-001', type: 'evidence.exported', phase: 'FASE 2', desc: 'Pacote criptográfico de provas digitais gerado com manifesto e prova Merkle completa.' },
  { step: 17, title: '17. Verificação Offline da Integridade', infra: 'Perícia / Verificador Offline', target: 'evidence://STF-POC-001', type: 'evidence.verified', phase: 'FASE 2', desc: 'Perícia independente valida as provas matemáticas localmente e sem conexão à rede.' }
];

// =========================================================================
// TOPOLOGIA OFICIAL DA INFRAESTRUTURA DO STF (18 ELEMENTOS EM CAMADAS)
// Conforme diagrama oficial: Borda, Gabinete, Linux, LAN, STF Digital, SEI,
// MNI 2.2.2, Oracle RAC, DW, BI, Data Lake, IA/HPC, Backup e HeraclitusDB
// =========================================================================
const FIXED_INFRA_NODES = [
  // Camada 1: Borda e Autenticação
  { id: 'asset:internet', label: 'internet', kind: 'asset', friendlyName: 'Internet / Tráfego Externo', icon: '🌐', nx: 0.10, ny: 0.12, r: 20 },
  { id: 'asset:public-edge', label: 'public-edge', kind: 'asset', friendlyName: 'Firewall / WAF Borda', icon: '🛡️', nx: 0.28, ny: 0.12, r: 22 },
  { id: 'asset:identity-provider', label: 'identity-provider', kind: 'asset', friendlyName: 'Identity (ICP-Brasil / OIDC)', icon: '🪪', nx: 0.48, ny: 0.12, r: 22 },

  // Camada 2: Estações e Servidores de Aplicação
  { id: 'asset:vdi-ministros', label: 'vdi-ministros', kind: 'asset', friendlyName: 'Gabinete Ministros (Horizon VDI)', icon: '⚖️', nx: 0.36, ny: 0.28, r: 22 },
  { id: 'actor:human:approver-01', label: 'human:approver-01', kind: 'actor', friendlyName: 'Aprovador de Gabinete (HITL)', icon: '👨‍⚖️', nx: 0.18, ny: 0.28, r: 18 },
  { id: 'asset:srv-app-07', label: 'srv-app-07', kind: 'asset', friendlyName: 'SUSE Linux Enterprise (srv-app-07)', icon: '🐧', nx: 0.62, ny: 0.28, r: 22 },

  // Camada 3: Rede Corporativa (Backbone Seguro)
  { id: 'asset:lan-wlan', label: 'lan-wlan', kind: 'asset', friendlyName: 'Rede LAN / WLAN STF', icon: '🖧', nx: 0.50, ny: 0.44, r: 22 },

  // Camada 4: Sistemas Judiciais e Administrativos
  { id: 'asset:case://SYNTHETIC/RE-000001', label: 'case://SYNTHETIC/RE-000001', kind: 'asset', friendlyName: 'STF Digital (Autos RE-000001)', icon: '🏛️', nx: 0.30, ny: 0.58, r: 24 },
  { id: 'asset:document://SYNTHETIC/DOC-001', label: 'document://SYNTHETIC/DOC-001', kind: 'asset', friendlyName: 'Acórdão DOC-001 (Sigiloso)', icon: '📄', nx: 0.14, ny: 0.58, r: 18 },
  { id: 'asset:sei-admin', label: 'sei-admin', kind: 'asset', friendlyName: 'SEI (Processos Administrativos)', icon: '📂', nx: 0.50, ny: 0.58, r: 22 },
  { id: 'asset:mni-interop', label: 'mni-interop', kind: 'asset', friendlyName: 'MNI 2.2.2 / STF Tribunais', icon: '🔄', nx: 0.68, ny: 0.58, r: 22 },

  // Camada 5: Dados e Auditoria Transacional
  { id: 'asset:db-judicial-lab', label: 'db-judicial-lab', kind: 'asset', friendlyName: 'Oracle Database RAC / Audit', icon: '🗄️', nx: 0.50, ny: 0.72, r: 24 },
  { id: 'asset:srv-db-02', label: 'srv-db-02', kind: 'asset', friendlyName: 'Conexão DB (srv-db-02)', icon: '🔌', nx: 0.68, ny: 0.72, r: 18 },

  // Camada 6: Analytics, BI e Repositório Big Data
  { id: 'asset:data-warehouse', label: 'data-warehouse', kind: 'asset', friendlyName: 'Data Warehouse (DW STF)', icon: '📊', nx: 0.32, ny: 0.88, r: 20 },
  { id: 'asset:bi-corteaberta', label: 'bi-corteaberta', kind: 'asset', friendlyName: 'BI / Corte Aberta / Power BI', icon: '📈', nx: 0.16, ny: 0.88, r: 20 },
  { id: 'asset:data-lake', label: 'data-lake', kind: 'asset', friendlyName: 'Data Lake (Elasticsearch)', icon: '🎲', nx: 0.50, ny: 0.88, r: 20 },

  // Bloco Especializado: Inteligência Artificial, Backup e Ledger Imutável
  { id: 'asset:ia-hpc', label: 'ia-hpc', kind: 'asset', friendlyName: 'IA & HPC (Victor / MARIA)', icon: '🤖', nx: 0.86, ny: 0.28, r: 22 },
  { id: 'asset:backup-appliance', label: 'backup-appliance', kind: 'asset', friendlyName: 'Backup / Data Protection', icon: '💾', nx: 0.86, ny: 0.50, r: 20 },
  { id: 'asset:heraclitusdb', label: 'heraclitusdb', kind: 'asset', friendlyName: 'HeraclitusDB (Ledger HRKL v6)', icon: '🛡️', nx: 0.86, ny: 0.74, r: 28 }
];

// Conexões e fluxos permanentes da infraestrutura do STF
const FIXED_INFRA_EDGES = [
  // Borda, Identidade e Acesso
  { from: 'asset:internet', to: 'asset:public-edge', type: 'INFRA_LINK', icon: '🌐', title: 'Tráfego Público Externo' },
  { from: 'asset:public-edge', to: 'asset:identity-provider', type: 'INFRA_LINK', icon: '🛡️', title: 'Inspeção WAF & Auth' },
  { from: 'asset:identity-provider', to: 'asset:vdi-ministros', type: 'INFRA_LINK', icon: '🪪', title: 'Autenticação OIDC / ICP-Brasil' },
  { from: 'asset:identity-provider', to: 'asset:srv-app-07', type: 'INFRA_LINK', icon: '🔑', title: 'Autenticação Kerberos / SSH' },
  { from: 'actor:human:approver-01', to: 'asset:document://SYNTHETIC/DOC-001', type: 'INFRA_LINK', icon: '✍️', title: 'Canal de Aprovação HITL' },

  // Backbone LAN / WLAN
  { from: 'asset:vdi-ministros', to: 'asset:lan-wlan', type: 'INFRA_LINK', icon: '⚖️', title: 'Acesso Gabinete Ministros' },
  { from: 'asset:srv-app-07', to: 'asset:lan-wlan', type: 'INFRA_LINK', icon: '🐧', title: 'Backend Linux Corporativo' },
  { from: 'asset:lan-wlan', to: 'asset:case://SYNTHETIC/RE-000001', type: 'INFRA_LINK', icon: '🏛️', title: 'Acesso STF Digital' },
  { from: 'asset:lan-wlan', to: 'asset:sei-admin', type: 'INFRA_LINK', icon: '📂', title: 'Acesso SEI Administrativo' },
  { from: 'asset:lan-wlan', to: 'asset:mni-interop', type: 'INFRA_LINK', icon: '🔄', title: 'Barramento MNI 2.2.2' },

  // Processamento e Banco de Dados
  { from: 'asset:case://SYNTHETIC/RE-000001', to: 'asset:document://SYNTHETIC/DOC-001', type: 'INFRA_LINK', icon: '📄', title: 'Autos do Processo RE-000001' },
  { from: 'asset:case://SYNTHETIC/RE-000001', to: 'asset:db-judicial-lab', type: 'INFRA_LINK', icon: '🗄️', title: 'Transações Processuais' },
  { from: 'asset:sei-admin', to: 'asset:db-judicial-lab', type: 'INFRA_LINK', icon: '🗄️', title: 'Processos Administrativos SEI' },
  { from: 'asset:mni-interop', to: 'asset:db-judicial-lab', type: 'INFRA_LINK', icon: '🗄️', title: 'Interoperabilidade de Dados' },
  { from: 'asset:srv-app-07', to: 'asset:srv-db-02', type: 'INFRA_LINK', icon: '🔀', title: 'Conexão Rede de Dados' },
  { from: 'asset:srv-db-02', to: 'asset:db-judicial-lab', type: 'INFRA_LINK', icon: '🔌', title: 'Cluster Oracle RAC Ativo' },

  // Analytics, DW & Data Lake
  { from: 'asset:db-judicial-lab', to: 'asset:data-warehouse', type: 'INFRA_LINK', icon: '📊', title: 'Carga ETL / Replicação DW' },
  { from: 'asset:data-warehouse', to: 'asset:bi-corteaberta', type: 'INFRA_LINK', icon: '📈', title: 'Painéis Corte Aberta / Power BI' },
  { from: 'asset:db-judicial-lab', to: 'asset:data-lake', type: 'INFRA_LINK', icon: '🎲', title: 'Streaming Elasticsearch' },

  // IA, Proteção de Dados e HeraclitusDB (Auditoria Imutável)
  { from: 'asset:ia-hpc', to: 'asset:backup-appliance', type: 'INFRA_LINK', icon: '💾', title: 'Checkpoints de IA & Backup' },
  { from: 'asset:ia-hpc', to: 'asset:case://SYNTHETIC/RE-000001', type: 'INFRA_LINK', icon: '🤖', title: 'Triagem Victor / MARIA' },
  { from: 'asset:case://SYNTHETIC/RE-000001', to: 'asset:heraclitusdb', type: 'INFRA_LINK', icon: '🛡️', title: 'Auditoria Imutável HRKL' },
  { from: 'asset:db-judicial-lab', to: 'asset:heraclitusdb', type: 'INFRA_LINK', icon: '🛡️', title: 'Preservação Criptográfica Oracle' },
  { from: 'asset:srv-app-07', to: 'asset:heraclitusdb', type: 'INFRA_LINK', icon: '📡', title: 'Telemetria OTLP (Porta 4318)' },
  { from: 'asset:ia-hpc', to: 'asset:heraclitusdb', type: 'INFRA_LINK', icon: '🛡️', title: 'Governança Agentes (Porta 8080)' },
  { from: 'asset:backup-appliance', to: 'asset:heraclitusdb', type: 'INFRA_LINK', icon: '🛡️', title: 'Validação Merkle de Backup' }
];

// ========================================================
// API E UTILITÁRIOS
// ========================================================
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-STF-POC': '1', ...(opts.headers || {}) };
  // Caminho relativo: funciona na raiz (local) e atrás do nginx em /stf/
  const r = await fetch(path.replace(/^\//, ''), { ...opts, headers });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

function esc(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function short(s, n = 18) {
  if (!s) return '—';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove('show'), 2600);
}

// FORMATADOR DE DATA E HORA INSTITUCIONAL
function formatDateTime(ev) {
  if (!ev) return '—';
  if (ev.timestamp) return ev.timestamp;
  if (ev.created_at) return ev.created_at;

  const lsn = ev.lsn || 1;
  const baseMs = new Date('2026-09-23T20:15:00-03:00').getTime();
  const d = new Date(baseMs + (lsn - 1) * 12000);

  const pad = n => String(n).padStart(2, '0');
  const day = pad(d.getDate());
  const mon = pad(d.getMonth() + 1);
  const yr = d.getFullYear();
  const hr = pad(d.getHours());
  const min = pad(d.getMinutes());
  const sec = pad(d.getSeconds());
  return `${day}/${mon}/${yr} ${hr}:${min}:${sec}`;
}

// ========================================================
// HINT / NOTIFICAÇÃO NO CANTO INFERIOR DIREITO COM DATA/HORA
// ========================================================
let hintTimeout = null;

window.closeAttackHint = function() {
  const h = $('#attackHint');
  if (h) h.classList.remove('show');
  if (hintTimeout) clearTimeout(hintTimeout);
};

function showAttackHint(attack, ev, equipCounter) {
  const h = $('#attackHint');
  if (!h || !attack) return;

  const outcome = ev?.outcome || (ev?.oracle_verdict ? (ev.oracle_verdict === 'pass' ? 'DENY' : 'PASS') : 'EXECUTADO');
  const upstreamDelta = ev?.upstream_delta ?? 0;
  const reasonCode = ev?.reason_code || ev?.details?.policy_decision?.reason_code || '';
  const dt = formatDateTime(ev || { lsn: attack.step || 1 });

  // Obter identificação do equipamento e total de tentativas
  const eqName = attack.infra || attack.equipment || 'Equipamento STF';
  const targetName = attack.target || attack.asset || '';
  const attempts = equipCounter ? equipCounter.attempts : (state?.equipment_counters?.[attack.equipment_id]?.attempts ?? 1);
  const blocked = equipCounter ? equipCounter.unauthorized_blocked : (state?.equipment_counters?.[attack.equipment_id]?.unauthorized_blocked ?? 0);

  const hintTime = $('#hintTime');
  if (hintTime) hintTime.textContent = dt;

  $('#hintAttackName').textContent = attack.title;
  $('#hintInfraName').textContent = `${eqName} [Tentativas: ${attempts} | Bloqueios: ${blocked}]`;

  const outcomeBadge = $('#hintOutcome');
  outcomeBadge.textContent = outcome + (reasonCode ? ` [${reasonCode}]` : '');
  // Legenda única: verde = bloqueado/detetado (não invadiu), roxo = passou, âmbar = aguarda aprovação
  outcomeBadge.className = 'hint-outcome-badge ' + (outcome === 'DENY' || outcome === 'BLOCKED' || outcome === 'DETECTED' ? 'DENY' : outcome === 'REQUIRE_HITL' ? 'REQUIRE_HITL' : outcome === 'PASS' || outcome === 'ALLOW' ? 'PASS' : 'INFO');

  const upstreamBadge = $('#hintUpstream');
  upstreamBadge.textContent = `upstream=${upstreamDelta}`;
  upstreamBadge.style.color = upstreamDelta > 0 ? 'var(--gov-green)' : 'var(--gov-muted)';

  const badge = $('#hintBadge');
  if (outcome === 'DENY' || outcome === 'BLOCKED') {
    h.className = 'attack-hint show deny';
    badge.textContent = '🛡️ ATAQUE BLOQUEADO — NÃO INVADIU';
    badge.style.color = 'var(--legend-blocked)';
    $('#hintDesc').textContent = `Invasão contra ${eqName} interceptada com sucesso! Tentativa #${attempts} neutralizada com efeito zero na rede judicial às ${dt}.`;
  } else if (outcome === 'REQUIRE_HITL') {
    h.className = 'attack-hint show hitl';
    badge.textContent = '⚠️ AUTORIZAÇÃO HUMANA EXIGIDA';
    badge.style.color = 'var(--gov-gold)';
    $('#hintDesc').textContent = `Operação de risco contra ${eqName} exige aprovação formal de gabinete (HITL) para prosseguir às ${dt}.`;
  } else if (outcome === 'DETECTED') {
    h.className = 'attack-hint show deny';
    badge.textContent = '🛡️ SABOTAGEM DETECTADA — NÃO INVADIU';
    badge.style.color = 'var(--legend-blocked)';
    $('#hintDesc').textContent = `Tentativa de adulteração detectada pelo elo criptográfico Merkle da trilha HRKL às ${dt}.`;
  } else {
    h.className = 'attack-hint show pass';
    badge.textContent = 'ℹ️ PROVA REGISTRADA NO LEDGER';
    badge.style.color = 'var(--gov-blue-primary)';
    $('#hintDesc').textContent = (attack.desc || attack.hypothesis || `Ação executada contra ${targetName}.`) + ` Gravado com prova imutável às ${dt}.`;
  }

  if (hintTimeout) clearTimeout(hintTimeout);
  hintTimeout = setTimeout(() => {
    h.classList.remove('show');
  }, 5000);
}

// ========================================================
// CATÁLOGO INSTITUCIONAL DE DESCRIÇÕES DOS NÓS DA INFRAESTRUTURA STF
// Exibido no canto inferior direito ao passar o mouse em qualquer nó
// ========================================================
const NODE_DESCRIPTIONS = {
  'asset:internet': {
    title: 'Internet / Tráfego Externo',
    icon: '🌐',
    layerBadge: 'CAMADA 1 • BORDA PERIMETRAL',
    role: 'Zona Externa Não Confiável (Público / OAB / Tribunais)',
    ledgerSync: 'FILTRADO NA BORDA',
    desc: 'Ponto de origem de acessos públicos, consultas processuais, envio de petições por advogados e requisições externas. Todo o tráfego que ingressa no Tribunal é inspecionado preventivamente pelo Firewall e WAF de borda antes de alcançar qualquer recurso interno.'
  },
  'asset:public-edge': {
    title: 'Firewall / WAF Borda',
    icon: '🛡️',
    layerBadge: 'CAMADA 1 • SEGURANÇA PERIMETRAL',
    role: 'Next-Generation Firewall & Web Application Firewall',
    ledgerSync: 'EVENTOS AUDITADOS',
    desc: 'Primeira linha de defesa cibernética do STF. Realiza filtragem profunda de pacotes L4-L7, mitigação anti-DDoS volumétrico, bloqueio de scanners e agentes maliciosos (OWASP Top 10) e encaminha tráfego legítimo com TLS 1.3 aos serviços autorizados.'
  },
  'asset:identity-provider': {
    title: 'Identity Provider (ICP-Brasil / OIDC / MFA)',
    icon: '🪪',
    layerBadge: 'CAMADA 1 • GESTÃO DE IDENTIDADE (IAM)',
    role: 'Autenticação Forte, Certificados Digitais e SSO',
    ledgerSync: 'SESSÕES ASSINADAS',
    desc: 'Núcleo central de identidade e acesso do STF. Emite tokens OIDC/SAML com verificação multifator (MFA), valida certificados digitais padrão ICP-Brasil (A3/nuvem) para Ministros e advogados e impede autenticações anômalas ou sequestro de credenciais.'
  },
  'asset:vdi-ministros': {
    title: 'Gabinete dos Ministros (Omnissa Horizon VDI)',
    icon: '⚖️',
    layerBadge: 'CAMADA 2 • ESTAÇÕES VIRTUAIS DE TRABALHO',
    role: 'Virtual Desktop Infrastructure (Windows 11 VDA)',
    ledgerSync: 'ISOLAMENTO DE GABINETE',
    desc: 'Estações de trabalho virtuais seguras utilizadas pelos Ministros, juízes instrutores e assessores para elaboração de votos, despachos e decisões colegiadas. O ambiente é virtualizado, blindado contra vazamento de dados (DLP) e protegido contra malware local.'
  },
  'actor:human:approver-01': {
    title: 'Aprovador de Gabinete (HITL)',
    icon: '👨‍⚖️',
    layerBadge: 'CAMADA 2 • GOVERNANÇA HUMANA (HITL)',
    role: 'Autoridade de Aprovação Formal e Assinatura Digital',
    ledgerSync: 'CHANCELA CRIPTOGRÁFICA',
    desc: 'Operador humano habilitado responsável pelo mecanismo Human-in-the-Loop (HITL). Nenhuma ação de alto risco executada por agentes de IA ou ferramentas autônomas — como exportação de acórdão sigiloso — pode prosseguir sem a concessão expressa deste aprovador.'
  },
  'asset:srv-app-07': {
    title: 'SUSE Linux Enterprise Server (srv-app-07)',
    icon: '🐧',
    layerBadge: 'CAMADA 2 • SERVIDORES DE APLICAÇÃO',
    role: 'SLES 15 Enterprise + SUSE Manager (Backend STF)',
    ledgerSync: 'TELEMETRIA OTLP (4318)',
    desc: 'Servidor corporativo Linux SUSE responsável pela execução dos backends e microsserviços do STF Digital. Conta com telemetria contínua via OpenTelemetry (OTLP), auditoria de processos via eBPF e integração com o HeraclitusDB para preservação de rastros.'
  },
  'asset:lan-wlan': {
    title: 'Rede LAN / WLAN STF',
    icon: '🖧',
    layerBadge: 'CAMADA 3 • BACKBONE CORPORATIVO SEGURO',
    role: 'Microsegmentação de Rede, VLANs e Controle 802.1X',
    ledgerSync: 'CONTROLE DE FLUXO',
    desc: 'Backbone de rede interna de alta performance e disponibilidade do Supremo Tribunal Federal. Implementa isolamento rigoroso entre as redes de gabinetes, servidores de dados, clusters de IA e zonas administrativas, mitigando riscos de movimentação lateral.'
  },
  'asset:case://SYNTHETIC/RE-000001': {
    title: 'STF Digital (Autos RE-000001)',
    icon: '🏛️',
    layerBadge: 'CAMADA 4 • PROCESSO JUDICIAL ELETRÔNICO',
    role: 'Plataforma Central Unificada de Tramitação Judicial',
    ledgerSync: 'HASH ENCADEADO NO LEDGER',
    desc: 'Plataforma oficial que substituiu sistemas legados e centralizou todo o processamento de feitos do STF. Gerencia a autuação, distribuição, tramitação e publicação de decisões. Toda mutação de autos gera assinatura criptográfica imutável vinculada ao processo.'
  },
  'asset:document://SYNTHETIC/DOC-001': {
    title: 'Acórdão DOC-001 (Sigiloso)',
    icon: '📄',
    layerBadge: 'CAMADA 4 • DOCUMENTO PROCESSUAL RESTRITO',
    role: 'Minuta de Julgamento com Grau de Sigilo Estrito',
    ledgerSync: 'POLÍTICA DLP ATIVA',
    desc: 'Documento judicial sensível contendo minuta de acórdão e fundamentos decisórios em segredo de justiça. Qualquer leitura, extração ou exportação requer validação de política no Agent Gateway e aprovação humana de gabinete (HITL), com zero tolerância a replay.'
  },
  'asset:sei-admin': {
    title: 'SEI (Processos Administrativos)',
    icon: '📂',
    layerBadge: 'CAMADA 4 • GESTÃO ADMINISTRATIVA',
    role: 'Sistema Eletrônico de Informações do STF',
    ledgerSync: 'AUDITORIA DE EXPEDIENTES',
    desc: 'Plataforma de tramitação eletrônica de processos administrativos, compras públicas, contratos e atos de gestão interna do STF. Opera em ambiente segregado e mantém trilha de integridade para atendimento às normas de transparência pública.'
  },
  'asset:mni-interop': {
    title: 'MNI 2.2.2 / STF Tribunais',
    icon: '🔄',
    layerBadge: 'CAMADA 4 • INTEROPERABILIDADE JUDICIÁRIA',
    role: 'Modelo Nacional de Interoperabilidade (SOAP/REST)',
    ledgerSync: 'BARRAMENTO DE TRIBUNAIS',
    desc: 'Barramento seguro de dados que conecta o STF aos demais tribunais brasileiros (CNJ, STJ, TST, TSE, TRFs e TJs). Permite o envio e recebimento eletrônico de recursos extraordinários, autos e certidões com validação estrita de esquemas XML e assinaturas.'
  },
  'asset:db-judicial-lab': {
    title: 'Oracle Database RAC / Audit',
    icon: '🗄️',
    layerBadge: 'CAMADA 5 • BANCO DE DADOS TRANSACIONAL',
    role: 'Oracle RAC Enterprise com Active Data Guard & TDE',
    ledgerSync: 'UNIFIED AUDITING INTEGRADA',
    desc: 'Repositório de dados relacional primário do STF em cluster de nós ativos (RAC) com criptografia transparente de dados (TDE). Armazena metadados, andamentos e peças judiciais. Cada transação é sincronizada com a trilha de auditoria e espelhada no HeraclitusDB.'
  },
  'asset:srv-db-02': {
    title: 'Conexão DB (srv-db-02)',
    icon: '🔌',
    layerBadge: 'CAMADA 5 • ROTEAMENTO DE DADOS',
    role: 'Nó Intermediário do Cluster de Banco de Dados',
    ledgerSync: 'SEGMENTO PROTEGIDO',
    desc: 'Nó de interconexão e balanceamento de conexões SQL entre os servidores de aplicação e a camada transacional Oracle. Monitorado para impedir injeção de túneis clandestinos, consultas diretas desautorizadas e exfiltração em massa de dados.'
  },
  'asset:data-warehouse': {
    title: 'Data Warehouse (DW STF)',
    icon: '📊',
    layerBadge: 'CAMADA 6 • ANALYTICS E BUSINESS INTELLIGENCE',
    role: 'Repositório Central Histórico e Modelagem OLAP',
    ledgerSync: 'ETL AUDITADO PERIODICAMENTE',
    desc: 'Base analítica consolidada contendo séries históricas de processos, estatísticas de julgamentos e tempos de tramitação. Alimenta relatórios estratégicos da Presidência, órgãos de controle e serve de alicerce analítico para a gestão do acervo processual.'
  },
  'asset:bi-corteaberta': {
    title: 'BI / Corte Aberta / Power BI',
    icon: '📈',
    layerBadge: 'CAMADA 6 • TRANSPARÊNCIA ATIVA',
    role: 'Painéis Analíticos Públicos e Corporativos',
    ledgerSync: 'DADOS ABERTOS / AUDITÁVEIS',
    desc: 'Solução de visualização executiva e transparência ativa do programa Corte Aberta. Apresenta indicadores de produtividade, taxas de congestionamento e acervo em tempo real, permitindo aos cidadãos e à comunidade jurídica auditar o desempenho da Corte.'
  },
  'asset:data-lake': {
    title: 'Data Lake (Elasticsearch)',
    icon: '🎲',
    layerBadge: 'CAMADA 6 • REPOSITÓRIO BIG DATA',
    role: 'Indexação Semântica e Busca em Texto Integral',
    ledgerSync: 'CORPUS PROCESSUAL ÍNTEGRO',
    desc: 'Repositório elástico de dados volumosos contendo o texto integral de petições, jurisprudência histórica e votos digitalizados. Oferece busca instantânea de alta relevância e fornece o corpus de dados para os sistemas de Inteligência Artificial do STF.'
  },
  'asset:ia-hpc': {
    title: 'IA & HPC (Victor / MARIA / VitórIA / RAFA 2030)',
    icon: '🤖',
    layerBadge: 'BLOCO ESPECIALIZADO • INTELIGÊNCIA ARTIFICIAL',
    role: 'Agentes Autônomos de Apoio à Jurisdição e Triagem',
    ledgerSync: 'POLÍTICAS NO GATEWAY (8080)',
    desc: 'Parque de modelos e agentes de IA do STF: Victor (triagem de Repercussão Geral), MARIA (análise de precedentes), VitórIA (pesquisa jurídica) e RAFA 2030 (Agenda 2030 ONU). Cada inferência e ferramenta chamada passa obrigatoriamente pelo Agent Gateway.'
  },
  'asset:backup-appliance': {
    title: 'Backup / Data Protection',
    icon: '💾',
    layerBadge: 'BLOCO ESPECIALIZADO • CONTINUIDADE DE NEGÓCIOS',
    role: 'Appliance de Proteção com Imutabilidade WORM',
    ledgerSync: 'PROVAS CRIPTOGRÁFICAS DE RESTORE',
    desc: 'Infraestrutura de salvaguarda de alta segurança contra desastres e ataques de ransomware. Armazena cópias com tecnologia WORM (Write Once, Read Many), impossibilitando deleção ou modificação indevida antes do decurso do tempo de retenção legal.'
  },
  'asset:heraclitusdb': {
    title: 'HeraclitusDB (Escudo Verde-Amarelo • Ledger HRKL)',
    icon: '🛡️',
    layerBadge: 'AUDITORIA IMUTÁVEL • LIVRO-RAZÃO CRIPTOGRÁFICO',
    role: 'Ledger com LSN Monotônico, Provas Merkle e OTLP (WSL 8080)',
    ledgerSync: 'CONEXÃO ATIVA WSL UBUNTU',
    desc: 'Motor central de governança cibernética e auditoria imutável do STF, sob o Escudo Verde e Amarelo de proteção criptográfica. Registra cada transação, decisão de segurança do Gateway e chamada de ferramentas em uma cadeia de blocos inviolável com provas Merkle independentes.'
  }
};

function getNodeFallbackDescription(nodeId, friendlyName, kind) {
  if (kind === 'incident' || (nodeId && nodeId.startsWith('incident:'))) {
    return {
      title: friendlyName || 'Incidente de Segurança Correlacionado',
      icon: '🚨',
      layerBadge: 'SIEM / SENTINEL • CORRELAÇÃO DE AMEAÇAS',
      role: 'Incidente Cibernético Formal Aberto',
      ledgerSync: 'REGISTRO DE INCIDENTE NO LEDGER',
      desc: 'Incidente acionado após correlação de múltiplos sinais anômalos no grafo temporal (ex: login suspeito, processo não autorizado e tentativa de acesso restrito). Desencadeia isolamento automático de credenciais e preservação imediata de evidências.'
    };
  }
  if (kind === 'actor' || (nodeId && (nodeId.startsWith('actor:') || nodeId.includes('service-account')))) {
    return {
      title: friendlyName || 'Identidade / Agente em Investigação',
      icon: '👤',
      layerBadge: 'CONTROLE DE IDENTIDADE • CONTEXTO DA SESSÃO',
      role: 'Entidade Autenticada Sob Monitoramento do Gateway',
      ledgerSync: 'RASTREABILIDADE COMPLETA',
      desc: 'Ator ou conta de serviço vinculada aos eventos monitorados. O Agent Gateway verifica suas chaves, restringe o escopo de atuação e aplica validação criptográfica estrita em cada requisição de ferramentas upstream.'
    };
  }
  return {
    title: friendlyName || nodeId,
    icon: '🏛️',
    layerBadge: 'INFRAESTRUTURA SUPREMO TRIBUNAL FEDERAL',
    role: 'Ativo de Rede e Processamento Corporativo',
    ledgerSync: 'AUDITADO NO HERACLITUSDB',
    desc: 'Componente da topologia computacional do Supremo Tribunal Federal, operando sob supervisão contínua de políticas de segurança de informação, telemetria OTLP e auditoria imutável.'
  };
}

function mapNodeToEquipmentKey(nodeId) {
  if (!nodeId) return null;
  const nid = nodeId.toLowerCase();
  if (nid.includes('public-edge') || nid.includes('internet')) return 'waf';
  if (nid.includes('identity')) return 'identity';
  if (nid.includes('vdi') || nid.includes('approver') || nid.includes('human')) return 'vdi';
  if (nid.includes('srv-app-07') || nid.includes('linux')) return 'linux';
  if (nid.includes('lan-wlan') || nid.includes('lan')) return 'lan';
  if (nid.includes('case://') || nid.includes('re-000001') || nid.includes('doc-001') || nid.includes('stf-digital')) return 'stf_digital';
  if (nid.includes('sei')) return 'sei';
  if (nid.includes('mni')) return 'mni';
  if (nid.includes('db-judicial') || nid.includes('srv-db-02') || nid.includes('oracle')) return 'db_oracle';
  if (nid.includes('data-warehouse') || nid.includes('bi-corteaberta') || nid.includes('dw')) return 'dw';
  if (nid.includes('data-lake')) return 'data_lake';
  if (nid.includes('ia-hpc') || nid.includes('ia')) return 'ia_agents';
  if (nid.includes('backup')) return 'backup';
  if (nid.includes('heraclitus')) return 'hdb_api';
  return null;
}

let nodeHintLeaveTimeout = null;

window.showNodeHintBottomRight = function(nodeId, friendlyName, kind) {
  if (nodeHintLeaveTimeout) {
    clearTimeout(nodeHintLeaveTimeout);
    nodeHintLeaveTimeout = null;
  }
  if (hintTimeout) {
    clearTimeout(hintTimeout);
    hintTimeout = null;
  }
  const h = $('#attackHint');
  if (!h) return;

  const descObj = NODE_DESCRIPTIONS[nodeId] || getNodeFallbackDescription(nodeId, friendlyName, kind);

  // Buscar contadores de intrusão do equipamento se existir
  const equipKey = mapNodeToEquipmentKey(nodeId);
  const counter = equipKey && state?.equipment_counters ? state.equipment_counters[equipKey] : null;

  h.className = 'attack-hint show info';

  const badge = $('#hintBadge');
  if (badge) {
    badge.textContent = descObj.layerBadge || '🏛️ INFRAESTRUTURA DO STF';
    badge.style.color = 'var(--gov-blue-primary)';
  }

  const hintTime = $('#hintTime');
  if (hintTime) {
    hintTime.textContent = counter ? `STATUS: ${counter.status}` : 'STATUS: OPERACIONAL';
  }

  const title = $('#hintAttackName');
  if (title) {
    title.textContent = `${descObj.icon || '🏛️'} ${descObj.title || friendlyName}`;
  }

  const infra = $('#hintInfraName');
  if (infra) {
    infra.textContent = descObj.role || friendlyName;
  }

  const outcomeBadge = $('#hintOutcome');
  if (outcomeBadge) {
    if (counter && (counter.attempts > 0 || counter.unauthorized_blocked > 0)) {
      outcomeBadge.textContent = `${counter.attempts} Tentativas | ${counter.unauthorized_blocked} Bloqueios`;
      outcomeBadge.className = 'hint-outcome-badge ' + (counter.attempts > counter.unauthorized_blocked ? 'PASS' : 'DENY');
    } else {
      outcomeBadge.textContent = '100% ÍNTEGRO';
      outcomeBadge.className = 'hint-outcome-badge DENY';
    }
  }

  const upstreamBadge = $('#hintUpstream');
  if (upstreamBadge) {
    upstreamBadge.textContent = descObj.ledgerSync || 'LEDGER HRKL v6';
    upstreamBadge.style.color = 'var(--gov-blue-primary)';
  }

  const desc = $('#hintDesc');
  if (desc) {
    desc.textContent = descObj.desc;
  }
};

window.hideNodeHintBottomRight = function() {
  if (nodeHintLeaveTimeout) clearTimeout(nodeHintLeaveTimeout);
  nodeHintLeaveTimeout = setTimeout(() => {
    const h = $('#attackHint');
    if (h && h.classList.contains('info')) {
      h.classList.remove('show');
    }
  }, 2200);
};

// ========================================================
// POPUP DO NÚMERO DO ATAQUE NO NÓ DO GRAFO (APARECE E SOME)
// ========================================================
const activeNodeAttacks = new Map(); // nodeId -> { attackNum, text, title, expireTime }
const nodeAttackCounts = new Map(); // nodeId -> disparos vistos nesta sessão do browser
const serverNodeTotals = new Map(); // nodeId -> tentativas acumuladas no servidor (equipment_counters)
const serverNodeBlocked = new Map(); // nodeId -> tentativas bloqueadas no servidor
const localNodeOutcomes = new Map(); // nodeId -> { blocked, passed } vistos nesta sessão

function syncNodeAttackCountsFromState(s) {
  if (!s) return;
  const counters = s.equipment_counters || {};
  const equipToNode = {
    waf: 'asset:public-edge',
    identity: 'asset:identity-provider',
    vdi: 'asset:vdi-ministros',
    linux: 'asset:srv-app-07',
    lan: 'asset:lan-wlan',
    stf_digital: 'asset:case://SYNTHETIC/RE-000001',
    sei: 'asset:sei-admin',
    mni: 'asset:mni-interop',
    db_oracle: 'asset:db-judicial-lab',
    dw: 'asset:data-warehouse',
    data_lake: 'asset:data-lake',
    ia_agents: 'asset:ia-hpc',
    backup: 'asset:backup-appliance',
    hdb_api: 'asset:heraclitusdb',
    hdb_otlp: 'asset:heraclitusdb',
    hdb_mcp: 'asset:heraclitusdb',
    hdb_grpc: 'asset:heraclitusdb',
    hdb_rest: 'asset:heraclitusdb'
  };

  // Soma as tentativas de todos os equipamentos que caem no mesmo nó (ex.: hdb_* → HeraclitusDB)
  const totals = new Map();
  const blocked = new Map();
  for (const [eqId, eqData] of Object.entries(counters)) {
    const nodeId = equipToNode[eqId];
    if (nodeId && eqData && typeof eqData.attempts === 'number') {
      totals.set(nodeId, (totals.get(nodeId) || 0) + eqData.attempts);
      blocked.set(nodeId, (blocked.get(nodeId) || 0) + (eqData.unauthorized_blocked || 0));
    }
  }
  serverNodeTotals.clear();
  for (const [nodeId, total] of totals) serverNodeTotals.set(nodeId, total);
  serverNodeBlocked.clear();
  for (const [nodeId, b] of blocked) serverNodeBlocked.set(nodeId, b);
}

// Total mostrado no nó: o acumulado do servidor já inclui os disparos locais, por isso é o maior dos dois (não a soma)
function nodeAttackTotal(nodeId) {
  return Math.max(serverNodeTotals.get(nodeId) || 0, nodeAttackCounts.get(nodeId) || 0);
}

// Legenda do painel: vermelho = tentativa, verde = bloqueado (não invadiu), roxo = não bloqueado
const BLOCKED_OUTCOMES = new Set(['DENY', 'BLOCKED', 'DETECTED', 'REJECTED', 'FAIL']);
const PASSED_OUTCOMES = new Set(['PASS', 'ALLOW', 'MISSED', 'EXECUTED']);

function outcomeOf(res) {
  const ev = res?.event;
  // Mesma regra do hint: sem outcome, o oráculo "pass" do teste HeraclitusDB significa defesa bloqueou
  const o = ev?.outcome || res?.outcome || (ev?.oracle_verdict ? (ev.oracle_verdict === 'pass' ? 'DENY' : 'PASS') : '');
  return String(o).toUpperCase();
}

function recordNodeOutcome(nodeId, outcome) {
  const o = String(outcome || '').toUpperCase();
  if (!nodeId || !o) return;
  const cur = localNodeOutcomes.get(nodeId) || { blocked: 0, passed: 0 };
  if (BLOCKED_OUTCOMES.has(o)) cur.blocked++;
  else if (PASSED_OUTCOMES.has(o)) cur.passed++;
  localNodeOutcomes.set(nodeId, cur);
}

// Bloqueados e não bloqueados do nó: servidor quando o nó tem contadores, senão o visto nesta sessão
function nodeOutcomeTotals(nodeId) {
  const local = localNodeOutcomes.get(nodeId) || { blocked: 0, passed: 0 };
  if (serverNodeTotals.has(nodeId)) {
    const attempts = serverNodeTotals.get(nodeId) || 0;
    const blocked = Math.max(serverNodeBlocked.get(nodeId) || 0, local.blocked);
    return { blocked, passed: Math.max(0, attempts - blocked, local.passed) };
  }
  return local;
}

function findNodeIdForTarget(target) {
  if (!target) return null;
  const t = String(target).toLowerCase();

  // 1. Procura direta em FIXED_INFRA_NODES
  for (const fn of FIXED_INFRA_NODES) {
    if (fn.id.toLowerCase() === t || fn.label.toLowerCase() === t) return fn.id;
  }

  // 2. Procura em simNodes (nós ativos na simulação)
  for (const [id, node] of simNodes.entries()) {
    const nid = id.toLowerCase();
    const nlabel = (node.label || '').toLowerCase();
    const nname = (node.friendlyName || '').toLowerCase();
    if (nid === t || nlabel === t || nname === t) return id;
  }

  // 3. Heurísticas por componente
  if (t.includes('ia-hpc') || t.includes('victor') || t.includes('maria') || t.includes('vitoria') || t.includes('rafa') || t.includes('ia_')) return 'asset:ia-hpc';
  if (t.includes('data-warehouse') || t.includes('dw') || t.includes('olap')) return 'asset:data-warehouse';
  if (t.includes('data-lake') || t.includes('lake') || t.includes('elastic')) return 'asset:data-lake';
  if (t.includes('bi-corteaberta') || t.includes('corteaberta') || t.includes('power bi')) return 'asset:bi-corteaberta';
  if (t.includes('vdi-ministros') || t.includes('vdi') || t.includes('horizon')) return 'asset:vdi-ministros';
  if (t.includes('lan-wlan') || t.includes('lan') || t.includes('wlan')) return 'asset:lan-wlan';
  if (t.includes('sei-admin') || t.includes('sei')) return 'asset:sei-admin';
  if (t.includes('mni-interop') || t.includes('mni')) return 'asset:mni-interop';
  if (t.includes('backup-appliance') || t.includes('backup') || t.includes('bkp')) return 'asset:backup-appliance';
  if (t.includes('re-000001') || t.includes('stf-digital') || t.includes('estf')) return 'asset:case://SYNTHETIC/RE-000001';
  if (t.includes('doc-001') || t.includes('doc-999') || t.includes('acordao')) return 'asset:document://SYNTHETIC/DOC-001';
  if (t.includes('public-edge') || t.includes('edge') || t.includes('waf') || t.includes('firewall')) return 'asset:public-edge';
  if (t.includes('identity') || t.includes('iam') || t.includes('oidc') || t.includes('icp')) return 'asset:identity-provider';
  if (t.includes('srv-app-07') || t.includes('suse') || t.includes('linux')) return 'asset:srv-app-07';
  if (t.includes('srv-db-02')) return 'asset:srv-db-02';
  if (t.includes('db-judicial') || t.includes('oracle') || t.includes('rac') || t.includes('database')) return 'asset:db-judicial-lab';
  if (t.includes('8080') || t.includes('7474') || t.includes('7475') || t.includes('4318') || t.includes('8787') || t.includes('heraclitus') || t.includes('evidence')) return 'asset:heraclitusdb';
  if (t.includes('human') || t.includes('approver')) return 'actor:human:approver-01';

  return null;
}

function triggerNodeAttackPopup(targetId, attackNum, title, outcome) {
  if (!targetId) return;
  recordNodeOutcome(targetId, outcome);
  const now = Date.now();
  const text = typeof attackNum === 'number' ? `Ataque #${String(attackNum).padStart(2, '0')}` : `Ataque #${attackNum}`;
  activeNodeAttacks.set(targetId, {
    attackNum,
    text,
    title: title || '',
    expireTime: now + 3500
  });

  // Incrementa contador do componente no grafo
  const nextCount = (nodeAttackCounts.get(targetId) || 0) + 1;
  nodeAttackCounts.set(targetId, nextCount);

  // Re-renderiza e acorda simulação física para animar o popup e o pulso
  simAlpha = Math.max(simAlpha, 0.4);
  startPhysicsLoop();
  if (state) renderGraph(state);

  // Remove automaticamente o popup temporário após expiração
  setTimeout(() => {
    const item = activeNodeAttacks.get(targetId);
    if (item && item.expireTime <= Date.now() + 100) {
      activeNodeAttacks.delete(targetId);
      if (state) renderGraph(state);
    }
  }, 3600);
}

// ========================================================
// CONTROLE DE TELA CHEIA DO GRAFO TEMPORAL
// ========================================================
window.toggleFullscreenGraph = function() {
  const panel = $('#graphPanel');
  const btn = $('#fullscreenGraphBtn');
  const btnIcon = $('#fsBtnIcon');
  const btnText = $('#fsBtnText');

  isFullscreen = !isFullscreen;
  panel.classList.toggle('fullscreen', isFullscreen);
  document.body.classList.toggle('panel-fullscreen-active', isFullscreen);
  btn.classList.toggle('active', isFullscreen);

  if (isFullscreen) {
    if (btnIcon) btnIcon.textContent = '✕';
    if (btnText) btnText.textContent = 'Restaurar';
    btn.title = 'Sair da Tela Cheia (Esc)';
    toast('Modo Tela Cheia ativado. Pressione ESC para restaurar.');
  } else {
    if (btnIcon) btnIcon.textContent = '⛶';
    if (btnText) btnText.textContent = 'Tela Cheia';
    btn.title = 'Maximizar Grafo em Tela Cheia';
  }

  // Despertar a simulação com expansão física
  simAlpha = 1.0;
  if (state) renderGraph(state);
  startPhysicsLoop();
};

window.addEventListener('keydown', e => {
  if (e.key === 'Escape' && isFullscreen) {
    toggleFullscreenGraph();
  }
});

// ========================================================
// MOTOR DE FÍSICA DINÂMICA (FORCE-DIRECTED GRAPH)
// ========================================================
let simNodes = new Map();
let simEdges = [];
let simAlpha = 0;
let simAnimFrame = null;
let draggedNodeId = null;

function getSvgCoords(svg, clientX, clientY) {
  const pt = svg.createSVGPoint();
  pt.x = clientX;
  pt.y = clientY;
  const ctm = svg.getScreenCTM();
  return ctm ? pt.matrixTransform(ctm.inverse()) : { x: clientX, y: clientY };
}

function startPhysicsLoop() {
  if (simAnimFrame) return;
  simAnimFrame = requestAnimationFrame(physicsTick);
}

function physicsTick() {
  const container = $('#graph');
  if (!container) {
    simAnimFrame = null;
    return;
  }
  const rect = container.getBoundingClientRect();
  const W = Math.max(Math.floor(rect.width) || 760, 680);
  const H = Math.max(Math.floor(rect.height) || 460, 420);

  const nodeList = Array.from(simNodes.values());
  const nLen = nodeList.length;

  // 1. REPULSÃO ENTRE TODOS OS NÓS (Garante que arestas e nós NUNCA fiquem amontoados)
  for (let i = 0; i < nLen; i++) {
    const n1 = nodeList[i];
    for (let j = i + 1; j < nLen; j++) {
      const n2 = nodeList[j];
      let dx = n2.x - n1.x;
      let dy = n2.y - n1.y;
      let dist = Math.hypot(dx, dy);
      if (dist < 1) {
        dx = (Math.random() - 0.5) * 2;
        dy = (Math.random() - 0.5) * 2;
        dist = Math.hypot(dx, dy) || 1;
      }

      // Folga mínima generosa: 70px livre entre nós
      const minDist = n1.r + n2.r + 70;
      const repForce = (7000 / (dist * dist)) + (dist < minDist ? (minDist - dist) * 0.22 : 0);
      const fx = (dx / dist) * repForce;
      const fy = (dy / dist) * repForce;

      if (!n1.isFixed) { n1.vx -= fx; n1.vy -= fy; }
      else { n1.vx -= fx * 0.25; n1.vy -= fy * 0.25; }

      if (!n2.isFixed) { n2.vx += fx; n2.vy += fy; }
      else { n2.vx += fx * 0.25; n2.vy += fy * 0.25; }
    }
  }

  // 2. FORÇA DE MOLA NAS ARESTAS
  for (let i = 0; i < simEdges.length; i++) {
    const edge = simEdges[i];
    const n1 = simNodes.get(edge.from);
    const n2 = simNodes.get(edge.to);
    if (!n1 || !n2) continue;

    const dx = n2.x - n1.x;
    const dy = n2.y - n1.y;
    const dist = Math.hypot(dx, dy) || 1;

    // Arestas longas e espaçadas
    const idealDist = edge.isInfra ? 150 : edge.type === 'PART_OF_INCIDENT' ? 105 : 135;
    const springForce = (dist - idealDist) * 0.038;
    const fx = (dx / dist) * springForce;
    const fy = (dy / dist) * springForce;

    if (!n1.isFixed) { n1.vx += fx; n1.vy += fy; }
    if (!n2.isFixed) { n2.vx -= fx; n2.vy -= fy; }
  }

  // 3. ANCORAGEM ELÁSTICA DOS NÓS FIXOS DA REDE
  for (let i = 0; i < nLen; i++) {
    const n = nodeList[i];
    if (n.isFixed) {
      // Nós de rede retornam suavemente à sua posição arquitetural ideal
      const targetX = W * n.nx;
      const targetY = H * n.ny;
      n.vx += (targetX - n.x) * 0.045;
      n.vy += (targetY - n.y) * 0.045;
    }
  }

  // 4. INTEGRAÇÃO DE VELOCIDADE E AMORTECIMENTO
  const friction = 0.82;
  for (let i = 0; i < nLen; i++) {
    const n = nodeList[i];
    if (n.id === draggedNodeId) continue;

    n.vx *= friction;
    n.vy *= friction;
    n.x += n.vx * simAlpha;
    n.y += n.vy * simAlpha;

    const pad = n.r + 28;
    n.x = Math.max(pad, Math.min(W - pad, n.x));
    n.y = Math.max(pad, Math.min(H - pad, n.y));
  }

  // 5. ATUALIZAR ELEMENTOS SVG EM TEMPO REAL
  for (let i = 0; i < nLen; i++) {
    const n = nodeList[i];
    const nodeEl = document.getElementById('gn-' + n.idx);
    if (nodeEl) {
      nodeEl.setAttribute('transform', `translate(${n.x.toFixed(1)}, ${n.y.toFixed(1)})`);
    }
  }

  for (let i = 0; i < simEdges.length; i++) {
    const edge = simEdges[i];
    const n1 = simNodes.get(edge.from);
    const n2 = simNodes.get(edge.to);
    if (!n1 || !n2) continue;

    const mx = (n1.x + n2.x) / 2;
    const my = (n1.y + n2.y) / 2;

    const lineEl = document.getElementById('ge-line-' + i);
    if (lineEl) {
      lineEl.setAttribute('x1', n1.x.toFixed(1));
      lineEl.setAttribute('y1', n1.y.toFixed(1));
      lineEl.setAttribute('x2', n2.x.toFixed(1));
      lineEl.setAttribute('y2', n2.y.toFixed(1));
    }

    const badgeEl = document.getElementById('ge-badge-' + i);
    if (badgeEl) {
      badgeEl.setAttribute('transform', `translate(${mx.toFixed(1)}, ${my.toFixed(1)})`);
    }
  }

  simAlpha *= 0.988;
  if (simAlpha > 0.003 || draggedNodeId !== null) {
    simAnimFrame = requestAnimationFrame(physicsTick);
  } else {
    simAnimFrame = null;
  }
}

function hintWidthForEdge(edge, fallback) {
  return fallback || 180;
}

// DETERMINAR METADADOS E ÍCONE DA ARESTA
function getEdgeInfo(edge, s, currentStep) {
  if (edge.isInfra) {
    return {
      lsn: null,
      ev: null,
      att: null,
      isCurrentAttack: false,
      icon: edge.icon || '🌐',
      badgeColor: '#0c326f',
      badgeBg: '#f0f5fc',
      attackTitle: edge.title || 'Infraestrutura STF',
      outcomeText: ''
    };
  }

  let lsn = null;
  if (edge.to && edge.to.startsWith('event:')) {
    lsn = parseInt(edge.to.replace('event:', ''), 10);
  } else if (edge.from && edge.from.startsWith('event:')) {
    lsn = parseInt(edge.from.replace('event:', ''), 10);
  }

  const ev = (s.events && lsn) ? s.events.find(e => e.lsn === lsn) : null;
  const att = lsn && lsn <= ATTACKS.length ? ATTACKS[lsn - 1] : null;
  // Campanha: o passo atual; ataques do menu: o LSN real acabado de disparar
  const isCampaignStep = Boolean(currentStep && lsn === currentStep && lsn <= ATTACKS.length);
  const isCurrentAttack = isCampaignStep || isLiveAttackLsn(lsn);

  let icon = '⚡';
  let badgeColor = '#0c326f';
  let badgeBg = '#f0f5fc';

  if (edge.type === 'PART_OF_INCIDENT') {
    icon = '🚨';
    badgeColor = '#c9182b';
    badgeBg = '#fdebee';
  } else if (ev) {
    if (ev.outcome === 'DENY') {
      // Bloqueado = não invadiu (verde, igual à legenda dos gráficos)
      icon = '🛡️';
      badgeColor = '#2fa66a';
      badgeBg = '#e9f7ef';
    } else if (ev.outcome === 'REQUIRE_HITL') {
      icon = '⚠️';
      badgeColor = '#b87704';
      badgeBg = '#fff8e8';
    } else if (ev.outcome === 'DETECTED') {
      icon = '🛡️';
      badgeColor = '#2fa66a';
      badgeBg = '#e9f7ef';
    } else if (ev.outcome === 'PASS' || ev.outcome === 'ALLOW' || ev.outcome === 'MISSED') {
      // Chegou ao alvo = invadiu (roxo)
      icon = '⚠️';
      badgeColor = '#7a3fbf';
      badgeBg = '#f3ecfb';
    } else if (ev.actor && ev.actor.includes('human')) {
      icon = '✍️';
      badgeColor = '#147a24';
      badgeBg = '#eaf8ed';
    } else if (ev.event_type && ev.event_type.includes('lateral')) {
      icon = '🔀';
      badgeColor = '#b87704';
      badgeBg = '#fff8e8';
    } else if (ev.event_type && (ev.event_type.includes('login') || ev.event_type.includes('process') || ev.event_type.includes('query'))) {
      icon = '⚔️';
      badgeColor = '#df9b15';
      badgeBg = '#fff8e8';
    } else if (ev.asset && (ev.asset.includes('public-edge') || ev.asset.includes('edge'))) {
      icon = '🛡️';
      badgeColor = '#0c326f';
      badgeBg = '#f0f5fc';
    } else if (ev.asset && ev.asset.includes('case')) {
      icon = '🏛️';
      badgeColor = '#0c326f';
      badgeBg = '#f0f5fc';
    } else {
      icon = '⚡';
    }
  }

  const attackTitle = att ? att.title : (ev ? `${ev.event_type}` : 'Conexão');
  const outcomeText = ev ? ` [${ev.outcome}]` : '';

  return {
    lsn,
    ev,
    att,
    isCurrentAttack,
    icon,
    badgeColor,
    badgeBg,
    attackTitle,
    outcomeText
  };
}

// ========================================================
// RENDERIZAÇÃO DO GRAFO (REDE FIXA + ATAQUES DINÂMICOS)
// ========================================================
// ========================================================
// CAMINHO DE ATAQUE "AO VIVO" (MESMO EFEITO DA CAMPANHA PARA OS ATAQUES DO MENU)
// ========================================================
const liveAttackLsns = new Map(); // lsn -> expireTime

function markLiveAttackLsn(lsn) {
  const n = Number(lsn);
  if (!Number.isFinite(n) || n <= 0) return;
  liveAttackLsns.set(n, Date.now() + 3500);
}

function isLiveAttackLsn(lsn) {
  const exp = liveAttackLsns.get(lsn);
  if (!exp) return false;
  if (exp > Date.now()) return true;
  liveAttackLsns.delete(lsn);
  return false;
}

// Os eventos dos ataques do menu trazem asset "asset:x" e o servidor prefixa de novo
// ("asset:asset:x"); os endpoints reais do HeraclitusDB vêm como URL. Normaliza tudo
// para o nó fixo da rede, para o caminho do ataque ligar ao componente real.
const FIXED_NODE_IDS = new Set();
function canonicalNodeId(id) {
  if (!id || !id.startsWith('asset:')) return id;
  let bare = id.slice('asset:'.length);
  while (bare.startsWith('asset:')) bare = bare.slice('asset:'.length);
  const direct = `asset:${bare}`;
  if (FIXED_NODE_IDS.has(direct)) return direct;
  const mapped = findNodeIdForTarget(bare);
  return mapped && FIXED_NODE_IDS.has(mapped) ? mapped : direct;
}

// Mantém só os eventos mais recentes (e quem está ligado a eles) para o grafo ficar legível
const MAX_GRAPH_EVENTS = 18;
function buildDynamicGraph(s) {
  if (!FIXED_NODE_IDS.size) FIXED_INFRA_NODES.forEach(n => FIXED_NODE_IDS.add(n.id));

  const nodesById = new Map();
  for (const n of s?.graph?.nodes || []) {
    const id = canonicalNodeId(n.id);
    if (!nodesById.has(id)) nodesById.set(id, { ...n, id });
  }

  const seen = new Set();
  const edges = [];
  for (const e of s?.graph?.edges || []) {
    const from = canonicalNodeId(e.from);
    const to = canonicalNodeId(e.to);
    const key = `${from}|${to}|${e.type}`;
    if (from === to || seen.has(key)) continue;
    seen.add(key);
    edges.push({ ...e, from, to });
  }

  // Ordem de chegada no grafo do servidor (a campanha usa LSN local e o menu o LSN real do ledger)
  const recentEvents = [...nodesById.values()]
    .filter(n => n.kind === 'event')
    .slice(-MAX_GRAPH_EVENTS);
  // Só um salto a partir dos eventos recentes (senão o atacante puxa todos os eventos antigos)
  const recentIds = new Set(recentEvents.map(n => n.id));
  const keep = new Set(recentIds);
  for (const e of edges) {
    if (recentIds.has(e.from)) keep.add(e.to);
    if (recentIds.has(e.to)) keep.add(e.from);
  }
  for (const n of nodesById.values()) if (n.kind === 'incident') keep.add(n.id);

  return {
    nodes: [...nodesById.values()].filter(n => keep.has(n.id)),
    edges: edges.filter(e => keep.has(e.from) && keep.has(e.to))
  };
}

// Cores da legenda única (iguais às dos gráficos em styles.css)
const LEGEND = { attack: '#c9182b', blocked: '#2fa66a', blockedText: '#1d7a4a', breached: '#7a3fbf' };

function renderGraph(s) {
  const e = $('#graph');
  const dyn = buildDynamicGraph(s);
  const rawNodes = dyn.nodes;
  const rawEdges = dyn.edges;

  // Botão de tela cheia
  const fsBtn = $('#fullscreenGraphBtn');
  if (fsBtn) fsBtn.onclick = () => toggleFullscreenGraph();

  // Banner do ataque ativo (opcional)
  const currentStep = s?.step || 0;
  const currentAttack = currentStep > 0 ? ATTACKS[currentStep - 1] : null;
  const nextAttack = currentStep < ATTACKS.length ? ATTACKS[currentStep] : null;

  const bit = $('#bannerInfraTarget');
  const ban = $('#bannerAttackName');
  if (bit && ban) {
    if (currentAttack) {
      bit.textContent = `${currentAttack.infra} (${currentAttack.target})`;
      ban.textContent = currentAttack.title;
    } else {
      bit.textContent = 'Infraestrutura Ativa • Topologia do STF';
      ban.textContent = `Próximo: ${nextAttack ? nextAttack.title : 'Nenhum'}`;
    }
  }

  const rect = e.getBoundingClientRect();
  const W = Math.max(Math.floor(rect.width) || 760, 680);
  const H = Math.max(Math.floor(rect.height) || 520, 460);

  // 1. CARREGAR NÓS FIXOS DA REDE DO STF (SEMPRE VISÍVEIS)
  FIXED_INFRA_NODES.forEach((fn, idx) => {
    if (!simNodes.has(fn.id)) {
      simNodes.set(fn.id, {
        id: fn.id,
        kind: fn.kind,
        label: fn.label,
        friendlyName: fn.friendlyName,
        icon: fn.icon,
        isFixed: true,
        nx: fn.nx,
        ny: fn.ny,
        r: fn.r,
        idx: idx,
        x: W * fn.nx,
        y: H * fn.ny,
        vx: 0,
        vy: 0,
        style: { r: fn.r, fill: '#f0f5fc', stroke: '#0c326f', iconSize: 15 }
      });
    } else {
      const existing = simNodes.get(fn.id);
      existing.isFixed = true;
      existing.nx = fn.nx;
      existing.ny = fn.ny;
      existing.idx = idx;
    }
  });

  // 2. SINCRONIZAR NÓS DINÂMICOS DE ATAQUE (Invasor, Eventos, Incidente)
  let nextIdx = FIXED_INFRA_NODES.length;
  const activeIds = new Set(FIXED_INFRA_NODES.map(n => n.id));

  // buildDynamicGraph já limitou aos eventos recentes
  rawNodes.forEach(n => {
    activeIds.add(n.id);
    if (simNodes.has(n.id)) return;

    let friendlyName = n.label;
    let icon = '⚡';
    let r = 14;
    let fill = '#ffffff';
    let stroke = '#1351b4';
    let iconSize = 10;

    if (n.kind === 'incident') {
      friendlyName = `INCIDENTE ${n.label}`;
      icon = '🚨';
      r = 25;
      fill = '#fff0f2';
      stroke = '#c9182b';
      iconSize = 17;
    } else if (n.kind === 'actor') {
      friendlyName = n.label.includes('ai') ? 'Agente Atacante' : 'Identidade Invasora (Conta 17)';
      icon = n.label.includes('ai') ? '🤖' : '👤';
      r = 18;
      fill = '#fff8e8';
      stroke = '#b87704';
      iconSize = 13;
    }

    // Posição de entrada dinâmica perto da área do invasor ou centro
    const angle = Math.random() * Math.PI * 2;
    const dist = 30 + Math.random() * 80;
    const startX = n.kind === 'incident' ? W * 0.55 : (W * 0.18 + Math.cos(angle) * dist);
    const startY = n.kind === 'incident' ? H * 0.35 : (H * 0.25 + Math.sin(angle) * dist);

    simNodes.set(n.id, {
      id: n.id,
      kind: n.kind,
      label: n.label,
      friendlyName,
      icon,
      isFixed: false,
      r,
      idx: nextIdx++,
      x: startX,
      y: startY,
      vx: (Math.random() - 0.5) * 5,
      vy: (Math.random() - 0.5) * 5,
      style: { r, fill, stroke, iconSize }
    });
  });

  // Remover nós dinâmicos antigos não mais em cena
  for (const [id, node] of simNodes.entries()) {
    if (!node.isFixed && !activeIds.has(id)) {
      simNodes.delete(id);
    }
  }

  // 3. COMBINAR ARESTAS FIXAS DA REDE + ARESTAS DINÂMICAS DE ATAQUE
  const infraEdgesWithFlag = FIXED_INFRA_EDGES.map(e => ({ ...e, isInfra: true }));
  const dynamicEdgesWithFlag = rawEdges
    .filter(e => simNodes.has(e.from) && simNodes.has(e.to))
    .map(e => ({ ...e, isInfra: false }));

  simEdges = [...infraEdgesWithFlag, ...dynamicEdgesWithFlag];
  $('#graphStats').textContent = `${simNodes.size} nós / ${simEdges.length} arestas`;

  // Relógio único do frame: usado pelas arestas (passo 4) e pelos nós (passo 5)
  const now = Date.now();

  // 4. RENDERIZAR ARESTAS COM ÍCONES NO CENTRO (SEM POPUPS EM CIMA DO GRAFO)
  const linesAndBadges = simEdges.map((x, i) => {
    const n1 = simNodes.get(x.from);
    const n2 = simNodes.get(x.to);
    if (!n1 || !n2) return '';

    const mx = (n1.x + n2.x) / 2;
    const my = (n1.y + n2.y) / 2;
    const edgeInfo = getEdgeInfo(x, s, currentStep);
    const hasNodeAttack = (activeNodeAttacks.has(x.from) && activeNodeAttacks.get(x.from).expireTime > now) ||
                          (activeNodeAttacks.has(x.to) && activeNodeAttacks.get(x.to).expireTime > now);
    // Acende o caminho do ataque atual e a rede até ao componente atingido (não os eventos antigos desse nó)
    const isAttack = edgeInfo.isCurrentAttack || (hasNodeAttack && x.isInfra);

    return `
      <g class="graph-edge-group ${isAttack ? 'active-attack-edge' : ''} ${x.isInfra ? 'infra-edge' : 'attack-edge'}">
        <line id="ge-line-${i}" x1="${n1.x}" y1="${n1.y}" x2="${n2.x}" y2="${n2.y}" 
              class="graph-line ${isAttack ? 'attack-pulse-line' : x.isInfra ? 'infra-line' : ''}" 
              stroke="${isAttack ? '#c9182b' : x.isInfra ? '#cbd7e4' : edgeInfo.badgeColor}" 
              stroke-width="${isAttack ? 3.2 : x.isInfra ? 1.5 : 2}" />

        <!-- ÍCONE NO CENTRO DA ARESTA -->
        <g id="ge-badge-${i}" class="edge-icon-badge" transform="translate(${mx}, ${my})">
          <circle cx="0" cy="0" r="${isAttack ? 13 : x.isInfra ? 9 : 10}" 
                  fill="${edgeInfo.badgeBg}" 
                  stroke="${isAttack ? '#c9182b' : x.isInfra ? '#9bb3cc' : edgeInfo.badgeColor}" 
                  stroke-width="${isAttack ? 2.5 : 1.5}" />
          <text x="0" y="0" text-anchor="middle" dominant-baseline="central" 
                font-size="${isAttack ? 12 : x.isInfra ? 9 : 9.5}" class="edge-glyph">${edgeInfo.icon}</text>
        </g>
      </g>
    `;
  }).join('');

  // 5. RENDERIZAR NÓS ARRASTÁVEIS COM POPUP DE NÚMERO DO ATAQUE E HOVER NO CANTO INFERIOR DIREITO
  const circles = Array.from(simNodes.values()).map(n => {
    const isIncident = n.kind === 'incident';
    const isSelected = selectedNode && selectedNode.id === n.id;
    const isTargeted = currentAttack && (n.label === currentAttack.target || n.id.includes(currentAttack.target));
    const attackPopup = activeNodeAttacks.get(n.id);
    const hasActiveAttack = attackPopup && attackPopup.expireTime > now;
    const attackCount = nodeAttackTotal(n.id);

    // Legenda: vermelho = a ser atacado agora; depois fica verde se tudo foi bloqueado
    // (não invadiu) ou roxo se algum ataque chegou ao alvo (invadiu)
    const isUnderAttackNow = Boolean(isTargeted || hasActiveAttack);
    const hasBeenAttacked = attackCount > 0;
    const outcomes = nodeOutcomeTotals(n.id);
    const wasBreached = outcomes.passed > 0;

    let nodeFill = n.style.fill;
    let nodeStroke = n.style.stroke;
    let nodeStrokeWidth = 2;

    if (isUnderAttackNow) {
      nodeFill = LEGEND.attack;
      nodeStroke = '#ffffff';
      nodeStrokeWidth = 3.5;
    } else if (hasBeenAttacked && wasBreached) {
      nodeFill = '#f3ecfb';
      nodeStroke = LEGEND.breached;
      nodeStrokeWidth = 3;
    } else if (hasBeenAttacked) {
      nodeFill = '#e9f7ef';
      nodeStroke = LEGEND.blocked;
      nodeStrokeWidth = 3;
    } else if (isSelected) {
      nodeStroke = '#df9b15';
      nodeStrokeWidth = 3;
    }

    // Vermelho leva caveira (tentativas), tal como o verde leva ✓ (bloqueados)
    const countStr = `☠${attackCount}`;
    const pillW = Math.max(30, countStr.length * 7 + 12);

    return `
      <g class="graph-node ${n.isFixed ? 'fixed-network-node' : 'dynamic-attack-node'} ${isUnderAttackNow ? 'targeted-node attack-active-now' : ''} ${hasBeenAttacked ? 'node-has-attacks' : ''}" 
         id="gn-${n.idx}" data-node-id="${esc(n.id)}" 
         transform="translate(${n.x}, ${n.y})" 
         onmouseenter="showNodeHintBottomRight('${esc(n.id)}', '${esc(n.friendlyName)}', '${esc(n.kind)}')"
         onmouseleave="hideNodeHintBottomRight()"
         onclick="selectGraphNode('${esc(n.id)}', '${esc(n.kind)}', '${esc(n.friendlyName)}')">
        
        <!-- ANÉIS DE PULSO DE ALARME QUANDO SOB ATAQUE -->
        ${isIncident ? `<circle cx="0" cy="0" r="${n.r + 7}" fill="none" stroke="#c9182b" stroke-width="2" stroke-dasharray="4 3" class="pulse-ring"/>` : ''}
        ${isUnderAttackNow ? `
          <circle cx="0" cy="0" r="${n.r + 8}" fill="none" stroke="#c9182b" stroke-width="3" class="pulse-ring attack-node-pulse-ring"/>
          <circle cx="0" cy="0" r="${n.r + 16}" fill="rgba(201, 24, 43, 0.25)" stroke="#c9182b" stroke-width="1.5" class="pulse-ring attack-node-pulse-ring"/>
        ` : ''}
        ${isSelected ? `<circle cx="0" cy="0" r="${n.r + 5}" fill="none" stroke="#df9b15" stroke-width="3" />` : ''}
        
        <!-- CÍRCULO PRINCIPAL DO NÓ (FICA VERMELHO) -->
        <circle cx="0" cy="0" r="${n.r}" fill="${nodeFill}" stroke="${nodeStroke}" stroke-width="${nodeStrokeWidth}" class="${isUnderAttackNow ? 'circle-under-attack' : ''}" />
        
        ${n.id === 'asset:heraclitusdb' ? `
          <!-- ESCUDO VERDE E AMARELO (HERACLITUSDB) -->
          <g class="escudo-verde-amarelo" transform="scale(1.15)">
            <path d="M 0 -20 C 14 -20, 18 -12, 18 0 C 18 12, 8 20, 0 24 C -8 20, -18 12, -18 0 C -18 -12, -14 -20, 0 -20 Z" fill="#000000" opacity="0.35" transform="translate(0, 2)" />
            <path d="M 0 -20 C 14 -20, 18 -12, 18 0 C 18 12, 8 20, 0 24 C -8 20, -18 12, -18 0 C -18 -12, -14 -20, 0 -20 Z" fill="${isUnderAttackNow ? '#ff4d4f' : '#ffd000'}" />
            <path d="M 0 -18 C 12 -18, 15.5 -10.5, 15.5 0 C 15.5 10.5, 7 17.5, 0 21.5 C -7 17.5, -15.5 10.5, -15.5 0 C -15.5 -10.5, -12 -18, 0 -18 Z" fill="${isUnderAttackNow ? '#b71c1c' : '#009b3a'}" />
            <polygon points="0,-13 12,0 0,13 -12,0" fill="${isUnderAttackNow ? '#ffd54f' : '#fedf00'}" stroke="${isUnderAttackNow ? '#ffffff' : '#007a2a'}" stroke-width="0.8" />
            <circle cx="0" cy="0" r="5.8" fill="${isUnderAttackNow ? '#7f0000' : '#006428'}" stroke="#ffffff" stroke-width="0.7" />
            <polygon points="0,-4.5 1.3,-1.2 4.8,-1.2 2.0,0.9 3.0,4.2 0,2.2 -3.0,4.2 -2.0,0.9 -4.8,-1.2 -1.3,-1.2" fill="#ffffff" />
          </g>
        ` : `
          <text x="0" y="0" text-anchor="middle" dominant-baseline="central" font-size="${n.style.iconSize}" class="node-icon">${n.icon}</text>
        `}
        
        <!-- RÓTULO DO COMPONENTE -->
        <text x="0" y="${n.r + 14}" text-anchor="middle" class="node-label ${hasBeenAttacked ? 'label-attacked' : ''}">
          ${esc(short(n.friendlyName, 22))}
        </text>

        <!-- SUBRÓTULO: TENTATIVAS (VERMELHO) · BLOQUEADOS (VERDE ✓) · INVADIU (ROXO) -->
        ${hasBeenAttacked ? `
          <text x="0" y="${n.r + 26}" text-anchor="middle" font-size="9.5" font-weight="900" class="attack-count-sublabel">
            <tspan fill="${LEGEND.attack}">${attackCount} ${attackCount === 1 ? 'ataque' : 'ataques'}</tspan>${outcomes.blocked ? `<tspan fill="${LEGEND.blockedText}"> · ✓${outcomes.blocked} bloq.</tspan>` : ''}${wasBreached ? `<tspan fill="${LEGEND.breached}"> · ${outcomes.passed} invadiu</tspan>` : ''}
          </text>
        ` : ''}

        <!-- CONTADORES NO COMPONENTE: tentativas (vermelho, direita) e bloqueados (verde ✓, esquerda) -->
        ${hasBeenAttacked ? `
          <g class="node-attack-counter-badge ${isUnderAttackNow ? 'counter-pulse-anim' : ''}" transform="translate(${n.r * 0.72}, ${-n.r * 0.72})">
            <title>${attackCount} tentativas de ataque</title>
            <rect x="${-pillW / 2}" y="-10" width="${pillW}" height="20" rx="10" fill="${LEGEND.attack}" stroke="#ffffff" stroke-width="2" class="popup-rect-shadow" />
            <text x="0" y="0" text-anchor="middle" dominant-baseline="central" fill="#ffffff" font-size="11" font-weight="900" font-family="ui-monospace, Consolas, monospace">
              ${countStr}
            </text>
          </g>
        ` : ''}
        ${outcomes.blocked ? (() => {
          const bStr = `✓${outcomes.blocked}`;
          const bW = Math.max(26, bStr.length * 7 + 10);
          return `
          <g class="node-blocked-badge" transform="translate(${-n.r * 0.72}, ${-n.r * 0.72})">
            <title>${outcomes.blocked} bloqueados — não invadiu</title>
            <rect x="${-bW / 2}" y="-10" width="${bW}" height="20" rx="10" fill="${LEGEND.blocked}" stroke="#ffffff" stroke-width="2" />
            <text x="0" y="0" text-anchor="middle" dominant-baseline="central" fill="#ffffff" font-size="11" font-weight="900" font-family="ui-monospace, Consolas, monospace">${bStr}</text>
          </g>`;
        })() : ''}
        ${wasBreached ? `
          <g class="node-breached-badge" transform="translate(${n.r * 0.72}, ${n.r * 0.72})">
            <title>${outcomes.passed} chegaram ao alvo — invadiu</title>
            <rect x="-12" y="-10" width="24" height="20" rx="10" fill="${LEGEND.breached}" stroke="#ffffff" stroke-width="2" />
            <text x="0" y="0" text-anchor="middle" dominant-baseline="central" fill="#ffffff" font-size="11" font-weight="900" font-family="ui-monospace, Consolas, monospace">${outcomes.passed}</text>
          </g>
        ` : ''}

        <!-- POPUP DO ATAQUE: APARECE NO NÓ SOB ATAQUE -->
        ${hasActiveAttack ? `
          <g class="node-attack-badge-popup">
            <polygon points="0,${-n.r - 4} -5,${-n.r - 10} 5,${-n.r - 10}" fill="#c9182b" />
            <rect x="${-Math.max(96, (attackPopup.text.length + 3) * 7.5) / 2}" y="${-n.r - 34}" width="${Math.max(96, (attackPopup.text.length + 3) * 7.5)}" height="24" rx="12" fill="#c9182b" stroke="#ffffff" stroke-width="2" class="popup-rect-shadow" />
            <text x="0" y="${-n.r - 21}" text-anchor="middle" dominant-baseline="central" fill="#ffffff" font-size="11.5" font-weight="900" font-family="system-ui, -apple-system, sans-serif">
              ⚡ ${esc(attackPopup.text)}
            </text>
          </g>
        ` : ''}
      </g>
    `;
  }).join('');

  e.innerHTML = `
    <svg id="graphSvg" viewBox="0 0 ${W} ${H}" width="100%" height="100%">
      <g class="graph-edges-layer">${linesAndBadges}</g>
      <g class="graph-nodes-layer">${circles}</g>
    </svg>
    <div class="graph-legend" aria-label="Legenda do grafo">
      <span class="lg-item"><span class="lg-dot" style="background:${LEGEND.attack}">☠</span>tentativas de ataque</span>
      <span class="lg-item"><span class="lg-dot" style="background:${LEGEND.blocked}">✓</span>bloqueado — não invadiu</span>
      <span class="lg-item"><span class="lg-dot" style="background:${LEGEND.breached}">2</span>chegou ao alvo — invadiu</span>
    </div>
  `;

  // Configurar eventos de arrastar nós
  const svg = document.getElementById('graphSvg');
  if (svg) {
    svg.onmousedown = (evt) => {
      const nodeG = evt.target.closest('.graph-node');
      if (!nodeG) return;
      const nodeId = nodeG.getAttribute('data-node-id');
      if (!nodeId) return;

      draggedNodeId = nodeId;
      dragStart = { x: evt.clientX, y: evt.clientY };
      dragMoved = false;
      nodeG.classList.add('dragging');
      simAlpha = 0.85;
      startPhysicsLoop();
    };
  }

  // Despertar relaxamento físico
  simAlpha = Math.max(simAlpha, 0.7);
  startPhysicsLoop();
}

// ARRASTAR NÓS COM O MOUSE (um arrasto não conta como clique de seleção)
let dragStart = null;
let dragMoved = false;
window.addEventListener('mousemove', evt => {
  if (!draggedNodeId) return;
  if (dragStart && Math.hypot(evt.clientX - dragStart.x, evt.clientY - dragStart.y) > 5) dragMoved = true;
  const svg = document.getElementById('graphSvg');
  if (!svg) return;

  const p = getSvgCoords(svg, evt.clientX, evt.clientY);
  const n = simNodes.get(draggedNodeId);
  if (n) {
    n.x = p.x;
    n.y = p.y;
    n.vx = 0;
    n.vy = 0;
    simAlpha = Math.max(simAlpha, 0.4);
    startPhysicsLoop();
  }
});

window.addEventListener('mouseup', () => {
  if (draggedNodeId) {
    const nodeG = document.querySelector(`.graph-node[data-node-id="${draggedNodeId}"]`);
    if (nodeG) nodeG.classList.remove('dragging');
    draggedNodeId = null;
    simAlpha = 0.5;
    startPhysicsLoop();
  }
});

// SELEÇÃO DE NÓ NO GRAFO
window.selectGraphNode = function(id, kind, label) {
  if (dragMoved) { dragMoved = false; return; }
  selectedNode = { id, kind, label };
  $('#focusAsset').textContent = label;
  $('#focusNarrative').textContent = `Nó selecionado na infraestrutura: [${kind.toUpperCase()}] ${label}.`;
  setNodeFilter(id, label);
  if (!nodeFilter) selectedNode = null;
  if (state) renderGraph(state);
};

// ========================================================
// ATUALIZAÇÃO DO CARD DE FOCO DO DIAGNÓSTICO
// ========================================================
function updateFocusCard(s) {
  const ev = s?.events && s.events.length ? s.events[s.events.length - 1] : null;
  const badge = $('#lastActionBadge');

  if (!ev) {
    $('#focusAsset').textContent = '—';
    $('#focusActor').textContent = '—';
    $('#focusDecision').textContent = '—';
    $('#focusUpstream').textContent = '0';
    $('#focusNarrative').textContent = 'Topologia da infraestrutura do STF pronta. Dispare um ataque à esquerda para visualizar o impacto no grafo.';
    badge.textContent = 'PRONTO';
    badge.className = 'status-pill ready';
    return;
  }

  $('#focusAsset').textContent = ev.asset || '—';
  $('#focusActor').textContent = ev.actor || '—';

  const dec = ev.details?.policy_decision;
  if (dec) {
    $('#focusDecision').textContent = `${ev.outcome} (${dec.reason_code || 'POLÍTICA'})`;
    badge.textContent = ev.outcome;
    badge.className = ev.outcome === 'DENY' ? 'status-pill deny' : 'status-pill ready';
  } else {
    $('#focusDecision').textContent = ev.outcome || 'OBSERVADO';
    badge.textContent = ev.outcome;
    badge.className = 'status-pill ready';
  }

  $('#focusUpstream').textContent = ev.upstream_delta ?? 0;
  $('#focusNarrative').textContent = `[${formatDateTime(ev)}] LSN ${ev.lsn} (${ev.source}): ${ev.summary}`;
}

// ========================================================
// PAINEL INFERIOR: TRILHA (Eventos e Rastros) — DADOS REAIS HERACLITUSDB COM PAGINAÇÃO
// ========================================================
let hdbCurrentPage = 1;
let hdbPageSize = 15;
let hdbAllEvents = [];
let hdbLedgerLimit = 500;

async function loadRealHeraclitusTrail() {
  const badge = $('#integrationBadge');
  const summaryBadge = $('#heraclitusSummaryBadge');
  const rows = $('#heraclitusEventRows');
  if (!rows) return;

  try {
    const res = await api('/api/heraclitus-events');
    const data = res.data || {};
    const events = data.events || [];
    if (res.limit) hdbLedgerLimit = res.limit;

    if (res.status === 'PASS' && Array.isArray(events)) {
      if (badge) {
        badge.textContent = 'CONECTADO (WSL 8080)';
        badge.className = 'tag-status normal';
      }
      if (summaryBadge) {
        summaryBadge.textContent = `${events.length} eventos reais registrados no Ledger HRKL`;
        summaryBadge.style.color = 'var(--gov-green-light)';
      }

      // Ordena por LSN decrescente para os mais recentes ficarem no topo
      hdbAllEvents = [...events].sort((a, b) => (Number(b.lsn) || 0) - (Number(a.lsn) || 0));
      renderHdbPage();
      renderIncidentCharts();
    } else {
      if (badge) {
        badge.textContent = 'OFFLINE (WSL 8080)';
        badge.className = 'tag-status';
      }
      if (summaryBadge) {
        summaryBadge.textContent = 'HeraclitusDB local indisponível';
      }
      rows.innerHTML = `<tr><td colspan="9" class="empty">HeraclitusDB não respondeu na porta 8080 do WSL (${esc(res.error || 'Indisponível')}).</td></tr>`;
      updateHdbPaginationControls(0, 0, 0);
    }
  } catch (err) {
    if (badge) {
      badge.textContent = 'ERRO CONEXÃO';
      badge.className = 'tag-status';
    }
    if (summaryBadge) {
      summaryBadge.textContent = 'Erro ao consultar HeraclitusDB';
    }
    rows.innerHTML = `<tr><td colspan="9" class="empty">Erro ao conectar ao HeraclitusDB: ${esc(err.message)}</td></tr>`;
    updateHdbPaginationControls(0, 0, 0);
  }
}

function renderHdbPage() {
  const rows = $('#heraclitusEventRows');
  if (!rows) return;

  const total = hdbAllEvents.length;
  if (!total) {
    rows.innerHTML = '<tr><td colspan="9" class="empty">HeraclitusDB conectado. Nenhum evento registrado no ledger. Dispare um ataque acima.</td></tr>';
    updateHdbPaginationControls(0, 0, 0);
    return;
  }

  const totalPages = Math.max(1, Math.ceil(total / hdbPageSize));
  if (hdbCurrentPage > totalPages) hdbCurrentPage = totalPages;
  if (hdbCurrentPage < 1) hdbCurrentPage = 1;

  const startIndex = (hdbCurrentPage - 1) * hdbPageSize;
  const endIndex = Math.min(startIndex + hdbPageSize, total);
  const pageSlice = hdbAllEvents.slice(startIndex, endIndex);

  rows.innerHTML = pageSlice.map(ev => {
    let dtStr = '—';
    if (ev.observed_at_unix_nanos) {
      try {
        const ms = Math.floor(Number(ev.observed_at_unix_nanos) / 1000000);
        dtStr = new Date(ms).toLocaleString('pt-BR');
      } catch (_) {
        dtStr = String(ev.observed_at_unix_nanos);
      }
    }

    const resUpper = (ev.result || 'UNKNOWN').toUpperCase();
    const decision = classifyDecision(ev);
    let badgeClass = 'PASS';
    let label = resUpper;
    if (decision === 'PASS') {
      badgeClass = 'PASS';
      label = 'CHEGOU AO ALVO';
    } else if (decision === 'DENY') {
      badgeClass = 'DENY';
      label = 'BLOQUEADO';
    } else if (decision === 'OBSERVED' && resUpper !== 'OBSERVED') {
      badgeClass = 'OBSERVED';
      label = 'SONDAGEM SEM EFEITO';
    } else if (resUpper === 'REQUIRE_HITL') {
      badgeClass = 'REQUIRE_HITL';
      label = 'RETIDO (HITL)';
    } else if (resUpper === 'APPROVED') {
      badgeClass = 'APPROVED';
      label = 'APROVADO';
    } else if (resUpper === 'OBSERVED') {
      badgeClass = 'OBSERVED';
      label = 'OBSERVADO';
    } else if (resUpper === 'PASS' || resUpper === 'ALLOW') {
      badgeClass = 'PASS';
      label = 'CHEGOU AO ALVO';
    } else if (resUpper === 'INCONCLUSIVE') {
      badgeClass = 'INCONCLUSIVE';
      label = 'INCONCLUSIVO';
    }

    const reasonHtml = ev.reason_code ? `<br><small style="color:var(--gov-muted); font-size:10px;">${esc(ev.reason_code)}</small>` : '';
    const upstreamVal = ev.upstream_delta ?? 0;
    const upstreamColor = upstreamVal > 0 ? 'var(--gov-green)' : 'var(--gov-muted)';

    return `
      <tr>
        <td><strong style="color:var(--gov-blue-light); font-size:13px;">${ev.lsn ?? '—'}</strong></td>
        <td><span class="trail-timestamp">${dtStr}</span></td>
        <td><code style="color:var(--gov-text); font-size:11px;">${esc(short(ev.attack_id || '—', 22))}</code></td>
        <td><strong style="color:var(--gov-text);">${esc(ev.vector || '—')}</strong></td>
        <td><code style="color:var(--gov-gold); font-weight:700;">${esc(short(ev.target || '—', 26))}</code></td>
        <td><span class="outcome-tag ${badgeClass}">${label}</span>${reasonHtml}</td>
        <td style="font-weight:900; color:${upstreamColor}; text-align:center;">${upstreamVal}</td>
        <td><code title="${esc(ev.record_hash || '')}">${esc(short(ev.record_hash || '—', 14))}</code></td>
        <td><code style="font-size:10.5px; color:var(--gov-muted);">${esc(short(ev.evidence_id || '—', 18))}</code></td>
      </tr>
    `;
  }).join('');

  updateHdbPaginationControls(startIndex, endIndex, total);
}

function updateHdbPaginationControls(start, end, total) {
  const pageInfo = $('#hdbPageInfo');
  const pageBadge = $('#hdbCurrentPageBadge');
  const totalPagesBadge = $('#hdbTotalPagesBadge');
  const btnFirst = $('#hdbPageFirst');
  const btnPrev = $('#hdbPagePrev');
  const btnNext = $('#hdbPageNext');
  const btnLast = $('#hdbPageLast');

  const totalPages = Math.max(1, Math.ceil(total / hdbPageSize));

  if (pageInfo) {
    if (total === 0) {
      pageInfo.textContent = 'Nenhum registro encontrado';
    } else {
      pageInfo.textContent = `Mostrando ${start + 1}–${end} de ${total} registros`;
    }
  }

  if (pageBadge) pageBadge.textContent = total === 0 ? 0 : hdbCurrentPage;
  if (totalPagesBadge) totalPagesBadge.textContent = totalPages;

  if (btnFirst) btnFirst.disabled = (hdbCurrentPage <= 1 || total === 0);
  if (btnPrev) btnPrev.disabled = (hdbCurrentPage <= 1 || total === 0);
  if (btnNext) btnNext.disabled = (hdbCurrentPage >= totalPages || total === 0);
  if (btnLast) btnLast.disabled = (hdbCurrentPage >= totalPages || total === 0);
}

window.changeHdbPageSize = function(val) {
  hdbPageSize = parseInt(val, 10) || 15;
  hdbCurrentPage = 1;
  renderHdbPage();
};

window.gotoHdbPage = function(action) {
  const total = hdbAllEvents.length;
  const totalPages = Math.max(1, Math.ceil(total / hdbPageSize));

  if (action === 'first') {
    hdbCurrentPage = 1;
  } else if (action === 'prev') {
    hdbCurrentPage = Math.max(1, hdbCurrentPage - 1);
  } else if (action === 'next') {
    hdbCurrentPage = Math.min(totalPages, hdbCurrentPage + 1);
  } else if (action === 'last') {
    hdbCurrentPage = totalPages;
  }
  renderHdbPage();
};

// Aliases para compatibilidade total
function renderTrail(s) {
  loadRealHeraclitusTrail();
}
function loadHeraclitusWslData() {
  loadRealHeraclitusTrail();
}

// ========================================================
// EXECUÇÃO DE ATAQUE ATÉ UM PASSO ESPECÍFICO
// ========================================================
window.executeAttackTo = async function(targetStep) {
  if (running) return;
  if (!state) state = await api('/api/state');

  if (state.step >= targetStep) {
    toast(`O ataque #${targetStep} já foi executado. Clique em "Reiniciar" para recomeçar.`);
    return;
  }

  running = true;
  $('#runBtn').disabled = true;
  $('#stepBtn').disabled = true;

  try {
    while (state.step < targetStep && !state.completed) {
      const nextStep = state.step + 1;
      const r = await api('/api/step', { method: 'POST' });
      render(r);
      const currentAtt = ATTACKS[r.step - 1];
      const lastEv = r.events && r.events.length ? r.events[r.events.length - 1] : null;
      const targetNodeId = findNodeIdForTarget(currentAtt?.target);
      if (targetNodeId && currentAtt) triggerNodeAttackPopup(targetNodeId, currentAtt.step, currentAtt.title, lastEv?.outcome);
      showAttackHint(currentAtt, lastEv);
      loadRealHeraclitusTrail();
      if (state.step < targetStep) {
        await new Promise(res => setTimeout(res, 350));
      }
    }
  } catch (err) {
    toast('Falha ao disparar ataque: ' + err.message);
  } finally {
    running = false;
    $('#runBtn').disabled = false;
    $('#stepBtn').disabled = false;
  }
};

// BOTÕES DE AÇÃO GLOBAIS
$('#stepBtn').onclick = async () => {
  if (state && state.completed) {
    toast('Campanha já concluída. Reinicie para nova execução.');
    return;
  }
  try {
    const r = await api('/api/step', { method: 'POST' });
    render(r);
    const currentAtt = ATTACKS[r.step - 1];
    const lastEv = r.events && r.events.length ? r.events[r.events.length - 1] : null;
    const targetNodeId = findNodeIdForTarget(currentAtt?.target);
    if (targetNodeId && currentAtt) triggerNodeAttackPopup(targetNodeId, currentAtt.step, currentAtt.title, lastEv?.outcome);
    showAttackHint(currentAtt, lastEv);
    toast(`Passo ${r.step} executado com sucesso`);
  } catch (e) {
    toast('Erro no passo: ' + e.message);
  }
};

$('#runBtn').onclick = async () => {
  if (running) return;
  running = true;
  $('#runBtn').disabled = true;
  $('#runBtn').textContent = 'Executando…';

  try {
    while (running && state && !state.completed) {
      const r = await api('/api/step', { method: 'POST' });
      render(r);
      const currentAtt = ATTACKS[r.step - 1];
      const lastEv = r.events && r.events.length ? r.events[r.events.length - 1] : null;
      const targetNodeId = findNodeIdForTarget(currentAtt?.target);
      if (targetNodeId && currentAtt) triggerNodeAttackPopup(targetNodeId, currentAtt.step, currentAtt.title, lastEv?.outcome);
      showAttackHint(currentAtt, lastEv);
      await new Promise(res => setTimeout(res, 380));
    }
    if (state?.completed) toast('Campanha de ataques executada integralmente!');
  } catch (e) {
    toast('Erro durante a execução: ' + e.message);
  } finally {
    running = false;
    $('#runBtn').disabled = false;
    $('#runBtn').textContent = 'Executar Campanha Completa';
  }
};

$('#resetBtn').onclick = async () => {
  running = false;
  try {
    const r = await api('/api/reset', { method: 'POST' });
    nodeAttackCounts.clear();
    render(r);
    toast('Ambiente reiniciado');
  } catch (e) {
    toast('Erro ao reiniciar: ' + e.message);
  }
};

const expBtn = $('#exportBtn');
if (expBtn) {
  expBtn.onclick = async () => {
    try {
      const r = await api('/api/export', { method: 'POST' });
      toast(`Evidence Bundle gerado: ${r.status}`);
    } catch (e) {
      toast('Falha ao exportar bundle: ' + e.message);
    }
  };
}

const dlBtn = $('#downloadBtn');
if (dlBtn) {
  dlBtn.onclick = () => {
    location.href = 'api/evidence/download';
  };
}

// ATUALIZAÇÃO DA BARRA DE INFRAESTRUTURA DO STF NO TOPO
function updateInfraStatusBar(s) {
  const step = s?.step || 0;

  // 1. Firewall / WAF Borda
  const nodeFw = $('#node-fw');
  const statusFw = $('#status-fw');
  if (nodeFw && statusFw) {
    if (step >= 2) {
      nodeFw.className = 'infra-node-item targeted';
      statusFw.textContent = 'SONDAGEM OBSERVADA';
      statusFw.style.color = 'var(--gov-gold)';
    } else {
      nodeFw.className = 'infra-node-item';
      statusFw.textContent = 'PERÍMETRO NORMAL';
      statusFw.style.color = 'var(--gov-green)';
    }
  }

  // 2. Gabinete dos Ministros (VDI)
  const nodeMin = $('#node-ministro');
  const statusMin = $('#status-ministro');
  if (nodeMin && statusMin) {
    if (step >= 13) {
      nodeMin.className = 'infra-node-item compromised';
      statusMin.textContent = 'TROCA IDENTIDADE (DENY)';
      statusMin.style.color = 'var(--gov-red)';
    } else if (step >= 3) {
      nodeMin.className = 'infra-node-item compromised';
      statusMin.textContent = 'SESSÃO ANÔMALA (IAM)';
      statusMin.style.color = 'var(--gov-red)';
    } else {
      nodeMin.className = 'infra-node-item';
      statusMin.textContent = 'AUTENTICAÇÃO SEGURA';
      statusMin.style.color = 'var(--gov-green)';
    }
  }

  // 3. Servidores Linux (SUSE Enterprise)
  const nodeLinux = $('#node-linux');
  const statusLinux = $('#status-linux');
  if (nodeLinux && statusLinux) {
    if (step >= 4) {
      nodeLinux.className = 'infra-node-item compromised';
      statusLinux.textContent = 'PROCESSO ATÍPICO';
      statusLinux.style.color = 'var(--gov-red)';
    } else {
      nodeLinux.className = 'infra-node-item';
      statusLinux.textContent = 'BACKEND REGULAR';
      statusLinux.style.color = 'var(--gov-green)';
    }
  }

  // 4. STF Digital / e-STF
  const nodeStf = $('#node-stfdigital');
  const statusStf = $('#status-stfdigital');
  if (nodeStf && statusStf) {
    if (step >= 8) {
      nodeStf.className = 'infra-node-item compromised';
      statusStf.textContent = 'ESCRITA BARRADA (DENY)';
      statusStf.style.color = 'var(--gov-gold)';
    } else if (step >= 7) {
      nodeStf.className = 'infra-node-item targeted';
      statusStf.textContent = 'AUTOS SOB INCIDENTE';
      statusStf.style.color = 'var(--gov-red)';
    } else {
      nodeStf.className = 'infra-node-item';
      statusStf.textContent = 'AUTOS ÍNTEGROS';
      statusStf.style.color = 'var(--gov-green)';
    }
  }

  // 5. Banco de Dados (Oracle Database RAC)
  const nodeDb = $('#node-db');
  const statusDb = $('#status-db');
  if (nodeDb && statusDb) {
    if (step >= 6) {
      nodeDb.className = 'infra-node-item targeted';
      statusDb.textContent = 'QUERY ANÔMALA';
      statusDb.style.color = 'var(--gov-gold)';
    } else {
      nodeDb.className = 'infra-node-item';
      statusDb.textContent = 'TRANSACIONAL ÍNTEGRO';
      statusDb.style.color = 'var(--gov-green)';
    }
  }

  // 6. Agentes IA & HPC (Victor / MARIA)
  const nodeIa = $('#node-ia');
  const statusIa = $('#status-ia');
  if (nodeIa && statusIa) {
    if (step >= 12) {
      nodeIa.className = 'infra-node-item compromised';
      statusIa.textContent = 'REPLAY BARRADO (DENY)';
      statusIa.style.color = 'var(--gov-red)';
    } else if (step >= 11) {
      nodeIa.className = 'infra-node-item';
      statusIa.textContent = 'EXPORTAÇÃO 1X (OK)';
      statusIa.style.color = 'var(--gov-green)';
    } else if (step >= 9) {
      nodeIa.className = 'infra-node-item targeted';
      statusIa.textContent = 'HITL EXIGIDO';
      statusIa.style.color = 'var(--gov-gold)';
    } else {
      nodeIa.className = 'infra-node-item';
      statusIa.textContent = 'GOVERNANÇA HITL';
      statusIa.style.color = 'var(--gov-green)';
    }
  }

  // 7. HeraclitusDB (Ledger HRKL v6 no WSL)
  const nodeHdb = $('#node-heraclitus');
  const statusHdb = $('#status-heraclitus');
  if (nodeHdb && statusHdb) {
    const lastEv = s?.events && s.events.length ? s.events[s.events.length - 1] : null;
    const realLsn = lastEv?.lsn;
    if (step >= 16) {
      nodeHdb.className = 'infra-node-item targeted';
      statusHdb.textContent = `BUNDLE EXPORTADO (LSN ${realLsn || 3026})`;
      statusHdb.style.color = 'var(--gov-green)';
    } else if (step >= 1) {
      nodeHdb.className = 'infra-node-item targeted';
      statusHdb.textContent = `PERSISTÊNCIA REAL (LSN ${realLsn || 'OK'})`;
      statusHdb.style.color = 'var(--gov-gold)';
    } else {
      nodeHdb.className = 'infra-node-item';
      statusHdb.textContent = 'LEDGER HRKL (WSL 8080)';
      statusHdb.style.color = 'var(--gov-green)';
    }
  }
}

// PAINEL ESQUERDO: LISTA DE ATAQUES DA CAMPANHA STF (17 ATAQUES)
function renderAttackList(s) {
  const container = $('#attackList');
  if (!container) return;
  const currentStep = s?.step || 0;

  container.innerHTML = ATTACKS.map(att => {
    const isExecuted = currentStep >= att.step;
    const isCurrent = currentStep === att.step - 1;
    const ev = isExecuted && s.events ? s.events[att.step - 1] : null;

    let statusText = 'PENDENTE';
    let cardClass = 'attack-card';
    let btnText = 'Disparar Ataque';

    if (isExecuted && ev) {
      statusText = ev.outcome || 'EXECUTADO';
      if (ev.outcome === 'DENY') {
        cardClass += ' executed-deny';
        btnText = '✓ Bloqueado (DENY)';
      } else if (ev.outcome === 'REQUIRE_HITL') {
        cardClass += ' active-step';
        btnText = '✓ Aguardando HITL';
      } else if (ev.outcome === 'DETECTED') {
        cardClass += ' executed-deny';
        btnText = '✓ Detectado (Tamper)';
      } else {
        cardClass += ' executed';
        btnText = '✓ Concluído';
      }
    } else if (isCurrent) {
      cardClass += ' active-step';
      btnText = 'Disparar Agora ▶';
    }

    return `
      <div class="${cardClass}" id="attack-step-${att.step}"${attackCardAttrs(att.target, `${att.infra} → ${att.target}`)}>
        <div class="attack-card-main">
          <div class="attack-meta">
            <span class="attack-phase-tag">${esc(att.phase)}</span>
            <span class="attack-source-tag">${esc(att.infra)}</span>
            <span class="tag-status ${isExecuted ? (ev && ev.outcome === 'DENY' ? 'critical' : 'normal') : ''}">${esc(statusText)}</span>
          </div>
          <div class="attack-title">${esc(att.title)}</div>
          <div class="attack-target">Infra: <code>${esc(att.infra)}</code> → Alvo: <code>${esc(att.target)}</code></div>
        </div>
        <button class="attack-btn" onclick="executeAttackTo(${att.step})">${esc(btnText)}</button>
      </div>
    `;
  }).join('');
  applyNodeFilter();
}

// PAINEL ESQUERDO: ATAQUES REAIS DO HERACLITUSDB (9 TESTES DE AGENT-ATACK-2.0)
let cachedHdbAttacks = [];

async function loadAndRenderHdbAttacks() {
  const container = $('#hdbAttackList');
  if (!container) return;

  try {
    if (!cachedHdbAttacks.length) {
      const res = await api('/api/heraclitus-attacks');
      cachedHdbAttacks = res.attacks || [];
    }

    container.innerHTML = cachedHdbAttacks.map(atk => {
      const riskClass = atk.risk === 'ELEVATED' ? 'critical' : 'normal';
      return `
        <div class="attack-card hdb-attack-card" id="hdb-atk-${atk.id}"${attackCardAttrs(atk.target, `Alvo: ${atk.target} [Porta: ${atk.port}]\n${atk.hypothesis || ''}`, 'asset:heraclitusdb')}>
          <div class="attack-card-main">
            <div class="attack-meta">
              <span class="attack-phase-tag" style="background:#0c326f; color:#fff;">HERACLITUS 2.0</span>
              <span class="attack-source-tag">${esc(atk.equipment)}</span>
              <span class="tag-status ${riskClass}">${esc(atk.risk)}</span>
            </div>
            <div class="attack-title">${esc(atk.id)}: ${esc(atk.title)}</div>
            <div class="attack-target">Alvo: <code>${esc(atk.target)}</code> [Porta: ${esc(atk.port)}]</div>
            <small class="hdb-hypo-text">${esc(atk.hypothesis)}</small>
          </div>
          <button class="attack-btn hdb-btn" onclick="executeHdbAttack('${atk.id}')">⚡ Disparar</button>
        </div>
      `;
    }).join('');
    applyNodeFilter();
  } catch (err) {
    container.innerHTML = `<div class="empty">Erro ao carregar catálogo do HeraclitusDB: ${esc(err.message)}</div>`;
  }
}

// EXECUÇÃO DE ATAQUE HERACLITUSDB INDIVIDUAL
window.executeHdbAttack = async function(attackId) {
  if (running) return;
  running = true;
  try {
    toast(`Executando teste real ${attackId} contra o HeraclitusDB...`);
    const res = await api('/api/heraclitus-attacks/execute', {
      method: 'POST',
      body: JSON.stringify({ attack_id: attackId })
    });
    if (res.state) {
      render(res.state);
    } else {
      const s = await api('/api/state');
      render(s);
    }
    const atk = res.attack;
    const ev = res.event;
    const counters = res.counters || (state?.equipment_counters);
    const eqCounter = counters && atk?.equipment_id ? counters[atk.equipment_id] : null;
    const targetNodeId = findNodeIdForTarget(atk?.target) || 'asset:heraclitusdb';
    markLiveAttackLsn(res.lsn ?? res.event?.lsn);
    if (targetNodeId && atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(res));
    showAttackHint(atk, ev, eqCounter);
    toast(`Teste ${attackId} executado no HeraclitusDB (LSN real ${res.lsn})`);
    loadHeraclitusWslData();
  } catch (err) {
    toast('Falha no ataque HeraclitusDB: ' + err.message);
  } finally {
    running = false;
  }
};

// EXECUÇÃO DA BATERIA COMPLETA DE 9 ATAQUES AO HERACLITUSDB
window.executeAllHdbAttacks = async function() {
  if (running) return;
  running = true;
  const btn = $('#runAllHdbBtn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Executando Bateria (9)...';
  }
  try {
    toast('Disparando bateria completa de 9 testes no HeraclitusDB...');
    const res = await api('/api/heraclitus-attacks/execute', {
      method: 'POST',
      body: JSON.stringify({ attack_id: 'all' })
    });
    if (res.state) render(res.state);
    const results = res.results || [];
    for (const item of results) {
      const atk = item.attack;
      const targetNodeId = findNodeIdForTarget(atk?.target) || 'asset:heraclitusdb';
      markLiveAttackLsn(item.lsn ?? item.event?.lsn);
      if (atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(item));
      await new Promise(r => setTimeout(r, 80));
    }
    if (results.length) showAttackHint(results[results.length - 1].attack, results[results.length - 1].event);
    toast(`Bateria de ${res.count || 9} ataques executada com sucesso no HeraclitusDB!`);
    loadHeraclitusWslData();
  } catch (err) {
    toast('Erro na bateria: ' + err.message);
  } finally {
    running = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⚡ Executar Todos no HeraclitusDB';
    }
  }
};

// CONTADOR DE INTRUSÃO POR EQUIPAMENTO
function renderEquipmentCounters(counters) {
  const tbody = $('#equipmentCounterRows');
  if (!tbody) return;

  if (!counters || !Object.keys(counters).length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">Nenhum equipamento registrado ainda.</td></tr>';
    return;
  }

  const items = Object.values(counters);
  let totalAtt = 0;
  let totalBlk = 0;

  tbody.innerHTML = items.map(eq => {
    totalAtt += (eq.attempts || 0);
    totalBlk += (eq.unauthorized_blocked || 0);
    const isAttacked = (eq.attempts || 0) > 0;
    const isBlocked = (eq.unauthorized_blocked || 0) > 0;
    // Legenda: verde = todas bloqueadas (não invadiu); roxo = alguma chegou ao alvo
    const breached = (eq.attempts || 0) > (eq.unauthorized_blocked || 0);
    const statusClass = breached ? 'breached' : isBlocked ? 'blocked-ok' : 'normal';
    const statusText = breached ? 'CHEGOU AO ALVO' : isBlocked ? 'ATACADO • BLOQUEADO' : 'PROTEGIDO';

    return `
      <tr class="${isAttacked ? 'row-attacked' : ''}">
        <td>
          <div class="equip-cell">
            <span class="equip-icon">${eq.icon || '🖥️'}</span>
            <div>
              <strong>${esc(eq.name)}</strong>
              <small class="equip-sub">${esc(eq.type)} • ${esc(eq.port)}</small>
            </div>
          </div>
        </td>
        <td style="text-align:center; font-weight:800; font-size:13px; color:var(--legend-attack);">${eq.attempts || 0}</td>
        <td style="text-align:center; font-weight:800; font-size:13px; color:var(--legend-blocked-text);">${eq.unauthorized_blocked || 0}</td>
        <td style="text-align:center;">
          <span class="tag-status ${statusClass}" style="font-size:9.5px; padding:2px 5px;">${statusText}</span>
        </td>
      </tr>
    `;
  }).join('');

  const totAttBadge = $('#totalAttemptsBadge');
  const totBlkBadge = $('#totalBlockedBadge');
  if (totAttBadge) totAttBadge.textContent = totalAtt;
  if (totBlkBadge) totBlkBadge.textContent = totalBlk;
  syncNodeAttackCountsFromState(state);
  const accBadge = $('#totalAttemptsAccBadge');
  if (accBadge) accBadge.textContent = totalAtt;
  renderIncidentCharts();
}

// ========================================================
// PAINEL ESQUERDO: 20 ATAQUES NA INFRAESTRUTURA DO STF (CATEGORIZADOS)
// ========================================================
let cachedStfAttacks = [];

async function loadAndRenderStfAttacks() {
  const catContainers = {
    IA: $('#catListIA'),
    DB: $('#catListDB'),
    LINUX: $('#catListLINUX'),
    NETWORK: $('#catListNETWORK')
  };

  try {
    if (!cachedStfAttacks.length) {
      const res = await api('/api/stf-attacks');
      cachedStfAttacks = res.attacks || [];
    }

    const grouped = { IA: [], DB: [], LINUX: [], NETWORK: [] };
    // O servidor usa DATABASE; o painel agrupa em DB
    const CAT_ALIAS = { DATABASE: 'DB' };
    for (const atk of cachedStfAttacks) {
      const cat = CAT_ALIAS[atk.category] || atk.category;
      if (grouped[cat]) grouped[cat].push(atk);
    }

    for (const [cat, container] of Object.entries(catContainers)) {
      if (!container) continue;
      const atks = grouped[cat] || [];
      container.innerHTML = atks.map(atk => {
        const riskClass = atk.risk === 'CRÍTICO' ? 'critical' : atk.risk === 'ELEVADO' ? 'warning' : 'normal';
        return `
          <div class="attack-card stf-infra-card" id="stf-atk-${atk.id}"${attackCardAttrs(atk.target, `Alvo: ${atk.target} • Vetor: ${atk.vector}\n${atk.hypothesis || ''}`)}>
            <div class="attack-card-main">
              <div class="attack-meta">
                <span class="attack-phase-tag">${esc(atk.phase)}</span>
                <span class="attack-source-tag">${esc(atk.equipment)}</span>
                <span class="tag-status ${riskClass}">${esc(atk.risk)}</span>
              </div>
              <div class="attack-title">${esc(atk.title)}</div>
              <div class="attack-target">Alvo: <code>${esc(atk.target)}</code> • Vetor: <strong>${esc(atk.vector)}</strong></div>
              <small class="hdb-hypo-text">${esc(atk.hypothesis)}</small>
            </div>
            <button class="attack-btn" onclick="executeStfAttack('${atk.id}')">⚡ Disparar</button>
          </div>
        `;
      }).join('');
    }
    applyNodeFilter();
  } catch (err) {
    console.error('Erro ao carregar catálogo da infraestrutura STF:', err);
  }
}

// EXECUÇÃO DE ATAQUE DA INFRAESTRUTURA INDIVIDUAL
window.executeStfAttack = async function(attackId) {
  if (running) return;
  running = true;
  try {
    toast(`Disparando ataque ${attackId} contra o componente do STF...`);
    const res = await api('/api/stf-attacks/execute', {
      method: 'POST',
      body: JSON.stringify({ attack_id: attackId })
    });
    if (res.state) {
      render(res.state);
    } else {
      const s = await api('/api/state');
      render(s);
    }
    const atk = res.attack;
    const ev = res.event;
    const counters = res.counters || (state?.equipment_counters);
    const eqCounter = counters && atk?.equipment_id ? counters[atk.equipment_id] : null;
    const targetNodeId = findNodeIdForTarget(atk?.target) || 'asset:heraclitusdb';
    markLiveAttackLsn(res.lsn ?? res.event?.lsn);
    if (targetNodeId && atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(res));
    showAttackHint(atk, ev, eqCounter);
    toast(`Ataque ${attackId} auditado no HeraclitusDB (LSN real ${res.lsn})`);
    loadRealHeraclitusTrail();
  } catch (err) {
    toast('Falha ao disparar ataque: ' + err.message);
  } finally {
    running = false;
  }
};

// EXECUÇÃO DE TODOS OS ATAQUES DE UMA CATEGORIA (OU TODOS OS 20)
window.executeStfCategoryAttacks = async function(category) {
  if (running) return;
  running = true;
  const isAll = category === 'ALL';
  toast(`Executando bateria de ataques ${isAll ? 'em toda a infraestrutura (20)' : 'na categoria ' + category}...`);

  try {
    const res = await api('/api/stf-attacks/execute', {
      method: 'POST',
      body: JSON.stringify({ category })
    });
    if (res.state) render(res.state);

    if (res.results && res.results.length) {
      for (const item of res.results) {
        const atk = item.attack;
        const targetNodeId = findNodeIdForTarget(atk?.target) || 'asset:heraclitusdb';
        markLiveAttackLsn(item.lsn ?? item.event?.lsn);
        if (targetNodeId && atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(item));
        await new Promise(r => setTimeout(r, 80));
      }
      const lastItem = res.results[res.results.length - 1];
      showAttackHint(lastItem.attack, lastItem.event);
    }

    toast(`Bateria de ${res.count} testes concluída e auditada no HeraclitusDB!`);
    loadRealHeraclitusTrail();
  } catch (err) {
    toast('Erro na bateria: ' + err.message);
  } finally {
    running = false;
  }
};

// ========================================================
// CONTROLE DE ATAQUES MASSIVOS CONTÍNUOS & RANDÔMICOS
// ========================================================
let massiveLoopTimer = null;
let massiveLoopActive = false;
let currentMassiveMode = null;
let massiveAttackCount = 0;

const MASSIVE_TARGETS = {
  firewall: ['NET_WAF_01', 'NET_IAM_02', 'NET_LAN_04', 'NET_VDI_03'],
  database: ['DB_ORA_01', 'DB_ORA_02', 'LNX_DB_02'],
  heraclitus: ['H01', 'H02', 'H03', 'H04', 'H05', 'H06', 'H07', 'H08', 'H09'],
  dw: ['DB_DW_03', 'DB_LAKE_04', 'DB_BI_05'],
  random: [
    'IA_VIC_01', 'IA_MAR_02', 'IA_VIT_03', 'IA_RAF_04',
    'DB_ORA_01', 'DB_ORA_02', 'DB_DW_03', 'DB_LAKE_04', 'DB_BI_05',
    'LNX_APP_01', 'LNX_DB_02', 'LNX_MGR_03',
    'NET_WAF_01', 'NET_IAM_02', 'NET_VDI_03', 'NET_LAN_04',
    'APP_STF_05', 'APP_SEI_06', 'APP_MNI_07', 'BKP_APP_08',
    'H01', 'H02', 'H03', 'H04', 'H05', 'H06', 'H07', 'H08', 'H09'
  ]
};

const MASSIVE_BUTTON_IDS = {
  firewall: '#loopMassiveFwBtn',
  database: '#loopMassiveDbBtn',
  heraclitus: '#loopMassiveHdbBtn',
  dw: '#loopMassiveDwBtn',
  random: '#loopRandomBtn'
};

const MODE_LABELS = {
  firewall: 'WAF / Firewall de Borda',
  database: 'Banco de Dados Oracle RAC',
  heraclitus: 'HeraclitusDB (WSL 8080)',
  dw: 'Data Warehouse & Analytics',
  random: 'Randômico (Toda a Infraestrutura)'
};

window.toggleMassiveAttack = function(mode) {
  if (massiveLoopActive && currentMassiveMode === mode) {
    stopAllMassiveAttacks();
    return;
  }

  if (massiveLoopActive) {
    stopAllMassiveAttacks(false);
  }

  currentMassiveMode = mode;
  massiveLoopActive = true;
  massiveAttackCount = 0;

  Object.values(MASSIVE_BUTTON_IDS).forEach(id => {
    const b = $(id);
    if (b) b.classList.remove('active-loop');
  });
  const activeBtn = $(MASSIVE_BUTTON_IDS[mode]);
  if (activeBtn) activeBtn.classList.add('active-loop');

  const stopBtn = $('#stopMassiveBtn');
  if (stopBtn) stopBtn.style.display = 'inline-flex';

  const banner = $('#massiveActiveBanner');
  const bannerText = $('#massiveBannerText');
  if (banner && bannerText) {
    banner.style.display = 'flex';
    bannerText.textContent = `ATAQUE MASSIVO CONTÍNUO [${MODE_LABELS[mode] || mode.toUpperCase()}]: 0 disparos`;
  }

  toast(`Iniciando ataque massivo contínuo contra ${MODE_LABELS[mode] || mode}...`);
  runMassiveCycle();
};

window.stopAllMassiveAttacks = function(showToast = true) {
  if (massiveLoopTimer) {
    clearTimeout(massiveLoopTimer);
    massiveLoopTimer = null;
  }
  massiveLoopActive = false;

  Object.values(MASSIVE_BUTTON_IDS).forEach(id => {
    const b = $(id);
    if (b) b.classList.remove('active-loop');
  });

  const stopBtn = $('#stopMassiveBtn');
  if (stopBtn) stopBtn.style.display = 'none';

  const banner = $('#massiveActiveBanner');
  if (banner) banner.style.display = 'none';

  if (showToast && currentMassiveMode) {
    toast(`Ataque massivo interrompido pelo operador. Total de ${massiveAttackCount} disparos auditados no HeraclitusDB.`);
  }
  currentMassiveMode = null;
  loadRealHeraclitusTrail();
};

async function runMassiveCycle() {
  if (!massiveLoopActive || !currentMassiveMode) return;

  const targetList = MASSIVE_TARGETS[currentMassiveMode] || MASSIVE_TARGETS.random;
  const attackId = targetList[Math.floor(Math.random() * targetList.length)];

  try {
    massiveAttackCount++;
    const bannerText = $('#massiveBannerText');
    if (bannerText) {
      bannerText.textContent = `ATAQUE MASSIVO CONTÍNUO [${MODE_LABELS[currentMassiveMode] || currentMassiveMode.toUpperCase()}]: ${massiveAttackCount} disparos`;
    }

    if (attackId.startsWith('H')) {
      await executeHdbAttackSilent(attackId);
    } else {
      await executeStfAttackSilent(attackId);
    }
  } catch (err) {
    console.warn('[MassiveLoop] Erro no disparo:', err);
  }

  if (massiveLoopActive) {
    massiveLoopTimer = setTimeout(runMassiveCycle, 650);
  }
}

// Hint do canto inferior direito durante o massivo: mesmo conteúdo dos ataques
// individuais (tentativas/bloqueios do equipamento), re-disparado a cada tiro
// para piscar enquanto o componente está sob ataque.
function showMassiveAttackHint(res) {
  const atk = res?.attack;
  if (!atk) return;
  const counters = res.counters || state?.equipment_counters;
  const eqCounter = counters && atk.equipment_id ? counters[atk.equipment_id] : null;
  showAttackHint(atk, res.event, eqCounter);
  const h = $('#attackHint');
  if (h) {
    h.classList.remove('hint-flash');
    void h.offsetWidth; // reinicia a animação
    h.classList.add('hint-flash');
  }
}

async function executeStfAttackSilent(attackId) {
  try {
    const res = await api('/api/stf-attacks/execute', {
      method: 'POST',
      body: JSON.stringify({ attack_id: attackId })
    });
    if (res.state) {
      state = res.state;
      $('#riskValue').textContent = state.risk;
      $('#upstreamHits').textContent = state.upstream_hits;
      if (state.equipment_counters) renderEquipmentCounters(state.equipment_counters);
      updateFocusCard(state);
    }
    const atk = res.attack;
    const targetNodeId = findNodeIdForTarget(atk?.target) || 'asset:heraclitusdb';
    markLiveAttackLsn(res.lsn ?? res.event?.lsn);
    if (targetNodeId && atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(res));
    showMassiveAttackHint(res);

    if (massiveAttackCount % 2 === 0) {
      loadRealHeraclitusTrail();
    }
  } catch (e) {
    console.warn('Erro silent STF:', e);
  }
}

async function executeHdbAttackSilent(attackId) {
  try {
    const res = await api('/api/heraclitus-attacks/execute', {
      method: 'POST',
      body: JSON.stringify({ attack_id: attackId })
    });
    if (res.state) {
      state = res.state;
      $('#riskValue').textContent = state.risk;
      $('#upstreamHits').textContent = state.upstream_hits;
      if (state.equipment_counters) renderEquipmentCounters(state.equipment_counters);
      updateFocusCard(state);
    }
    const atk = res.attack;
    const targetNodeId = findNodeIdForTarget(atk?.target) || 'asset:heraclitusdb';
    markLiveAttackLsn(res.lsn ?? res.event?.lsn);
    if (targetNodeId && atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(res));
    showMassiveAttackHint(res);

    if (massiveAttackCount % 2 === 0) {
      loadRealHeraclitusTrail();
    }
  } catch (e) {
    console.warn('Erro silent HDB:', e);
  }
}

// PAINEL ESQUERDO EM SANFONA: SECÇÕES E CATEGORIAS ABREM/FECHAM, PAINEL RECOLHE
function setupLeftPanelTabs() {
  const sections = [
    { head: '#tabStfInfraBtn', onOpen: () => loadAndRenderStfAttacks() },
    { head: '#tabHdbAttacksBtn', onOpen: () => loadAndRenderHdbAttacks() },
    { head: '#tabStfAttacksBtn' },
    { head: '#tabEquipCountersBtn', onOpen: () => state?.equipment_counters && renderEquipmentCounters(state.equipment_counters) }
  ];

  for (const sec of sections) {
    const head = $(sec.head);
    if (!head) continue;
    head.onclick = () => {
      const section = head.closest('.acc-section');
      const open = !section.classList.contains('open');
      section.classList.toggle('open', open);
      head.setAttribute('aria-expanded', String(open));
      if (open && sec.onOpen) sec.onOpen();
    };
  }

  const runAllInfraBtn = $('#runAllStfInfraBtn');
  if (runAllInfraBtn) runAllInfraBtn.onclick = () => executeStfCategoryAttacks('ALL');

  const runAllHdbBtn = $('#runAllHdbBtn');
  if (runAllHdbBtn) runAllHdbBtn.onclick = () => executeAllHdbAttacks();

  try {
    if (localStorage.getItem('stf.attacksCollapsed') === '1') setAttacksPanelCollapsed(true);
  } catch (_) { /* armazenamento indisponível: começa expandido */ }
}

window.toggleCategory = function(headEl) {
  headEl.closest('.stf-category-block')?.classList.toggle('collapsed');
};

function setAttacksPanelCollapsed(collapsed) {
  const ws = $('#workspace');
  if (!ws) return;
  ws.classList.toggle('attacks-collapsed', collapsed);
  try { localStorage.setItem('stf.attacksCollapsed', collapsed ? '1' : '0'); } catch (_) {}
  // O grafo mede o contentor: redesenha depois de a coluna mudar de largura
  requestAnimationFrame(() => { if (state) renderGraph(state); });
}

window.toggleAttacksPanel = function() {
  const ws = $('#workspace');
  setAttacksPanelCollapsed(!ws?.classList.contains('attacks-collapsed'));
};

// ========================================================
// FILTRO DOS ATAQUES PELO COMPONENTE CLICADO NO GRAFO
// ========================================================
let nodeFilter = null; // { id, label }

function attackCardAttrs(target, tip, fallbackNode) {
  const node = findNodeIdForTarget(target) || fallbackNode || '';
  return ` data-node="${esc(node)}" title="${esc(tip || '')}"`;
}

function applyNodeFilter() {
  const cards = document.querySelectorAll('#attacksAccordion .attack-card');
  cards.forEach(c => {
    c.classList.toggle('filtered-out', Boolean(nodeFilter) && c.dataset.node !== nodeFilter.id);
  });

  // Esconde categorias sem ataques visíveis e abre as que têm
  document.querySelectorAll('#attacksAccordion .stf-category-block').forEach(block => {
    const visible = block.querySelectorAll('.attack-card:not(.filtered-out)').length;
    block.classList.toggle('filtered-empty', Boolean(nodeFilter) && visible === 0);
    if (nodeFilter && visible) block.classList.remove('collapsed');
  });

  // Com filtro, abre as secções que têm ataques deste componente
  document.querySelectorAll('#attacksAccordion .acc-section').forEach(section => {
    const count = section.querySelectorAll('.attack-card:not(.filtered-out)').length;
    if (nodeFilter && count && section.dataset.acc !== 'conta') {
      section.classList.add('open');
      section.querySelector('.acc-head')?.setAttribute('aria-expanded', 'true');
    }
  });

  const bar = $('#nodeFilterBar');
  if (bar) {
    bar.hidden = !nodeFilter;
    const lbl = $('#nodeFilterLabel');
    if (lbl && nodeFilter) {
      const n = document.querySelectorAll('#attacksAccordion .attack-card:not(.filtered-out)').length;
      lbl.textContent = `${nodeFilter.label} (${n} ${n === 1 ? 'ataque' : 'ataques'})`;
    }
  }
}

function setNodeFilter(id, label) {
  nodeFilter = nodeFilter && nodeFilter.id === id ? null : { id, label };
  if (nodeFilter && $('#workspace')?.classList.contains('attacks-collapsed')) setAttacksPanelCollapsed(false);
  applyNodeFilter();
}

window.clearNodeFilter = function() {
  nodeFilter = null;
  applyNodeFilter();
};
// ========================================================
// ANÁLISE DE INCIDENTES: GRÁFICOS A PARTIR DO LEDGER REAL E DOS CONTADORES
// ========================================================
const DECISION_CATS = [
  { key: 'DENY', label: 'Bloqueado (não invadiu)', color: 'var(--chart-blocked)' },
  { key: 'REQUIRE_HITL', label: 'Retido (HITL)', color: 'var(--chart-hitl)' },
  { key: 'PASS', label: 'Chegou ao alvo (invadiu)', color: 'var(--chart-pass)' },
  { key: 'OBSERVED', label: 'Sondagem sem efeito', color: 'var(--chart-observed)' },
  { key: 'OTHER', label: 'Outros', color: 'var(--chart-other)' }
];

// No ledger, result "pass" é o veredito do TESTE (a defesa aguentou), não "o ataque passou".
// Só conta como invasão (chegou ao alvo) o evento com efeito real no sistema: upstream_delta > 0.
function classifyDecision(ev) {
  const r = String(ev.result || '').toUpperCase();
  if ((Number(ev.upstream_delta) || 0) > 0) return 'PASS';
  if (r === 'DENY' || r === 'BLOCKED' || ev.blocked || /_BLOCKED$/.test(String(ev.reason_code || ''))) return 'DENY';
  if (r === 'REQUIRE_HITL') return 'REQUIRE_HITL';
  if (r === 'OBSERVED' || r === 'PASS' || r === 'ALLOW' || r === 'APPROVED') return 'OBSERVED';
  return 'OTHER';
}

function eventTimeMs(ev) {
  const ns = Number(ev.observed_at_unix_nanos);
  return Number.isFinite(ns) && ns > 0 ? Math.floor(ns / 1e6) : null;
}

const fmtInt = n => Number(n || 0).toLocaleString('pt-BR');

function renderIncidentCharts() {
  const events = hdbAllEvents || [];
  const counters = state?.equipment_counters || {};

  // KPIs
  const byDecision = Object.fromEntries(DECISION_CATS.map(c => [c.key, 0]));
  let upstream = 0;
  for (const ev of events) {
    byDecision[classifyDecision(ev)]++;
    upstream += Number(ev.upstream_delta) || 0;
  }
  const total = events.length;
  const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  setText('#kpiEvents', fmtInt(total));
  // O servidor pede ao ledger no máximo hdbLedgerLimit eventos (/api/heraclitus-events)
  setText('#kpiEventsSub', total >= hdbLedgerLimit ? `as ${fmtInt(hdbLedgerLimit)} mais recentes do ledger` : 'todas as do ledger');
  setText('#kpiBlocked', fmtInt(byDecision.DENY));
  setText('#kpiBlockedPct', total ? `${Math.round((byDecision.DENY / total) * 100)}% do total` : '');
  setText('#kpiHitl', fmtInt(byDecision.REQUIRE_HITL));
  setText('#kpiUpstream', fmtInt(upstream));
  const topEq = Object.values(counters).sort((a, b) => (b.attempts || 0) - (a.attempts || 0))[0];
  setText('#kpiTopEquip', topEq && topEq.attempts ? `${topEq.name} (${fmtInt(topEq.attempts)})` : '—');

  renderTimelineChart(events);
  renderDecisionDonut(byDecision, total);
  renderEquipmentChart(counters);
  renderVectorChart(events);
}

// Mesma legenda do grafo: cada evento do ledger é uma TENTATIVA (vermelho); ao lado, o
// que lhe aconteceu (verde = bloqueado, roxo = invadiu, ...). Sem a coluna vermelha o
// gráfico ficava só verde e o ataque desaparecia.
const ATTEMPT_CAT = { key: 'ATTEMPT', label: 'Tentativas de ataque', color: 'var(--chart-attempts)' };

// Por intervalo de tempo: coluna de tentativas + coluna empilhada com o desfecho
function renderTimelineChart(events) {
  const host = $('#chartTimeline');
  const legend = $('#legendTimeline');
  if (!host) return;
  const timed = events.map(ev => ({ t: eventTimeMs(ev), k: classifyDecision(ev) })).filter(e => e.t);
  if (!timed.length) {
    host.innerHTML = '<div class="chart-empty">Sem eventos com data no ledger.</div>';
    if (legend) legend.innerHTML = '';
    return;
  }

  const minT = Math.min(...timed.map(e => e.t));
  const maxT = Math.max(...timed.map(e => e.t));
  const STEPS = [60e3, 5 * 60e3, 15 * 60e3, 3600e3, 6 * 3600e3, 86400e3, 7 * 86400e3];
  const step = STEPS.find(s => (maxT - minT) / s <= 48) || STEPS[STEPS.length - 1];
  const start = Math.floor(minT / step) * step;
  const nBuckets = Math.floor((maxT - start) / step) + 1;

  const buckets = Array.from({ length: nBuckets }, (_, i) => ({ t: start + i * step, c: Object.fromEntries(DECISION_CATS.map(d => [d.key, 0])), total: 0 }));
  for (const e of timed) {
    const b = buckets[Math.floor((e.t - start) / step)];
    b.c[e.k]++;
    b.total++;
  }
  const present = DECISION_CATS.filter(d => buckets.some(b => b.c[d.key]));
  if (legend) legend.innerHTML = [ATTEMPT_CAT, ...present].map(d => `<span class="lg-item"><i class="lg-swatch" style="background:${d.color}"></i>${d.label}</span>`).join('');

  const W = 1000, H = 220, padL = 36, padR = 8, padT = 10, padB = 26;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const maxY = niceMax(Math.max(...buckets.map(b => b.total)));
  const slot = plotW / nBuckets;
  const barW = Math.max(2, Math.min(18, (slot - 3) / 2));
  const y = v => padT + plotH - (v / maxY) * plotH;

  const fmtTick = t => {
    const d = new Date(t);
    return step >= 86400e3
      ? d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })
      : d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  };

  const grid = [0, 0.5, 1].map(f => {
    const v = Math.round(maxY * f);
    return `<line class="grid-line" x1="${padL}" x2="${W - padR}" y1="${y(v)}" y2="${y(v)}"/>
            <text class="axis-text" x="${padL - 6}" y="${y(v)}" text-anchor="end" dominant-baseline="central">${fmtInt(v)}</text>`;
  }).join('');

  const labelEvery = Math.ceil(nBuckets / 8);
  const bars = buckets.map((b, i) => {
    const xAttempt = padL + i * slot + (slot - (barW * 2 + 2)) / 2;
    const x = xAttempt + barW + 2;
    const attempt = b.total ? `<rect class="mark" x="${xAttempt}" y="${y(b.total)}" width="${barW}" height="${Math.max(1, y(0) - y(b.total))}" rx="1.5" fill="${ATTEMPT_CAT.color}"/>` : '';
    let acc = 0;
    const segs = present.map(d => {
      const v = b.c[d.key];
      if (!v) return '';
      const y1 = y(acc + v), y0 = y(acc);
      acc += v;
      // 1px de folga entre segmentos empilhados
      return `<rect class="mark" x="${x}" y="${y1}" width="${barW}" height="${Math.max(1, y0 - y1 - 1)}" rx="1.5" fill="${d.color}"/>`;
    }).join('');
    const tip = `<strong>${esc(new Date(b.t).toLocaleString('pt-BR'))}</strong>` +
      `<div class="tt-row"><i class="lg-swatch" style="background:${ATTEMPT_CAT.color}"></i>${ATTEMPT_CAT.label}<b>${fmtInt(b.total)}</b></div>` +
      present.map(d => `<div class="tt-row"><i class="lg-swatch" style="background:${d.color}"></i>${d.label}<b>${fmtInt(b.c[d.key])}</b></div>`).join('');
    const tick = i % labelEvery === 0 ? `<text class="axis-text" x="${xAttempt + barW + 1}" y="${H - 8}" text-anchor="middle">${fmtTick(b.t)}</text>` : '';
    return `<g class="bar-group" data-tip="${esc(tip)}"><rect class="hit" x="${padL + i * slot}" y="${padT}" width="${slot}" height="${plotH}"/>${attempt}${segs}</g>${tick}`;
  }).join('');

  host.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="height:${H}px">${grid}
    <line x1="${padL}" x2="${W - padR}" y1="${y(0)}" y2="${y(0)}" stroke="#b9c7d8"/>${bars}</svg>`;
}

function renderDecisionDonut(byDecision, total) {
  const host = $('#chartDecisions');
  if (!host) return;
  if (!total) {
    host.innerHTML = '<div class="chart-empty">Sem decisões registadas.</div>';
    return;
  }
  // Anel exterior vermelho = todas as tentativas; anel interior = o desfecho de cada uma.
  const R = 58, r = 38, C = 75, RA = 70, ra = 64;
  const cats = DECISION_CATS.filter(d => byDecision[d.key]);
  let a0 = -Math.PI / 2;
  const gap = cats.length > 1 ? 0.025 : 0;
  const arcs = cats.map(d => {
    const frac = byDecision[d.key] / total;
    const a1 = a0 + frac * Math.PI * 2;
    const s = a0 + gap / 2, e = a1 - gap / 2;
    a0 = a1;
    const pct = Math.round(frac * 100);
    const tip = `<strong>${d.label}</strong><div class="tt-row">Eventos<b>${fmtInt(byDecision[d.key])}</b></div><div class="tt-row">Parcela<b>${pct}%</b></div>`;
    if (frac >= 0.999) {
      return `<g data-tip="${esc(tip)}"><circle class="mark" cx="${C}" cy="${C}" r="${(R + r) / 2}" fill="none" stroke="${d.color}" stroke-width="${R - r}"/></g>`;
    }
    const large = e - s > Math.PI ? 1 : 0;
    const p = (rad, ang) => `${C + rad * Math.cos(ang)} ${C + rad * Math.sin(ang)}`;
    return `<g data-tip="${esc(tip)}"><path class="mark" fill="${d.color}" d="M ${p(R, s)} A ${R} ${R} 0 ${large} 1 ${p(R, e)} L ${p(r, e)} A ${r} ${r} 0 ${large} 0 ${p(r, s)} Z"/></g>`;
  }).join('');
  const attemptTip = `<strong>${ATTEMPT_CAT.label}</strong><div class="tt-row">Eventos<b>${fmtInt(total)}</b></div>`;
  const attemptRing = `<g data-tip="${esc(attemptTip)}"><circle class="mark" cx="${C}" cy="${C}" r="${(RA + ra) / 2}" fill="none" stroke="${ATTEMPT_CAT.color}" stroke-width="${RA - ra}"/></g>`;
  const pctOf = n => `${Math.round((n / total) * 100)}%`;

  host.innerHTML = `<div class="donut-wrap">
    <svg viewBox="0 0 150 150">${attemptRing}${arcs}
      <text x="${C}" y="${C - 5}" text-anchor="middle" class="value-text" style="font-size:20px; fill:${ATTEMPT_CAT.color}">${fmtInt(total)}</text>
      <text x="${C}" y="${C + 13}" text-anchor="middle" class="axis-text">tentativas</text>
    </svg>
    <div class="donut-legend">
      <span class="lg-item"><span><i class="lg-swatch" style="background:${ATTEMPT_CAT.color}"></i> ${ATTEMPT_CAT.label}</span><b>${fmtInt(total)}</b></span>
      ${cats.map(d =>
        `<span class="lg-item"><span><i class="lg-swatch" style="background:${d.color}"></i> ${d.label}</span><b>${fmtInt(byDecision[d.key])} · ${pctOf(byDecision[d.key])}</b></span>`).join('')}
    </div></div>`;
}

// Barras horizontais: tentativas e bloqueios por equipamento (top 10)
function renderEquipmentChart(counters) {
  const host = $('#chartEquipment');
  if (!host) return;
  const rows = Object.values(counters).filter(eq => (eq.attempts || 0) > 0)
    .sort((a, b) => (b.attempts || 0) - (a.attempts || 0)).slice(0, 10);
  if (!rows.length) {
    host.innerHTML = '<div class="chart-empty">Nenhum equipamento atacado ainda.</div>';
    return;
  }
  const maxV = niceMax(Math.max(...rows.map(r => r.attempts || 0)));
  const W = 420, labelW = 130, valW = 34, rowH = 26, barH = 8;
  const plotW = W - labelW - valW;
  const H = rows.length * rowH + 4;
  const body = rows.map((eq, i) => {
    const y0 = i * rowH + 4;
    const wA = Math.max(2, ((eq.attempts || 0) / maxV) * plotW);
    const wB = (eq.unauthorized_blocked || 0) ? Math.max(2, (eq.unauthorized_blocked / maxV) * plotW) : 0;
    const tip = `<strong>${esc(eq.name)}</strong><div class="tt-row"><i class="lg-swatch" style="background:var(--chart-attempts)"></i>Tentativas<b>${fmtInt(eq.attempts)}</b></div><div class="tt-row"><i class="lg-swatch" style="background:var(--chart-blocked)"></i>Bloqueadas<b>${fmtInt(eq.unauthorized_blocked)}</b></div>`;
    return `<g class="bar-group" data-tip="${esc(tip)}">
      <rect class="hit" x="0" y="${y0 - 3}" width="${W}" height="${rowH}"/>
      <text class="label-text" x="${labelW - 8}" y="${y0 + barH}" text-anchor="end" dominant-baseline="central">${esc(short(eq.name, 20))}</text>
      <rect class="mark" x="${labelW}" y="${y0 + 1}" width="${wA}" height="${barH}" rx="2" fill="var(--chart-attempts)"/>
      ${wB ? `<rect class="mark" x="${labelW}" y="${y0 + barH + 3}" width="${wB}" height="${barH}" rx="2" fill="var(--chart-blocked)"/>` : ''}
      <text class="value-text" x="${labelW + wA + 5}" y="${y0 + 1 + barH / 2}" dominant-baseline="central">${fmtInt(eq.attempts)}</text>
    </g>`;
  }).join('');
  host.innerHTML = `<svg viewBox="0 0 ${W} ${H}">${body}</svg>`;
}

// Barras horizontais: vetores de ataque mais frequentes no ledger (top 8)
function renderVectorChart(events) {
  const host = $('#chartVectors');
  if (!host) return;
  const counts = new Map();
  for (const ev of events) {
    const v = ev.vector || ev.attack_id;
    if (!v) continue;
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!rows.length) {
    host.innerHTML = '<div class="chart-empty">Sem vetores registados.</div>';
    return;
  }
  const maxV = niceMax(rows[0][1]);
  const W = 420, labelW = 150, valW = 34, rowH = 24, barH = 12;
  const plotW = W - labelW - valW;
  const H = rows.length * rowH + 4;
  const body = rows.map(([name, n], i) => {
    const y0 = i * rowH + 4;
    const w = Math.max(2, (n / maxV) * plotW);
    const tip = `<strong>${esc(name)}</strong><div class="tt-row">Eventos<b>${fmtInt(n)}</b></div>`;
    return `<g class="bar-group" data-tip="${esc(tip)}">
      <rect class="hit" x="0" y="${y0 - 3}" width="${W}" height="${rowH}"/>
      <text class="label-text" x="${labelW - 8}" y="${y0 + barH / 2}" text-anchor="end" dominant-baseline="central">${esc(short(name, 24))}</text>
      <rect class="mark" x="${labelW}" y="${y0}" width="${w}" height="${barH}" rx="2" fill="var(--chart-attempts)"/>
      <text class="value-text" x="${labelW + w + 5}" y="${y0 + barH / 2}" dominant-baseline="central">${fmtInt(n)}</text>
    </g>`;
  }).join('');
  host.innerHTML = `<svg viewBox="0 0 ${W} ${H}">${body}</svg>`;
}

function niceMax(v) {
  if (!v || v <= 0) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / mag;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * mag;
}

// Tooltip único para todos os gráficos (delegação por data-tip)
function setupChartTooltip() {
  const panel = $('#chartsPanel');
  const tt = $('#chartTooltip');
  if (!panel || !tt) return;
  panel.addEventListener('mousemove', evt => {
    const g = evt.target.closest('[data-tip]');
    if (!g) { tt.classList.remove('show'); return; }
    tt.innerHTML = g.getAttribute('data-tip');
    const pad = 14;
    let x = evt.clientX + pad, yy = evt.clientY + pad;
    const r = tt.getBoundingClientRect();
    if (x + r.width > window.innerWidth - 8) x = evt.clientX - r.width - pad;
    if (yy + r.height > window.innerHeight - 8) yy = evt.clientY - r.height - pad;
    tt.style.left = `${x}px`;
    tt.style.top = `${yy}px`;
    tt.classList.add('show');
  });
  panel.addEventListener('mouseleave', () => tt.classList.remove('show'));
}
// RENDERIZAÇÃO GERAL DO ESTADO
function render(s) {
  state = s;

  $('#riskValue').textContent = s.risk;
  const rl = $('#riskLabel');
  if (s.risk >= 80) {
    rl.textContent = 'CRÍTICO';
    rl.className = 'tag-status critical';
  } else if (s.risk >= 50) {
    rl.textContent = 'ALTO';
    rl.className = 'tag-status critical';
  } else if (s.risk >= 20) {
    rl.textContent = 'ELEVADO';
    rl.className = 'tag-status';
  } else {
    rl.textContent = 'NORMAL';
    rl.className = 'tag-status normal';
  }

  const incState = $('#incidentState');
  if (s.incident) {
    incState.textContent = `${s.incident.incident_id} (${s.incident.severity})`;
    incState.style.color = 'var(--gov-gold)';
  } else {
    incState.textContent = 'NÃO ABERTO';
    incState.style.color = 'var(--gov-muted)';
  }

  $('#upstreamHits').textContent = s.upstream_hits;
  $('#attackProgress').textContent = `${s.step} / ${s.total_steps} executados`;

  updateInfraStatusBar(s);
  renderAttackList(s);
  if (s.equipment_counters) renderEquipmentCounters(s.equipment_counters);
  renderGraph(s);
  renderTrail(s);
  updateFocusCard(s);
}

// INICIALIZAÇÃO
async function init() {
  setupLeftPanelTabs();
  setupChartTooltip();
  const refreshTrailBtn = $('#refreshTrailBtn');
  if (refreshTrailBtn) refreshTrailBtn.onclick = () => loadRealHeraclitusTrail();
  try {
    const s = await api('/api/state');
    render(s);
  } catch (e) {
    toast('Falha ao conectar à POC: ' + e.message);
  }
  loadRealHeraclitusTrail();
  loadAndRenderStfAttacks();
  loadAndRenderHdbAttacks();
  // Atualização contínua leve da trilha real do HeraclitusDB
  setInterval(loadRealHeraclitusTrail, 4000);
}

init();
