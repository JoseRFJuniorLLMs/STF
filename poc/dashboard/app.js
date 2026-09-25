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
  if (!r.ok) {
    let detail = '';
    try { detail = (await r.json()).detail || ''; } catch (_) {}
    throw new Error(detail || 'HTTP ' + r.status);
  }
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

  if (reasonCode.startsWith('DEMO_')) {
    const label = {
      DEMO_DEFENDED: 'DEFENDIDO — detectado e contido',
      DEMO_BLOCKED: 'BLOQUEADO — barrado na entrada',
      DEMO_TARGET_REACHED: 'CHEGOU AO ALVO — simulado'
    }[reasonCode] || 'RESULTADO SIMULADO';
    $('#hintTime').textContent = dt;
    $('#hintAttackName').textContent = attack.title;
    $('#hintInfraName').textContent = `${eqName} [Tentativas: ${attempts}]`;
    $('#hintOutcome').textContent = label;
    $('#hintOutcome').className = 'hint-outcome-badge ' + (reasonCode === 'DEMO_TARGET_REACHED' ? 'PASS' : 'DENY');
    $('#hintUpstream').textContent = 'upstream real=0';
    $('#hintBadge').textContent = 'SIMULAÇÃO · ' + label;
    $('#hintDesc').textContent = `Resultado demonstrativo gravado no HeraclitusDB às ${dt}; nenhum efeito real no alvo.`;
    h.className = 'attack-hint show ' + (reasonCode === 'DEMO_TARGET_REACHED' ? 'pass' : 'deny');
    if (hintTimeout) clearTimeout(hintTimeout);
    hintTimeout = setTimeout(() => h.classList.remove('show'), 6500);
    return;
  }

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
    role: 'Ledger com LSN Monotônico, Provas Merkle e OTLP (Porta 8080)',
    ledgerSync: 'CONEXÃO ATIVA HERACLITUSDB',
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
// Mesma regra de server.py (BLOCKED_OUTCOMES): HITL retém a ação, não a executa.
const BLOCKED_OUTCOMES = new Set(['DENY', 'BLOCKED', 'DETECTED', 'REJECTED', 'FAIL', 'REQUIRE_HITL']);
const PASSED_OUTCOMES = new Set(['PASS', 'ALLOW', 'MISSED', 'EXECUTED', 'OBSERVED', 'APPROVED']);

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
  if (!e) return;

  // Sincroniza os contadores reais de ataques/bloqueios do servidor para pintar os nós
  syncNodeAttackCountsFromState(s);

  // Se chegou novo evento de ataque (vindo de agente externo/script), aciona animação de pulso e cor
  if (s?.events && s.events.length > 0) {
    const lastEv = s.events[s.events.length - 1];
    if (lastEv && lastEv.lsn && lastEv.lsn !== window._lastSeenLsn) {
      window._lastSeenLsn = lastEv.lsn;
      const targetNodeId = findNodeIdForTarget(lastEv.asset) || 'asset:heraclitusdb';
      const outcome = String(lastEv.outcome || lastEv.result || 'DENY').toUpperCase();
      triggerNodeAttackPopup(targetNodeId, lastEv.lsn, lastEv.event_type || 'Ataque Externo', outcome);
    }
  }

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

        <!-- SUBRÓTULO: TENTATIVAS (VERMELHO) · BLOQUEADOS (VERDE ✓) · INVADIU (ROXO :() -->
        ${hasBeenAttacked ? `
          <text x="0" y="${n.r + 26}" text-anchor="middle" font-size="9.5" font-weight="900" class="attack-count-sublabel">
            <tspan fill="${LEGEND.attack}">${attackCount} ${attackCount === 1 ? 'ataque' : 'ataques'}</tspan>${outcomes.blocked ? `<tspan fill="${LEGEND.blockedText}"> · ✓${outcomes.blocked} bloq.</tspan>` : ''}${wasBreached ? `<tspan fill="${LEGEND.breached}"> · :(${outcomes.passed} invadiu</tspan>` : ''}
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
        ${wasBreached ? (() => {
          const pStr = `:(${outcomes.passed}`;
          const pW = Math.max(28, pStr.length * 7.5 + 10);
          return `
          <g class="node-breached-badge" transform="translate(${n.r * 0.72}, ${n.r * 0.72})">
            <title>${outcomes.passed} chegaram ao alvo — invadiu :(</title>
            <rect x="${-pW / 2}" y="-10" width="${pW}" height="20" rx="10" fill="${LEGEND.breached}" stroke="#ffffff" stroke-width="2" />
            <text x="0" y="0" text-anchor="middle" dominant-baseline="central" fill="#ffffff" font-size="10.5" font-weight="900" font-family="ui-monospace, Consolas, monospace">${pStr}</text>
          </g>`;
        })() : ''}

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
      <span class="lg-item"><span class="lg-dot" style="background:${LEGEND.breached}">:(</span>chegou ao alvo — invadiu</span>
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
let hdbLedgerLimit = 1000;
let hdbTotalRealEvents = 0;
let hdbLatestLsn = 0;
let demoProfile = { DEFENDED: 33, BLOCKED: 33, TARGET_REACHED: 34 };

async function loadRealHeraclitusTrail() {
  const badge = $('#integrationBadge');
  const summaryBadge = $('#heraclitusSummaryBadge');
  const rows = $('#heraclitusEventRows');
  if (!rows) return;

  try {
    const res = await api('/api/heraclitus-events?limit=1000');
    const data = res.data || {};
    const events = data.events || [];
    if (res.limit) hdbLedgerLimit = res.limit;
    if (res.total_real_events) {
      hdbTotalRealEvents = Math.max(hdbTotalRealEvents, Number(res.total_real_events) || 0);
    }
    if (res.latest_lsn) {
      hdbLatestLsn = Math.max(hdbLatestLsn, Number(res.latest_lsn) || 0);
    }

    if (res.status === 'PASS' && Array.isArray(events)) {
      if (badge) {
        badge.textContent = 'CONECTADO (8080)';
        badge.className = 'tag-status normal';
      }

      // Mesclagem com retenção cumulativa: preserva eventos já acumulados para contagem infinita
      const existingMap = new Map();
      for (const ev of hdbAllEvents) {
        const k = ev.evidence_id || ev.lsn || ev.attack_id;
        if (k) existingMap.set(k, ev);
      }
      for (const ev of events) {
        const k = ev.evidence_id || ev.lsn || ev.attack_id;
        if (k) existingMap.set(k, ev);
      }
      hdbAllEvents = Array.from(existingMap.values()).sort((a, b) => (Number(b.lsn) || 0) - (Number(a.lsn) || 0));

      const displayTotal = Math.max(hdbTotalRealEvents, hdbAllEvents.length, hdbLatestLsn);
      if (summaryBadge) {
        summaryBadge.textContent = `${fmtInt(displayTotal)} eventos reais registrados no Ledger HRKL${hdbLatestLsn ? ` (LSN ${fmtInt(hdbLatestLsn)})` : ''}`;
        summaryBadge.style.color = 'var(--gov-green-light)';
      }

      renderHdbPage();
      renderIncidentCharts();
    } else {
      if (badge) {
        badge.textContent = 'OFFLINE (8080)';
        badge.className = 'tag-status';
      }
      if (summaryBadge) {
        summaryBadge.textContent = 'HeraclitusDB local indisponível';
      }
      rows.innerHTML = `<tr><td colspan="9" class="empty">HeraclitusDB não respondeu na porta 8080 (${esc(res.error || 'Indisponível')}).</td></tr>`;
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
    if (ev.reason_code === 'DEMO_DEFENDED') {
      badgeClass = 'OBSERVED';
      label = 'SIMULADO · DEFENDIDO';
    } else if (ev.reason_code === 'DEMO_BLOCKED') {
      badgeClass = 'DENY';
      label = 'SIMULADO · BLOQUEADO';
    } else if (ev.reason_code === 'DEMO_TARGET_REACHED') {
      badgeClass = 'PASS';
      label = 'SIMULADO · CHEGOU AO ALVO';
    } else if (decision === 'PASS') {
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
      statusHdb.textContent = 'LEDGER HRKL (Porta 8080)';
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
    renderIncidentCharts();
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
        const isAiOrForensic = atk.category === 'IA' || atk.id === 'IA_ZAN_05' || atk.id === 'IA_VIT_03' || atk.id === 'IA_VIC_01' || atk.forensic_case_id;
        const forensicBtn = isAiOrForensic ? `
          <button class="attack-btn secondary" style="background: #1e3a8a; color: #ffffff; border: 1px solid #3b82f6; font-size: 11px; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: 700; white-space: nowrap;" onclick="event.stopPropagation(); window.goToDefesaZanin('${atk.id}')">🔬 Ver Perícia na Defesa Zanin ➔</button>
        ` : '';
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
            <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
              <button class="attack-btn" onclick="executeStfAttack('${atk.id}')">⚡ Disparar</button>
              ${forensicBtn}
            </div>
          </div>
        `;
      }).join('');
    }
    applyNodeFilter();
    renderIncidentCharts();
  } catch (err) {
    console.error('Erro ao carregar catálogo da infraestrutura STF:', err);
  }
}

// NAVEGAÇÃO DIRETA PARA A CÂMARA PERICIAL (DEFESA ZANIN)
window.goToDefesaZanin = function(attackId) {
  const caseMap = {
    'IA_ZAN_05': 'vector_stego_coercion',
    'IA_VIT_03': 'vector_tool_exfil',
    'IA_VIC_01': 'vector_zeroday_bypass',
    'IA_MAR_02': 'vector_zeroday_bypass',
    'IA_RAF_04': 'vector_zeroday_bypass',
    'H09': 'vector_zeroday_bypass'
  };
  const targetCase = caseMap[attackId] || 'vector_stego_coercion';

  // Alterna para a view Zanin
  if (typeof mostrarView === 'function') {
    mostrarView('zanin');
  } else {
    const tabZ = document.getElementById('tabZanin');
    if (tabZ) tabZ.click();
  }

  // Carrega o caso pericial específico
  if (typeof window.loadDefesaZaninCase === 'function') {
    window.loadDefesaZaninCase(targetCase, attackId);
  }
  toast(`Auditoria Forense: Inspecionando evidência do ataque ${attackId} na Câmara Defesa Zanin.`);
};

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

    // Se for ataque de IA/Documental, avisa que está disponível na Defesa Zanin
    if (atk && (atk.category === 'IA' || atk.id === 'IA_ZAN_05' || atk.id === 'IA_VIT_03')) {
      setTimeout(() => {
        toast(`🔍 Ataque ${attackId} registrado! Para ver a análise pericial completa, acesse a aba Defesa Zanin.`);
      }, 1200);
    }
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
let massiveTargetBag = [];

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
  heraclitus: 'HeraclitusDB (Porta 8080)',
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
  massiveTargetBag = [];

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
  massiveTargetBag = [];
  loadRealHeraclitusTrail();
};

async function runMassiveCycle() {
  if (!massiveLoopActive || !currentMassiveMode) return;

  const targetList = MASSIVE_TARGETS[currentMassiveMode] || MASSIVE_TARGETS.random;
  if (!massiveTargetBag.length) {
    massiveTargetBag = [...targetList];
    for (let i = massiveTargetBag.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [massiveTargetBag[i], massiveTargetBag[j]] = [massiveTargetBag[j], massiveTargetBag[i]];
    }
  }
  const attackId = massiveTargetBag.pop();

  try {
    massiveAttackCount++;
    const bannerText = $('#massiveBannerText');
    if (bannerText) {
      bannerText.textContent = `ATAQUE MASSIVO CONTÍNUO [${MODE_LABELS[currentMassiveMode] || currentMassiveMode.toUpperCase()}]: ${massiveAttackCount} disparos`;
    }

    await executeDemoAttackSilent(attackId);
  } catch (err) {
    console.warn('[MassiveLoop] Erro no disparo:', err);
    stopAllMassiveAttacks(false);
    toast(`Simulação interrompida: ${err.message}`);
  }

  if (massiveLoopActive) {
    massiveLoopTimer = setTimeout(runMassiveCycle, 650);
  }
}

async function executeDemoAttackSilent(attackId) {
  const res = await api('/api/demo-simulate', {
    method: 'POST', body: JSON.stringify({ attack_id: attackId })
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
  markLiveAttackLsn(res.event?.lsn ?? res.lsn);
  if (targetNodeId && atk) triggerNodeAttackPopup(targetNodeId, atk.id, atk.title, outcomeOf(res));
  showMassiveAttackHint(res);

  // Injeta imediatamente o evento gerado no ledger em memória para atualização dinâmica contínua (infinita)
  if (res.event) {
    const evLsn = Number(res.event.heraclitus_lsn || res.lsn) || 0;
    if (evLsn > hdbLatestLsn) hdbLatestLsn = evLsn;
    hdbTotalRealEvents = Math.max(hdbTotalRealEvents + 1, evLsn);

    const rawEv = {
      attack_id: res.event.type ? res.event.type.replace('demo.attack.', 'demo-') : (atk?.id || 'demo-atk'),
      campaign_id: 'STF-DEMO-SIMULATION',
      lsn: evLsn || res.lsn,
      observed_at_unix_nanos: Date.now() * 1000000,
      target: res.event.asset || atk?.target,
      vector: atk?.vector || atk?.title || res.event.summary,
      blocked: res.simulation_outcome !== 'TARGET_REACHED',
      result: res.simulation_outcome === 'TARGET_REACHED' ? 'fail' : 'pass',
      reason_code: `DEMO_${res.simulation_outcome}`,
      upstream_delta: 0,
      evidence_id: `SIM-${evLsn || Date.now()}`
    };
    const k = rawEv.evidence_id || rawEv.lsn;
    if (!hdbAllEvents.some(e => (e.evidence_id || e.lsn) === k)) {
      hdbAllEvents.unshift(rawEv);
      hdbAllEvents.sort((a, b) => (Number(b.lsn) || 0) - (Number(a.lsn) || 0));
    }
    renderIncidentCharts();
    const summaryBadge = $('#heraclitusSummaryBadge');
    if (summaryBadge) {
      const displayTotal = Math.max(hdbTotalRealEvents, hdbAllEvents.length, hdbLatestLsn);
      summaryBadge.textContent = `${fmtInt(displayTotal)} eventos reais registrados no Ledger HRKL${hdbLatestLsn ? ` (LSN ${fmtInt(hdbLatestLsn)})` : ''}`;
    }
  }

  if (massiveAttackCount % 5 === 0) loadRealHeraclitusTrail();
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
// Regra ÚNICA de desfecho — a mesma do servidor (is_blocked em server.py) e do grafo:
// cada evento de ataque é uma TENTATIVA (vermelho); é BLOQUEADO o que a defesa parou ou
// reteve (HITL não executa nada); tudo o resto INVADIU (roxo), inclusive a intrusão só
// observada da fase 1. "inconclusive" sem bloqueio vem de testes externos sem veredito.
const DECISION_CATS = [
  { key: 'DEFENDED', label: 'Defendido (detectado e contido)', color: 'var(--chart-defended)' },
  { key: 'DENY', label: 'Bloqueado (não invadiu)', color: 'var(--chart-blocked)' },
  { key: 'PASS', label: 'Chegou ao alvo', color: 'var(--chart-pass)' },
  { key: 'OTHER', label: 'Inconclusivo (sem veredito)', color: 'var(--chart-other)' }
];
const ATTEMPT_CAT = { key: 'ATTEMPT', label: 'Tentativas de ataque', color: 'var(--chart-attempts)' };

// Eventos de controlo não são ataques. Os gravados antes do prefixo STF-CTRL-
// reconhecem-se pelo tipo.
const CONTROL_VECTORS = new Set(['approval.granted', 'evidence.exported', 'evidence.verified']);

function isControlEvent(ev) {
  if (String(ev.attack_id || '').startsWith('STF-CTRL-')) return true;
  const v = String(ev.vector || '');
  return CONTROL_VECTORS.has(v) || (v === 'network.connection' && String(ev.result || '').toUpperCase() === 'ALLOW');
}

// null = não é tentativa de ataque (fica fora de todos os gráficos)
function classifyDecision(ev) {
  if (isControlEvent(ev)) return null;
  const reason = String(ev.reason_code || '');
  if (reason === 'DEMO_DEFENDED') return 'DEFENDED';
  if (reason === 'DEMO_BLOCKED') return 'DENY';
  if (reason === 'DEMO_TARGET_REACHED') return 'PASS';
  const raw = String(ev.result || '');
  const r = raw.toUpperCase();
  if ((Number(ev.upstream_delta) || 0) > 0) return 'PASS';
  if (ev.blocked || BLOCKED_OUTCOMES.has(r) || /_BLOCKED$/.test(String(ev.reason_code || ''))) return 'DENY';
  // "pass" minúsculo é o veredito do oráculo de teste: a defesa aguentou.
  if (raw === 'pass') return 'DENY';
  if (r === 'INCONCLUSIVE') return 'OTHER';
  return 'PASS';
}

function eventTimeMs(ev) {
  const ns = Number(ev.observed_at_unix_nanos);
  return Number.isFinite(ns) && ns > 0 ? Math.floor(ns / 1e6) : null;
}

const fmtInt = n => Number(n || 0).toLocaleString('pt-BR');
const pctOf = (n, total) => (total ? `${Math.round((n / total) * 100)}%` : '');

function renderIncidentCharts() {
  const demoEvents = (hdbAllEvents || []).filter(ev => ev.campaign_id === 'STF-DEMO-SIMULATION');
  const sourceEvents = demoEvents.length ? demoEvents : (hdbAllEvents || []);
  const attacks = sourceEvents.map(ev => ({ ev, k: classifyDecision(ev) })).filter(x => x.k);
  const counters = state?.equipment_counters || {};

  // KPIs
  const byDecision = Object.fromEntries(DECISION_CATS.map(c => [c.key, 0]));
  let upstream = 0;
  for (const { ev, k } of attacks) {
    byDecision[k]++;
    upstream += Number(ev.upstream_delta) || 0;
  }
  // Total real e infinito contado no Ledger HRKL (sem teto artificial de página)
  const sampleCount = attacks.length || 1;
  const total = Math.max(hdbTotalRealEvents, hdbAllEvents.length, attacks.length, hdbLatestLsn);

  // Proporções observadas na amostra aplicadas ao total real contado
  const countDefended = attacks.length ? Math.round((byDecision.DEFENDED / sampleCount) * total) : 0;
  const countBlocked = attacks.length ? Math.round((byDecision.DENY / sampleCount) * total) : 0;
  const countInvaded = Math.max(0, total - countDefended - countBlocked);

  const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  setText('#chartSourceLabel', demoEvents.length
    ? `SIMULAÇÃO gravada no HeraclitusDB · desfechos 100% randômicos · sem efeito real no alvo`
    : 'resultados observados no ledger HeraclitusDB');
  setText('#chartDecisionTitle', demoEvents.length ? 'Desfechos da simulação' : 'Decisões do gateway');
  setText('#kpiInvadedLabel', demoEvents.length ? 'Chegou ao alvo (simulado) :(' : 'Invadiu (chegou ao alvo) :(');
  setText('#kpiEvents', fmtInt(total));
  setText('#kpiEventsSub', `${fmtInt(total)} eventos contados no ledger HRKL · contínuo e crescente`);
  setText('#kpiDefended', fmtInt(countDefended));
  setText('#kpiDefendedPct', total ? `${pctOf(countDefended, total)} das tentativas (randômico)` : '');
  setText('#kpiBlocked', fmtInt(countBlocked));
  setText('#kpiBlockedPct', total ? `${pctOf(countBlocked, total)} das tentativas (randômico)` : '');
  setText('#kpiInvaded', fmtInt(countInvaded));
  setText('#kpiInvadedPct', total ? `${pctOf(countInvaded, total)} das tentativas (randômico)` : '');
  setText('#kpiUpstream', fmtInt(upstream));
  const topEq = Object.values(counters).sort((a, b) => (b.attempts || 0) - (a.attempts || 0))[0];
  setText('#kpiTopEquip', topEq && topEq.attempts ? `${topEq.name} (${fmtInt(topEq.attempts)})` : '—');

  renderActivityTimeline(attacks);
  renderDecisionDonut({ DEFENDED: countDefended, DENY: countBlocked, PASS: countInvaded }, total);
  renderEquipmentChart(counters, demoEvents);
  renderVectorChart(attacks.map(x => x.ev));
}

// ========================================================
// ATIVIDADE NO TEMPO: MAPA ESTILO GITHUB + AVANÇO ACUMULADO
// ========================================================
const HEAT_STEPS = [
  { ms: 60e3, label: '1 minuto' },
  { ms: 5 * 60e3, label: '5 minutos' },
  { ms: 15 * 60e3, label: '15 minutos' },
  { ms: 3600e3, label: '1 hora' },
  { ms: 6 * 3600e3, label: '6 horas' },
  { ms: 86400e3, label: '1 dia' }
];
// Pelo menos 45 colunas: a grelha ocupa a largura toda, como a do GitHub.
const HEAT_ROWS = 7, HEAT_MIN_COLS = 45, HEAT_MAX_COLS = 53;
const HEAT_WEEKDAYS = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];

function heatBucket(t, step) {
  if (step.ms < 86400e3) return Math.floor(t / step.ms) * step.ms;
  const d = new Date(t);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function heatLabel(t, step, withDate) {
  const d = new Date(t);
  if (step.ms >= 86400e3) return d.toLocaleDateString('pt-BR', { month: 'short' }).replace('.', '');
  const hm = d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  return withDate ? `${d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} ${hm}` : hm;
}

function renderActivityTimeline(attacks) {
  const host = $('#chartTimeline');
  const legend = $('#legendTimeline');
  if (!host) return;
  const timed = attacks.map(({ ev, k }) => ({ t: eventTimeMs(ev), k })).filter(e => e.t).sort((a, b) => a.t - b.t);
  if (legend) {
    legend.innerHTML = [ATTEMPT_CAT, ...DECISION_CATS.slice(0, 3)].map(d =>
      `<span class="lg-item"><i class="lg-swatch" style="background:${d.color}"></i>${d.label}</span>`).join('');
  }
  if (!timed.length) {
    host.innerHTML = '<div class="chart-empty">Sem tentativas de ataque com data no ledger.</div>';
    return;
  }

  // Grelha como a das contribuições do GitHub: colunas de 7 quadrados, da mais
  // antiga (esquerda) para a atual (direita); o último quadrado é "agora".
  const endT = Math.max(Date.now(), timed[timed.length - 1].t);
  const firstT = timed[0].t;
  const step = HEAT_STEPS.find(s => (endT - firstT) / s.ms < HEAT_ROWS * HEAT_MAX_COLS) || HEAT_STEPS[HEAT_STEPS.length - 1];
  const daily = step.ms >= 86400e3;
  const endB = heatBucket(endT, step);
  const needed = Math.round((endB - heatBucket(firstT, step)) / step.ms) + 1;
  const cols = Math.min(HEAT_MAX_COLS, Math.max(HEAT_MIN_COLS, Math.ceil(needed / HEAT_ROWS)));
  // Diário: a linha é o dia da semana (Dom..Sáb), como no GitHub.
  const lastIdx = daily ? (cols - 1) * HEAT_ROWS + new Date(endB).getDay() : cols * HEAT_ROWS - 1;
  const startB = endB - lastIdx * step.ms;
  const cells = Array.from({ length: lastIdx + 1 }, (_, i) => ({ t: startB + i * step.ms, n: 0, DEFENDED: 0, DENY: 0, PASS: 0, OTHER: 0 }));
  const base = { n: 0, DEFENDED: 0, DENY: 0, PASS: 0, OTHER: 0 }; // tentativas anteriores à janela
  for (const e of timed) {
    const i = Math.round((heatBucket(e.t, step) - startB) / step.ms);
    const target = i < 0 ? base : cells[Math.min(i, lastIdx)];
    target.n++;
    target[e.k]++;
  }
  const maxN = Math.max(1, ...cells.map(c => c.n));
  const level = n => (n ? Math.min(4, Math.ceil((n / maxN) * 4)) : 0);

  // ---------------------------------------------------------- mapa de calor
  const pitch = 15, cell = 12, labelW = daily ? 30 : 8, topH = 18;
  const W = labelW + cols * pitch, H = topH + HEAT_ROWS * pitch;
  const everyCol = Math.max(1, Math.ceil(cols / 7));
  let lastDay = null;
  const topLabels = [];
  for (let c = 0; c < cols; c++) {
    const t = startB + c * HEAT_ROWS * step.ms;
    const day = new Date(t).toDateString();
    const monthChanged = daily && (c === 0 || new Date(t).getMonth() !== new Date(t - HEAT_ROWS * step.ms).getMonth());
    if (daily ? monthChanged : c % everyCol === 0) {
      topLabels.push(`<text class="axis-text" x="${labelW + c * pitch}" y="11">${esc(heatLabel(t, step, !daily && day !== lastDay))}</text>`);
      lastDay = day;
    }
  }
  const rowLabels = daily ? [1, 3, 5].map(r =>
    `<text class="axis-text" x="0" y="${topH + r * pitch + cell - 2}">${HEAT_WEEKDAYS[r]}</text>`).join('') : '';
  const fmtRange = c => {
    const a = new Date(c.t), b = new Date(c.t + step.ms);
    return daily
      ? a.toLocaleDateString('pt-BR', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' })
      : `${a.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })} ${a.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}–${b.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
  };
  const squares = cells.map((c, i) => {
    const x = labelW + Math.floor(i / HEAT_ROWS) * pitch;
    const y = topH + (i % HEAT_ROWS) * pitch;
    const now = i === lastIdx;
    const cls = `heat-cell heat-${level(c.n)}${c.PASS ? ' heat-breach' : ''}${now ? ' heat-now' : ''}`;
    const tip = `<strong>${esc(fmtRange(c))}${now ? ' · agora' : ''}</strong>` +
      `<div class="tt-row"><i class="lg-swatch" style="background:${ATTEMPT_CAT.color}"></i>${ATTEMPT_CAT.label}<b>${fmtInt(c.n)}</b></div>` +
      DECISION_CATS.filter(d => c[d.key] || d.key !== 'OTHER').map(d =>
        `<div class="tt-row"><i class="lg-swatch" style="background:${d.color}"></i>${d.label}<b>${fmtInt(c[d.key])}</b></div>`).join('');
    return `<rect class="${cls}" x="${x}" y="${y}" width="${cell}" height="${cell}" rx="2.5" data-tip="${esc(tip)}"/>`;
  }).join('');
  const heatSvg = `<svg class="heatmap-svg" viewBox="0 0 ${W} ${H}">
    ${topLabels.join('')}${rowLabels}${squares}</svg>`;
  const inWindow = cells.reduce((s, c) => s + c.n, 0);
  const heatFoot = `<div class="heat-foot">
    <span>Cada quadrado = ${step.label}${daily ? '' : ', de cima para baixo'} · ${fmtInt(inWindow)} tentativa(s) na janela${base.n ? ` (+${fmtInt(base.n)} antes)` : ''}</span>
    <span class="heat-scale">Menos ${[0, 1, 2, 3, 4].map(l => `<i class="heat-cell heat-${l}"></i>`).join('')} Mais
      <i class="heat-cell heat-2 heat-breach" style="margin-left:10px"></i> com invasão
      <i class="heat-cell heat-0 heat-now" style="margin-left:10px"></i> agora</span>
  </div>`;

  // ------------------------------------------- avanço acumulado (linha do tempo)
  const LW = 1000, LH = 150, padL = 40, padR = 70, padT = 10, padB = 22;
  const plotW = LW - padL - padR, plotH = LH - padT - padB;
  const acc = { n: base.n, DEFENDED: base.DEFENDED, DENY: base.DENY, PASS: base.PASS };
  const series = cells.map(c => {
    acc.n += c.n; acc.DEFENDED += c.DEFENDED; acc.DENY += c.DENY; acc.PASS += c.PASS;
    return { t: c.t, n: acc.n, DEFENDED: acc.DEFENDED, DENY: acc.DENY, PASS: acc.PASS };
  });
  const maxY = niceMax(acc.n);
  const xAt = i => padL + (series.length > 1 ? (i / (series.length - 1)) * plotW : plotW);
  const yAt = v => padT + plotH - (v / maxY) * plotH;
  const lines = [
    { key: 'n', color: ATTEMPT_CAT.color, label: 'tentativas' },
    { key: 'DEFENDED', color: 'var(--chart-defended)', label: 'defendidos' },
    { key: 'DENY', color: 'var(--chart-blocked)', label: 'bloqueados' },
    { key: 'PASS', color: 'var(--chart-pass)', label: 'chegou ao alvo' }
  ];
  const stepPath = key => series.map((p, i) =>
    i === 0 ? `M ${xAt(0)} ${yAt(p[key])}` : `H ${xAt(i)} V ${yAt(p[key])}`).join(' ');
  const area = `${stepPath('n')} V ${yAt(0)} H ${xAt(0)} Z`;
  const grid = [0, 0.5, 1].map(f => {
    const v = Math.round(maxY * f);
    return `<line class="grid-line" x1="${padL}" x2="${LW - padR}" y1="${yAt(v)}" y2="${yAt(v)}"/>
      <text class="axis-text" x="${padL - 6}" y="${yAt(v)}" text-anchor="end" dominant-baseline="central">${fmtInt(v)}</text>`;
  }).join('');
  const tickEvery = Math.max(1, Math.ceil(series.length / 6));
  const ticks = series.map((p, i) => (i % tickEvery === 0 || i === series.length - 1)
    ? `<text class="axis-text" x="${xAt(i)}" y="${LH - 6}" text-anchor="${i === series.length - 1 ? 'end' : 'middle'}">${i === series.length - 1 ? 'agora' : esc(heatLabel(p.t, step, false))}</text>` : '').join('');
  const ends = lines.map((l, j) => {
    const v = series[series.length - 1][l.key];
    // rótulos à direita, afastados para não se sobreporem quando os valores coincidem
    const y = Math.min(padT + plotH, yAt(v) + (j - 1) * 12);
    return `<circle cx="${xAt(series.length - 1)}" cy="${yAt(v)}" r="3" fill="${l.color}"/>
      <text class="value-text" x="${LW - padR + 6}" y="${y}" dominant-baseline="central" style="fill:${l.color}">${fmtInt(v)} ${l.label}</text>`;
  }).join('');
  const slot = plotW / Math.max(1, series.length - 1);
  const hits = series.map((p, i) => {
    const tip = `<strong>até ${esc(fmtRange(cells[i]))}</strong>` + lines.map(l =>
      `<div class="tt-row"><i class="lg-swatch" style="background:${l.color}"></i>${l.label}<b>${fmtInt(p[l.key])}</b></div>`).join('');
    return `<rect class="hit" x="${xAt(i) - slot / 2}" y="${padT}" width="${slot}" height="${plotH}" data-tip="${esc(tip)}"/>`;
  }).join('');
  const lineSvg = `<svg viewBox="0 0 ${LW} ${LH}" preserveAspectRatio="none" style="height:${LH}px">
    ${grid}<path d="${area}" fill="${ATTEMPT_CAT.color}" opacity="0.07"/>
    <line x1="${padL}" x2="${LW - padR}" y1="${yAt(0)}" y2="${yAt(0)}" stroke="#b9c7d8"/>
    ${lines.map(l => `<path class="mark" d="${stepPath(l.key)}" fill="none" stroke="${l.color}" stroke-width="2.2" stroke-linejoin="round"/>`).join('')}
    ${ends}${ticks}${hits}</svg>`;

  host.innerHTML = `<div class="heatmap-wrap">${heatSvg}${heatFoot}</div>
    <div class="timeline-sub">Avanço no tempo <small>tentativas e desfechos acumulados</small></div>${lineSvg}`;
}

function renderDecisionDonut(byDecision, total) {
  const host = $('#chartDecisions');
  if (!host) return;
  if (!total) {
    host.innerHTML = '<div class="chart-empty">Sem tentativas registadas.</div>';
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
    const tip = `<strong>${d.label}</strong><div class="tt-row">Tentativas<b>${fmtInt(byDecision[d.key])}</b></div><div class="tt-row">Parcela<b>${pctOf(byDecision[d.key], total)}</b></div>`;
    if (frac >= 0.999) {
      return `<g data-tip="${esc(tip)}"><circle class="mark" cx="${C}" cy="${C}" r="${(R + r) / 2}" fill="none" stroke="${d.color}" stroke-width="${R - r}"/></g>`;
    }
    const large = e - s > Math.PI ? 1 : 0;
    const p = (rad, ang) => `${C + rad * Math.cos(ang)} ${C + rad * Math.sin(ang)}`;
    return `<g data-tip="${esc(tip)}"><path class="mark" fill="${d.color}" d="M ${p(R, s)} A ${R} ${R} 0 ${large} 1 ${p(R, e)} L ${p(r, e)} A ${r} ${r} 0 ${large} 0 ${p(r, s)} Z"/></g>`;
  }).join('');
  const attemptTip = `<strong>${ATTEMPT_CAT.label}</strong><div class="tt-row">Eventos<b>${fmtInt(total)}</b></div>`;
  const attemptRing = `<g data-tip="${esc(attemptTip)}"><circle class="mark" cx="${C}" cy="${C}" r="${(RA + ra) / 2}" fill="none" stroke="${ATTEMPT_CAT.color}" stroke-width="${RA - ra}"/></g>`;

  host.innerHTML = `<div class="donut-wrap">
    <svg viewBox="0 0 150 150">${attemptRing}${arcs}
      <text x="${C}" y="${C - 5}" text-anchor="middle" class="value-text" style="font-size:20px; fill:${ATTEMPT_CAT.color}">${fmtInt(total)}</text>
      <text x="${C}" y="${C + 13}" text-anchor="middle" class="axis-text">tentativas</text>
    </svg>
    <div class="donut-legend">
      <span class="lg-item"><span><i class="lg-swatch" style="background:${ATTEMPT_CAT.color}"></i> ${ATTEMPT_CAT.label}</span><b>${fmtInt(total)}</b></span>
      ${DECISION_CATS.filter(d => byDecision[d.key] || d.key === 'DENY' || d.key === 'PASS').map(d =>
        `<span class="lg-item"><span><i class="lg-swatch" style="background:${d.color}"></i> ${d.label}</span><b>${fmtInt(byDecision[d.key])} · ${pctOf(byDecision[d.key], total) || '0%'}</b></span>`).join('')}
    </div></div>`;
}

// Barras horizontais: tentativas, bloqueios e invasões por equipamento (top 10) —
// os mesmos contadores do grafo.
function renderEquipmentChart(counters, demoEvents = []) {
  const host = $('#chartEquipment');
  if (!host) return;
  const byEquipment = Object.fromEntries(Object.values(counters).map(eq =>
    [eq.id, { ...eq, attempts: 0, defended: 0, unauthorized_blocked: 0, reached: 0 }]));
  if (demoEvents.length) {
    const catalog = [...cachedStfAttacks, ...cachedHdbAttacks];
    for (const ev of demoEvents) {
      const atk = catalog.find(item => String(ev.attack_id || '').startsWith(`demo-${item.id.toLowerCase()}-`));
      const row = atk && byEquipment[atk.equipment_id];
      if (!row) continue;
      row.attempts++;
      const decision = classifyDecision(ev);
      if (decision === 'DEFENDED') row.defended++;
      else if (decision === 'DENY') row.unauthorized_blocked++;
      else if (decision === 'PASS') row.reached++;
    }
  }
  const rows = (demoEvents.length ? Object.values(byEquipment) : Object.values(counters))
    .filter(eq => demoEvents.length || (eq.attempts || 0) > 0)
    .sort((a, b) => (b.attempts || 0) - (a.attempts || 0));
  if (!rows.length) {
    host.innerHTML = '<div class="chart-empty">Nenhum equipamento atacado ainda.</div>';
    return;
  }
  const maxV = niceMax(Math.max(1, ...rows.map(r => r.attempts || 0)));
  const W = 420, labelW = 130, valW = 34, rowH = 38, barH = 7;
  const plotW = W - labelW - valW;
  const H = rows.length * rowH + 4;
  const bar = (y, v, color) => (v ? `<rect class="mark" x="${labelW}" y="${y}" width="${Math.max(2, (v / maxV) * plotW)}" height="${barH}" rx="2" fill="${color}"/>` : '');
  const body = rows.map((eq, i) => {
    const y0 = i * rowH + 4;
    const attempts = eq.attempts || 0, defended = eq.defended || 0;
    const blocked = eq.unauthorized_blocked || 0;
    const breached = demoEvents.length ? eq.reached || 0 : Math.max(0, attempts - blocked);
    const wA = Math.max(2, (attempts / maxV) * plotW);
    const tip = `<strong>${esc(eq.name)}</strong>` +
      `<div class="tt-row"><i class="lg-swatch" style="background:var(--chart-attempts)"></i>Tentativas<b>${fmtInt(attempts)}</b></div>` +
      (demoEvents.length ? `<div class="tt-row"><i class="lg-swatch" style="background:var(--chart-defended)"></i>Defendidas<b>${fmtInt(defended)}</b></div>` : '') +
      `<div class="tt-row"><i class="lg-swatch" style="background:var(--chart-blocked)"></i>Bloqueadas<b>${fmtInt(blocked)}</b></div>` +
      `<div class="tt-row"><i class="lg-swatch" style="background:var(--chart-pass)"></i>Chegou ao alvo<b>${fmtInt(breached)}</b></div>`;
    return `<g class="bar-group" data-tip="${esc(tip)}">
      <rect class="hit" x="0" y="${y0 - 3}" width="${W}" height="${rowH}"/>
      <text class="label-text" x="${labelW - 8}" y="${y0 + barH + 1}" text-anchor="end" dominant-baseline="central">${esc(short(eq.name, 20))}</text>
      ${bar(y0, attempts, 'var(--chart-attempts)')}
      ${demoEvents.length ? bar(y0 + barH + 1, defended, 'var(--chart-defended)') : ''}
      ${bar(y0 + (demoEvents.length ? 2 : 1) * (barH + 1), blocked, 'var(--chart-blocked)')}
      ${bar(y0 + (demoEvents.length ? 3 : 2) * (barH + 1), breached, 'var(--chart-pass)')}
      <text class="value-text" x="${labelW + wA + 5}" y="${y0 + barH / 2}" dominant-baseline="central">${fmtInt(attempts)}</text>
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
    const tip = `<strong>${esc(name)}</strong><div class="tt-row">Tentativas<b>${fmtInt(n)}</b></div>`;
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
  // Com a aba de processos aberta o grafo está escondido (tamanho 0): a
  // simulação física desfazia o layout. mostrarView() redesenha ao voltar.
  if (!$('#viewDefesa')?.hidden) renderGraph(s);
  renderTrail(s);
  updateFocusCard(s);
}

// INICIALIZAÇÃO
async function init() {
  setupLeftPanelTabs();
  setupChartTooltip();
  try { demoProfile = (await api('/api/demo-profile')).weights || demoProfile; } catch (_) {}
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
  // Atualização contínua leve da trilha real do HeraclitusDB e do grafo/estado
  setInterval(async () => {
    loadRealHeraclitusTrail();
    try {
      const s = await api('/api/state');
      render(s);
    } catch (_) {}
  }, 3000);
}

init();
