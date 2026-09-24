const $ = s => document.querySelector(s);
let state = null;
let running = false;
let selectedNode = null;

// Catálogo dos 17 ataques mapeados diretamente à Infraestrutura do STF
const ATTACKS = [
  { step: 1, title: '01. Calibração e Tráfego Benigno', infra: 'Firewall / WAF', target: 'public-edge', type: 'network.connection', phase: 'FASE 1', desc: 'Tráfego legítimo de calibração para estabelecer a linha de base no perímetro do STF.' },
  { step: 2, title: '02. Sondagem no Perímetro (WAF)', infra: 'Firewall / WAF', target: 'public-edge', type: 'edge.suspicious', phase: 'FASE 1', desc: 'Padrão incomum de requisições no perímetro de borda do Portal do STF.' },
  { step: 3, title: '03. Invasão de Sessão (IAM)', infra: 'Máquinas Ministros (VDI)', target: 'identity-provider', type: 'identity.login', phase: 'FASE 1', desc: 'Novo contexto de autenticação suspeito em estação de trabalho de gabinete (service-account-17).' },
  { step: 4, title: '04. Execução de Processo Atípico', infra: 'Servidores Linux', target: 'srv-app-07', type: 'host.process', phase: 'FASE 1', desc: 'Processo incomum executado no servidor Linux do backend da aplicação judicial.' },
  { step: 5, title: '05. Movimento Lateral Interno', infra: 'Servidores Linux', target: 'srv-db-02', type: 'network.lateral', phase: 'FASE 1', desc: 'Conexão lateral correlacionada entre o servidor de aplicação e o banco srv-db-02.' },
  { step: 6, title: '06. Consulta Anômala a Metadados', infra: 'Banco Judicial', target: 'db-judicial-lab', type: 'db.query', phase: 'FASE 1', desc: 'Query fora do padrão da identidade em metadados processuais restritos no banco de dados.' },
  { step: 7, title: '07. Acesso a Autos no PJe', infra: 'PJe / STF Digital', target: 'case://SYNTHETIC/RE-000001', type: 'app.resource_access', phase: 'FASE 1', desc: 'Acesso a processo restrito no PJe. O Sentinel correlaciona os sinais e ABRE O INCIDENTE!' },
  { step: 8, title: '08. Tentativa de Alterar Processo', infra: 'PJe / STF Digital', target: 'case://SYNTHETIC/RE-000001', type: 'app.case_update_requested', phase: 'FASE 2', desc: 'Tentativa de alteração no processo RE-000001. Bloqueio automático pelo Gateway: DENY.' },
  { step: 9, title: '09. Tentativa de Exportar Acórdão Sigiloso', infra: 'Agentes IA (VitórIA/Rafa)', target: 'document://SYNTHETIC/DOC-001', type: 'agent.tool_requested', phase: 'FASE 2', desc: 'Agente solicita exportação de documento restrito. O Gateway exige aprovação humana: REQUIRE_HITL.' },
  { step: 10, title: '10. Aprovação Humana de Operador', infra: 'Gabinete / Operador', target: 'document://SYNTHETIC/DOC-001', type: 'approval.granted', phase: 'FASE 2', desc: 'Operador humano concede autorização vinculada estritamente à identidade, ação e parâmetros.' },
  { step: 11, title: '11. Execução Única da Exportação', infra: 'PJe / Gateway', target: 'document://SYNTHETIC/DOC-001', type: 'tool.executed', phase: 'FASE 2', desc: 'Ação autorizada executa exatamente uma vez. Oráculo upstream emite recibo e soma 1.' },
  { step: 12, title: '12. Tentativa de Replay de Autorização', infra: 'Agentes IA (VitórIA/Rafa)', target: 'document://SYNTHETIC/DOC-001', type: 'approval.replay', phase: 'FASE 2', desc: 'Invasor tenta reaproveitar a autorização consumida: Bloqueio estrito (REPLAY_DETECTED).' },
  { step: 13, title: '13. Tentativa de Troca de Identidade', infra: 'Máquinas Ministros (VDI)', target: 'document://SYNTHETIC/DOC-001', type: 'identity.swap', phase: 'FASE 2', desc: 'Outro agente tenta usar a autorização concedida: Bloqueio (IDENTITY_BINDING_MISMATCH).' },
  { step: 14, title: '14. Tentativa de Troca de Parâmetros', infra: 'PJe / STF Digital', target: 'document://SYNTHETIC/DOC-999', type: 'parameters.swap', phase: 'FASE 2', desc: 'Documento-alvo alterado após aprovação: Bloqueio (PARAMETERS_DIGEST_MISMATCH).' },
  { step: 15, title: '15. Tentativa de Apagar Rastros (Tamper)', infra: 'Trilha HRKL', target: 'evidence-log', type: 'tamper.attempt', phase: 'FASE 2', desc: 'Invasor tenta sabotar histórico. Árvore Merkle e Hash-chain acusam quebra: DETECTED.' },
  { step: 16, title: '16. Geração do Evidence Bundle', infra: 'HeraclitusDB', target: 'evidence://STF-POC-001', type: 'evidence.exported', phase: 'FASE 2', desc: 'Pacote criptográfico de provas digitais gerado com manifesto e prova Merkle completa.' },
  { step: 17, title: '17. Verificação Offline da Integridade', infra: 'Auditoria Externa', target: 'evidence://STF-POC-001', type: 'evidence.verified', phase: 'FASE 2', desc: 'Perícia independente valida as provas matemáticas localmente e sem conexão à rede.' }
];

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-STF-POC': '1', ...(opts.headers || {}) };
  const r = await fetch(path, { ...opts, headers });
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

// RENDERIZAÇÃO GERAL DO ESTADO
function render(s) {
  state = s;

  // Header badges institucionais
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
    incState.style.color = 'var(--gov-gold-light)';
  } else {
    incState.textContent = 'NÃO ABERTO';
    incState.style.color = 'var(--gov-muted)';
  }

  $('#upstreamHits').textContent = s.upstream_hits;
  $('#attackProgress').textContent = `${s.step} / ${s.total_steps} executados`;

  // Atualizar Barra de Infraestrutura do STF
  updateInfraStatusBar(s);

  // Renderizar os 3 componentes da tela
  renderAttackList(s);
  renderGraph(s);
  renderTrail(s);
  updateFocusCard(s);
}

// ATUALIZAÇÃO DA BARRA DE INFRAESTRUTURA DO STF NO TOPO
function updateInfraStatusBar(s) {
  const step = s.step || 0;

  // 1. Firewall / WAF
  const nodeFw = $('#node-fw');
  const statusFw = $('#status-fw');
  if (step >= 2) {
    nodeFw.className = 'infra-node-item targeted';
    statusFw.textContent = 'SONDAGEM OBSERVADA';
    statusFw.style.color = 'var(--gov-gold-light)';
  } else {
    nodeFw.className = 'infra-node-item';
    statusFw.textContent = 'PERÍMETRO NORMAL';
    statusFw.style.color = 'var(--gov-green-light)';
  }

  // 2. Máquinas de Ministros (VDI)
  const nodeMin = $('#node-ministro');
  const statusMin = $('#status-ministro');
  if (step >= 13) {
    nodeMin.className = 'infra-node-item compromised';
    statusMin.textContent = 'TROCA IDENTIDADE (DENY)';
    statusMin.style.color = '#ff9ca6';
  } else if (step >= 3) {
    nodeMin.className = 'infra-node-item compromised';
    statusMin.textContent = 'SESSÃO ANÔMALA (IAM)';
    statusMin.style.color = '#ff9ca6';
  } else {
    nodeMin.className = 'infra-node-item';
    statusMin.textContent = 'AUTENTICAÇÃO SEGURA';
    statusMin.style.color = 'var(--gov-green-light)';
  }

  // 3. Servidores Linux
  const nodeLinux = $('#node-linux');
  const statusLinux = $('#status-linux');
  if (step >= 4) {
    nodeLinux.className = 'infra-node-item compromised';
    statusLinux.textContent = 'PROCESSO ATÍPICO';
    statusLinux.style.color = '#ff9ca6';
  } else {
    nodeLinux.className = 'infra-node-item';
    statusLinux.textContent = 'BACKEND REGULAR';
    statusLinux.style.color = 'var(--gov-green-light)';
  }

  // 4. PJe / STF Digital
  const nodePje = $('#node-pje');
  const statusPje = $('#status-pje');
  if (step >= 8) {
    nodePje.className = 'infra-node-item compromised';
    statusPje.textContent = 'ESCRITA BARRADA (DENY)';
    statusPje.style.color = 'var(--gov-gold-light)';
  } else if (step >= 7) {
    nodePje.className = 'infra-node-item targeted';
    statusPje.textContent = 'AUTOS SOB INCIDENTE';
    statusPje.style.color = '#ff9ca6';
  } else {
    nodePje.className = 'infra-node-item';
    statusPje.textContent = 'AUTOS ÍNTEGROS';
    statusPje.style.color = 'var(--gov-green-light)';
  }

  // 5. Banco Judicial
  const nodeDb = $('#node-db');
  const statusDb = $('#status-db');
  if (step >= 6) {
    nodeDb.className = 'infra-node-item targeted';
    statusDb.textContent = 'QUERY ANÔMALA';
    statusDb.style.color = 'var(--gov-gold-light)';
  } else {
    nodeDb.className = 'infra-node-item';
    statusDb.textContent = 'TRANSACIONAL ÍNTEGRO';
    statusDb.style.color = 'var(--gov-green-light)';
  }

  // 6. Agentes IA (VitórIA/Rafa)
  const nodeIa = $('#node-ia');
  const statusIa = $('#status-ia');
  if (step >= 12) {
    nodeIa.className = 'infra-node-item compromised';
    statusIa.textContent = 'REPLAY BARRADO (DENY)';
    statusIa.style.color = '#ff9ca6';
  } else if (step >= 11) {
    nodeIa.className = 'infra-node-item';
    statusIa.textContent = 'EXPORTAÇÃO 1X (OK)';
    statusIa.style.color = 'var(--gov-green-light)';
  } else if (step >= 9) {
    nodeIa.className = 'infra-node-item targeted';
    statusIa.textContent = 'HITL EXIGIDO';
    statusIa.style.color = 'var(--gov-gold-light)';
  } else {
    nodeIa.className = 'infra-node-item';
    statusIa.textContent = 'GOVERNANÇA HITL';
    statusIa.style.color = 'var(--gov-green-light)';
  }
}

// PAINEL ESQUERDO: LISTA DE ATAQUES
function renderAttackList(s) {
  const container = $('#attackList');
  const currentStep = s.step || 0;

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
      <div class="${cardClass}" id="attack-step-${att.step}">
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

// HINT / NOTIFICAÇÃO DE ATAQUE NO CANTO INFERIOR DIREITO
let hintTimeout = null;

window.closeAttackHint = function() {
  const h = $('#attackHint');
  if (h) h.classList.remove('show');
  if (hintTimeout) clearTimeout(hintTimeout);
};

function showAttackHint(attack, ev) {
  const h = $('#attackHint');
  if (!h || !attack) return;

  const outcome = ev?.outcome || 'EXECUTADO';
  const upstreamDelta = ev?.upstream_delta ?? 0;
  const reasonCode = ev?.reason_code || ev?.details?.policy_decision?.reason_code || '';
  const dt = formatDateTime(ev || { lsn: attack.step });

  const hintTime = $('#hintTime');
  if (hintTime) hintTime.textContent = dt;

  $('#hintAttackName').textContent = attack.title;
  $('#hintInfraName').textContent = `${attack.infra} (${attack.target})`;

  const outcomeBadge = $('#hintOutcome');
  outcomeBadge.textContent = outcome + (reasonCode ? ` [${reasonCode}]` : '');
  outcomeBadge.className = 'hint-outcome-badge ' + (outcome === 'DENY' ? 'DENY' : outcome === 'REQUIRE_HITL' ? 'REQUIRE_HITL' : outcome === 'DETECTED' ? 'DENY' : 'PASS');

  const upstreamBadge = $('#hintUpstream');
  upstreamBadge.textContent = `upstream=${upstreamDelta}`;
  upstreamBadge.style.color = upstreamDelta > 0 ? 'var(--gov-green)' : 'var(--gov-muted)';

  const badge = $('#hintBadge');
  if (outcome === 'DENY') {
    h.className = 'attack-hint show deny';
    badge.textContent = '🛑 ATAQUE BLOQUEADO';
    badge.style.color = 'var(--gov-red)';
    $('#hintDesc').textContent = `Ação contra ${attack.infra} interceptada e BARRADA pelo Gateway com efeito zero (upstream=0) em ${dt}.`;
  } else if (outcome === 'REQUIRE_HITL') {
    h.className = 'attack-hint show hitl';
    badge.textContent = '⚠️ AUTORIZAÇÃO HUMANA EXIGIDA';
    badge.style.color = 'var(--gov-gold)';
    $('#hintDesc').textContent = `Ação de alto risco exige chancela humana de operador de gabinete (HITL) para prosseguir. Registrado em ${dt}.`;
  } else if (outcome === 'DETECTED') {
    h.className = 'attack-hint show deny';
    badge.textContent = '🚨 FRAUDE / SABOTAGEM DETECTADA';
    badge.style.color = 'var(--gov-red)';
    $('#hintDesc').textContent = `Tentativa de adulteração detectada pelo elo criptográfico Merkle da trilha HRKL em ${dt}.`;
  } else {
    h.className = 'attack-hint show pass';
    badge.textContent = 'ℹ️ EVENTO PROCESSADO';
    badge.style.color = 'var(--gov-blue-primary)';
    $('#hintDesc').textContent = (attack.desc || `Ação executada com sucesso contra ${attack.target}.`) + ` Registrado em ${dt}.`;
  }

  if (hintTimeout) clearTimeout(hintTimeout);
  hintTimeout = setTimeout(() => {
    h.classList.remove('show');
  }, 5500);
}

// DETERMINAR METADADOS E ÍCONE DA ARESTA
function getEdgeInfo(edge, s, currentStep) {
  let lsn = null;
  if (edge.to && edge.to.startsWith('event:')) {
    lsn = parseInt(edge.to.replace('event:', ''), 10);
  } else if (edge.from && edge.from.startsWith('event:')) {
    lsn = parseInt(edge.from.replace('event:', ''), 10);
  }

  const ev = (s.events && lsn) ? s.events.find(e => e.lsn === lsn) : null;
  const att = lsn ? ATTACKS[lsn - 1] : null;
  const isCurrentAttack = Boolean(currentStep && lsn === currentStep);

  let icon = '⚡';
  let badgeColor = '#0c326f';
  let badgeBg = '#f0f5fc';

  if (edge.type === 'PART_OF_INCIDENT') {
    icon = '🚨';
    badgeColor = '#c9182b';
    badgeBg = '#fdebee';
  } else if (ev) {
    if (ev.outcome === 'DENY') {
      icon = '🛑';
      badgeColor = '#c9182b';
      badgeBg = '#fdebee';
    } else if (ev.outcome === 'REQUIRE_HITL') {
      icon = '⚠️';
      badgeColor = '#b87704';
      badgeBg = '#fff8e8';
    } else if (ev.outcome === 'DETECTED') {
      icon = '🚨';
      badgeColor = '#c9182b';
      badgeBg = '#fdebee';
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

  const attackTitle = att ? att.title : (ev ? `${ev.event_type}` : 'Conexão Monitorada');
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

// PAINEL DIREITO: GRAFO TEMPORAL COM INFRAESTRUTURA E ATAQUE EM TEMPO REAL
function renderGraph(s) {
  const e = $('#graph');
  const nodes = s.graph.nodes || [];
  const edges = s.graph.edges || [];
  $('#graphStats').textContent = `${nodes.length} nós / ${edges.length} arestas`;

  // Atualizar Banner de Ataque em Tempo Real
  const currentStep = s.step || 0;
  const currentAttack = currentStep > 0 ? ATTACKS[currentStep - 1] : null;
  const nextAttack = currentStep < ATTACKS.length ? ATTACKS[currentStep] : null;

  if (currentAttack) {
    $('#bannerInfraTarget').textContent = `${currentAttack.infra} (${currentAttack.target})`;
    $('#bannerAttackName').textContent = currentAttack.title;
  } else {
    $('#bannerInfraTarget').textContent = 'Infraestrutura Pronta • Perímetro Monitorado';
    $('#bannerAttackName').textContent = `Próximo: ${nextAttack ? nextAttack.title : 'Nenhum'}`;
  }

  if (!nodes.length) {
    e.innerHTML = '<div class="empty graph-empty">O grafo temporal surgirá conforme os ataques forem executados contra a infraestrutura do STF.</div>';
    return;
  }

  const W = 760;
  const H = 460;
  const v = nodes.slice(-28);
  const ids = new Set(v.map(n => n.id));
  const pos = new Map();

  // Mapeamento institucional de nomes no Grafo
  const labelMap = {
    'public-edge': 'Firewall/WAF Borda',
    'edge': 'Rede Perímetro',
    'identity-provider': 'VDI Ministro (IAM)',
    'srv-app-07': 'Servidor Linux STF',
    'srv-db-02': 'Rede Banco Judicial',
    'db-judicial-lab': 'Banco Judicial Autos',
    'case://SYNTHETIC/RE-000001': 'PJe Autos RE-000001',
    'document://SYNTHETIC/DOC-001': 'Acórdão DOC-001 (Sigiloso)',
    'document://SYNTHETIC/DOC-999': 'Documento Alvo DOC-999',
    'evidence-log': 'Preservação HRKL',
    'evidence://STF-POC-001': 'Evidence Bundle',
    'ai-attacker-synthetic': 'Agente Atacante',
    'service-account-17': 'Identidade Invasora (Conta 17)',
    'human:approver-01': 'Aprovador de Gabinete'
  };

  const nodeIconMap = {
    'public-edge': '🛡️',
    'edge': '🛡️',
    'identity-provider': '⚖️',
    'srv-app-07': '🐧',
    'srv-db-02': '🗄️',
    'db-judicial-lab': '🗄️',
    'case://SYNTHETIC/RE-000001': '🏛️',
    'document://SYNTHETIC/DOC-001': '📄',
    'document://SYNTHETIC/DOC-999': '📄',
    'evidence-log': '⛓️',
    'evidence://STF-POC-001': '📦',
    'ai-attacker-synthetic': '🤖',
    'service-account-17': '👤',
    'human:approver-01': '👨‍⚖️'
  };

  // Posicionamento concêntrico dos nós
  v.forEach(n => {
    const ring = n.kind === 'incident' ? 0 : n.kind === 'event' ? 1 : 2;
    const a = v.filter(x => (x.kind === 'incident' ? 0 : x.kind === 'event' ? 1 : 2) === ring);
    const k = a.indexOf(n);
    const r = ring === 0 ? 0 : ring === 1 ? 110 : 175;
    const ang = Math.PI * 2 * (k / Math.max(a.length, 1)) - Math.PI / 2;
    pos.set(n.id, { x: W / 2 + Math.cos(ang) * r, y: H / 2 + Math.sin(ang) * r });
  });

  const activeHints = [];

  // Renderização das Arestas com Ícones nas arestas e Hints no local do ataque
  const linesAndBadges = edges.filter(x => ids.has(x.from) && ids.has(x.to)).map(x => {
    const a = pos.get(x.from);
    const b = pos.get(x.to);
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;

    const edgeInfo = getEdgeInfo(x, s, currentStep);
    const isAttack = edgeInfo.isCurrentAttack;

    // Calculo do Hint na Aresta com o nome do ataque
    const hintText = `${edgeInfo.icon} ${edgeInfo.attackTitle}${edgeInfo.outcomeText}`;
    const hintWidth = Math.min(Math.max(hintText.length * 6.5 + 24, 120), 280);
    let hintX = Math.max(hintWidth / 2 + 10, Math.min(W - hintWidth / 2 - 10, mx));
    let hintY = my - 24;
    let arrowPoints = `${mx - 5},${my - 12} ${mx + 5},${my - 12} ${mx},${my - 7}`;

    if (my < 50) {
      hintY = my + 24;
      arrowPoints = `${mx - 5},${my + 12} ${mx + 5},${my + 12} ${mx},${my + 7}`;
    }

    if (isAttack) {
      activeHints.push(`
        <g class="edge-attack-hint-callout">
          <polygon points="${arrowPoints}" fill="#c9182b" />
          <rect x="${hintX - hintWidth / 2}" y="${hintY - 11}" width="${hintWidth}" height="22" rx="4" class="edge-hint-rect" />
          <text x="${hintX}" y="${hintY}" text-anchor="middle" dominant-baseline="central" class="edge-hint-label">
            ${esc(hintText)}
          </text>
        </g>
      `);
    }

    return `
      <g class="graph-edge-group ${isAttack ? 'active-attack-edge' : ''}">
        <!-- Linha da aresta -->
        <line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" 
              class="graph-line ${isAttack ? 'attack-pulse-line' : ''}" 
              stroke="${isAttack ? '#c9182b' : edgeInfo.badgeColor}" 
              stroke-width="${isAttack ? 3 : 1.5}" />

        <!-- ÍCONE NO LUGAR / CENTRO DA ARESTA -->
        <g class="edge-icon-badge" transform="translate(${mx}, ${my})">
          <circle cx="0" cy="0" r="${isAttack ? 13 : 10}" 
                  fill="${edgeInfo.badgeBg}" 
                  stroke="${isAttack ? '#c9182b' : edgeInfo.badgeColor}" 
                  stroke-width="${isAttack ? 2.5 : 1.5}" />
          <text x="0" y="0" text-anchor="middle" dominant-baseline="central" 
                font-size="${isAttack ? 12 : 9.5}" class="edge-glyph">${edgeInfo.icon}</text>
        </g>

        <!-- Tooltip no hover da aresta -->
        ${!isAttack ? `
          <g class="edge-hover-hint">
            <polygon points="${arrowPoints}" fill="#0c326f" />
            <rect x="${hintX - hintWidth / 2}" y="${hintY - 10}" width="${hintWidth}" height="20" rx="4" class="edge-hover-rect" />
            <text x="${hintX}" y="${hintY}" text-anchor="middle" dominant-baseline="central" class="edge-hover-label">
              ${esc(hintText)}
            </text>
          </g>
        ` : ''}
      </g>
    `;
  }).join('');

  // Estilização institucional dos nós
  const nodeStyles = {
    incident: { r: 24, fill: '#fff0f2', stroke: '#c9182b', defaultIcon: '🚨', iconSize: 16 },
    actor:    { r: 18, fill: '#fff8e8', stroke: '#b87704', defaultIcon: '👤', iconSize: 13 },
    asset:    { r: 18, fill: '#f0f5fc', stroke: '#0c326f', defaultIcon: '🏛️', iconSize: 13 },
    event:    { r: 13, fill: '#ffffff', stroke: '#1351b4', defaultIcon: '⚡', iconSize: 10 }
  };

  const circles = v.map(n => {
    const p = pos.get(n.id);
    const style = nodeStyles[n.kind] || nodeStyles.asset;
    const isIncident = n.kind === 'incident';
    const isSelected = selectedNode && selectedNode.id === n.id;
    const friendlyName = labelMap[n.label] || n.label;
    const icon = nodeIconMap[n.label] || (n.kind === 'actor' && n.label.includes('ai') ? '🤖' : style.defaultIcon);

    return `
      <g class="graph-node" onclick="selectGraphNode('${esc(n.id)}', '${esc(n.kind)}', '${esc(friendlyName)}')">
        ${isIncident ? `<circle cx="${p.x}" cy="${p.y}" r="${style.r + 7}" fill="none" stroke="#c9182b" stroke-width="2" stroke-dasharray="4 3" class="pulse-ring"/>` : ''}
        ${isSelected ? `<circle cx="${p.x}" cy="${p.y}" r="${style.r + 5}" fill="none" stroke="#df9b15" stroke-width="3" />` : ''}
        <circle cx="${p.x}" cy="${p.y}" r="${style.r}" fill="${style.fill}" stroke="${isSelected ? '#df9b15' : style.stroke}" stroke-width="${isSelected ? 3 : 2}" />
        <text x="${p.x}" y="${p.y}" text-anchor="middle" dominant-baseline="central" font-size="${style.iconSize}" class="node-icon">${icon}</text>
        <text x="${p.x}" y="${p.y + style.r + 13}" text-anchor="middle" class="node-label">${esc(short(friendlyName, 20))}</text>
      </g>
    `;
  }).join('');

  e.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}">
      <g class="graph-edges-layer">${linesAndBadges}</g>
      <g class="graph-nodes-layer">${circles}</g>
      <g class="graph-hints-layer">${activeHints.join('')}</g>
    </svg>
  `;
}

// SELEÇÃO DE NÓ NO GRAFO
window.selectGraphNode = function(id, kind, label) {
  selectedNode = { id, kind, label };
  $('#focusAsset').textContent = label;
  $('#focusNarrative').textContent = `Nó selecionado na infraestrutura: [${kind.toUpperCase()}] ${label}.`;
  if (state) renderGraph(state);
};

// ATUALIZAÇÃO DO CARD DE FOCO DO DIAGNÓSTICO
function updateFocusCard(s) {
  const ev = s.events && s.events.length ? s.events[s.events.length - 1] : null;
  const badge = $('#lastActionBadge');

  if (!ev) {
    $('#focusAsset').textContent = '—';
    $('#focusActor').textContent = '—';
    $('#focusDecision').textContent = '—';
    $('#focusUpstream').textContent = '0';
    $('#focusNarrative').textContent = 'Aguardando o início da simulação. Dispare um ataque à esquerda para visualizar o impacto no grafo.';
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

// PAINEL INFERIOR: TRILHA (Eventos e Rastros)
function renderTrail(s) {
  const b = $('#eventRows');
  if (!s.events || !s.events.length) {
    b.innerHTML = '<tr><td colspan="8" class="empty">Nenhum evento registrado ainda. Dispare um ataque acima.</td></tr>';
    return;
  }

  b.innerHTML = [...s.events].reverse().map(e => `
    <tr>
      <td><strong>${e.lsn}</strong></td>
      <td><span class="trail-timestamp">${formatDateTime(e)}</span></td>
      <td><span style="color:var(--gov-blue-light); font-weight:700;">${esc(e.source)}</span></td>
      <td><strong>${esc(e.event_type)}</strong><br><small style="color:var(--gov-muted);">${esc(e.summary)}</small></td>
      <td><code>${esc(e.actor)}</code> → <code style="color:var(--gov-gold); font-weight:700;">${esc(short(e.asset, 26))}</code></td>
      <td><span class="outcome-tag ${esc(e.outcome)}">${esc(e.outcome)}</span><br><small style="color:var(--gov-muted);">${esc(e.reason_code || '')}</small></td>
      <td style="font-weight:900; color:${e.upstream_delta ? 'var(--gov-green)' : 'var(--gov-muted)'};">${e.upstream_delta ?? 0}</td>
      <td><code>${esc(short(e.event_hash, 10))}</code></td>
    </tr>
  `).join('');
}

// EXECUÇÃO DE ATAQUE ATÉ UM PASSO ESPECÍFICO
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
      showAttackHint(currentAtt, lastEv);
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

// CONSULTA E RENDERIZAÇÃO DO HERACLITUSDB (WSL LINUX)
async function loadHeraclitusWslData() {
  const badge = $('#integrationBadge');
  const summaryBadge = $('#heraclitusSummaryBadge');
  const rows = $('#heraclitusEventRows');

  try {
    const res = await api('/api/heraclitus-adapter');
    const snap = res.snapshot || {};

    if (snap.connected) {
      badge.textContent = 'CONECTADO (WSL 8080)';
      badge.className = 'tag-status normal';

      const redTeam = snap.surfaces?.red_team?.data;
      if (redTeam && Array.isArray(redTeam.events)) {
        summaryBadge.textContent = `${redTeam.events.length} eventos lidos ao vivo do WSL Linux`;
        summaryBadge.style.color = 'var(--gov-green-light)';

        rows.innerHTML = redTeam.events.map(ev => `
          <tr>
            <td><strong>${ev.lsn}</strong></td>
            <td><span class="trail-timestamp">${formatDateTime(ev)}</span></td>
            <td><code>${esc(short(ev.attack_id, 22))}</code></td>
            <td>${esc(ev.vector || '—')}</td>
            <td><code style="color:var(--gov-gold); font-weight:700;">${esc(ev.target || '—')}</code></td>
            <td><span class="outcome-tag ${ev.result === 'pass' ? 'PASS' : 'DENY'}">${esc(ev.result?.toUpperCase() || 'PASS')}</span></td>
            <td><code>${esc(short(ev.record_hash, 16))}</code></td>
          </tr>
        `).join('');
      } else {
        summaryBadge.textContent = 'Adapter conectado (aguardando eventos)';
        rows.innerHTML = '<tr><td colspan="7" class="empty">Heraclitus conectado, nenhum evento retornado.</td></tr>';
      }
    } else {
      badge.textContent = 'NÃO CONECTADO';
      badge.className = 'tag-status';
      summaryBadge.textContent = 'HeraclitusDB local indisponível';
      rows.innerHTML = '<tr><td colspan="7" class="empty">HeraclitusDB não respondeu na porta 8080 do WSL.</td></tr>';
    }
  } catch (e) {
    badge.textContent = 'ERRO CONEXÃO';
    summaryBadge.textContent = e.message;
    rows.innerHTML = `<tr><td colspan="7" class="empty">Erro ao conectar: ${esc(e.message)}</td></tr>`;
  }
}

// NAVEGAÇÃO DE ABAS NA TRILHA INFERIOR
$('#tabTrailBtn').onclick = () => {
  $('#tabTrailBtn').classList.add('active');
  $('#tabHeraclitusBtn').classList.remove('active');
  $('#trailTabContent').classList.add('active');
  $('#heraclitusTabContent').classList.remove('active');
};

$('#tabHeraclitusBtn').onclick = () => {
  $('#tabHeraclitusBtn').classList.add('active');
  $('#tabTrailBtn').classList.remove('active');
  $('#heraclitusTabContent').classList.add('active');
  $('#trailTabContent').classList.remove('active');
  loadHeraclitusWslData();
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
    render(r);
    toast('Ambiente reiniciado');
  } catch (e) {
    toast('Erro ao reiniciar: ' + e.message);
  }
};

$('#exportBtn').onclick = async () => {
  try {
    const r = await api('/api/export', { method: 'POST' });
    toast(`Evidence Bundle gerado: ${r.status}`);
  } catch (e) {
    toast('Falha ao exportar bundle: ' + e.message);
  }
};

$('#downloadBtn').onclick = () => {
  location.href = '/api/evidence/download';
};

// INICIALIZAÇÃO
async function init() {
  try {
    const s = await api('/api/state');
    render(s);
  } catch (e) {
    toast('Falha ao conectar à POC: ' + e.message);
  }
  loadHeraclitusWslData();
}

init();
