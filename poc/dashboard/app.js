const $ = s => document.querySelector(s);
let state = null;
let running = false;
let selectedNode = null;
let isFullscreen = false;

// ========================================================
// CATÁLOGO DOS 17 ATAQUES MAPEADOS À INFRAESTRUTURA DO STF
// ========================================================
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

// ========================================================
// TOPOLOGIA FIXA DA INFRAESTRUTURA DO STF (SEMPRE VISÍVEL)
// ========================================================
// Posições normalizadas (nx, ny de 0 a 1) para espaçamento amplo
const FIXED_INFRA_NODES = [
  { id: 'asset:public-edge', label: 'public-edge', kind: 'asset', friendlyName: 'Firewall / WAF Borda', icon: '🛡️', nx: 0.12, ny: 0.50, r: 20 },
  { id: 'asset:identity-provider', label: 'identity-provider', kind: 'asset', friendlyName: 'VDI Ministros (IAM)', icon: '⚖️', nx: 0.30, ny: 0.22, r: 20 },
  { id: 'asset:srv-app-07', label: 'srv-app-07', kind: 'asset', friendlyName: 'Servidor Linux STF', icon: '🐧', nx: 0.32, ny: 0.72, r: 20 },
  { id: 'actor:human:approver-01', label: 'human:approver-01', kind: 'actor', friendlyName: 'Aprovador de Gabinete', icon: '👨‍⚖️', nx: 0.52, ny: 0.16, r: 20 },
  { id: 'asset:case://SYNTHETIC/RE-000001', label: 'case://SYNTHETIC/RE-000001', kind: 'asset', friendlyName: 'PJe Autos RE-000001', icon: '🏛️', nx: 0.55, ny: 0.50, r: 22 },
  { id: 'asset:document://SYNTHETIC/DOC-001', label: 'document://SYNTHETIC/DOC-001', kind: 'asset', friendlyName: 'Acórdão DOC-001 (Sigiloso)', icon: '📄', nx: 0.76, ny: 0.24, r: 20 },
  { id: 'asset:srv-db-02', label: 'srv-db-02', kind: 'asset', friendlyName: 'Rede Banco Judicial', icon: '🗄️', nx: 0.50, ny: 0.82, r: 18 },
  { id: 'asset:db-judicial-lab', label: 'db-judicial-lab', kind: 'asset', friendlyName: 'Banco Judicial Autos', icon: '🗄️', nx: 0.72, ny: 0.82, r: 20 },
  { id: 'asset:evidence-log', label: 'evidence-log', kind: 'asset', friendlyName: 'Trilha HRKL Preservação', icon: '⛓️', nx: 0.88, ny: 0.52, r: 20 }
];

// Conexões permanentes da infraestrutura do STF
const FIXED_INFRA_EDGES = [
  { from: 'asset:public-edge', to: 'asset:identity-provider', type: 'INFRA_LINK', icon: '🌐', title: 'Tráfego Perímetro STF' },
  { from: 'asset:identity-provider', to: 'asset:srv-app-07', type: 'INFRA_LINK', icon: '🔑', title: 'Sessão Gabinete → Backend' },
  { from: 'asset:srv-app-07', to: 'asset:case://SYNTHETIC/RE-000001', type: 'INFRA_LINK', icon: '🏛️', title: 'Acesso PJe STF Digital' },
  { from: 'asset:case://SYNTHETIC/RE-000001', to: 'asset:document://SYNTHETIC/DOC-001', type: 'INFRA_LINK', icon: '📄', title: 'Autos do Processo' },
  { from: 'asset:srv-app-07', to: 'asset:srv-db-02', type: 'INFRA_LINK', icon: '🔀', title: 'Conexão Rede de Dados' },
  { from: 'asset:srv-db-02', to: 'asset:db-judicial-lab', type: 'INFRA_LINK', icon: '🗄️', title: 'Cluster Banco de Dados' },
  { from: 'asset:case://SYNTHETIC/RE-000001', to: 'asset:evidence-log', type: 'INFRA_LINK', icon: '⛓️', title: 'Elo de Auditoria Merkle' },
  { from: 'actor:human:approver-01', to: 'asset:document://SYNTHETIC/DOC-001', type: 'INFRA_LINK', icon: '✍️', title: 'Canal de Aprovação HITL' }
];

// ========================================================
// API E UTILITÁRIOS
// ========================================================
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

    const hintEl = document.getElementById('ge-hint-' + i);
    if (hintEl) {
      const hintW = parseFloat(hintEl.getAttribute('data-hint-w')) || 180;
      const hintX = Math.max(hintW / 2 + 10, Math.min(W - hintWidthForEdge(edge, hintW) / 2 - 10, mx));
      const hintY = my < 55 ? my + 24 : my - 24;
      const arrowY = my < 55 ? my + 12 : my - 12;
      const tipY = my < 55 ? my + 7 : my - 7;

      const arrowEl = hintEl.querySelector('polygon');
      if (arrowEl) {
        arrowEl.setAttribute('points', `${mx - 5},${arrowY} ${mx + 5},${arrowY} ${mx},${tipY}`);
      }
      const rectEl = hintEl.querySelector('rect');
      if (rectEl) {
        rectEl.setAttribute('x', (hintX - hintW / 2).toFixed(1));
        rectEl.setAttribute('y', (hintY - 11).toFixed(1));
      }
      const textEl = hintEl.querySelector('text');
      if (textEl) {
        textEl.setAttribute('x', hintX.toFixed(1));
        textEl.setAttribute('y', hintY.toFixed(1));
      }
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
function renderGraph(s) {
  const e = $('#graph');
  const rawNodes = s?.graph?.nodes || [];
  const rawEdges = s?.graph?.edges || [];

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

  const dynamicSlice = rawNodes.slice(-24);
  dynamicSlice.forEach(n => {
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

  // 4. RENDERIZAR ARESTAS COM ÍCONES E HINTS DINÂMICOS
  const activeHints = [];
  const linesAndBadges = simEdges.map((x, i) => {
    const n1 = simNodes.get(x.from);
    const n2 = simNodes.get(x.to);
    if (!n1 || !n2) return '';

    const mx = (n1.x + n2.x) / 2;
    const my = (n1.y + n2.y) / 2;
    const edgeInfo = getEdgeInfo(x, s, currentStep);
    const isAttack = edgeInfo.isCurrentAttack;

    const hintText = `${edgeInfo.icon} ${edgeInfo.attackTitle}${edgeInfo.outcomeText}`;
    const hintWidth = Math.min(Math.max(hintText.length * 6.5 + 24, 120), 280);
    const hintX = Math.max(hintWidth / 2 + 10, Math.min(W - hintWidth / 2 - 10, mx));
    const hintY = my < 55 ? my + 24 : my - 24;
    const arrowY = my < 55 ? my + 12 : my - 12;
    const tipY = my < 55 ? my + 7 : my - 7;
    const arrowPoints = `${mx - 5},${arrowY} ${mx + 5},${arrowY} ${mx},${tipY}`;

    // Hint dinâmico destacado quando o local sofrer ataque
    if (isAttack) {
      activeHints.push(`
        <g class="edge-attack-hint-callout" id="ge-hint-${i}" data-hint-w="${hintWidth}">
          <polygon points="${arrowPoints}" fill="#c9182b" />
          <rect x="${hintX - hintWidth / 2}" y="${hintY - 11}" width="${hintWidth}" height="22" rx="4" class="edge-hint-rect" />
          <text x="${hintX}" y="${hintY}" text-anchor="middle" dominant-baseline="central" class="edge-hint-label">
            ${esc(hintText)}
          </text>
        </g>
      `);
    }

    return `
      <g class="graph-edge-group ${isAttack ? 'active-attack-edge' : ''} ${x.isInfra ? 'infra-edge' : 'attack-edge'}">
        <line id="ge-line-${i}" x1="${n1.x}" y1="${n1.y}" x2="${n2.x}" y2="${n2.y}" 
              class="graph-line ${isAttack ? 'attack-pulse-line' : x.isInfra ? 'infra-line' : ''}" 
              stroke="${isAttack ? '#c9182b' : x.isInfra ? '#cbd7e4' : edgeInfo.badgeColor}" 
              stroke-width="${isAttack ? 3.2 : x.isInfra ? 1.5 : 2}" />

        <!-- ÍCONE NO LUGAR DA ARESTA -->
        <g id="ge-badge-${i}" class="edge-icon-badge" transform="translate(${mx}, ${my})">
          <circle cx="0" cy="0" r="${isAttack ? 13 : x.isInfra ? 9 : 10}" 
                  fill="${edgeInfo.badgeBg}" 
                  stroke="${isAttack ? '#c9182b' : x.isInfra ? '#9bb3cc' : edgeInfo.badgeColor}" 
                  stroke-width="${isAttack ? 2.5 : 1.5}" />
          <text x="0" y="0" text-anchor="middle" dominant-baseline="central" 
                font-size="${isAttack ? 12 : x.isInfra ? 9 : 9.5}" class="edge-glyph">${edgeInfo.icon}</text>
        </g>

        <!-- Hover Hint -->
        ${!isAttack ? `
          <g id="ge-hint-${i}" class="edge-hover-hint" data-hint-w="${hintWidth}">
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

  // 5. RENDERIZAR NÓS ARRASTÁVEIS
  const circles = Array.from(simNodes.values()).map(n => {
    const isIncident = n.kind === 'incident';
    const isSelected = selectedNode && selectedNode.id === n.id;
    const isTargeted = currentAttack && (n.label === currentAttack.target || n.id.includes(currentAttack.target));

    return `
      <g class="graph-node ${n.isFixed ? 'fixed-network-node' : 'dynamic-attack-node'} ${isTargeted ? 'targeted-node' : ''}" 
         id="gn-${n.idx}" data-node-id="${esc(n.id)}" 
         transform="translate(${n.x}, ${n.y})" 
         onclick="selectGraphNode('${esc(n.id)}', '${esc(n.kind)}', '${esc(n.friendlyName)}')">
        ${isIncident ? `<circle cx="0" cy="0" r="${n.r + 7}" fill="none" stroke="#c9182b" stroke-width="2" stroke-dasharray="4 3" class="pulse-ring"/>` : ''}
        ${isTargeted ? `<circle cx="0" cy="0" r="${n.r + 6}" fill="none" stroke="#c9182b" stroke-width="2.5" class="pulse-ring"/>` : ''}
        ${isSelected ? `<circle cx="0" cy="0" r="${n.r + 5}" fill="none" stroke="#df9b15" stroke-width="3" />` : ''}
        <circle cx="0" cy="0" r="${n.r}" fill="${n.style.fill}" stroke="${isSelected ? '#df9b15' : isTargeted ? '#c9182b' : n.style.stroke}" stroke-width="${isSelected || isTargeted ? 3 : 2}" />
        <text x="0" y="0" text-anchor="middle" dominant-baseline="central" font-size="${n.style.iconSize}" class="node-icon">${n.icon}</text>
        <text x="0" y="${n.r + 14}" text-anchor="middle" class="node-label">${esc(short(n.friendlyName, 22))}</text>
      </g>
    `;
  }).join('');

  e.innerHTML = `
    <svg id="graphSvg" viewBox="0 0 ${W} ${H}" width="100%" height="100%">
      <g class="graph-edges-layer">${linesAndBadges}</g>
      <g class="graph-nodes-layer">${circles}</g>
      <g class="graph-hints-layer">${activeHints.join('')}</g>
    </svg>
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
      nodeG.classList.add('dragging');
      simAlpha = 0.85;
      startPhysicsLoop();
    };
  }

  // Despertar relaxamento físico
  simAlpha = Math.max(simAlpha, 0.7);
  startPhysicsLoop();
}

// ARRASTAR NÓS COM O MOUSE
window.addEventListener('mousemove', evt => {
  if (!draggedNodeId) return;
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
  selectedNode = { id, kind, label };
  $('#focusAsset').textContent = label;
  $('#focusNarrative').textContent = `Nó selecionado na infraestrutura: [${kind.toUpperCase()}] ${label}.`;
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
// PAINEL INFERIOR: TRILHA (Eventos e Rastros)
// ========================================================
function renderTrail(s) {
  const b = $('#eventRows');
  if (!s?.events || !s.events.length) {
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

// ========================================================
// CONSULTA E RENDERIZAÇÃO DO HERACLITUSDB (WSL LINUX)
// ========================================================
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

// ATUALIZAÇÃO DA BARRA DE INFRAESTRUTURA DO STF NO TOPO
function updateInfraStatusBar(s) {
  const step = s?.step || 0;

  // 1. Firewall / WAF
  const nodeFw = $('#node-fw');
  const statusFw = $('#status-fw');
  if (step >= 2) {
    nodeFw.className = 'infra-node-item targeted';
    statusFw.textContent = 'SONDAGEM OBSERVADA';
    statusFw.style.color = 'var(--gov-gold)';
  } else {
    nodeFw.className = 'infra-node-item';
    statusFw.textContent = 'PERÍMETRO NORMAL';
    statusFw.style.color = 'var(--gov-green)';
  }

  // 2. Máquinas de Ministros (VDI)
  const nodeMin = $('#node-ministro');
  const statusMin = $('#status-ministro');
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

  // 3. Servidores Linux
  const nodeLinux = $('#node-linux');
  const statusLinux = $('#status-linux');
  if (step >= 4) {
    nodeLinux.className = 'infra-node-item compromised';
    statusLinux.textContent = 'PROCESSO ATÍPICO';
    statusLinux.style.color = 'var(--gov-red)';
  } else {
    nodeLinux.className = 'infra-node-item';
    statusLinux.textContent = 'BACKEND REGULAR';
    statusLinux.style.color = 'var(--gov-green)';
  }

  // 4. PJe / STF Digital
  const nodePje = $('#node-pje');
  const statusPje = $('#status-pje');
  if (step >= 8) {
    nodePje.className = 'infra-node-item compromised';
    statusPje.textContent = 'ESCRITA BARRADA (DENY)';
    statusPje.style.color = 'var(--gov-gold)';
  } else if (step >= 7) {
    nodePje.className = 'infra-node-item targeted';
    statusPje.textContent = 'AUTOS SOB INCIDENTE';
    statusPje.style.color = 'var(--gov-red)';
  } else {
    nodePje.className = 'infra-node-item';
    statusPje.textContent = 'AUTOS ÍNTEGROS';
    statusPje.style.color = 'var(--gov-green)';
  }

  // 5. Banco Judicial
  const nodeDb = $('#node-db');
  const statusDb = $('#status-db');
  if (step >= 6) {
    nodeDb.className = 'infra-node-item targeted';
    statusDb.textContent = 'QUERY ANÔMALA';
    statusDb.style.color = 'var(--gov-gold)';
  } else {
    nodeDb.className = 'infra-node-item';
    statusDb.textContent = 'TRANSACIONAL ÍNTEGRO';
    statusDb.style.color = 'var(--gov-green)';
  }

  // 6. Agentes IA (VitórIA/Rafa)
  const nodeIa = $('#node-ia');
  const statusIa = $('#status-ia');
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

// PAINEL ESQUERDO: LISTA DE ATAQUES
function renderAttackList(s) {
  const container = $('#attackList');
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
  renderGraph(s);
  renderTrail(s);
  updateFocusCard(s);
}

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
