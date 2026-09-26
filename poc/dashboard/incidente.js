// Incidente 360º — leitura da campanha, das decisões e do log processual.
// API pública da aba: initIncidente360() e refreshIncidente360(snapshot?).
// Todas as consultas são de leitura; nenhum estado operacional é inventado.
(() => {
  'use strict';

  const root = document.getElementById('viewIncidente');
  if (!root) return;

  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const clean = value => value === null || value === undefined || value === '' ? '—' : escapeHtml(value);
  const number = value => Number.isFinite(Number(value)) ? Number(value) : 0;
  const shortHash = value => value ? `${escapeHtml(String(value).slice(0, 15))}…` : '—';

  let snapshot = null;
  let processInfo = null;
  let processDetail = null;
  let processError = null;
  let processBusy = false;
  let processCheckedAt = 0;
  let stateBusy = false;
  let demoEvents = [];
  let demoCatalog = [];
  let demoProfile = { DEFENDED: 60, BLOCKED: 30, TARGET_REACHED: 10 };
  let activeFilter = 'all';
  let initialized = false;

  async function getJson(path) {
    const response = await fetch(path.replace(/^\//, ''), {
      headers: { 'X-STF-POC': '1' }, cache: 'no-store'
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }

  async function loadDemo() {
    try {
      if (!demoCatalog.length) {
        const [stf, hdb, profile] = await Promise.all([getJson('/api/stf-attacks'), getJson('/api/heraclitus-attacks'), getJson('/api/demo-profile')]);
        demoCatalog = [...(stf.attacks || []), ...(hdb.attacks || [])];
        demoProfile = profile.weights || demoProfile;
      }
      const ledger = await getJson('/api/heraclitus-events?limit=1000');
      if (ledger.status === 'PASS') {
        demoEvents = (ledger.data?.events || []).filter(event => event.campaign_id === 'STF-DEMO-SIMULATION');
      }
      if (!demoEvents.length && snapshot?.events) {
        demoEvents = snapshot.events.filter(e => e.simulation || String(e.type || '').startsWith('demo.')).map(e => ({
          attack_id: e.details?.attack_id || (e.type ? e.type.replace('demo.attack.', 'demo-') : 'demo-atk'),
          campaign_id: 'STF-DEMO-SIMULATION',
          lsn: e.lsn,
          reason_code: e.reason_code || (e.outcome === 'PASS' ? 'DEMO_TARGET_REACHED' : e.outcome === 'DENY' ? 'DEMO_BLOCKED' : 'DEMO_DEFENDED'),
        }));
      }
    } catch (_) {
      // A aba continua a mostrar o incidente mesmo se a leitura do ledger falhar.
    }
  }

  function renderDemo() {
    const counts = { DEFENDED: 0, BLOCKED: 0, TARGET_REACHED: 0 };
    const byEquipment = new Map();
    for (const attack of demoCatalog) {
      if (!byEquipment.has(attack.equipment_id)) {
        byEquipment.set(attack.equipment_id, {
          name: attack.equipment, total: 0, DEFENDED: 0, BLOCKED: 0, TARGET_REACHED: 0
        });
      }
    }
    for (const event of demoEvents) {
      const kind = String(event.reason_code || '').replace(/^DEMO_/, '');
      if (!(kind in counts)) continue;
      counts[kind]++;
      const attack = demoCatalog.find(item => String(event.attack_id || '').startsWith(`demo-${item.id.toLowerCase()}-`));
      const equipment = attack && byEquipment.get(attack.equipment_id);
      if (equipment) { equipment.total++; equipment[kind]++; }
    }
    const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
    const pct = value => total ? `${Math.round(value * 100 / total)}%` : '0%';
    const rows = [...byEquipment.values()].sort((a, b) => b.total - a.total || a.name.localeCompare(b.name));
    return `<section class="inc360-section">
      <div class="inc360-section-head"><div><span class="inc360-section-kicker">SIMULAÇÃO · HERACLITUSDB</span><h3>Ataques em todos os componentes</h3></div><span class="inc360-count">${total} tentativa(s)</span></div>
      <p class="inc360-section-copy">Desfechos 100% randômicos gravados no HeraclitusDB. Efeito real no alvo: zero (isolamento sandbox). Execute “Simular rede” na aba Defesa cibernética.</p>
      <div class="inc360-kpis">
        <div><span>Defendidos</span><strong>${counts.DEFENDED}</strong><small>${pct(counts.DEFENDED)} · detectados e contidos</small></div>
        <div><span>Bloqueados</span><strong>${counts.BLOCKED}</strong><small>${pct(counts.BLOCKED)} · barrados na entrada</small></div>
        <div><span>Chegaram ao alvo</span><strong>${counts.TARGET_REACHED}</strong><small>${pct(counts.TARGET_REACHED)} · :( somente simulação</small></div>
      </div>
      <div class="table-wrap"><table class="simple-table"><thead><tr><th>Componente</th><th>Tent.</th><th>Def.</th><th>Bloq.</th><th>Alvo</th></tr></thead><tbody>
        ${rows.map(row => `<tr><td>${escapeHtml(row.name)}</td><td>${row.total}</td><td>${row.DEFENDED}</td><td>${row.BLOCKED}</td><td>${row.TARGET_REACHED}</td></tr>`).join('')}
      </tbody></table></div>
    </section>`;
  }

  function processId(s) {
    const target = s?.case_state?.id;
    const match = typeof target === 'string' && target.match(/\/([A-Z]{2,5}-\d{6})$/);
    return match ? match[1] : 'RE-000001';
  }

  function relevantEvents(s) {
    const incident = s?.incident;
    const openingLsns = new Set((s?.why_incident?.evidence_lsns || []).map(Number));
    const events = Array.isArray(s?.events) ? s.events : [];
    const filtered = events.filter(event => {
      if (incident) {
        return event.incident_id === incident.incident_id || openingLsns.has(Number(event.lsn)) || event.phase === 'FASE 1' || String(event.event_type || '').startsWith('hdb.') || String(event.event_type || '').startsWith('stf.') || event.simulation;
      }
      return true;
    }).sort((a, b) => number(a.lsn) - number(b.lsn));
    return filtered.length ? filtered : events;
  }

  function assessment(event) {
    const details = event?.details || {};
    const decision = details.policy_decision;
    if (details.stf_attack_id) return {
      label: 'SIMULADO', kind: 'simulated',
      explanation: 'O resultado foi atribuído pelo cenário do catálogo; não há medição do efeito no destino.'
    };
    if (details.heraclitus_attack_id) {
      const fallback = String(details.oracle_reason || '').startsWith('Executado via canal loopback seguro:');
      if (fallback || details.oracle_verdict === 'inconclusive' || !details.oracle_verdict) return {
        label: 'INCONCLUSIVO', kind: 'uncertain',
        explanation: 'O resultado do oráculo não confirma o efeito no destino.'
      };
      return {
        label: 'VERIFICADO', kind: 'verified',
        explanation: 'Resultado registrado pelo oráculo do teste local; alcance limitado ao laboratório.'
      };
    }
    if (decision) {
      const delta = event.upstream_delta;
      const receipt = details.upstream_receipt;
      const consistent = event.outcome === 'DENY'
        ? delta === 0 && !receipt && decision.effect_allowed === false
        : decision.effect_allowed === true && delta === 1 && !!receipt;
      if (details.ingest_mode === 'external_loopback' && consistent) return {
        label: 'VERIFICADO', kind: 'verified',
        explanation: 'Decisão e variação do oráculo upstream conferidas no loopback local.'
      };
      if (details.ingest_mode === 'external_loopback') return {
        label: 'INCONCLUSIVO', kind: 'uncertain',
        explanation: 'A resposta não contém decisão, contador e recibo suficientes para confirmar o efeito.'
      };
      return {
        label: 'SIMULADO', kind: 'simulated',
        explanation: 'Decisão executada no roteiro sintético da POC.'
      };
    }
    if (details.ingest_mode === 'external_loopback') return {
      label: 'OBSERVADO', kind: 'observed',
      explanation: 'Telemetria recebida da API local; este evento não mede um efeito externo.'
    };
    return {
      label: 'SIMULADO', kind: 'simulated',
      explanation: 'Evento do roteiro sintético; este registro isolado não comprova efeito no destino.'
    };
  }

  function filteredEvents(events) {
    if (activeFilter === 'signals') return events.filter(event => event.phase === 'FASE 1');
    if (activeFilter === 'response') return events.filter(event => event.details?.policy_decision || event.event_type === 'approval.granted');
    return events;
  }

  function renderTimeline(events) {
    const shown = filteredEvents(events);
    if (!shown.length) return '<div class="inc360-empty">Nenhum evento nesta seleção. Execute a campanha ou envie telemetria local para iniciar a linha do tempo.</div>';
    return `<ol class="inc360-timeline">${shown.map(event => {
      const evidence = assessment(event);
      const decision = event.details?.policy_decision;
      const reason = event.reason_code ? ` · ${escapeHtml(event.reason_code)}` : '';
      const receipt = event.details?.upstream_receipt;
      const atkId = event.details?.stf_attack_id || event.details?.heraclitus_attack_id;
      const attackBadge = atkId ? `<span class="inc360-attack-tag">⚡ ATAQUE ${escapeHtml(atkId)}</span>` : '';
      const actionBtn = atkId ? `
        <div style="margin-top: 8px; display: flex; gap: 8px; flex-wrap: wrap;">
          <button type="button" class="btn tiny ghost" onclick="event.stopPropagation(); goToAttack('${atkId}')">🎯 Localizar Ataque na Aba 1 ➔</button>
          ${atkId === 'IA_ZAN_05' ? `<button type="button" class="btn tiny primary" onclick="event.stopPropagation(); goToDefesaZanin('IA_ZAN_05')">🏛️ Ver Perícia na Defesa Zanin</button>` : ''}
        </div>
      ` : '';
      const effect = decision ? `<div class="inc360-event-effect">Gateway: <strong>${clean(decision.outcome || event.outcome)}</strong> · upstream Δ ${event.upstream_delta === null || event.upstream_delta === undefined ? '—' : clean(event.upstream_delta)}${receipt ? ' · recibo local presente' : ''}${reason}</div>` : '';

      return `<li class="inc360-event">
        <span class="inc360-event-marker" aria-hidden="true"></span>
        <div class="inc360-event-card">
          <div class="inc360-event-top">
            <span class="inc360-lsn">LSN ${clean(event.lsn)}</span>
            <span class="inc360-event-source">${clean(event.source)}</span>
            ${attackBadge}
            <span class="inc360-badge ${evidence.kind}" title="${escapeHtml(evidence.explanation)}">${evidence.label}</span>
          </div>
          <strong>${clean(event.summary)}</strong>
          <div class="inc360-event-meta">${clean(event.actor)} → ${clean(event.asset)} · ${clean(event.event_type)} · ${clean(event.outcome)}</div>
          ${effect}
          ${actionBtn}
        </div>
      </li>`;
    }).join('')}</ol>`;
  }

  function renderResponse(s, events) {
    const policy = events.filter(event => event.details?.policy_decision);
    const denied = policy.filter(event => event.outcome === 'DENY');
    const requireHuman = policy.filter(event => event.outcome === 'REQUIRE_HITL');
    const approvals = events.filter(event => event.event_type === 'approval.granted');
    const executed = policy.filter(event => event.details?.upstream_receipt && number(event.upstream_delta) > 0);
    const pending = s?.pending_approval;
    const cards = [
      { name: 'Abertura do incidente', value: s?.incident ? clean(s.incident.state) : 'AGUARDANDO', note: s?.incident ? `Correlação de ${number(s.signals?.length)} sinais observados` : 'Critério de correlação ainda não alcançado', kind: s?.incident ? 'verified' : 'uncertain' },
      { name: 'Bloqueios de política', value: String(denied.length), note: 'Decisões DENY registradas no histórico', kind: denied.length ? 'verified' : 'uncertain' },
      { name: 'Revisão humana solicitada', value: String(requireHuman.length), note: pending ? `Aprovação ${clean(pending.approval_id)}: ${clean(pending.state)}` : 'Nenhuma aprovação pendente', kind: requireHuman.length ? 'observed' : 'uncertain' },
      { name: 'Aprovações registradas', value: String(approvals.length), note: executed.length ? `${executed.length} efeito(s) com recibo local` : 'Nenhum efeito autorizado com recibo local', kind: approvals.length ? 'observed' : 'uncertain' },
    ];
    return `<div class="inc360-response-grid">${cards.map(card => `<div class="inc360-response-card"><span>${card.name}</span><strong class="inc360-text-${card.kind}">${card.value}</strong><small>${card.note}</small></div>`).join('')}</div>
      <p class="inc360-caveat">A API registra detecção, decisões do gateway e aprovações. Ticket, responsável, aceite, SLA e encerramento do suporte ainda não são registrados; portanto, não há status operacional de atendimento a afirmar.</p>`;
  }

  function renderProcess(s) {
    const id = processId(s);
    const target = s?.case_state?.id || `case://SYNTHETIC/${id}`;
    let body;
    if (processError) {
      body = `<div class="inc360-empty">Log processual indisponível: ${escapeHtml(processError)}.</div>`;
    } else if (!processInfo) {
      body = '<div class="inc360-empty">Ainda não há registro desse processo no log processual.</div>';
    } else {
      const integrity = processDetail?.integridade;
      const integrityText = integrity ? integrity.integra ? `Cadeia íntegra · ${number(integrity.elos)} elos` : `Cadeia com falha · ${clean(integrity.falha)}` : 'Integridade ainda não consultada';
      body = `<div class="inc360-process-stats"><div><span>Situação</span><strong>${clean(processInfo.situacao)}</strong></div><div><span>Eventos</span><strong>${number(processInfo.eventos)}</strong></div><div><span>Último LSN</span><strong>${clean(processInfo.ultimo_lsn)}</strong></div></div><div class="inc360-integrity ${integrity?.integra === false ? 'broken' : ''}">${integrityText}</div>`;
    }
    return `<div class="inc360-process-head"><strong>${escapeHtml(id)}</strong><span class="inc360-badge observed">PROCESSO FICTÍCIO</span></div>
      <div class="inc360-mono inc360-target">${escapeHtml(target)}</div>${body}
      <p class="inc360-caveat">O identificador aparece no alvo da campanha e no catálogo processual. Os dois logs são independentes; esta tela não afirma que um andamento foi causado ou bloqueado pelo incidente.</p>
      <button type="button" class="btn small" data-inc360-process>Ver acompanhamento processual</button>`;
  }

  function render() {
    if (!snapshot) {
      root.innerHTML = '<section class="panel inc360"><div class="inc360-empty">Carregando incidente...</div></section>';
      return;
    }
    const s = snapshot;
    const incident = s.incident;
    const events = relevantEvents(s);
    const why = s.why_incident || {};
    const reasons = Array.isArray(why.reasons) ? why.reasons : [];
    const sourceCount = new Set(reasons.map(reason => reason.source).filter(Boolean)).size;
    const policyCount = events.filter(event => event.details?.policy_decision).length;
    const lastHash = events.length ? events[events.length - 1].event_hash : null;
    root.innerHTML = `<section class="panel inc360">
      <div class="inc360-hero">
        <div><span class="inc360-eyebrow">VISÃO CONSOLIDADA · AMBIENTE SINTÉTICO</span><h2>Incidente 360º</h2><p>Da correlação de sinais à decisão do gateway, aprovação humana e consulta ao processo fictício.</p></div>
        <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
          <button type="button" class="btn small primary" data-inc360-action="correlacionar">⚡ Executar Correlação de Sinais</button>
          <div class="inc360-hero-state"><span class="inc360-badge ${incident ? 'alert' : 'uncertain'}">${incident ? clean(incident.state) : 'NÃO ABERTO'}</span><strong>${incident ? clean(incident.incident_id) : 'Aguardando sinais'}</strong><small>${incident ? `Severidade ${clean(incident.severity)}` : 'Sem correlação qualificada'}</small></div>
        </div>
      </div>
      <div class="inc360-kpis">
        <div><span>Risco</span><strong>${number(s.risk)}</strong><small>pontuação do cenário</small></div>
        <div><span>Sinais vinculados</span><strong>${reasons.length}</strong><small>${sourceCount} fonte(s) na abertura</small></div>
        <div><span>Decisões do gateway</span><strong>${policyCount}</strong><small>registradas no histórico</small></div>
        <div><span>Efeitos upstream</span><strong>${number(s.upstream_hits)}</strong><small>oráculo local da campanha</small></div>
      </div>
      ${renderDemo()}
      <div class="inc360-grid">
        <div class="inc360-main">
          <section class="inc360-section"><div class="inc360-section-head"><div><span class="inc360-section-kicker">DETECÇÃO</span><h3>Por que o incidente foi aberto</h3></div><span class="inc360-badge ${incident ? 'verified' : 'uncertain'}">${incident ? 'CORRELACIONADO' : 'PENDENTE'}</span></div>
            <p class="inc360-section-copy">${escapeHtml(why.summary || 'Ainda não há evidência suficiente para abrir o incidente.')}</p>
            ${reasons.length ? `<div class="inc360-reasons">${reasons.map(reason => `<div><span>LSN ${clean(reason.lsn)} · ${clean(reason.source)}</span><strong>${clean(reason.reason_code)}</strong><small>${reason.hash_reference_valid ? 'Hash da referência confere' : 'Referência sem confirmação'} · ${clean(reason.asset)}</small></div>`).join('')}</div>` : '<div class="inc360-empty">Os sinais que compõem a abertura aparecerão aqui após a correlação.</div>'}
          </section>
          <section class="inc360-section"><div class="inc360-section-head"><div><span class="inc360-section-kicker">HISTÓRICO</span><h3>Linha do tempo</h3></div><span class="inc360-count">${events.length} evento(s)</span></div>
            <div class="inc360-filters" role="group" aria-label="Filtrar linha do tempo"><button type="button" data-inc360-filter="all" aria-pressed="${activeFilter === 'all'}" class="${activeFilter === 'all' ? 'active' : ''}">Todos</button><button type="button" data-inc360-filter="signals" aria-pressed="${activeFilter === 'signals'}" class="${activeFilter === 'signals' ? 'active' : ''}">Sinais</button><button type="button" data-inc360-filter="response" aria-pressed="${activeFilter === 'response'}" class="${activeFilter === 'response' ? 'active' : ''}">Resposta</button></div>
            ${renderTimeline(events)}
          </section>
        </div>
        <div class="inc360-side">
          <section class="inc360-section"><div class="inc360-section-head"><div><span class="inc360-section-kicker">RESPOSTA</span><h3>Decisões registradas</h3></div></div>${renderResponse(s, events)}</section>
          <section class="inc360-section"><div class="inc360-section-head"><div><span class="inc360-section-kicker">CONTEXTO</span><h3>Processo referenciado</h3></div></div>${renderProcess(s)}</section>
          <section class="inc360-section inc360-evidence"><div class="inc360-section-head"><div><span class="inc360-section-kicker">RASTREABILIDADE</span><h3>Última evidência local</h3></div></div><div class="inc360-mono">${shortHash(lastHash)}</div><p class="inc360-caveat">Hash do último evento mostrado. Confira a cadeia e o pacote exportado na aba Auditoria e Evidências.</p></section>
        </div>
      </div>
    </section>`;
  }

  async function loadProcess(force = false) {
    if (processBusy || (!force && Date.now() - processCheckedAt < 10000)) return;
    processBusy = true;
    processCheckedAt = Date.now();
    try {
      const response = await getJson('/api/processos');
      if (!response.connected) throw new Error(response.error || 'HeraclitusDB indisponível');
      const id = processId(snapshot);
      processInfo = Array.isArray(response.processos) ? response.processos.find(item => item.id === id) || null : null;
      processDetail = null;
      if (processInfo) {
        const detail = await getJson(`/api/processos/detalhe?id=${encodeURIComponent(id)}`);
        if (!detail.connected) throw new Error(detail.error || 'detalhe indisponível');
        processDetail = detail;
      }
      processError = null;
    } catch (error) {
      processInfo = null;
      processDetail = null;
      processError = error.message || 'falha de consulta';
    } finally {
      processBusy = false;
      if (!root.hidden) render();
    }
  }

  async function refreshIncidente360(nextSnapshot) {
    if (nextSnapshot) {
      snapshot = nextSnapshot;
      if (!root.hidden) {
        render();
        loadProcess();
      }
      return;
    }
    if (stateBusy) return;
    stateBusy = true;
    try {
      snapshot = await getJson('/api/state');
      if (!root.hidden) {
        await loadDemo();
        render();
        loadProcess();
      }
    } catch (error) {
      if (!snapshot && !root.hidden) root.innerHTML = `<section class="panel inc360"><div class="inc360-empty">Falha ao ler o incidente: ${escapeHtml(error.message)}.</div></section>`;
    } finally {
      stateBusy = false;
    }
  }

  async function dispararCorrelacao() {
    try {
      if (typeof toast === 'function') toast('⚡ Disparando sinais de correlação para o HeraclitusDB...');
      if (typeof api === 'function') {
        await api('/api/run', { method: 'POST' });
      } else {
        await fetch('api/run', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-STF-POC': '1' } });
      }
      await refreshIncidente360();
      if (typeof toast === 'function') toast('🚨 Incidente correlacionado e registrado no HeraclitusDB!');
    } catch (e) {
      if (typeof toast === 'function') toast(`Erro ao disparar correlação: ${e.message}`);
    }
  }

  function initIncidente360() {
    if (initialized) return;
    initialized = true;
    root.addEventListener('click', event => {
      if (event.target.closest('[data-inc360-action="correlacionar"]')) {
        dispararCorrelacao();
        return;
      }
      const filter = event.target.closest('[data-inc360-filter]');
      if (filter) {
        activeFilter = filter.dataset.inc360Filter;
        render();
        return;
      }
      if (event.target.closest('[data-inc360-process]')) {
        if (typeof mostrarView === 'function') mostrarView('processos');
        else location.hash = '#processos';
        if (processInfo && typeof selecionarProcesso === 'function') selecionarProcesso(processInfo.id);
      }
    });
    new MutationObserver(() => {
      if (!root.hidden) {
        render();
        refreshIncidente360();
        loadProcess(true);
      }
    }).observe(root, { attributes: true, attributeFilter: ['hidden'] });
    if (!root.hidden) render();
    refreshIncidente360();
    setInterval(() => { if (!root.hidden) refreshIncidente360(); }, 5000);
  }

  window.initIncidente360 = initIncidente360;
  window.refreshIncidente360 = refreshIncidente360;
  initIncidente360();
})();
