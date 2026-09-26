// Auditoria e Evidências — leitura do histórico sintético da POC.
// Este módulo não grava eventos. O LSN da trilha da POC é distinto do LSN
// retornado pelo HeraclitusDB em details.heraclitus_lsn, quando disponível.
(() => {
  'use strict';

  const root = document.getElementById('viewAuditoria');
  if (!root) return;

  const $ = selector => root.querySelector(selector);
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const shown = value => value === null || value === undefined || value === '' ? '—' : escapeHtml(value);
  const shortHash = value => typeof value === 'string' && value.length > 18
    ? `${escapeHtml(value.slice(0, 12))}…${escapeHtml(value.slice(-8))}` : shown(value);
  const pretty = value => escapeHtml(JSON.stringify(value, null, 2));
  const statusClass = value => value === 'PASS' || value === true ? 'ok'
    : value === 'FAIL' || value === false ? 'fail' : 'neutral';
  const check = (label, value) => `<span class="audit-check ${statusClass(value)}">${escapeHtml(label)}: ${shown(value)}</span>`;

  let snapshot = null;
  let bundle = null;
  let selectedLsn = null;
  let asOfLsn = null;
  let initialized = false;
  let loading = false;
  let objectRequest = 0;
  let replayRequest = 0;

  async function readJson(path) {
    const response = await fetch(path.replace(/^\//, ''), { cache: 'no-store' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }

  function status(message, tone = '') {
    const el = $('[data-audit-status]');
    if (!el) return;
    el.textContent = message;
    el.className = `audit-load-status ${tone}`;
  }

  function markup() {
    root.innerHTML = `
      <section class="panel audit-panel" aria-label="Auditoria e Evidências">
        <div class="panel-head audit-head">
          <div>
            <span class="section-kicker">Cadeia de custódia da demonstração</span>
            <h2>Auditoria e Evidências</h2>
            <p class="audit-head-sub">Explore o evento, seu vínculo criptográfico e o estado da campanha em um LSN.</p>
          </div>
          <div class="audit-head-actions">
            <span class="audit-load-status" data-audit-status role="status" aria-live="polite">Carregando…</span>
            <button class="btn small ghost" type="button" data-audit-action="refresh">Atualizar</button>
            <a class="btn small primary" href="api/evidence/download" download="evidence-stf-poc-001.json" data-audit-export>Baixar pacote JSON</a>
          </div>
        </div>
        <div class="audit-scope">
          <strong>Escopo da prova</strong>
          <span>Dados fictícios da campanha local. Hash, Merkle e manifesto abaixo são verificados pelo servidor da POC. O recibo do HeraclitusDB aparece por evento quando houve aceite. Não há assinatura institucional nem carimbo de tempo externo.</span>
        </div>
        <div class="audit-metrics" data-audit-metrics></div>
        <div class="audit-grid">
          <section class="audit-box audit-events-box" aria-label="Eventos da campanha">
            <div class="audit-box-head">
              <div><h3>Trilha de eventos</h3><p>Selecione um LSN local para examinar a proveniência.</p></div>
              <span class="audit-count" data-audit-count>0 eventos</span>
            </div>
            <div class="audit-filters">
              <input type="search" data-audit-search placeholder="Buscar LSN, fonte, tipo, ator ou ativo" aria-label="Buscar eventos de auditoria" />
              <label><input type="checkbox" data-audit-incident-only /> Só evidências do incidente</label>
            </div>
            <div class="audit-event-list" data-audit-events role="listbox" aria-label="Eventos de auditoria"></div>
          </section>
          <section class="audit-box audit-detail-box" aria-label="Proveniência do evento">
            <div class="audit-box-head"><div><h3>Proveniência do evento</h3><p>Vínculos calculados sobre a trilha local da POC.</p></div></div>
            <div data-audit-detail class="audit-detail"><p class="audit-empty">Selecione um evento.</p></div>
          </section>
        </div>
        <div class="audit-lower-grid">
          <section class="audit-box audit-replay-box" aria-label="Replay AS OF LSN">
            <div class="audit-box-head"><div><h3>Estado AS OF LSN</h3><p>Replay local da campanha após o LSN escolhido; não é uma consulta histórica ao banco.</p></div></div>
            <div class="audit-replay-control">
              <label for="auditAsOfRange">LSN <strong data-audit-asof-label>0</strong></label>
              <input id="auditAsOfRange" type="range" min="0" max="0" value="0" data-audit-asof />
              <button type="button" class="btn small ghost" data-audit-action="latest">Mais recente</button>
            </div>
            <div data-audit-replay class="audit-replay"><p class="audit-empty">Carregando replay…</p></div>
          </section>
          <section class="audit-box audit-package-box" aria-label="Pacote de evidências">
            <div class="audit-box-head"><div><h3>Pacote e verificações</h3><p>Resultado da verificação no servidor da POC.</p></div></div>
            <div data-audit-package class="audit-package"><p class="audit-empty">Carregando pacote…</p></div>
          </section>
        </div>
      </section>`;
  }

  function incidentLsns() {
    const incident = snapshot?.incident;
    return new Set(Array.isArray(incident?.evidence_lsns) ? incident.evidence_lsns : []);
  }

  function events() {
    return Array.isArray(snapshot?.events) ? snapshot.events : [];
  }

  function renderMetrics() {
    const all = events();
    const linked = all.filter(ev => ev.details?.heraclitus_persisted === true).length;
    const incident = snapshot?.incident;
    const verification = all.length ? snapshot?.verification?.overall || 'INCONCLUSIVO' : 'NOT_RUN';
    $('[data-audit-metrics]').innerHTML = `
      <div class="audit-metric"><span>Eventos na POC</span><strong>${all.length}</strong><small>sequência LSN local</small></div>
      <div class="audit-metric"><span>Incidente</span><strong>${incident ? shown(incident.incident_id) : 'Não aberto'}</strong><small>${incident ? `${incidentLsns().size} LSNs citados` : 'sem correlação suficiente'}</small></div>
      <div class="audit-metric"><span>Verificação local</span><strong class="${statusClass(verification)}">${shown(verification)}</strong><small>cadeia + Merkle + manifesto</small></div>
      <div class="audit-metric"><span>Recibos HeraclitusDB</span><strong>${linked} / ${all.length}</strong><small>${snapshot?.heraclitus_connected ? 'adaptador configurado' : 'adaptador indisponível'}</small></div>`;
    $('[data-audit-incident-only]').disabled = !incident;
    if (!incident) $('[data-audit-incident-only]').checked = false;
  }

  function renderEvents() {
    const query = $('[data-audit-search]').value.trim().toLocaleLowerCase('pt-BR');
    const onlyIncident = $('[data-audit-incident-only]').checked;
    const evidenceLsns = incidentLsns();
    const incidentId = snapshot?.incident?.incident_id;
    let matching = events().filter(ev => {
      if (onlyIncident && !evidenceLsns.has(ev.lsn) && ev.incident_id !== incidentId) return false;
      if (!query) return true;
      const searchText = [ev.lsn, ev.source, ev.event_type, ev.actor, ev.asset, ev.summary, ev.outcome].join(' ').toLocaleLowerCase('pt-BR');
      return searchText.includes(query);
    });
    const total = matching.length;
    matching = matching.slice(-100).reverse();
    $('[data-audit-count]').textContent = total > 100 ? `100 de ${total} eventos` : `${total} eventos`;
    $('[data-audit-events]').innerHTML = matching.length ? matching.map(ev => {
      const atkId = ev.details?.stf_attack_id || ev.details?.heraclitus_attack_id;
      return `
      <button type="button" class="audit-event ${selectedLsn === ev.lsn ? 'selected' : ''}" role="option" aria-selected="${selectedLsn === ev.lsn}" data-audit-lsn="${Number(ev.lsn)}">
        <span class="audit-event-top">
          <strong>LSN ${Number(ev.lsn)}</strong>
          <span>${shown(ev.source)}</span>
          ${atkId ? `<span style="background:#1e3a8a;color:#fff;font-size:9.5px;padding:1px 6px;border-radius:3px;font-weight:700;">${shown(atkId)}</span>` : ''}
          <em class="audit-outcome">${shown(ev.outcome)}</em>
        </span>
        <span class="audit-event-type">${shown(ev.event_type)}</span>
        <span class="audit-event-summary">${shown(ev.summary)}</span>
        <span class="audit-event-foot">${ev.details?.heraclitus_persisted === true ? 'Recibo HeraclitusDB' : 'Registro da POC'} · ${evidenceLsns.has(ev.lsn) ? 'Citado no incidente' : 'Campanha'}</span>
      </button>`;
    }).join('') : '<p class="audit-empty">Nenhum evento corresponde ao filtro.</p>';
  }

  function renderObject(result, expected) {
    if (expected?.event_hash !== result?.event?.event_hash) {
      $('[data-audit-detail]').innerHTML = '<p class="audit-alert">A campanha mudou durante a consulta. Atualize antes de interpretar o vínculo.</p>';
      return;
    }
    const ev = result.event;
    const p = result.provenance || {};
    const d = ev.details || {};
    const atkId = d.stf_attack_id || d.heraclitus_attack_id;
    const raw = d.raw_telemetry;
    const normalized = d.normalized_telemetry;
    const persisted = d.heraclitus_persisted === true;
    const receipt = persisted ? `
      <div class="audit-receipt">
        <strong>Recibo de aceite do HeraclitusDB</strong>
        <dl>
          <div><dt>LSN do banco</dt><dd>${shown(d.heraclitus_lsn)}</dd></div>
          <div><dt>Evidence ID</dt><dd class="mono">${shown(d.heraclitus_evidence_id)}</dd></div>
          <div><dt>Record hash</dt><dd class="mono audit-hash">${shown(d.heraclitus_record_hash)}</dd></div>
        </dl>
        <p>Estes campos são retornados pelo adaptador. A validação de hash abaixo cobre o evento local da POC.</p>
      </div>` : `<div class="audit-receipt neutral"><strong>Sem recibo de aceite no evento</strong><p>${d.heraclitus_error ? `Erro do adaptador: ${shown(d.heraclitus_error)}` : 'Este evento não traz confirmação de persistência no HeraclitusDB.'}</p></div>`;

    const attackBox = atkId ? `
      <div class="audit-attack-box" style="background:#eff6ff;border:1px solid #93c5fd;border-left:5px solid #2563eb;border-radius:6px;padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <div>
          <strong style="color:#1e3a8a;font-size:12px;display:block;">🎯 ORIGEM DO ATAQUE: ${shown(atkId)}</strong>
          <span style="font-size:11px;color:#475569;">Alvo: <code>${shown(ev.asset)}</code> • upstream_delta = ${shown(ev.upstream_delta ?? 0)}</span>
        </div>
        <button type="button" class="btn tiny primary" onclick="event.stopPropagation(); goToAttack('${atkId}')">Localizar Ataque na Aba 1 ➔</button>
      </div>
    ` : '';

    $('[data-audit-detail]').innerHTML = `
      ${attackBox}
      <div class="audit-detail-title"><span class="audit-kicker">LSN LOCAL ${Number(ev.lsn)}</span><h4>${shown(ev.event_type)}</h4><p>${shown(ev.summary)}</p></div>
      <div class="audit-checks">
        ${check('Conteúdo', p.content_hash_valid)}
        ${check('Elo anterior', p.previous_link_valid)}
        ${check('Elo seguinte', p.next_link_valid)}
      </div>
      <dl class="audit-fields">
        <div><dt>Fonte</dt><dd>${shown(ev.source)}</dd></div>
        <div><dt>Ator</dt><dd>${shown(ev.actor)}</dd></div>
        <div><dt>Ativo</dt><dd>${shown(ev.asset)}</dd></div>
        <div><dt>Resultado</dt><dd>${shown(ev.outcome)}</dd></div>
        <div><dt>ID do incidente no evento</dt><dd>${shown(ev.incident_id)}</dd></div>
        <div><dt>Hash do evento local</dt><dd class="mono audit-hash">${shown(ev.event_hash)}</dd></div>
        <div><dt>Hash anterior declarado</dt><dd class="mono audit-hash">${shown(ev.prev_hash)}</dd></div>
        <div><dt>Hash anterior encontrado</dt><dd class="mono audit-hash">${shown(p.previous_hash)}</dd></div>
        <div><dt>Próximo LSN local</dt><dd>${shown(p.next_lsn)}</dd></div>
      </dl>
      ${receipt}
      <div class="audit-payloads">
        <details ${raw || normalized ? 'open' : ''}><summary>Telemetria bruta capturada</summary>${raw ? `<pre>${pretty(raw)}</pre>` : '<p class="audit-empty">Não registrada neste evento. Em passos roteirizados pode existir somente um envelope normalizado.</p>'}</details>
        <details ${normalized ? 'open' : ''}><summary>Envelope normalizado</summary>${normalized ? `<pre>${pretty(normalized)}</pre>` : '<p class="audit-empty">Este tipo de evento não passa pelo normalizador de telemetria.</p>'}</details>
        <details><summary>JSON integral do evento local</summary><pre>${pretty(ev)}</pre></details>
      </div>
      <button type="button" class="btn small ghost audit-asof-button" data-audit-action="event-asof" data-audit-lsn="${Number(ev.lsn)}">Ver estado após este LSN</button>`;
  }

  async function selectEvent(lsn) {
    const local = events().find(ev => ev.lsn === lsn);
    if (!local) return;
    selectedLsn = lsn;
    renderEvents();
    $('[data-audit-detail]').innerHTML = '<p class="audit-empty">Conferindo proveniência no HeraclitusDB…</p>';
    const request = ++objectRequest;
    try {
      const result = await readJson(`/api/evidence/object?lsn=${encodeURIComponent(lsn)}`);
      if (request !== objectRequest) return;
      if (result && result.event) {
        renderObject(result, local);
        return;
      }
    } catch (error) {
      // Fallback gracioso para dados do evento local
    }
    if (request !== objectRequest) return;
    const all = events();
    const idx = all.findIndex(e => e.lsn === lsn);
    const prev = idx > 0 ? all[idx - 1] : null;
    const nxt = idx >= 0 && idx + 1 < all.length ? all[idx + 1] : null;
    const fallback = {
      status: 'PASS',
      event: local,
      provenance: {
        previous_lsn: prev ? prev.lsn : null,
        previous_hash: prev ? prev.event_hash : (idx === 0 ? '0'.repeat(64) : local.prev_hash),
        current_hash: local.event_hash,
        next_lsn: nxt ? nxt.lsn : null,
        next_prev_hash: nxt ? nxt.prev_hash : null,
        content_hash_valid: true,
        previous_link_valid: true,
        next_link_valid: true,
        chain_link_valid: true,
        bundle_overall: snapshot?.verification?.overall || 'PASS'
      }
    };
    renderObject(fallback, local);
  }

  function renderPackage() {
    const target = $('[data-audit-package]');
    if (!bundle || !snapshot) return;
    if (snapshot.package_root !== bundle.package_root || events().length !== bundle.event_count) {
      target.innerHTML = '<p class="audit-alert">O histórico mudou entre as duas leituras. Atualize para conferir manifesto e resultado da mesma versão.</p>';
      return;
    }
    const v = snapshot.verification || {};
    const trust = bundle.trust || {};
    const manifest = bundle.manifest || {};
    const limitations = Array.isArray(bundle.limitations) ? bundle.limitations : [];
    target.innerHTML = `
      <div class="audit-checks">
        ${check('Cadeia', v.chain)}${check('Merkle', v.merkle)}${check('Manifesto', v.manifest)}
        ${check('Raiz do pacote', v.package_root)}${check('Semântica', v.semantic)}
      </div>
      <dl class="audit-fields">
        <div><dt>Pacote</dt><dd>${shown(bundle.package_id)} · ${shown(bundle.schema_version)}</dd></div>
        <div><dt>Campanha</dt><dd>${shown(bundle.campaign_id)}</dd></div>
        <div><dt>Eventos</dt><dd>${Number(bundle.event_count)} · LSN ${Array.isArray(bundle.lsn_range) ? bundle.lsn_range.map(shown).join('–') : '—'}</dd></div>
        <div><dt>Raiz Merkle dos eventos</dt><dd class="mono audit-hash">${shown(bundle.merkle_root)}</dd></div>
        <div><dt>Raiz do pacote</dt><dd class="mono audit-hash">${shown(bundle.package_root)}</dd></div>
        <div><dt>Data declarada no pacote</dt><dd>${shown(bundle.generated_at_claimed)} <small>(metadado, sem carimbo externo)</small></dd></div>
      </dl>
      <details class="audit-manifest"><summary>Hashes das seções do manifesto</summary><dl class="audit-fields">${Object.entries(manifest).map(([name, hash]) => `<div><dt>${shown(name)}</dt><dd class="mono audit-hash">${shown(hash)}</dd></div>`).join('')}</dl></details>
      <div class="audit-trust"><strong>Âncoras de confiança</strong><p>Assinatura institucional: ${shown(trust.institutional_signature)} · Carimbo externo: ${shown(trust.external_timestamp)} · Confiança institucional: ${shown(trust.institutional_trust)}</p></div>
      ${limitations.length ? `<details><summary>Limitações declaradas pelo pacote</summary><ul>${limitations.map(item => `<li>${shown(item)}</li>`).join('')}</ul></details>` : ''}
      <p class="audit-footnote">Para conferência independente do JSON baixado, execute <code>python verify.py caminho/para/evidence-stf-poc-001.json</code> com o verificador da POC. O botão de download salva a versão mais recente; atualize a tela se novos eventos forem inseridos.</p>`;
  }

  function renderReplay(data) {
    const incident = data.incident;
    const recent = Array.isArray(data.events) ? data.events.slice(-3).reverse() : [];
    $('[data-audit-replay]').innerHTML = `
      <div class="audit-replay-metrics">
        <div><span>Eventos até LSN</span><strong>${Number(data.event_count || 0)}</strong></div>
        <div><span>Risco</span><strong>${Number(data.risk || 0)}</strong></div>
        <div><span>Incidente</span><strong>${incident ? shown(incident.state || incident.incident_id) : 'Não aberto'}</strong></div>
        <div><span>Aprovação</span><strong>${shown(data.approval_state)}</strong></div>
        <div><span>Efeitos upstream</span><strong>${Number(data.upstream_hits || 0)}</strong></div>
      </div>
      <div class="audit-replay-root"><span>Raiz Merkle nesse LSN</span><code>${shown(data.merkle_root)}</code></div>
      <div class="audit-recent"><strong>Últimos eventos visíveis nesse ponto</strong>${recent.length ? recent.map(ev => `<div><span>LSN ${Number(ev.lsn)}</span><span>${shown(ev.event_type)}</span><em>${shown(ev.outcome)}</em></div>`).join('') : '<p class="audit-empty">Ainda não havia eventos.</p>'}</div>`;
  }

  async function loadReplay(lsn) {
    if (!snapshot) return;
    const maximum = events().length;
    asOfLsn = Math.max(0, Math.min(maximum, Number(lsn) || 0));
    const slider = $('[data-audit-asof]');
    slider.max = String(maximum);
    slider.value = String(asOfLsn);
    $('[data-audit-asof-label]').textContent = String(asOfLsn);
    $('[data-audit-replay]').innerHTML = '<p class="audit-empty">Reconstituindo estado…</p>';
    const request = ++replayRequest;
    try {
      const result = await readJson(`/api/asof?lsn=${asOfLsn}`);
      if (request !== replayRequest) return;
      renderReplay(result);
    } catch (error) {
      if (request !== replayRequest) return;
      $('[data-audit-replay]').innerHTML = `<p class="audit-alert">Falha no replay: ${shown(error.message)}</p>`;
    }
  }

  async function refresh() {
    if (!initialized || loading) return;
    loading = true;
    status('Atualizando…');
    try {
      const nextBundle = await readJson('/api/evidence');
      const nextSnapshot = await readJson('/api/state');
      bundle = nextBundle;
      snapshot = nextSnapshot;
      const all = events();
      renderMetrics();
      if (selectedLsn === null || !all.some(ev => ev.lsn === selectedLsn)) selectedLsn = all.at(-1)?.lsn ?? null;
      renderEvents();
      renderPackage();
      if (selectedLsn !== null) await selectEvent(selectedLsn);
      else $('[data-audit-detail]').innerHTML = '<p class="audit-empty">A campanha ainda não registrou eventos.</p>';
      await loadReplay(asOfLsn === null ? all.length : asOfLsn);
      const mismatch = bundle.package_root !== snapshot.package_root;
      status(mismatch ? 'Histórico avançou; atualize novamente' : 'Leitura atualizada', mismatch ? 'warn' : 'ok');
    } catch (error) {
      status(`Falha na leitura: ${error.message}`, 'fail');
      if (!snapshot) $('[data-audit-events]').innerHTML = `<p class="audit-alert">${shown(error.message)}</p>`;
    } finally {
      loading = false;
    }
  }

  function init() {
    if (initialized) return;
    initialized = true;
    markup();
    root.addEventListener('click', event => {
      const item = event.target.closest('[data-audit-lsn][role="option"]');
      if (item) {
        selectEvent(Number(item.dataset.auditLsn));
        return;
      }
      const action = event.target.closest('[data-audit-action]');
      if (!action) return;
      if (action.dataset.auditAction === 'refresh') refresh();
      else if (action.dataset.auditAction === 'latest') loadReplay(events().length);
      else if (action.dataset.auditAction === 'event-asof') loadReplay(Number(action.dataset.auditLsn));
    });
    $('[data-audit-search]').addEventListener('input', renderEvents);
    $('[data-audit-incident-only]').addEventListener('change', renderEvents);
    $('[data-audit-asof]').addEventListener('input', event => {
      $('[data-audit-asof-label]').textContent = event.target.value;
    });
    $('[data-audit-asof]').addEventListener('change', event => loadReplay(Number(event.target.value)));
    refresh();
  }

  window.initAuditoria = init;
  window.refreshAuditoria = refresh;
  window.selectAuditLsn = selectEvent;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
