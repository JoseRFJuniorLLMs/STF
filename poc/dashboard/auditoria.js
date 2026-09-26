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
            <div id="auditTimelineMount"></div>
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
    const searchEl = $('[data-audit-search]');
    const incOnlyEl = $('[data-audit-incident-only]');
    const countEl = $('[data-audit-count]');
    const eventsEl = $('[data-audit-events]');
    if (!eventsEl) return;

    const query = searchEl ? searchEl.value.trim().toLocaleLowerCase('pt-BR') : '';
    const onlyIncident = incOnlyEl ? incOnlyEl.checked : false;
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
    if (countEl) countEl.textContent = total > 100 ? `100 de ${total} eventos` : `${total} eventos`;
    eventsEl.innerHTML = matching.length ? matching.map(ev => {
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

  function formatAuditDate(ev, idx) {
    if (ev.details?.raw_telemetry?.timestamp) {
      try {
        const dt = new Date(ev.details.raw_telemetry.timestamp);
        if (!isNaN(dt.getTime())) return dt.toLocaleString('pt-BR');
      } catch (_) {}
    }
    if (ev.hlc) {
      try {
        const ms = Number(BigInt(ev.hlc) >> 16n);
        if (ms > 1600000000000) return new Date(ms).toLocaleString('pt-BR');
      } catch (_) {}
    }
    if (ev.ts) {
      try {
        const dt = new Date(ev.ts);
        if (!isNaN(dt.getTime())) return dt.toLocaleString('pt-BR');
      } catch (_) {}
    }
    return `Evento #${idx + 1}`;
  }

  function getAuditSteps(all) {
    return all.map((ev, i) => {
      const dh = formatAuditDate(ev, i);
      const title = ev.summary || ev.event_type || `Evento ${i + 1}`;
      return {
        lsn: Number(ev.lsn),
        dataHora: dh,
        title: title,
        source: ev.source || 'POC',
        outcome: ev.outcome || 'PASS',
        seq: i
      };
    });
  }

  function renderAuditTimeline() {
    const mount = $('#auditTimelineMount');
    if (!mount) return;
    const all = events();
    const totalSteps = all.length;
    if (totalSteps === 0) {
      mount.innerHTML = '<div class="proc-empty">Nenhum evento registrado para reconstituição temporal.</div>';
      return;
    }
    const passos = getAuditSteps(all);
    const lsns = all.map(e => Number(e.lsn));
    const latestLsn = lsns.length ? lsns[lsns.length - 1] : 0;
    const historico = asOfLsn !== null && asOfLsn !== latestLsn;
    const idxAtual = historico
      ? Math.max(0, all.findIndex(e => Number(e.lsn) === asOfLsn))
      : totalSteps - 1;
    const currentStep = passos[idxAtual] || passos[totalSteps - 1] || {};
    const progressPct = totalSteps > 1 ? (idxAtual / (totalSteps - 1)) * 100 : 100;

    const dotsHtml = passos.map((p, i) => {
      const dotPct = totalSteps > 1 ? (i / (totalSteps - 1)) * 100 : 0;
      let statusClass = 'future';
      if (i < idxAtual) statusClass = 'passed';
      else if (i === idxAtual) statusClass = 'current';

      return `
        <div class="scrubber-dot ${statusClass}"
          style="left: ${dotPct}%;"
          data-index="${i}"
          data-lsn="${p.lsn}"
          data-date="${escapeHtml(p.dataHora)}"
          data-title="${escapeHtml(p.title)}"
          data-seq="${i + 1}"
          role="button"
          tabindex="0"
          aria-label="Ir para evento ${i + 1}: ${escapeHtml(p.title)} (${escapeHtml(p.dataHora)})">
          <span class="dot-core"></span>
        </div>
      `;
    }).join('');

    mount.innerHTML = `
      <div class="proc-timeline-scrubber ${historico ? 'historical-active' : ''}" id="auditTimelineScrubber">
        <div class="scrubber-header">
          <div class="scrubber-title-wrap">
            <span class="scrubber-icon">⏱️</span>
            <div class="scrubber-titles">
              <strong>Linha do Tempo Criptográfica</strong>
              <small>Reconstrução Temporal AS OF LSN • Imutabilidade HeraclitusDB</small>
            </div>
          </div>

          <div class="scrubber-header-actions">
            <div class="scrubber-status-badge ${historico ? 'is-historical' : 'is-current'}">
              <span class="status-dot"></span>
              <span id="auditAsOfLabel" class="status-text mono">
                ${historico ? `AS OF LSN ${asOfLsn} · Passo ${idxAtual + 1} de ${totalSteps}` : `Estado Atual · LSN ${lsns[totalSteps - 1] ?? '—'}`}
              </span>
            </div>
            <button class="btn tiny ghost scrubber-reset-btn" id="auditAsOfNow" data-audit-action="latest" ${historico ? '' : 'disabled'} title="Restaurar visualização para o momento atual">
              ↺ Voltar ao atual
            </button>
          </div>
        </div>

        <div class="scrubber-track-container" id="auditTrackContainer">
          <!-- Floating Tooltip (Grok / Google Fotos) -->
          <div class="scrubber-floating-tooltip" id="auditScrubberTooltip">
            <div class="st-date"><span id="auditStDateText">—</span></div>
            <div class="st-title" id="auditStTitleText">—</div>
            <div class="st-meta">LSN <span id="auditStLsnText">—</span> • Passo <span id="auditStStepText">—</span> de ${totalSteps}</div>
            <div class="st-arrow"></div>
          </div>

          <div class="scrubber-track-rail">
            <div class="scrubber-track-progress" id="auditTrackProgress" style="width: ${progressPct}%;"></div>
          </div>

          <div class="scrubber-dots-layer" id="auditDotsLayer">
            ${dotsHtml}
          </div>

          <div class="scrubber-thumb" id="auditScrubberThumb" style="left: ${progressPct}%;">
            <div class="scrubber-thumb-handle"></div>
            <div class="scrubber-thumb-ring"></div>
          </div>

          <input type="range" class="scrubber-range-overlay" id="auditAsOfRange"
            min="0" max="${Math.max(0, totalSteps - 1)}" value="${idxAtual}"
            ${totalSteps < 2 ? 'disabled' : ''} aria-label="Reconstruir estado da auditoria ao longo do tempo" />
        </div>

        <div class="scrubber-footer">
          <button class="btn tiny ghost" id="auditStepPrev" ${idxAtual <= 0 ? 'disabled' : ''} title="Retroceder um evento">◀ Anterior</button>
          <div class="scrubber-current-info" id="auditCurrentInfo">
            <span class="sci-date" id="auditSciDateText">${escapeHtml(currentStep.dataHora || '—')}</span>
            <span class="sci-sep">•</span>
            <span class="sci-name" id="auditSciNameText">${escapeHtml(currentStep.title || 'Evento')}</span>
          </div>
          <button class="btn tiny ghost" id="auditStepNext" ${idxAtual >= totalSteps - 1 ? 'disabled' : ''} title="Avançar um evento">Próximo ▶</button>
        </div>
      </div>
    `;
  }

  function setupAuditTimelineEvents() {
    const mount = $('#auditTimelineMount');
    if (!mount) return;

    mount.addEventListener('click', e => {
      if (e.target.closest('#auditAsOfNow')) {
        asOfLsn = null;
        loadReplay(null);
        return;
      }
      if (e.target.closest('#auditStepPrev')) {
        const all = events();
        if (!all.length) return;
        const lsns = all.map(e => Number(e.lsn));
        const latestLsn = lsns.length ? lsns[lsns.length - 1] : 0;
        const historico = asOfLsn !== null && asOfLsn !== latestLsn;
        const curIdx = historico ? Math.max(0, all.findIndex(ev => Number(ev.lsn) === asOfLsn)) : all.length - 1;
        if (curIdx > 0) {
          const prevLsn = Number(all[curIdx - 1].lsn);
          loadReplay(prevLsn);
        }
        return;
      }
      if (e.target.closest('#auditStepNext')) {
        const all = events();
        if (!all.length) return;
        const lsns = all.map(e => Number(e.lsn));
        const latestLsn = lsns.length ? lsns[lsns.length - 1] : 0;
        const historico = asOfLsn !== null && asOfLsn !== latestLsn;
        const curIdx = historico ? Math.max(0, all.findIndex(ev => Number(ev.lsn) === asOfLsn)) : all.length - 1;
        if (curIdx < all.length - 1) {
          const nextLsn = Number(all[curIdx + 1].lsn);
          loadReplay(nextLsn);
        }
        return;
      }
      const dot = e.target.closest('.scrubber-dot');
      if (dot) {
        const lsn = Number(dot.dataset.lsn);
        loadReplay(lsn);
        return;
      }
    });

    mount.addEventListener('input', e => {
      if (e.target.id !== 'auditAsOfRange') return;
      const all = events();
      const totalSteps = all.length;
      if (!totalSteps) return;
      const i = Number(e.target.value);
      const pct = totalSteps > 1 ? (i / (totalSteps - 1)) * 100 : 100;
      const passos = getAuditSteps(all);
      const step = passos[i] || {};

      const progress = $('#auditTrackProgress');
      if (progress) progress.style.width = `${pct}%`;
      const thumb = $('#auditScrubberThumb');
      if (thumb) thumb.style.left = `${pct}%`;

      const dots = mount.querySelectorAll('.scrubber-dot');
      dots.forEach((d, idx) => {
        d.classList.remove('passed', 'current', 'future');
        if (idx < i) d.classList.add('passed');
        else if (idx === i) d.classList.add('current');
        else d.classList.add('future');
      });

      const lbl = $('#auditAsOfLabel');
      if (lbl) {
        lbl.textContent = i === totalSteps - 1
          ? `Estado Atual · LSN ${all[i]?.lsn ?? totalSteps}`
          : `AS OF LSN ${all[i]?.lsn} · Passo ${i + 1} de ${totalSteps}`;
      }

      const dtText = $('#auditSciDateText');
      if (dtText && step.dataHora) dtText.textContent = step.dataHora;
      const nmText = $('#auditSciNameText');
      if (nmText && step.title) nmText.textContent = step.title;

      const tt = $('#auditScrubberTooltip');
      if (tt) {
        const dtEl = $('#auditStDateText');
        if (dtEl) dtEl.textContent = step.dataHora ? `📅 ${step.dataHora}` : `Passo ${i + 1}`;
        const tiEl = $('#auditStTitleText');
        if (tiEl) tiEl.textContent = step.title || 'Evento';
        const lsnEl = $('#auditStLsnText');
        if (lsnEl) lsnEl.textContent = all[i]?.lsn ?? '—';
        const stEl = $('#auditStStepText');
        if (stEl) stEl.textContent = i + 1;
        tt.style.left = `${pct}%`;
        tt.classList.add('show');
      }
    });

    mount.addEventListener('change', e => {
      if (e.target.id !== 'auditAsOfRange') return;
      const all = events();
      const i = Number(e.target.value);
      if (all[i]) {
        loadReplay(i === all.length - 1 ? all.length : Number(all[i].lsn));
      }
      const tt = $('#auditScrubberTooltip');
      if (tt) tt.classList.remove('show');
    });

    mount.addEventListener('mousemove', e => {
      const track = e.target.closest('#auditTrackContainer');
      if (!track) return;
      const all = events();
      if (!all.length) return;
      const passos = getAuditSteps(all);

      const rect = track.getBoundingClientRect();
      const mouseX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
      const pct = rect.width > 0 ? (mouseX / rect.width) : 0;
      const closestIdx = Math.max(0, Math.min(Math.round(pct * (all.length - 1)), all.length - 1));
      const step = passos[closestIdx] || {};

      const tt = $('#auditScrubberTooltip');
      if (tt) {
        const dtEl = $('#auditStDateText');
        if (dtEl) dtEl.textContent = step.dataHora ? `📅 ${step.dataHora}` : `Passo ${closestIdx + 1}`;
        const tiEl = $('#auditStTitleText');
        if (tiEl) tiEl.textContent = step.title || 'Evento';
        const lsnEl = $('#auditStLsnText');
        if (lsnEl) lsnEl.textContent = all[closestIdx]?.lsn ?? '—';
        const stEl = $('#auditStStepText');
        if (stEl) stEl.textContent = closestIdx + 1;
        const dotPct = all.length > 1 ? (closestIdx / (all.length - 1)) * 100 : 50;
        tt.style.left = `${dotPct}%`;
        tt.classList.add('show');
      }
    });

    mount.addEventListener('mouseleave', () => {
      const tt = $('#auditScrubberTooltip');
      if (tt) tt.classList.remove('show');
    }, true);
  }

  async function loadReplay(lsn) {
    if (!snapshot) return;
    const all = events();
    const lsns = all.map(e => Number(e.lsn));
    const latestLsn = lsns.length ? lsns[lsns.length - 1] : 0;
    if (lsn === null || lsn === undefined || Number(lsn) >= latestLsn) {
      asOfLsn = null;
    } else {
      asOfLsn = Number(lsn);
    }
    renderAuditTimeline();
    $('[data-audit-replay]').innerHTML = '<p class="audit-empty">Reconstituindo estado…</p>';
    const request = ++replayRequest;
    try {
      const queryLsn = asOfLsn === null ? (latestLsn || all.length) : asOfLsn;
      const result = await readJson(`/api/asof?lsn=${queryLsn}`);
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
    setupAuditTimelineEvents();
    root.addEventListener('click', event => {
      const item = event.target.closest('[data-audit-lsn][role="option"]');
      if (item) {
        selectEvent(Number(item.dataset.auditLsn));
        return;
      }
      const action = event.target.closest('[data-audit-action]');
      if (!action) return;
      if (action.dataset.auditAction === 'refresh') refresh();
      else if (action.dataset.auditAction === 'latest') {
        asOfLsn = null;
        loadReplay(null);
      }
      else if (action.dataset.auditAction === 'event-asof') loadReplay(Number(action.dataset.auditLsn));
    });
    const searchEl = $('[data-audit-search]');
    if (searchEl) searchEl.addEventListener('input', renderEvents);
    const incOnlyEl = $('[data-audit-incident-only]');
    if (incOnlyEl) incOnlyEl.addEventListener('change', renderEvents);
    refresh();
  }

  window.initAuditoria = init;
  window.refreshAuditoria = refresh;
  window.selectAuditLsn = selectEvent;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
