// ========================================================
// LOG VISUAL HERACLITUSDB — VISÃO FORENSE DO LOG PROCESSUAL
// Usa api(), esc() e $() definidos em app.js.
// ========================================================
(() => {
  const state = {
    processos: [],
    selectedProcess: null,
    detail: null,
    selectedEventId: null,
    filter: 'all',
    loading: false,
    storageMode: 'UNKNOWN',
    durability: 'UNKNOWN'
  };

  const LANES = [
    { id: 'protocolo', label: 'Entrada / Protocolo', icon: '📥' },
    { id: 'peticao', label: 'Petições', icon: '📄' },
    { id: 'andamento', label: 'Andamentos', icon: '⚖️' },
    { id: 'deslocamento', label: 'Deslocamentos', icon: '📦' },
    { id: 'ledger', label: 'Ledger HeraclitusDB', icon: '🔗' }
  ];

  const FILTERS = [
    { id: 'all', label: 'Todos' },
    { id: 'protocolo', label: 'Protocolos' },
    { id: 'peticao', label: 'Petições' },
    { id: 'andamento', label: 'Andamentos' },
    { id: 'deslocamento', label: 'Deslocamentos' }
  ];

  const fmtDate = value => {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
  };

  const short = (value, n = 16) => {
    const s = String(value || '—');
    return s.length > n ? s.slice(0, n) + '…' : s;
  };

  function eventLabel(ev) {
    if (ev.tipo === 'andamento') return ev.conteudo?.movimento?.nome || ev.kind || 'Andamento';
    if (ev.tipo === 'protocolo') return 'Protocolo ' + (ev.conteudo?.protocolo?.numero || '');
    if (ev.tipo === 'peticao') return (ev.conteudo?.peticao?.tipo || 'Petição') + ' ' + (ev.conteudo?.peticao?.numero || '');
    if (ev.tipo === 'deslocamento') return 'Deslocamento ' + (ev.conteudo?.deslocamento?.guia || '');
    return ev.kind || ev.tipo || 'Evento';
  }

  function eventProcessTime(ev) {
    if (ev.tipo === 'andamento') return ev.conteudo?.dataHora;
    if (ev.tipo === 'protocolo') return ev.conteudo?.protocolo?.peticionadoEm;
    if (ev.tipo === 'peticao') return ev.conteudo?.peticao?.peticionadoEm;
    if (ev.tipo === 'deslocamento') return ev.conteudo?.deslocamento?.enviadoEm;
    return ev.ts_ms ? new Date(ev.ts_ms).toISOString() : null;
  }

  function verifyChain(events) {
    const ordered = [...events].sort((a, b) => Number(a.seq) - Number(b.seq));
    let previous = null;
    for (const ev of ordered) {
      const parents = Array.isArray(ev.parents) ? ev.parents : [];
      const expected = previous ? [previous.id] : [];
      if (parents.length !== expected.length || parents.some((p, i) => p !== expected[i])) {
        return { ok: false, eventId: ev.id, lsn: ev.lsn, reason: 'Elo anterior divergente' };
      }
      if (previous && Number(ev.lsn) <= Number(previous.lsn)) {
        return { ok: false, eventId: ev.id, lsn: ev.lsn, reason: 'LSN fora de ordem' };
      }
      previous = ev;
    }
    return { ok: true, links: ordered.length, eventId: null, lsn: null, reason: null };
  }

  function selectedEvent() {
    const events = state.detail?.eventos || [];
    return events.find(ev => ev.id === state.selectedEventId) || events[events.length - 1] || null;
  }

  function eventPct(ev, events) {
    if (events.length <= 1) return 50;
    const min = Math.min(...events.map(x => Number(x.lsn)));
    const max = Math.max(...events.map(x => Number(x.lsn)));
    if (max === min) return 50;
    return 3 + ((Number(ev.lsn) - min) / (max - min)) * 94;
  }

  function visibleForFilter(ev) {
    return state.filter === 'all' || ev.tipo === state.filter;
  }

  function eventNode(ev, events, compact = false) {
    const selected = ev.id === state.selectedEventId;
    const hidden = !visibleForFilter(ev);
    const pct = eventPct(ev, events);
    const label = eventLabel(ev);
    return `<button class="logv-event ${selected ? 'selected' : ''} ${hidden ? 'filtered-out' : ''} ${compact ? 'compact' : ''}"
      style="left:${pct}%" data-logv-event="${esc(ev.id)}"
      title="LSN ${esc(ev.lsn)} · ${esc(label)} · ${esc(fmtDate(eventProcessTime(ev)))}"
      aria-label="Abrir evento LSN ${esc(ev.lsn)}: ${esc(label)}">
      <span class="logv-event-core"></span>
      ${compact ? '' : `<span class="logv-event-caption">LSN ${esc(ev.lsn)}</span>`}
    </button>`;
  }

  function renderSwimlanes(events) {
    if (!events.length) return '<div class="logv-empty">Nenhum evento para representar.</div>';
    const rows = LANES.map(lane => {
      const laneEvents = lane.id === 'ledger' ? events : events.filter(ev => ev.tipo === lane.id);
      return `<div class="logv-lane">
        <div class="logv-lane-label"><span>${lane.icon}</span><strong>${lane.label}</strong><small>${laneEvents.length}</small></div>
        <div class="logv-lane-track">
          <div class="logv-lane-line"></div>
          ${laneEvents.map(ev => eventNode(ev, events, lane.id === 'ledger')).join('')}
        </div>
      </div>`;
    }).join('');
    const first = events[0], last = events[events.length - 1];
    return `<div class="logv-swimlanes">
      ${rows}
      <div class="logv-axis"><span>LSN ${esc(first?.lsn ?? '—')}</span><span>Tempo / causalidade →</span><span>LSN ${esc(last?.lsn ?? '—')}</span></div>
    </div>`;
  }

  function renderChain(events, integrity) {
    if (!events.length) return '<div class="logv-empty">Cadeia vazia.</div>';
    return `<div class="logv-chain-scroll"><div class="logv-chain">
      ${events.map((ev, idx) => {
        const bad = !integrity.ok && ev.id === integrity.eventId;
        const selected = ev.id === state.selectedEventId;
        return `<div class="logv-chain-step">
          <button class="logv-chain-node ${idx === 0 ? 'root' : ''} ${bad ? 'broken' : ''} ${selected ? 'selected' : ''}"
            data-logv-event="${esc(ev.id)}" title="${idx === 0 ? 'Evento raiz da cadeia' : 'Aponta criptograficamente para o evento anterior'}">
            <span>LSN ${esc(ev.lsn)}</span>
            <strong>${esc(short(ev.id, 13))}</strong>
            <small>${esc(ev.tipo || ev.kind || 'evento')}</small>
          </button>
          ${idx < events.length - 1 ? '<div class="logv-chain-arrow" title="Elo anterior / parents">→</div>' : ''}
        </div>`;
      }).join('')}
    </div></div>`;
  }

  function renderDetail(ev) {
    if (!ev) return '<div class="logv-empty">Selecione um evento na timeline ou na cadeia.</div>';
    const parent = Array.isArray(ev.parents) && ev.parents.length ? ev.parents[0] : '— (raiz)';
    return `<div class="logv-detail-head">
        <div><span class="logv-kicker">EVENTO SELECIONADO</span><h3>LSN ${esc(ev.lsn)} · ${esc(eventLabel(ev))}</h3></div>
        <span class="logv-kind">${esc(ev.kind || ev.tipo || 'evento')}</span>
      </div>
      <div class="logv-detail-grid">
        <div><span>Seq <b class="logv-help" title="Ordem do evento dentro deste processo.">ⓘ</b></span><strong>${esc(ev.seq)}</strong></div>
        <div><span>Registrado <b class="logv-help" title="Momento do Append no núcleo do HeraclitusDB.">ⓘ</b></span><strong>${esc(ev.ts_ms ? fmtDate(ev.ts_ms) : '—')}</strong></div>
        <div><span>Evento (ULID) <b class="logv-help" title="Identificador único e temporal do evento imutável.">ⓘ</b></span><strong class="mono">${esc(ev.id)}</strong></div>
        <div><span>Elo anterior <b class="logv-help" title="Referência parents que liga este evento ao imediatamente anterior.">ⓘ</b></span><strong class="mono">${esc(parent)}</strong></div>
        <div class="wide"><span>Chave de idempotência <b class="logv-help" title="Evita gravar duas vezes a mesma operação lógica com conteúdo divergente.">ⓘ</b></span><strong class="mono">${esc(ev.idempotency_key || '—')}</strong></div>
      </div>
      <details class="logv-json"><summary>Ver evento bruto</summary><pre>${esc(JSON.stringify(ev, null, 2))}</pre></details>`;
  }

  function render() {
    const root = $('#viewLogvisual');
    if (!root) return;
    const d = state.detail;
    const events = [...(d?.eventos || [])].sort((a, b) => Number(a.lsn) - Number(b.lsn));
    const integrity = verifyChain(events);
    const first = events[0], last = events[events.length - 1];
    const proc = state.processos.find(p => p.id === state.selectedProcess);
    const ev = selectedEvent();
    const fallback = state.storageMode === 'MEMORY_FALLBACK';

    root.innerHTML = `
      <section class="panel logv-panel">
        <div class="panel-head logv-head">
          <div>
            <h2 data-help="Visão visual do mesmo log processual. LSN ordena eventos; parents liga cada evento ao anterior.">Log Visual HeraclitusDB <small class="head-hint">timeline forense • cadeia de integridade • eventos clicáveis</small></h2>
            <p>Uma leitura visual do mesmo log imutável do acompanhamento processual, sem substituir a tabela técnica.</p>
          </div>
          <div class="logv-toolbar">
            <label>Processo
              <select id="logvProcessSelect" class="logv-select">
                ${state.processos.map(p => `<option value="${esc(p.id)}" ${p.id === state.selectedProcess ? 'selected' : ''}>${esc(p.capa?.numero || p.id)}</option>`).join('')}
              </select>
            </label>
            <button class="btn small primary" id="logvRefreshBtn" data-help="Reconsulta a API processual e redesenha a timeline, cadeia e inspetor sem alterar eventos.">↻ Atualizar</button>
          </div>
        </div>

        <div class="logv-note">
          <strong>${esc(proc?.capa?.numero || state.selectedProcess || '—')}</strong>
          <span>${esc(proc?.capa?.numeroUnico || '')}</span>
          <span class="logv-integrity ${integrity.ok ? 'ok' : 'broken'}">${integrity.ok ? '✓ Cadeia íntegra nesta representação' : '⛓ Cadeia quebrada'}</span>
          <span class="logv-integrity ${fallback ? 'broken' : 'ok'}">${fallback ? 'MEMORY FALLBACK · VOLATILE' : 'HERACLITUS CORE · DURABLE'}</span>
        </div>
        ${fallback ? '<div class="logv-fallback-warning">Leitura de contingência em memória. Os LSNs desta visão não são LSNs confirmados pelo núcleo e nenhuma escrita é permitida.</div>' : ''}

        <div class="logv-kpis">
          <div><span>Eventos <b class="logv-help" title="Quantidade de eventos imutáveis deste processo.">ⓘ</b></span><strong>${events.length}</strong></div>
          <div><span>Primeiro LSN <b class="logv-help" title="Primeira posição do processo no log consultado.">ⓘ</b></span><strong>${esc(first?.lsn ?? '—')}</strong></div>
          <div><span>Último LSN <b class="logv-help" title="Posição mais recente do processo no log.">ⓘ</b></span><strong>${esc(last?.lsn ?? '—')}</strong></div>
          <div><span>Integridade <b class="logv-help" title="Validação local da sequência de LSNs e dos elos parents entre eventos.">ⓘ</b></span><strong class="${integrity.ok ? 'ok' : 'broken'}">${integrity.ok ? 'OK' : 'FALHA'}</strong></div>
        </div>

        <div class="logv-section-head">
          <div><span class="logv-kicker">VISÃO TEMPORAL</span><h3 data-help="Distribui cada evento pela categoria funcional e pela posição do seu LSN.">Timeline por componentes</h3><p>Cada bolha é um evento. A linha inferior mostra todos os Appends no Ledger.</p></div>
          <div class="logv-filters" role="group" aria-label="Filtrar eventos">
            ${FILTERS.map(f => `<button class="logv-filter ${state.filter === f.id ? 'active' : ''}" data-logv-filter="${f.id}" data-help="Filtra visualmente a timeline; não altera nem exclui eventos do ledger.">${f.label}</button>`).join('')}
          </div>
        </div>
        ${renderSwimlanes(events)}

        <div class="logv-section-head compact"><div><span class="logv-kicker">INTEGRIDADE</span><h3 data-help="Mostra a sequência local: cada evento, exceto a raiz, deve apontar por parents para o evento anterior do mesmo processo.">Cadeia LSN → elo anterior</h3><p>Role horizontalmente quando houver muitos eventos.</p></div></div>
        ${renderChain(events, integrity)}

        <div class="logv-section-head compact"><div><span class="logv-kicker">INSPEÇÃO</span><h3 data-help="Inspetor do evento selecionado: identificadores, timestamp, elo parents, idempotência e JSON bruto.">Detalhe do evento</h3></div></div>
        <div class="logv-detail">${renderDetail(ev)}</div>
      </section>`;
  }

  async function loadDetail() {
    if (!state.selectedProcess) {
      state.detail = null;
      render();
      return;
    }
    const res = await api('/api/processos/detalhe?id=' + encodeURIComponent(state.selectedProcess));
    if (!res.connected && res.storage_mode !== 'MEMORY_FALLBACK') throw new Error(res.error || 'HeraclitusDB indisponível');
    state.storageMode = res.storage_mode || state.storageMode;
    state.durability = res.durability || state.durability;
    state.detail = res;
    const events = res.eventos || [];
    if (!events.some(ev => ev.id === state.selectedEventId)) {
      state.selectedEventId = events.length ? events[events.length - 1].id : null;
    }
    render();
  }

  async function refreshLogVisualHeraclitus() {
    if (state.loading) return;
    state.loading = true;
    const root = $('#viewLogvisual');
    if (root) root.innerHTML = '<section class="panel logv-panel"><div class="logv-loading">Carregando log visual do HeraclitusDB…</div></section>';
    try {
      const res = await api('/api/processos');
      if (!res.connected && res.storage_mode !== 'MEMORY_FALLBACK') throw new Error(res.error || 'HeraclitusDB indisponível');
      state.storageMode = res.storage_mode || 'UNKNOWN';
      state.durability = res.durability || 'UNKNOWN';
      state.processos = Array.isArray(res.processos) ? res.processos : [];
      if (!state.processos.some(p => p.id === state.selectedProcess)) {
        state.selectedProcess = state.processos[0]?.id || null;
      }
      await loadDetail();
    } catch (err) {
      if (root) root.innerHTML = `<section class="panel logv-panel"><div class="logv-empty">Não foi possível carregar o Log Visual HeraclitusDB: ${esc(err.message)}</div></section>`;
    } finally {
      state.loading = false;
    }
  }

  function setup() {
    const root = $('#viewLogvisual');
    if (!root) return;
    root.addEventListener('click', event => {
      const node = event.target.closest('[data-logv-event]');
      if (node) {
        state.selectedEventId = node.dataset.logvEvent;
        render();
        return;
      }
      const filter = event.target.closest('[data-logv-filter]');
      if (filter) {
        state.filter = filter.dataset.logvFilter;
        render();
        return;
      }
      if (event.target.closest('#logvRefreshBtn')) refreshLogVisualHeraclitus();
    });
    root.addEventListener('change', event => {
      if (event.target.id !== 'logvProcessSelect') return;
      state.selectedProcess = event.target.value;
      state.selectedEventId = null;
      loadDetail().catch(err => {
        root.innerHTML = `<section class="panel logv-panel"><div class="logv-empty">Falha ao carregar processo: ${esc(err.message)}</div></section>`;
      });
    });
  }

  window.refreshLogVisualHeraclitus = refreshLogVisualHeraclitus;
  setup();
})();
