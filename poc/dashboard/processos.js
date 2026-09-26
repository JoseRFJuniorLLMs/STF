// ========================================================
// ACOMPANHAMENTO PROCESSUAL — LOG IMUTÁVEL NO HERACLITUSDB
// Usa api(), esc(), toast() e $() definidos em app.js.
// ========================================================
const PROC_SITUACAO = {
  EM_TRAMITACAO: 'Em tramitação',
  TRANSITADO: 'Transitado em julgado',
  BAIXADO: 'Baixado'
};
const PROC_SUBTABS = [
  { id: 'andamentos', label: 'Andamentos' },
  { id: 'timeline', label: '⏳ Linha do tempo' },
  { id: 'peticoes', label: 'Protocolo e petições' },
  { id: 'deslocamentos', label: 'Deslocamentos' },
  { id: 'log', label: 'Log HeraclitusDB' }
];

let procLista = [];
let procSelecionado = null;
let procDetalhe = null;
let procAsOf = null;            // null = estado atual; número = AS OF LSN
let procSubtab = 'andamentos';
let procPrimeiraCarga = true;
let procAutoTimer = null;
let procPollTimer = null;
let procCarregando = false;
const procUltimoLsnVisto = new Map();   // id -> último LSN já visto na lista
const procNovos = new Set();            // ids com andamento novo ainda não aberto
const procLsnRenderizado = new Map();   // id -> maior LSN já desenhado no detalhe

const procDataFmt = new Intl.DateTimeFormat('pt-BR', {
  timeZone: 'America/Sao_Paulo', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'
});
const procDataHoraFmt = new Intl.DateTimeFormat('pt-BR', {
  timeZone: 'America/Sao_Paulo', day: '2-digit', month: '2-digit', year: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit'
});
const procData = iso => (iso ? procDataFmt.format(new Date(iso)) : '—');
const procDataHora = iso => (iso ? procDataHoraFmt.format(new Date(iso)) : '—');
const procHora = ms => (ms ? procDataHoraFmt.format(new Date(ms)) : '—');

const ALL_VIEWS = ['defesa', 'processos', 'zanin', 'incidente', 'auditoria', 'resiliencia', 'interoperabilidade'];

function procViewAtiva() {
  return !$('#viewProcessos').hidden;
}

// --------------------------------------------------------------- abas topo
function setupMainTabs() {
  document.querySelectorAll('.main-tab').forEach(btn => {
    btn.addEventListener('click', () => mostrarView(btn.dataset.view));
  });
  const hashView = () => {
    const h = (location.hash || '').replace(/^#/, '');
    return ALL_VIEWS.includes(h) ? h : 'defesa';
  };
  window.addEventListener('hashchange', () => mostrarView(hashView(), false));
  if (location.hash) mostrarView(hashView(), false);
}

function mostrarView(view, atualizarHash = true) {
  if (!ALL_VIEWS.includes(view)) view = 'defesa';
  ALL_VIEWS.forEach(v => {
    const elId = 'view' + v.charAt(0).toUpperCase() + v.slice(1);
    const el = $('#' + elId);
    if (el) el.hidden = (v !== view);
  });
  document.querySelectorAll('.main-tab').forEach(btn => {
    const ativo = btn.dataset.view === view;
    btn.classList.toggle('active', ativo);
    btn.setAttribute('aria-selected', String(ativo));
  });
  if (atualizarHash) history.replaceState(null, '', view === 'defesa' ? location.pathname + location.search : '#' + view);
  if (view === 'processos') {
    if (procSelecionado) procNovos.delete(procSelecionado);
    atualizarBadgeNovos();
    carregarProcessos();
  } else if (view === 'zanin' && typeof refreshDefesaZanin === 'function') {
    refreshDefesaZanin();
  } else if (view === 'incidente' && typeof refreshIncidente360 === 'function') {
    refreshIncidente360();
  } else if (view === 'auditoria' && typeof refreshAuditoria === 'function') {
    refreshAuditoria();
  } else if (view === 'resiliencia' && typeof refreshResiliencia === 'function') {
    refreshResiliencia();
  } else if (view === 'interoperabilidade' && typeof refreshInteroperabilidade === 'function') {
    refreshInteroperabilidade();
  } else if (view === 'defesa' && typeof state !== 'undefined' && state) {
    if (typeof renderGraph === 'function') renderGraph(state);
    if (typeof renderIncidentCharts === 'function') renderIncidentCharts();
  }
  agendarPoll();
}

function atualizarBadgeNovos() {
  const badge = $('#procNovosBadge');
  badge.textContent = procNovos.size;
  badge.hidden = procNovos.size === 0;
}

// ----------------------------------------------------------------- leitura
function agendarPoll() {
  clearTimeout(procPollTimer);
  // Aba aberta: acompanha de perto. Fechada: só para acender o contador.
  procPollTimer = setTimeout(async () => {
    await carregarProcessos();
    agendarPoll();
  }, procViewAtiva() ? 5000 : 20000);
}

function setProcStatus(texto, classe) {
  const el = $('#procStatus');
  el.textContent = texto;
  el.className = 'tag-status ' + classe;
}

async function carregarProcessos() {
  if (procCarregando) return;
  procCarregando = true;
  try {
    const res = await api('/api/processos');
    $('#procAddr').textContent = res.addr || '—';
    if (!res.connected) {
      setProcStatus('OFFLINE', 'critical');
      $('#procProtocolarBtn').hidden = true;
      procLista = [];
      $('#procList').innerHTML = `<div class="proc-empty">HeraclitusDB indisponível em <code>${esc(res.addr || '')}</code>.<br><small>${esc(res.error || '')}</small></div>`;
      if (!procDetalhe) $('#procDetail').innerHTML = '<div class="proc-empty">Sem ligação ao banco não há log para mostrar.</div>';
      return;
    }
    setProcStatus(`CONECTADO • ${res.eventos} eventos`, 'normal');
    $('#procProtocolarBtn').hidden = res.processos.length >= res.catalogo;
    detectarNovidades(res.processos);
    procLista = res.processos;
    renderListaProcessos();
    if (!procLista.length) {
      $('#procDetail').innerHTML = '<div class="proc-empty">Nenhum processo no HeraclitusDB ainda.<br>Use <strong>Protocolar processos sintéticos</strong> para gravar o protocolo e os primeiros andamentos.</div>';
      return;
    }
    const atual = procLista.find(p => p.id === procSelecionado);
    if (!atual) {
      if (procViewAtiva()) selecionarProcesso(procLista[0].id);
    } else if (procAsOf === null && procDetalhe && atual.ultimo_lsn !== procDetalhe.processo.ultimo_lsn) {
      carregarDetalhe();
    }
  } catch (e) {
    setProcStatus('ERRO', 'critical');
    $('#procList').innerHTML = `<div class="proc-empty">Falha ao consultar a POC: ${esc(e.message)}</div>`;
  } finally {
    procCarregando = false;
  }
}

// Como o STF Push: cada andamento novo gera um aviso, e o processo fica
// marcado até ser aberto.
function detectarNovidades(processos) {
  const avisos = [];
  processos.forEach(p => {
    const antes = procUltimoLsnVisto.get(p.id);
    if (!procPrimeiraCarga && (antes === undefined || p.ultimo_lsn > antes)) {
      const aberto = procViewAtiva() && p.id === procSelecionado && procAsOf === null;
      if (!aberto) procNovos.add(p.id);
      const ult = p.ultimo_andamento;
      avisos.push(`${p.capa.numero}: ${ult ? ult.nome : 'novo registro'}`);
    }
    procUltimoLsnVisto.set(p.id, p.ultimo_lsn);
  });
  procPrimeiraCarga = false;
  if (avisos.length) toast(`📬 Novo andamento — ${avisos.slice(0, 2).join(' • ')}${avisos.length > 2 ? ` (+${avisos.length - 2})` : ''}`);
  atualizarBadgeNovos();
}

function renderListaProcessos() {
  const termo = ($('#procBusca').value || '').trim().toLowerCase();
  const visiveis = procLista.filter(p => !termo || [p.id, p.capa.numero, p.capa.numeroUnico, p.capa.classe.nome, p.capa.relator]
    .some(v => String(v).toLowerCase().includes(termo)));
  if (!procLista.length) {
    $('#procList').innerHTML = '<div class="proc-empty">Nenhum processo protocolado no HeraclitusDB.</div>';
    return;
  }
  if (!visiveis.length) {
    $('#procList').innerHTML = '<div class="proc-empty">Nenhum processo corresponde à busca.</div>';
    return;
  }
  $('#procList').innerHTML = visiveis.map(p => {
    const ult = p.ultimo_andamento;
    const ativo = p.id === procSelecionado;
    const hasAttack = Boolean(p.has_attack_alert || (p.attack_intercepts && p.attack_intercepts.length));
    return `
      <button class="proc-card ${ativo ? 'active' : ''} ${hasAttack ? 'has-attack-threat' : ''}" role="option" aria-selected="${ativo}" data-id="${esc(p.id)}">
        <div class="proc-card-top">
          <strong>${esc(p.capa.numero)}</strong>
          ${hasAttack ? '<span class="proc-attack-badge">🚨 ATAQUE INTERCEPTADO</span>' : ''}
          ${procNovos.has(p.id) ? '<span class="proc-novo">NOVO</span>' : ''}
          <span class="proc-sit ${esc(p.situacao)}">${esc(PROC_SITUACAO[p.situacao] || p.situacao)}</span>
        </div>
        <div class="proc-card-nu mono">${esc(p.capa.numeroUnico)}</div>
        <div class="proc-card-meta">${esc(p.capa.orgaoJulgador)} • ${esc(p.capa.relator)}</div>
        <div class="proc-card-last">
          ${ult ? `<span>${procData(ult.dataHora)}</span> ${esc(ult.nome)}` : 'Protocolado'}
        </div>
        <div class="proc-card-foot">${p.eventos} eventos • LSN ${p.ultimo_lsn ?? '—'}</div>
      </button>`;
  }).join('');
}

function selecionarProcesso(id) {
  if (id !== procSelecionado) procSubtab = 'andamentos';
  procSelecionado = id;
  procAsOf = null;
  procNovos.delete(id);
  atualizarBadgeNovos();
  renderListaProcessos();
  carregarDetalhe();
}
window.selecionarProcesso = selecionarProcesso;

async function carregarDetalhe() {
  if (!procSelecionado) return;
  const id = procSelecionado;
  const asOf = procAsOf;
  try {
    const q = `id=${encodeURIComponent(id)}${asOf !== null ? `&as_of=${asOf}` : ''}`;
    const res = await api(`/api/processos/detalhe?${q}`);
    if (id !== procSelecionado || asOf !== procAsOf) return; // resposta obsoleta
    if (!res.connected) {
      $('#procDetail').innerHTML = `<div class="proc-empty">HeraclitusDB indisponível: ${esc(res.error || '')}</div>`;
      return;
    }
    procDetalhe = res;
    renderDetalhe();
  } catch (e) {
    $('#procDetail').innerHTML = `<div class="proc-empty">Falha ao ler o log do processo: ${esc(e.message)}</div>`;
  }
}

function renderProcessHeatmap(eventos) {
  if (!eventos || !eventos.length) return '';
  const porDia = new Map();
  eventos.forEach(ev => {
    const dataIso = ev.conteudo?.dataHora || (ev.ts_ms ? new Date(ev.ts_ms).toISOString() : null);
    if (!dataIso) return;
    const chave = String(dataIso).slice(0, 10);
    if (!porDia.has(chave)) {
      porDia.set(chave, { chave, count: 0, andamentos: 0, outros: 0 });
    }
    const item = porDia.get(chave);
    item.count++;
    if (ev.tipo === 'andamento') item.andamentos++;
    else item.outros++;
  });

  const semanas = 53;
  const hoje = new Date();
  const diaSemanaHoje = hoje.getDay();
  const fimGrade = new Date(hoje.getFullYear(), hoje.getMonth(), hoje.getDate() + (6 - diaSemanaHoje));
  const inicioGrade = new Date(fimGrade.getTime() - (semanas * 7 - 1) * 86400000);

  const mesesNomes = ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Jul', 'Ago', 'Set', 'Out', 'Nov', 'Dez'];
  const mesesLabels = [];
  let ultimoMes = -1;

  const cell = 11, gap = 3, pitch = cell + gap;
  const offsetX = 30, offsetY = 18;
  const squares = [];

  for (let w = 0; w < semanas; w++) {
    for (let d = 0; d < 7; d++) {
      const diaIdx = w * 7 + d;
      const dataAtual = new Date(inicioGrade.getTime() + diaIdx * 86400000);
      const chave = dataAtual.toISOString().slice(0, 10);
      const mesAtual = dataAtual.getMonth();

      if (d === 0 && mesAtual !== ultimoMes && w < semanas - 1) {
        mesesLabels.push(`<text class="axis-text" x="${offsetX + w * pitch}" y="12" fill="#64748b" font-size="9" font-family="sans-serif">${mesesNomes[mesAtual]}</text>`);
        ultimoMes = mesAtual;
      }

      const dados = porDia.get(chave);
      const count = dados ? dados.count : 0;
      const andamentos = dados ? dados.andamentos : 0;
      const outros = dados ? dados.outros : 0;

      const lvl = count === 0 ? 0 : count === 1 ? 1 : count <= 3 ? 2 : count <= 6 ? 3 : 4;
      const x = offsetX + w * pitch;
      const y = offsetY + d * pitch;

      const diaFmt = procData(dataAtual.toISOString());
      const tip = `<strong>${diaFmt}</strong><div class="tt-row">Total de atos<b>${count}</b></div>${andamentos ? `<div class="tt-row">Andamentos<b>${andamentos}</b></div>` : ''}${outros ? `<div class="tt-row">Petições/Deslocamentos<b>${outros}</b></div>` : ''}`;

      squares.push(`<rect class="heat-cell heat-${lvl}" x="${x}" y="${y}" width="${cell}" height="${cell}" rx="2" data-tip="${esc(tip)}"/>`);
    }
  }

  const weekdayLabels = [
    `<text class="axis-text" x="4" y="${offsetY + 1 * pitch + 9}" fill="#64748b" font-size="9" font-family="sans-serif">Seg</text>`,
    `<text class="axis-text" x="4" y="${offsetY + 3 * pitch + 9}" fill="#64748b" font-size="9" font-family="sans-serif">Qua</text>`,
    `<text class="axis-text" x="4" y="${offsetY + 5 * pitch + 9}" fill="#64748b" font-size="9" font-family="sans-serif">Sex</text>`
  ];

  const W = offsetX + semanas * pitch + 10;
  const H = offsetY + 7 * pitch + 8;

  return `
    <div class="proc-heatmap-box">
      <div class="proc-heatmap-head">
        <span>📊 Atividade processual no tempo (estilo GitHub · azul STF)</span>
        <small>${eventos.length} evento(s) imutáveis gravados no HeraclitusDB</small>
      </div>
      <div style="width: 100%; overflow-x: auto;">
        <svg class="proc-heatmap-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">
          ${mesesLabels.join('')}
          ${weekdayLabels.join('')}
          ${squares.join('')}
        </svg>
      </div>
      <div class="heat-foot">
        <span>Cada quadrado = 1 dia de tramitação · Passe o mouse para ver os atos</span>
        <span class="heat-scale">Menos ${[0, 1, 2, 3, 4].map(l => `<i class="heat-cell heat-${l}"></i>`).join('')} Mais</span>
      </div>
    </div>
  `;
}

function renderProcessTimelineScrubber(d, idxAtual, lsns, historico) {
  const passos = d.passos_timeline || (d.lsns || []).map((lsn, i) => {
    const ev = (d.eventos || []).find(e => e.lsn === lsn);
    let dh = ev?.conteudo?.dataHora || '';
    if (dh) {
      try {
        const dt = new Date(dh);
        if (!isNaN(dt.getTime())) dh = dt.toLocaleString('pt-BR');
      } catch (_) {}
    }
    return {
      lsn,
      dataHora: dh || `Evento ${i + 1}`,
      nome: ev?.conteudo?.nome || ev?.tipo || `Passo ${i + 1}`,
      tipo: ev?.tipo || 'andamento',
      seq: i
    };
  });

  const totalSteps = lsns.length;
  const currentStep = passos[idxAtual] || passos[passos.length - 1] || {};
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
        data-date="${esc(p.dataHora || '')}"
        data-title="${esc(p.nome || '')}"
        data-seq="${i + 1}"
        role="button"
        tabindex="0"
        aria-label="Ir para evento ${i + 1}: ${esc(p.nome)} (${esc(p.dataHora)})">
        <span class="dot-core"></span>
      </div>
    `;
  }).join('');

  return `
    <div class="proc-timeline-scrubber ${historico ? 'historical-active' : ''}" id="procTimelineScrubber">
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
            <span id="procAsOfLabel" class="status-text mono">
              ${historico ? `AS OF LSN ${procAsOf} · Passo ${idxAtual + 1} de ${totalSteps}` : `Estado Atual · LSN ${lsns[totalSteps - 1] ?? '—'}`}
            </span>
          </div>
          <button class="btn tiny ghost scrubber-reset-btn" id="procAsOfNow" ${historico ? '' : 'disabled'} title="Restaurar visualização para o momento atual">
            ↺ Voltar ao atual
          </button>
        </div>
      </div>

      <div class="scrubber-track-container" id="scrubberTrackContainer">
        <!-- Floating Tooltip (Grok / Google Fotos) -->
        <div class="scrubber-floating-tooltip" id="scrubberTooltip">
          <div class="st-date"><span id="stDateText">—</span></div>
          <div class="st-title" id="stTitleText">—</div>
          <div class="st-meta">LSN <span id="stLsnText">—</span> • Passo <span id="stStepText">—</span> de ${totalSteps}</div>
          <div class="st-arrow"></div>
        </div>

        <div class="scrubber-track-rail">
          <div class="scrubber-track-progress" id="scrubberTrackProgress" style="width: ${progressPct}%;"></div>
        </div>

        <div class="scrubber-dots-layer" id="scrubberDotsLayer">
          ${dotsHtml}
        </div>

        <div class="scrubber-thumb" id="scrubberThumb" style="left: ${progressPct}%;">
          <div class="scrubber-thumb-handle"></div>
          <div class="scrubber-thumb-ring"></div>
        </div>

        <input type="range" class="scrubber-range-overlay" id="procAsOfRange"
          min="0" max="${Math.max(0, totalSteps - 1)}" value="${idxAtual}"
          ${totalSteps < 2 ? 'disabled' : ''} aria-label="Reconstruir estado do processo ao longo do tempo" />
      </div>

      <div class="scrubber-footer">
        <button class="btn tiny ghost" id="procStepPrev" ${idxAtual <= 0 ? 'disabled' : ''} title="Retroceder um evento">◀ Anterior</button>
        <div class="scrubber-current-info" id="scrubberCurrentInfo">
          <span class="sci-date" id="sciDateText">${esc(currentStep.dataHora || '—')}</span>
          <span class="sci-sep">•</span>
          <span class="sci-name" id="sciNameText">${esc(currentStep.nome || 'Andamento')}</span>
        </div>
        <button class="btn tiny ghost" id="procStepNext" ${idxAtual >= totalSteps - 1 ? 'disabled' : ''} title="Avançar um evento">Próximo ▶</button>
      </div>
    </div>
  `;
}

// ----------------------------------------------------------------- detalhe
function renderDetalhe() {
  const d = procDetalhe;
  const p = d.processo;
  const c = p.capa;
  const integ = d.integridade;
  const eventos = d.eventos;
  const porTipo = tipo => eventos.filter(e => e.tipo === tipo);
  const contagem = {
    andamentos: porTipo('andamento').length,
    timeline: eventos.length,
    peticoes: porTipo('protocolo').length + porTipo('peticao').length,
    deslocamentos: porTipo('deslocamento').length,
    log: eventos.length
  };
  const lsns = d.lsns || [];
  const idxAtual = procAsOf === null ? lsns.length - 1 : Math.max(0, lsns.indexOf(procAsOf));
  const historico = procAsOf !== null;

  const attacks = d.attack_intercepts || p.attack_intercepts || [];
  const attacksHtml = attacks.length ? `
    <div class="proc-security-alert-box">
      <div class="proc-sec-alert-header">
        <span class="proc-sec-alert-icon">🛡️</span>
        <div>
          <strong>Tentativa de Ataque Adversarial Interceptada no HeraclitusDB (${attacks.length})</strong>
          <small>Autos protegidos contra mutação não autorizada • Decisão do Policy Gateway: DENY • upstream_delta = 0</small>
        </div>
      </div>
      <div class="proc-sec-attacks-list">
        ${attacks.map(atk => `
          <div class="proc-sec-attack-item">
            <div>
              <strong>${esc(atk.attack_id || 'Ataque')}: ${esc(atk.title || 'Tentativa de alteração não autorizada')}</strong>
              <div style="font-size: 11px; color: #64748b; margin-top: 2px;">
                Origem: <code>${esc(atk.source)}</code> • Alvo: <code>${esc(atk.target)}</code> • LSN: <code>${esc(atk.lsn)}</code>
              </div>
            </div>
            <div style="display: flex; gap: 6px;">
              <button class="btn tiny primary" onclick="event.stopPropagation(); goToAttack('${atk.attack_id}')">🎯 Ver Ataque</button>
              ${atk.attack_id === 'IA_ZAN_05' ? `<button class="btn tiny ghost" onclick="event.stopPropagation(); goToDefesaZanin('IA_ZAN_05')">🏛️ Ver Perícia</button>` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  ` : '';

  // Linhas acrescentadas desde o último desenho deste processo piscam uma vez.
  const jaVisto = historico ? Infinity : (procLsnRenderizado.get(c.id) ?? Infinity);
  if (!historico && eventos.length) procLsnRenderizado.set(c.id, eventos[eventos.length - 1].lsn);
  const novo = lsn => (lsn > jaVisto ? ' row-new' : '');

  $('#procDetail').innerHTML = `
    <div class="proc-capa">
      <div class="proc-capa-main">
        <div class="proc-num">
          <h3>${esc(c.numero)}</h3>
          <span class="proc-sit ${esc(p.situacao)}">${esc(PROC_SITUACAO[p.situacao] || p.situacao)}</span>
        </div>
        <div class="proc-nu mono" title="Número único CNJ (Resolução 65/2008)">${esc(c.numeroUnico)}</div>
        <dl class="proc-capa-grid">
          <div><dt>Classe</dt><dd>${esc(c.classe.nome)}</dd></div>
          <div><dt>Relator(a)</dt><dd>${esc(c.relator)}</dd></div>
          <div><dt>Órgão julgador</dt><dd>${esc(c.orgaoJulgador)}</dd></div>
          <div><dt>Origem</dt><dd>${esc(c.origem)}</dd></div>
          <div class="wide"><dt>Assunto</dt><dd>${esc(c.assunto)}</dd></div>
        </dl>
      </div>
      <div class="proc-capa-side">
        <div class="proc-chain ${integ.integra ? 'ok' : 'broken'}" title="Cada evento aponta (parents) para o evento anterior do mesmo processo">
          ${integ.integra ? `🔗 Cadeia íntegra — ${integ.elos} elos` : `⛓️‍💥 Cadeia quebrada: ${esc(integ.falha)}`}
        </div>
        <button class="btn small primary" id="procNextBtn" ${historico || p.pendentes <= 0 ? 'disabled' : ''}
          title="${p.pendentes > 0 ? 'Grava o próximo andamento do roteiro no HeraclitusDB' : 'Tramitação concluída'}">
          ▶ ${p.pendentes > 0 ? 'Próximo andamento' : 'Tramitação concluída'}
        </button>
        <small class="proc-side-note">${p.pendentes > 0 ? `${p.pendentes} passo(s) restantes no roteiro` : 'Sem passos restantes'}</small>
      </div>
    </div>

    ${attacksHtml}

    ${renderProcessTimelineScrubber(d, idxAtual, lsns, historico)}

    ${renderProcessHeatmap(eventos)}

    <div class="proc-subtabs" role="tablist">
      ${PROC_SUBTABS.map(t => `
        <button class="tab-btn ${t.id === procSubtab ? 'active' : ''}" role="tab" aria-selected="${t.id === procSubtab}" data-subtab="${t.id}">
          ${t.label} <span class="proc-count">${contagem[t.id]}</span>
        </button>`).join('')}
    </div>
    <div class="table-wrap proc-table-wrap">${renderSubtab(eventos, integ, novo)}</div>
    ${procSubtab === 'log' ? `<p class="proc-foot-note">
      <strong>Data do andamento</strong> é a data processual do roteiro sintético.
      <strong>Registrado</strong> é o relógio híbrido (HLC) do HeraclitusDB no momento do <code>Append</code>.
      A chave de idempotência impede que o mesmo andamento seja gravado duas vezes com conteúdo diferente.</p>` : ''}
  `;
}

function renderSubtab(eventos, integ, novo) {
  if (procSubtab === 'andamentos') {
    const linhas = eventos.filter(e => e.tipo === 'andamento').reverse();
    return tabela(['Data', 'Andamento', 'Complemento', 'Órgão julgador', 'TPU', 'LSN'], linhas, e => {
      const m = e.conteudo.movimento;
      return `<tr class="${novo(e.lsn)}">
        <td class="nowrap">${procData(e.conteudo.dataHora)}</td>
        <td><strong>${esc(m.nome)}</strong></td>
        <td>${esc(m.complemento || '—')}</td>
        <td>${esc(m.orgaoJulgador?.nome || '—')}</td>
        <td class="mono" title="Código da Tabela Processual Unificada de movimentos (CNJ)">${m.codigo}</td>
        <td class="mono proc-lsn">${e.lsn}</td>
      </tr>`;
    }, 'Nenhum andamento neste ponto do histórico.');
  }
  if (procSubtab === 'timeline') {
    const linhas = [...eventos].reverse();
    if (!linhas.length) return '<div class="proc-empty">Nenhum evento neste ponto do histórico.</div>';
    return `<div class="proc-timeline">${linhas.map((e, idx) => {
      const quebrado = !integ.integra && e.lsn === integ.lsn;
      let titulo = '';
      let badgeTipo = '';
      let badgeClasse = 'info';
      let detalheHtml = '';
      let dataProc = '';

      if (e.tipo === 'andamento') {
        const m = e.conteudo?.movimento || {};
        badgeTipo = `⚖️ Andamento · TPU ${m.codigo || '—'}`;
        badgeClasse = 'tpu';
        titulo = esc(m.nome || 'Andamento');
        dataProc = e.conteudo?.dataHora;
        detalheHtml = `
          ${m.complemento ? `<div class="proc-tl-complemento"><strong>Complemento:</strong> ${esc(m.complemento)}</div>` : ''}
          <div class="proc-tl-orgao"><strong>Órgão julgador:</strong> ${esc(m.orgaoJulgador?.nome || '—')}</div>
          ${e.origem === 'avulso' ? `<div class="proc-tl-avulso">🛡️ <strong>Andamento Avulso Aprovado</strong> (Aprovação: <span class="mono">${esc(e.approval_id || 'HITL')}</span>)</div>` : ''}
        `;
      } else if (e.tipo === 'protocolo') {
        const x = e.conteudo?.protocolo || {};
        badgeTipo = '📋 Protocolo Inicial';
        badgeClasse = 'protocolo';
        titulo = `Protocolo ${esc(x.numero || '—')}`;
        dataProc = x.peticionadoEm;
        detalheHtml = `
          <div class="proc-tl-desc">Peticionado por: <strong>${esc(x.meio || '—')}</strong> · Recebido por: ${esc(x.recebidoPor || '—')}</div>
          <div class="proc-tl-meta">Recebimento oficial: ${procDataHora(x.recebidoEm)}</div>
        `;
      } else if (e.tipo === 'peticao') {
        const x = e.conteudo?.peticao || {};
        badgeTipo = '📑 Petição';
        badgeClasse = 'peticao';
        titulo = `${esc(x.tipo || 'Petição')} — ${esc(x.numero || '—')}`;
        dataProc = x.peticionadoEm;
        detalheHtml = `
          <div class="proc-tl-desc">Peticionante: <strong>${esc(x.peticionante || '—')}</strong></div>
          <div class="proc-tl-meta">Recebido em: ${procDataHora(x.recebidoEm)}</div>
        `;
      } else if (e.tipo === 'deslocamento') {
        const x = e.conteudo?.deslocamento || {};
        badgeTipo = '📦 Deslocamento';
        badgeClasse = 'deslocamento';
        titulo = `Remessa dos autos (Guia ${esc(x.guia || '—')})`;
        dataProc = x.enviadoEm;
        detalheHtml = `
          <div class="proc-tl-desc">${esc(x.enviadoPor || '—')} ➔ <strong>${esc(x.recebidoPor || '—')}</strong></div>
          <div class="proc-tl-meta">Recebido em: ${procDataHora(x.recebidoEm)}</div>
        `;
      }

      return `
        <div class="proc-tl-item ${novo(e.lsn)}${quebrado ? ' broken' : ''}${idx === 0 ? ' latest' : ''}">
          <div class="proc-tl-marker"><div class="proc-tl-dot"></div></div>
          <div class="proc-tl-card">
            <div class="proc-tl-top">
              <span class="proc-tl-badge ${badgeClasse}">${badgeTipo}</span>
              <span class="proc-tl-datetime" title="Data e hora processual do andamento">📅 <strong>${procDataHora(dataProc)}</strong></span>
              <span class="proc-tl-hlc mono" title="Timestamp de registro imutável no HeraclitusDB">⏱️ Registrado: ${procHora(e.ts_ms)}</span>
              <span class="proc-lsn mono" title="Número Sequencial Lógico no HeraclitusDB">LSN ${e.lsn}</span>
            </div>
            <div class="proc-tl-title"><h4>${titulo}</h4></div>
            <div class="proc-tl-body">${detalheHtml}</div>
            <div class="proc-tl-footer">
              <span class="mono">Seq #${e.seq}</span>
              <span class="mono" title="ID único imutável do evento">ID: ${esc(e.id)}</span>
              <span class="mono" title="Elo pai anterior na cadeia imutável">Elo: ${esc((e.parents || [])[0] || 'raiz')}</span>
              <span class="mono" title="Chave de idempotência">Chave: ${esc(e.idempotency_key || '—')}</span>
            </div>
          </div>
        </div>
      `;
    }).join('')}</div>`;
  }
  if (procSubtab === 'peticoes') {
    const linhas = eventos.filter(e => e.tipo === 'protocolo' || e.tipo === 'peticao').reverse();
    return tabela(['Protocolo', 'Tipo', 'Peticionante / meio', 'Peticionado em', 'Recebido em', 'Recebido por', 'LSN'], linhas, e => {
      const inicial = e.tipo === 'protocolo';
      const x = inicial ? e.conteudo.protocolo : e.conteudo.peticao;
      return `<tr class="${novo(e.lsn)}">
        <td class="mono nowrap">${esc(x.numero)}</td>
        <td><strong>${inicial ? 'Protocolo inicial' : esc(x.tipo)}</strong></td>
        <td>${esc(inicial ? x.meio : x.peticionante)}</td>
        <td class="nowrap">${procData(x.peticionadoEm)}</td>
        <td class="nowrap">${procData(x.recebidoEm)}</td>
        <td>${esc(inicial ? x.recebidoPor : '—')}</td>
        <td class="mono proc-lsn">${e.lsn}</td>
      </tr>`;
    }, 'Nenhum protocolo neste ponto do histórico.');
  }
  if (procSubtab === 'deslocamentos') {
    const linhas = eventos.filter(e => e.tipo === 'deslocamento').reverse();
    return tabela(['Enviado por', 'Recebido por', 'Guia', 'Enviado em', 'Recebido em', 'LSN'], linhas, e => {
      const x = e.conteudo.deslocamento;
      return `<tr class="${novo(e.lsn)}">
        <td>${esc(x.enviadoPor)}</td>
        <td>${esc(x.recebidoPor)}</td>
        <td class="mono nowrap">${esc(x.guia)}</td>
        <td class="nowrap">${procData(x.enviadoEm)}</td>
        <td class="nowrap">${procData(x.recebidoEm)}</td>
        <td class="mono proc-lsn">${e.lsn}</td>
      </tr>`;
    }, 'Nenhum deslocamento neste ponto do histórico.');
  }
  const linhas = [...eventos].reverse();
  return tabela(['Seq', 'LSN', 'Registrado', 'Kind', 'Evento (ULID)', 'Elo anterior', 'Chave de idempotência'], linhas, e => {
    const quebrado = !integ.integra && e.lsn === integ.lsn;
    return `<tr class="${novo(e.lsn)}${quebrado ? ' row-broken' : ''}">
      <td class="mono">${e.seq}</td>
      <td class="mono proc-lsn">${e.lsn}</td>
      <td class="nowrap">${procHora(e.ts_ms)}</td>
      <td><code>${esc(e.kind)}</code></td>
      <td class="mono" title="${esc(e.id)}">${esc(e.id)}</td>
      <td class="mono" title="${esc((e.parents || []).join(', '))}">${e.parents && e.parents.length ? esc(e.parents[0]) : '— (raiz)'}</td>
      <td class="mono proc-key">${esc(e.idempotency_key || '—')}</td>
    </tr>`;
  }, 'Nenhum evento neste ponto do histórico.');
}

function tabela(cabecalhos, linhas, linhaHtml, vazio) {
  const corpo = linhas.length
    ? linhas.map(linhaHtml).join('')
    : `<tr><td colspan="${cabecalhos.length}" class="empty">${vazio}</td></tr>`;
  return `<table class="simple-table proc-table">
    <thead><tr>${cabecalhos.map(h => `<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${corpo}</tbody>
  </table>`;
}

// ----------------------------------------------------------------- escrita
// POST que devolve a mensagem do servidor (o api() de app.js só diz "HTTP n").
async function procPost(path, body) {
  const r = await fetch(path.replace(/^\//, ''), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-STF-POC': '1' },
    body: JSON.stringify(body || {})
  });
  const dados = await r.json().catch(() => ({}));
  if (!r.ok) {
    const erro = new Error(dados.error || 'HTTP ' + r.status);
    erro.status = r.status;
    throw erro;
  }
  return dados;
}

async function protocolarProcessos() {
  const btn = $('#procProtocolarBtn');
  btn.disabled = true;
  try {
    const res = await procPost('/api/processos/protocolar');
    toast(`📥 ${res.gravados} evento(s) gravados no HeraclitusDB`);
    procPrimeiraCarga = true; // o que o próprio utilizador gravou não é "novo"
    await carregarProcessos();
  } catch (e) {
    toast('Falha ao protocolar: ' + e.message);
  } finally {
    btn.disabled = false;
  }
}

async function proximoAndamento() {
  const btn = $('#procNextBtn');
  if (btn) btn.disabled = true;
  try {
    const res = await procPost('/api/processos/tramitar', { id: procSelecionado });
    procUltimoLsnVisto.set(res.processo_id, res.lsn);
    const m = res.evento.movimento;
    toast(`✍️ ${res.evento.processo}: ${m ? m.nome : res.evento.tipo} — gravado no LSN ${res.lsn}`);
    // Detalhe primeiro: a lista, ao ver o mesmo LSN, já não o redesenha (e a
    // linha nova continua a piscar).
    await carregarDetalhe();
    await carregarProcessos();
  } catch (e) {
    toast('Não foi possível tramitar: ' + e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function alternarTramitacaoAutomatica(ligar) {
  clearInterval(procAutoTimer);
  procAutoTimer = null;
  if (!ligar) return;
  const passo = async () => {
    try {
      const body = {};
      if (procSelecionado && procDetalhe && procDetalhe.processo && procDetalhe.processo.pendentes > 0) {
        body.id = procSelecionado;
      }
      let res;
      try {
        res = await procPost('/api/processos/tramitar', body);
      } catch (err) {
        if (body.id && err.status === 409) {
          res = await procPost('/api/processos/tramitar', {});
        } else {
          throw err;
        }
      }
      if (res && res.processo_id) {
        procUltimoLsnVisto.set(res.processo_id, res.lsn);
      }
      await carregarProcessos();
      await carregarDetalhe();
    } catch (e) {
      console.warn('Tramitação automática:', e.message);
      if (e.status !== 409) {
        toast('Tramitação automática aguardando: ' + e.message);
      }
    }
  };
  passo();
  procAutoTimer = setInterval(passo, 2800);
}

// ------------------------------------------------------------------ eventos
function setupProcessos() {
  setupMainTabs();
  const protoBtn = $('#procProtocolarBtn');
  if (protoBtn) protoBtn.addEventListener('click', protocolarProcessos);
  const autoTgl = $('#procAutoToggle');
  if (autoTgl) autoTgl.addEventListener('change', e => alternarTramitacaoAutomatica(e.target.checked));
  const busca = $('#procBusca');
  if (busca) busca.addEventListener('input', renderListaProcessos);
  const listEl = $('#procList');
  if (listEl) {
    listEl.addEventListener('click', e => {
      const card = e.target.closest('.proc-card');
      if (card) selecionarProcesso(card.dataset.id);
    });
  }
  const detalhe = $('#procDetail');
  if (detalhe) {
    detalhe.addEventListener('click', e => {
      const sub = e.target.closest('[data-subtab]');
      if (sub) {
        procSubtab = sub.dataset.subtab;
        renderDetalhe();
        return;
      }
      if (e.target.closest('#procNextBtn')) proximoAndamento();
      if (e.target.closest('#procAsOfNow')) {
        procAsOf = null;
        carregarDetalhe();
        return;
      }
      if (e.target.closest('#procStepPrev')) {
        if (!procDetalhe) return;
        const lsns = procDetalhe.lsns || [];
        const curIdx = procAsOf === null ? lsns.length - 1 : Math.max(0, lsns.indexOf(procAsOf));
        if (curIdx > 0) {
          const newIdx = curIdx - 1;
          procAsOf = newIdx === lsns.length - 1 ? null : lsns[newIdx];
          carregarDetalhe();
        }
        return;
      }
      if (e.target.closest('#procStepNext')) {
        if (!procDetalhe) return;
        const lsns = procDetalhe.lsns || [];
        const curIdx = procAsOf === null ? lsns.length - 1 : Math.max(0, lsns.indexOf(procAsOf));
        if (curIdx < lsns.length - 1) {
          const newIdx = curIdx + 1;
          procAsOf = newIdx === lsns.length - 1 ? null : lsns[newIdx];
          carregarDetalhe();
        }
        return;
      }
      const dot = e.target.closest('.scrubber-dot');
      if (dot && procDetalhe) {
        const i = Number(dot.dataset.index);
        const lsns = procDetalhe.lsns || [];
        procAsOf = i === lsns.length - 1 ? null : lsns[i];
        carregarDetalhe();
        return;
      }
    });

    detalhe.addEventListener('input', e => {
    if (e.target.id !== 'procAsOfRange' || !procDetalhe) return;
    const lsns = procDetalhe.lsns || [];
    const passos = procDetalhe.passos_timeline || [];
    const i = Number(e.target.value);
    const totalSteps = lsns.length;
    const pct = totalSteps > 1 ? (i / (totalSteps - 1)) * 100 : 100;
    const step = passos[i] || {};

    const progress = $('#scrubberTrackProgress');
    if (progress) progress.style.width = `${pct}%`;
    const thumb = $('#scrubberThumb');
    if (thumb) thumb.style.left = `${pct}%`;

    const dots = detalhe.querySelectorAll('.scrubber-dot');
    dots.forEach((d, idx) => {
      d.classList.remove('passed', 'current', 'future');
      if (idx < i) d.classList.add('passed');
      else if (idx === i) d.classList.add('current');
      else d.classList.add('future');
    });

    const lbl = $('#procAsOfLabel');
    if (lbl) {
      lbl.textContent = i === totalSteps - 1
        ? `Estado Atual · LSN ${lsns[i] ?? '—'}`
        : `AS OF LSN ${lsns[i]} · Passo ${i + 1} de ${totalSteps}`;
    }

    const dtText = $('#sciDateText');
    if (dtText && step.dataHora) dtText.textContent = step.dataHora;
    const nmText = $('#sciNameText');
    if (nmText && step.nome) nmText.textContent = step.nome;

    const tt = $('#scrubberTooltip');
    if (tt) {
      const dtEl = $('#stDateText');
      if (dtEl) dtEl.textContent = step.dataHora ? `📅 ${step.dataHora}` : `Evento ${i + 1}`;
      const tiEl = $('#stTitleText');
      if (tiEl) tiEl.textContent = step.nome || 'Andamento';
      const lsnEl = $('#stLsnText');
      if (lsnEl) lsnEl.textContent = lsns[i] ?? '—';
      const stEl = $('#stStepText');
      if (stEl) stEl.textContent = i + 1;
      tt.style.left = `${pct}%`;
      tt.classList.add('show');
    }
  });

  detalhe.addEventListener('change', e => {
    if (e.target.id !== 'procAsOfRange' || !procDetalhe) return;
    const lsns = procDetalhe.lsns || [];
    const i = Number(e.target.value);
    procAsOf = i === lsns.length - 1 ? null : lsns[i];
    const tt = $('#scrubberTooltip');
    if (tt) tt.classList.remove('show');
    carregarDetalhe();
  });

  detalhe.addEventListener('mousemove', e => {
    const track = e.target.closest('#scrubberTrackContainer');
    if (!track || !procDetalhe) return;
    const lsns = procDetalhe.lsns || [];
    const passos = procDetalhe.passos_timeline || [];
    if (!lsns.length) return;

    const rect = track.getBoundingClientRect();
    const mouseX = Math.max(0, Math.min(e.clientX - rect.left, rect.width));
    const pct = rect.width > 0 ? (mouseX / rect.width) : 0;
    const closestIdx = Math.max(0, Math.min(Math.round(pct * (lsns.length - 1)), lsns.length - 1));
    const step = passos[closestIdx] || {};

    const tt = $('#scrubberTooltip');
    if (tt) {
      const dtEl = $('#stDateText');
      if (dtEl) dtEl.textContent = step.dataHora ? `📅 ${step.dataHora}` : `Evento ${closestIdx + 1}`;
      const tiEl = $('#stTitleText');
      if (tiEl) tiEl.textContent = step.nome || 'Andamento';
      const lsnEl = $('#stLsnText');
      if (lsnEl) lsnEl.textContent = lsns[closestIdx] ?? '—';
      const stEl = $('#stStepText');
      if (stEl) stEl.textContent = closestIdx + 1;
      const dotPct = lsns.length > 1 ? (closestIdx / (lsns.length - 1)) * 100 : 50;
      tt.style.left = `${dotPct}%`;
      tt.classList.add('show');
    }
  });

  detalhe.addEventListener('mouseleave', e => {
    const tt = $('#scrubberTooltip');
    if (tt) tt.classList.remove('show');
  }, true);
  const viewProc = $('#viewProcessos');
  const tt = $('#chartTooltip');
  if (viewProc && tt) {
    viewProc.addEventListener('mousemove', evt => {
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
    viewProc.addEventListener('mouseleave', () => tt.classList.remove('show'));
  }
  carregarProcessos();
  agendarPoll();
}

setupProcessos();
