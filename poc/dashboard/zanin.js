// ========================================================
// DEFESA ZANIN — FRAUDE PROCESSUAL VIA IA & PROMPT INJECTION
// Caso Real STF (25/09/2026) · Relatoria Min. Cristiano Zanin
// ========================================================
(() => {
  'use strict';

  const root = document.getElementById('viewZanin');
  if (!root) return;

  const $ = sel => root.querySelector(sel);
  const esc = str => String(str ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  let caseData = null;
  let inspectionData = null;
  let certidaoData = null;
  let forensicMode = false;
  let loading = false;

  function renderSkeleton() {
    root.innerHTML = `
      <div class="zanin-container">
        <!-- Hero Banner Caso Real -->
        <header class="zanin-hero">
          <div class="zanin-hero-kicker">
            <span>⚖️ Supremo Tribunal Federal</span>
            <span>•</span>
            <span>Primeira Turma</span>
            <span>•</span>
            <span>Caso de Repercussão Nacional</span>
          </div>
          <h1 class="zanin-hero-title">Defesa Zanin — Fraude Processual via IA e Prompt Injection</h1>
          <p class="zanin-hero-desc">
            Em 25 de setembro de 2026, a Secretaria-Geral de Tecnologia do STF detectou a primeira tentativa inédita de fraude processual por <strong>Prompt Injection Esteganográfico</strong> em recurso relatado pelo <strong>Ministro Cristiano Zanin</strong>. A peça continha comandos ocultos em letras brancas e fonte microscópica para forçar a IA de gabinete a emitir minuta favorável. Esta aba demonstra o ataque, a blindagem pelo Gateway e a prova imutável gerada no HeraclitusDB Ledger para remessa ao MPF e à OAB.
          </p>

          <div class="zanin-meta-grid" id="zaninMetaGrid">
            <div class="zanin-meta-item">
              <span class="zanin-meta-label">Processo</span>
              <span class="zanin-meta-val" id="metaProcesso">ARE-1488204-MG</span>
            </div>
            <div class="zanin-meta-item">
              <span class="zanin-meta-label">Relator</span>
              <span class="zanin-meta-val" id="metaRelator">Ministro Cristiano Zanin</span>
            </div>
            <div class="zanin-meta-item">
              <span class="zanin-meta-label">Vetor de Ataque</span>
              <span class="zanin-meta-val" id="metaVetor">Esteganografia & Injeção de Prompt</span>
            </div>
            <div class="zanin-meta-item">
              <span class="zanin-meta-label">Gabinete / Alvo</span>
              <span class="zanin-meta-val" id="metaAlvo">IA de Triagem e Sumarização (Victor)</span>
            </div>
          </div>
        </header>

        <!-- Área Principal de Comparação e Diagnóstico -->
        <div class="zanin-workspace-grid">
          <!-- Coluna Esquerda: Peça Processual Periciada -->
          <div class="zanin-card">
            <div class="zanin-card-head">
              <h3 class="zanin-card-title">
                <span>📄 Petição Periciada</span>
                <span class="tag-status" id="badgeModo">Visão Convencional</span>
              </h3>
              <div class="zanin-view-toggle">
                <button type="button" class="zanin-toggle-btn active" id="btnModoNormal">Normal (Humana)</button>
                <button type="button" class="zanin-toggle-btn danger" id="btnModoForense">🔬 Revelar Oculto</button>
              </div>
            </div>

            <!-- Viewport do Documento -->
            <div class="zanin-doc-viewport" id="docViewport">
              <div class="doc-visible-text" id="docVisibleText">Carregando petição...</div>
              <div class="doc-hidden-payload" id="docHiddenPayload">
                <div class="forensic-callout">⚠️ CAMADA ESTEGANOGRÁFICA OCULTA DETECTADA (LETRAS BRANCAS / 0.5pt):</div>
                <span id="docInjectedText"></span>
              </div>
            </div>

            <div class="zanin-card-actions">
              <button type="button" class="btn small ghost" id="btnEditarPayload">✏️ Personalizar Prompt Injetado</button>
              <button type="button" class="btn small primary" id="btnReplicarBloqueio">🛡️ Replicar Bloqueio no HeraclitusDB</button>
            </div>
          </div>

          <!-- Coluna Direita: Análise do Gateway & Oráculo Criptográfico -->
          <div class="zanin-card">
            <div class="zanin-card-head">
              <h3 class="zanin-card-title">
                <span>🛡️ Diagnóstico do Gateway Anti-Fraude</span>
              </h3>
              <span class="tag-status normal" id="zaninGatewayBadge">ANALISANDO</span>
            </div>

            <div class="zanin-diag-body">
              <!-- Score de Ameaça -->
              <div class="zanin-score-box threat-high" id="scoreBox">
                <div>
                  <div class="zanin-score-label">Grau de Risco de Fraude Processual</div>
                  <small style="color: #64748b;">Detecção esteganográfica + comandos de coerção</small>
                </div>
                <div class="zanin-score-value" id="threatScoreVal">95 / 100</div>
              </div>

              <!-- Triggers Detectados -->
              <div>
                <strong style="font-size: 13px; color: #0f172a; display: block; margin-bottom: 8px;">Evidências Técnicas Levantadas:</strong>
                <div class="zanin-trigger-list" id="triggerList">
                  <!-- Inserido dinamicamente -->
                </div>
              </div>

              <!-- Prova Criptográfica Hashes -->
              <div>
                <strong style="font-size: 13px; color: #0f172a; display: block; margin-bottom: 8px;">Cadeia de Custódia e Hashes SHA-256:</strong>
                <div class="zanin-crypto-proof" id="cryptoProof">
                  <div class="zanin-crypto-row">
                    <span class="zanin-crypto-label">SHA-256 (Documento Bruto):</span>
                    <span id="hashDocBruto">Calculando...</span>
                  </div>
                  <div class="zanin-crypto-row">
                    <span class="zanin-crypto-label">SHA-256 (Camada Invisível):</span>
                    <span id="hashDocOculto">Calculando...</span>
                  </div>
                  <div class="zanin-crypto-row">
                    <span class="zanin-crypto-label">SHA-256 (Petição Sanitizada):</span>
                    <span id="hashDocSanitizado">Calculando...</span>
                  </div>
                  <div class="zanin-crypto-row">
                    <span class="zanin-crypto-label">Efeito Upstream no Banco STF:</span>
                    <span style="color: #4ade80;">0 (Bloqueio estrito — sem contaminação)</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Seção: Certidão Pericial Criptográfica (Para MPF e OAB) -->
        <div class="zanin-certidao-card" id="certidaoCard">
          <div class="zanin-certidao-header">
            <div class="zanin-certidao-brasao">🏛️</div>
            <div class="zanin-certidao-tribunal">SUPREMO TRIBUNAL FEDERAL</div>
            <div class="zanin-certidao-sub">Secretaria-Geral de Tecnologia e Inovação • Gabinete do Ministro Cristiano Zanin</div>
            <strong style="display:block; margin-top: 10px; font-size: 15px; color: #b91c1c;">
              CERTIDÃO PERICIAL DE TENTATIVA DE FRAUDE PROCESSUAL VIA INTELIGÊNCIA ARTIFICIAL
            </strong>
          </div>

          <div class="zanin-certidao-body">
            <p>
              Certifico, para os devidos fins de instrução processual e remessa aos órgãos de persecução e disciplinares, que o sistema de segurança cibernética do STF identificou e neutralizou tentativa deliberada de direcionamento indevido de sistemas automatizados de inteligência artificial da corte na peça processual cadastrada nos autos do <strong>ARE-1488204-MG</strong>.
            </p>
            <p id="certidaoConclusao">
              A manobra consistiu na inserção de camada esteganográfica com comandos imperceptíveis a olho nu para usurpar a triagem e forçar juízo de admissibilidade e provimento indevido. A fraude foi ineficaz perante o magistrado relator e selada de forma imutável no HeraclitusDB Ledger.
            </p>

            <div class="zanin-certidao-destinos">
              <strong style="color: #0f172a; display: block; margin-bottom: 6px;">Destinatários Oficiais Determinados pelo Ministro Relator:</strong>
              <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #334155;">
                <li><strong>Ministério Público Federal (MPF):</strong> Apuração de crime de fraude processual e atentado contra a administração da Justiça.</li>
                <li><strong>Ordem dos Advogados do Brasil (OAB):</strong> Apuração ético-disciplinar por violação dos deveres de probidade e lealdade processual (arts. 77 e 81 do CPC).</li>
              </ul>
            </div>

            <div class="zanin-certidao-seal">
              <div>
                <span>ID da Certidão: <strong id="certidaoId">—</strong></span><br/>
                <span>Registro Ledger HRKL: <strong id="certidaoLsn" style="color: #1d4ed8;">LSN —</strong></span>
              </div>
              <div style="text-align: right;">
                <span>Hash Pericial: <code id="certidaoHash" style="font-size: 11px;">—</code></span><br/>
                <span style="color: #16a34a; font-weight: 600;">✓ Integridade Criptográfica Selada no HeraclitusDB</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Conectar eventos
    $('#btnModoNormal').onclick = () => setForensicMode(false);
    $('#btnModoForense').onclick = () => setForensicMode(true);
    $('#btnReplicarBloqueio').onclick = () => replicarBloqueio();
    $('#btnEditarPayload').onclick = () => promptCustomPayload();
  }

  function setForensicMode(active) {
    forensicMode = active;
    const vp = $('#docViewport');
    const bNormal = $('#btnModoNormal');
    const bForense = $('#btnModoForense');
    const badge = $('#badgeModo');

    if (active) {
      vp.classList.add('forensic-mode');
      bNormal.classList.remove('active');
      bForense.classList.add('active');
      badge.textContent = 'Modo Forense (Oculto Revelado)';
      badge.className = 'tag-status';
      badge.style.background = '#dc2626';
      badge.style.color = '#ffffff';
    } else {
      vp.classList.remove('forensic-mode');
      bNormal.classList.add('active');
      bForense.classList.remove('active');
      badge.textContent = 'Visão Convencional (Humana)';
      badge.className = 'tag-status normal';
      badge.style.background = '';
      badge.style.color = '';
    }
  }

  async function loadCaseData() {
    try {
      const res = await api('/api/zanin/case');
      caseData = res;
      if (res.metadata) {
        $('#metaProcesso').textContent = res.metadata.case_id;
        $('#metaRelator').textContent = res.metadata.relator;
        $('#metaVetor').textContent = res.metadata.tipo_fraude;
        $('#metaAlvo').textContent = res.metadata.alvo;
      }
      $('#docVisibleText').textContent = res.visible_text;
      $('#docInjectedText').textContent = res.injected_prompt;

      // Realiza a inspeção automática inicial
      await inspecionarPeca(res.visible_text, res.injected_prompt);
    } catch (e) {
      console.error('Erro ao carregar dados do Caso Zanin:', e);
    }
  }

  async function inspecionarPeca(vis, hid) {
    try {
      const res = await api('/api/zanin/inspect', {
        method: 'POST',
        body: JSON.stringify({
          visible_text: vis,
          hidden_payload: hid,
          font_color: '#ffffff',
          font_size_pt: 0.5
        })
      });
      inspectionData = res;
      renderDiagnostico(res);
    } catch (e) {
      console.error('Erro ao inspecionar:', e);
    }
  }

  function renderDiagnostico(diag) {
    const sBox = $('#scoreBox');
    const sVal = $('#threatScoreVal');
    const gBadge = $('#zaninGatewayBadge');
    const tList = $('#triggerList');

    sVal.textContent = `${diag.threat_score} / 100`;
    if (diag.blocked) {
      sBox.className = 'zanin-score-box threat-high';
      gBadge.textContent = '🛡️ BLOQUEADO — FRAUDE DETECTADA';
      gBadge.className = 'tag-status';
      gBadge.style.background = '#dc2626';
      gBadge.style.color = '#ffffff';
    } else {
      sBox.className = 'zanin-score-box threat-none';
      gBadge.textContent = '✓ DOCUMENTO AUTÊNTICO';
      gBadge.className = 'tag-status normal';
      gBadge.style.background = '#16a34a';
      gBadge.style.color = '#ffffff';
    }

    tList.innerHTML = (diag.detected_triggers || []).map(tr => `
      <div class="zanin-trigger-item sev-critical">
        <span class="zanin-trigger-type">🚨 ${esc(tr.type)}</span>
        <span class="zanin-trigger-detail">${esc(tr.detail)}</span>
      </div>
    `).join('') || '<div class="zanin-trigger-item"><span>Nenhum gatilho de injeção detectado.</span></div>';

    if (diag.evidence) {
      $('#hashDocBruto').textContent = diag.evidence.sha256_full_document || '—';
      $('#hashDocOculto').textContent = diag.evidence.sha256_hidden || '—';
      $('#hashDocSanitizado').textContent = diag.evidence.sha256_sanitized || '—';
    }

    // Carregar certidão correspondente
    loadCertidao(10550);
  }

  async function loadCertidao(lsn) {
    try {
      const cert = await api(`/api/zanin/certidao?lsn=${lsn}`);
      certidaoData = cert;
      $('#certidaoId').textContent = cert.certidao_id;
      $('#certidaoLsn').textContent = `LSN ${cert.lsn_heraclitusdb}`;
      $('#certidaoHash').textContent = cert.hash_certidao_pericial ? cert.hash_certidao_pericial.slice(0, 24) + '…' : '—';
      if (cert.conclusao_tecnica) {
        $('#certidaoConclusao').textContent = cert.conclusao_tecnica;
      }
    } catch (e) {
      console.error('Erro ao carregar certidão:', e);
    }
  }

  async function replicarBloqueio() {
    const btn = $('#btnReplicarBloqueio');
    btn.disabled = true;
    btn.textContent = 'Gravando no Ledger HRKL...';
    try {
      const vis = caseData ? caseData.visible_text : '';
      const hid = caseData ? caseData.injected_prompt : '';
      const res = await api('/api/zanin/replicate-attack', {
        method: 'POST',
        body: JSON.stringify({
          visible_text: vis,
          hidden_payload: hid
        })
      });
      if (res.status === 'PASS') {
        renderDiagnostico(res.inspection);
        if (res.certidao) {
          $('#certidaoId').textContent = res.certidao.certidao_id;
          $('#certidaoLsn').textContent = `LSN ${res.certidao.lsn_heraclitusdb}`;
          $('#certidaoHash').textContent = res.certidao.hash_certidao_pericial ? res.certidao.hash_certidao_pericial.slice(0, 24) + '…' : '—';
        }
        if (typeof toast === 'function') {
          toast(`🛡️ Fraude bloqueada e selada com sucesso no Ledger HRKL (LSN ${res.lsn})!`);
        }
        // Ativa automaticamente o modo forense para o usuário ver
        setForensicMode(true);
      }
    } catch (e) {
      console.error('Erro na replicação:', e);
    } finally {
      btn.disabled = false;
      btn.textContent = '🛡️ Replicar Bloqueio no HeraclitusDB';
    }
  }

  function promptCustomPayload() {
    const atual = caseData ? caseData.injected_prompt : '';
    const novo = prompt('Insira o comando malicioso/prompt injection que deseja testar na petição oculta:', atual);
    if (novo !== null) {
      if (caseData) caseData.injected_prompt = novo;
      $('#docInjectedText').textContent = novo;
      inspecionarPeca(caseData ? caseData.visible_text : '', novo);
    }
  }

  window.refreshDefesaZanin = function() {
    if (!root.innerHTML || root.innerHTML.trim() === '') {
      renderSkeleton();
      loadCaseData();
    } else {
      loadCaseData();
    }
  };

  // Render inicial caso seja aberto diretamente
  renderSkeleton();
  loadCaseData();
})();
