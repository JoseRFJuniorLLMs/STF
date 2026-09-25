// ========================================================
// DEFESA ZANIN — LABORATÓRIO FORENSE DE PROMPT INJECTION
// POC INDEPENDENTE E SINTÉTICA (HeraclitusDB / STF)
// ========================================================
(() => {
  'use strict';

  const root = document.getElementById('viewZanin');
  if (!root) return;

  const $ = sel => root.querySelector(sel);
  const esc = str => String(str ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  let currentScenario = 'scenario_zanin_stego';
  let currentMode = 'human'; // 'human', 'structural', 'forensic', 'sanitized'
  let pipelineState = null;
  let bundleState = null;
  let verificationState = null;
  let factsState = null;

  function renderSkeleton() {
    root.innerHTML = `
      <div class="zanin-container">

        <!-- 1. HEADER TÉCNICO -->
        <header class="zanin-hero">
          <div class="zanin-hero-kicker">
            <span>Laboratório de Segurança de IA em Documento Processual</span>
            <span>•</span>
            <span>Ambiente Forense Standalone</span>
          </div>
          <h1 class="zanin-hero-title">Defesa Zanin — Análise Forense & Duas Barreiras de Defesa</h1>
          <p class="zanin-hero-desc">
            Demonstração técnica de como documentos processuais adversariais contendo <em>Indirect Prompt Injection</em>
            são periciados em múltiplas camadas. A demonstração comprova que, <strong>mesmo que a detecção de prompt falhe (MISS)</strong>,
            o texto do documento não adquire autoridade operacional sobre os bancos protegidos, mantendo <strong>upstream_delta = 0</strong> via Policy Gateway.
          </p>
        </header>

        <!-- 3. SEPARAÇÃO FORMAL: FATO REAL VS CENÁRIO SINTÉTICO -->
        <section class="zanin-facts-grid">
          <div class="zanin-facts-card public">
            <h3 class="zanin-facts-title blue">
              <span>📰 Incidente Publicamente Relatado</span>
              <small style="font-size: 10px; font-weight: normal; color: #64748b;">(O Globo · 25/09/2026)</small>
            </h3>
            <ul class="zanin-facts-list" id="factsListPublic">
              <li>Tentativa de prompt injection em peça processual protocolada no STF.</li>
              <li>Comandos ocultos inseridos em duas páginas do documento.</li>
              <li>Uso de letras brancas e tamanho reduzido, imperceptíveis na leitura convencional.</li>
              <li>Fragmentação atípica de palavras para dificultar filtros de segurança.</li>
              <li>Detecção pelo Núcleo de Inteligência Artificial da SGTI/STF.</li>
              <li>Sem efeito prático: gabinete de relatoria não utiliza IA para fundamentar decisões judiciais.</li>
            </ul>
          </div>

          <div class="zanin-facts-card synthetic">
            <h3 class="zanin-facts-title purple">
              <span>🔬 Cenário Sintético da POC</span>
              <small style="font-size: 10px; font-weight: normal; color: #64748b;">(Laboratório Controlado)</small>
            </h3>
            <ul class="zanin-facts-list">
              <li><strong>Dados Sintéticos:</strong> Identificadores como <code>ARE-SINTETICO-001</code> e números de OAB são fictícios.</li>
              <li><strong>Payload Simulado:</strong> Comandos de teste criados em laboratório isolado loopback.</li>
              <li><strong>Nenhuma Chamada Externa:</strong> Sem conexão com ChatGPT, Claude, Gemini ou sistemas reais do STF.</li>
              <li><strong>Arquitetura HeraclitusDB:</strong> Prova de preservação de bytes, evidência forense e bloqueio no Policy Gateway.</li>
            </ul>
          </div>
        </section>

        <!-- 3.1 BANNER DE HINT: ONDE E COMO O HERACLITUSDB ATUA -->
        <div class="zanin-heraclitus-hint-banner">
          <div class="zanin-hint-badge">💡 HINT ARQUITETURAL: ATUAÇÃO DO HERACLITUSDB NA DEFESA ZANIN</div>
          <h4 class="zanin-hint-title">Por que o HeraclitusDB é o pilar de proteção contra Injeção de Prompt?</h4>
          <div class="zanin-hint-grid">
            <div class="zanin-hint-col">
              <strong>1. Heraclitus Policy Gateway (Bloqueio Fail-Closed & upstream_delta = 0)</strong>
              <p>
                No caso real, o Ministro Zanin não usava IA para minutas. Mas se o STF estivesse utilizando IA autônoma para triagem processual, o documento teria induzido o modelo a tentar fraudar a repercussão geral.
                O <strong>Heraclitus Policy Gateway</strong> barra essa mutação na raiz: nenhuma IA tem autoridade direta no banco judicial sem assinatura humana digital (HITL), garantindo <code>upstream_delta = 0</code>.
              </p>
            </div>
            <div class="zanin-hint-col">
              <strong>2. Heraclitus LSN Ledger (Cadeia de Custódia Inviolável para MPF e OAB)</strong>
              <p>
                Para punir o infrator por má-fé processual (CPC) e crime perante o MPF/OAB, a prova técnica não pode ser contestada.
                O <strong>HeraclitusDB</strong> grava em livro-razão imutável <i>append-only</i> (com LSN e carimbo de tempo) os hashes SHA-256 de todas as camadas (bytes originais, texto legível e comandos ocultos). Ninguém consegue adulterar os registros.
              </p>
            </div>
          </div>
        </div>

        <!-- 4. SELETOR DE CENÁRIOS DE LABORATÓRIO -->
        <section class="zanin-scenarios-bar">
          <div class="zanin-scenarios-head">
            <span class="zanin-scenarios-title">Selecione o Cenário de Avaliação:</span>
            <span class="tag-status" id="badgeScenarioStatus">Cenário Ativo</span>
          </div>
          <div class="zanin-scenario-buttons">
            <button type="button" class="zanin-scen-btn active" id="btnScenZanin" data-scen="scenario_zanin_stego">
              <span class="zanin-scen-btn-title">🛡️ Cenário A: Incidente Zanin (Victor)</span>
              <span class="zanin-scen-btn-sub">Esteganografia visual + coerção detectada pré-LLM (Quarentena)</span>
            </button>
            <button type="button" class="zanin-scen-btn" id="btnScenVitoria" data-scen="scenario_vitoria_exfiltration">
              <span class="zanin-scen-btn-title">🕵️ Cenário B: Caso VitórIA (Exfiltração de Minutas)</span>
              <span class="zanin-scen-btn-sub">Tool abuse em segredo de justiça barrado pelo Heraclitus Gateway (upstream_delta=0)</span>
            </button>
            <button type="button" class="zanin-scen-btn" id="btnScenBypass" data-scen="scenario_b_miss">
              <span class="zanin-scen-btn-title">⚠️ Cenário C: Detector Falha (MISS / Zero-Day)</span>
              <span class="zanin-scen-btn-sub">LLM contaminado, mas Policy Gateway barra mutação (upstream_delta=0)</span>
            </button>
            <button type="button" class="zanin-scen-btn" id="btnScenLegit" data-scen="scenario_c_legit">
              <span class="zanin-scen-btn-title">✓ Cenário D: Ação Legítima (Sem Falso Positivo)</span>
              <span class="zanin-scen-btn-sub">Citação acadêmica com aprovação HITL vinculada (upstream_delta=1)</span>
            </button>
          </div>
        </section>

        <!-- 5. PAINEL PRINCIPAL DO LABORATÓRIO FORENSE -->
        <div class="zanin-card">
          <div class="zanin-card-head">
            <h3 class="zanin-card-title">
              <span>📄 Documento sob Análise Pericial:</span>
              <code id="docFilename" style="font-size: 13px; color: #1d4ed8;">documento.pdf</code>
            </h3>

            <!-- 4 Modos de Visualização -->
            <div class="zanin-mode-tabs">
              <button type="button" class="zanin-mode-btn active" id="btnModeHuman">Visão Humana</button>
              <button type="button" class="zanin-mode-btn" id="btnModeStructural">Visão Estrutural</button>
              <button type="button" class="zanin-mode-btn forensic" id="btnModeForensic">🔬 Visão Forense</button>
              <button type="button" class="zanin-mode-btn sanitized" id="btnModeSanitized">✓ Sanitizado</button>
            </div>
          </div>

          <!-- Viewport do Documento -->
          <div class="zanin-doc-viewport mode-human" id="docViewport">
            Carregando documento...
          </div>

          <!-- Forensic Diff: Antes vs Depois da Sanitização -->
          <div class="zanin-diff-grid">
            <div class="zanin-diff-col">
              <span class="zanin-diff-label">Antes da Sanitização (Camada Extraída Bruta):</span>
              <div class="zanin-diff-box" id="diffBefore">Carregando...</div>
            </div>
            <div class="zanin-diff-col">
              <span class="zanin-diff-label">Depois da Sanitização (Cópia Segura para IA):</span>
              <div class="zanin-diff-box" id="diffAfter" style="background: #f0fdf4;">Carregando...</div>
            </div>
          </div>

          <!-- Badges de Preservação e Imutabilidade -->
          <div class="zanin-integrity-badges">
            <span class="zanin-integrity-pill ok">✓ Bytes Originais Preservados: SIM</span>
            <span class="zanin-integrity-pill ok">✓ Documento Original Alterado: NÃO</span>
            <span class="zanin-integrity-pill ok">✓ Cópia Sanitizada Isolada: SIM</span>
            <span class="zanin-integrity-pill">SHA-256 Original: <code id="lblOriginalSha256" style="font-size: 11px;">—</code></span>
          </div>

          <!-- Findings Explicáveis -->
          <div class="zanin-findings-container">
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <strong style="font-size: 14px; text-transform: uppercase; color: #0f172a;">
                Achados Forenses Explicáveis (<span id="findingsCount">0</span>):
              </strong>
              <button type="button" class="btn small primary" id="btnWhyBlocked">❓ Por que foi bloqueado?</button>
            </div>
            <div id="findingsList">Carregando achados...</div>
          </div>
        </div>

        <!-- 6. DUAS BARREIRAS DE DEFESA & UPSTREAM_DELTA -->
        <section class="zanin-pipeline-box">
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <div>
              <span class="section-kicker" style="font-size: 11px; font-weight: 700; color: #2563eb; text-transform: uppercase;">
                Arquitetura de Defesa em Profundidade
              </span>
              <h3 style="margin: 3px 0 0 0; font-size: 16px; font-weight: 800; color: #0f172a;">
                Fluxo de Execução: Barreira 1 (Scanner) ➔ Barreira 2 (Policy Gateway)
              </h3>
            </div>
            <button type="button" class="btn small ghost" id="btnReexecutar">🔄 Reexecutar Pipeline</button>
          </div>

          <!-- Grafo do Incidente -->
          <div class="zanin-nodes-flow" id="pipelineFlowGraph">
            <!-- Renderizado dinamicamente -->
          </div>

          <!-- Card Gigante do Upstream Delta -->
          <div class="zanin-upstream-hero">
            <div class="zanin-upstream-desc">
              <span class="zanin-upstream-title" id="policyTitleLabel">DECISÃO DO POLICY GATEWAY: DENY</span>
              <p style="margin: 0; font-size: 13px; color: #cbd5e1; line-height: 1.5;" id="policyDescText">
                O acesso aos sistemas protegidos foi bloqueado por ausência de autorização formal humana.
                Nenhum comando malicioso contido em documento processual adquire autoridade operacional.
              </p>
              <div style="margin-top: 10px; font-size: 12px; color: #94a3b8;">
                Regra Aplicada: <code id="policyRuleCode" style="color: #93c5fd;">POLICY-HERACLITUS-FAILCLOSED-V1</code>
              </div>
              <div class="zanin-hint-inline" style="margin-top: 12px; background: rgba(15,23,42,0.6); border-color: #3b82f6; color: #e2e8f0;">
                💡 <strong style="color: #93c5fd;">Papel do Heraclitus Policy Gateway:</strong>
                <span id="policyHeraclitusHintText">Carregando atuação do HeraclitusDB...</span>
              </div>
            </div>
            <div class="zanin-upstream-score deny" id="upstreamScoreBox">
              <span class="zanin-upstream-val" id="upstreamDeltaVal">0</span>
              <span class="zanin-upstream-sub">upstream_delta</span>
              <strong style="font-size: 11px; margin-top: 4px; color: #86efac;" id="upstreamRealEffectLabel">EFEITO REAL: NENHUM</strong>
            </div>
          </div>
        </section>

        <!-- 7. CADEIA DE CUSTÓDIA E HASHES MULTI-CAMADA -->
        <div class="zanin-card">
          <div class="zanin-card-head">
            <h3 class="zanin-card-title">
              <span>🔐 Cadeia de Custódia Digital & Hashes de Todas as Camadas</span>
            </h3>
            <span class="tag-status normal" id="ledgerStatusBadge">HARNESS LOCAL</span>
          </div>
          <div style="padding: 16px 20px;">
            <table class="zanin-hashes-table">
              <tbody>
                <tr>
                  <td class="zanin-hash-key">1. SHA-256 (Bytes Originais do Arquivo):</td>
                  <td class="zanin-hash-val"><code id="hashOriginalBytes">—</code></td>
                </tr>
                <tr>
                  <td class="zanin-hash-key">2. SHA-256 (Texto Renderizado - Visão Humana):</td>
                  <td class="zanin-hash-val"><code id="hashRenderedText">—</code></td>
                </tr>
                <tr>
                  <td class="zanin-hash-key">3. SHA-256 (Texto Bruto Estrutural Completo):</td>
                  <td class="zanin-hash-val"><code id="hashRawExtracted">—</code></td>
                </tr>
                <tr>
                  <td class="zanin-hash-key">4. SHA-256 (Camada Invisível / Oculta Isolada):</td>
                  <td class="zanin-hash-val"><code id="hashHiddenContent">—</code></td>
                </tr>
                <tr>
                  <td class="zanin-hash-key">5. SHA-256 (Texto Normalizado):</td>
                  <td class="zanin-hash-val"><code id="hashNormalizedText">—</code></td>
                </tr>
                <tr>
                  <td class="zanin-hash-key">6. SHA-256 (Cópia Sanitizada para IA):</td>
                  <td class="zanin-hash-val"><code id="hashSanitizedText">—</code></td>
                </tr>
              </tbody>
            </table>
            <div class="zanin-hint-inline" style="margin-top: 14px;">
              💡 <strong>Papel do Heraclitus LSN Ledger:</strong> Todos os 6 hashes acima são ancorados com carimbo lógico sequencial (LSN) no livro-razão imutável do HeraclitusDB. Ninguém — nem os técnicos do tribunal — consegue alterar ou forjar a evidência pericial para MPF/OAB.
            </div>
          </div>
        </div>

        <!-- 8. RELATÓRIO TÉCNICO SINTÉTICO & OFFLINE VERIFIER -->
        <div class="zanin-report-card">
          <div class="zanin-report-header">
            <span class="zanin-report-disclaimer-tag">ARTEFATO SINTÉTICO DE DEMONSTRAÇÃO · NÃO EMITIDO PELO STF</span>
            <h2 class="zanin-report-title" style="margin-top: 8px;">RELATÓRIO TÉCNICO SINTÉTICO DA POC</h2>
            <div style="font-size: 12px; color: #64748b; margin-top: 4px;">
              Harness HeraclitusDB / STF • Módulo Forense de Injeção de Prompt • ID: <span id="lblReportId">—</span>
            </div>
          </div>

          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
            <strong style="font-size: 13px; text-transform: uppercase; color: #0f172a;">
              Verificação Offline do Evidence Bundle:
            </strong>
            <button type="button" class="btn small primary" id="btnVerifyBundle">⚡ Rodar Offline Verifier</button>
          </div>

          <table class="zanin-verifier-table">
            <thead>
              <tr>
                <th>Item Verificado</th>
                <th>Status</th>
                <th>Detalhes Técnicos</th>
              </tr>
            </thead>
            <tbody id="verifierTableBody">
              <tr><td colspan="3" style="text-align: center; color: #64748b;">Clique em "Rodar Offline Verifier" para testar o bundle.</td></tr>
            </tbody>
          </table>
        </div>

      </div>

      <!-- MODAL "POR QUE FOI BLOQUEADO?" -->
      <div id="modalWhyBlocked" class="zanin-why-modal" style="display: none;">
        <div class="zanin-why-content">
          <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px;">
            <h3 style="margin: 0; font-size: 16px; font-weight: 800; color: #0f172a;">❓ Por que foi bloqueado? (Análise Explicável)</h3>
            <button type="button" class="btn tiny ghost" id="btnCloseWhyModal">✕ Fechar</button>
          </div>
          <div id="modalWhyBody" style="font-size: 13px; line-height: 1.6; color: #334155;">
            Carregando justificativa técnica...
          </div>
        </div>
      </div>
    `;

    wireEvents();
  }

  function wireEvents() {
    // Cenários
    $('#btnScenZanin').onclick = () => selectScenario('scenario_zanin_stego');
    $('#btnScenVitoria').onclick = () => selectScenario('scenario_vitoria_exfiltration');
    $('#btnScenBypass').onclick = () => selectScenario('scenario_b_miss');
    $('#btnScenLegit').onclick = () => selectScenario('scenario_c_legit');

    // Modos de visualização
    $('#btnModeHuman').onclick = () => setViewMode('human');
    $('#btnModeStructural').onclick = () => setViewMode('structural');
    $('#btnModeForensic').onclick = () => setViewMode('forensic');
    $('#btnModeSanitized').onclick = () => setViewMode('sanitized');

    // Botões de ação
    $('#btnWhyBlocked').onclick = () => openWhyModal();
    $('#btnCloseWhyModal').onclick = () => closeWhyModal();
    $('#btnReexecutar').onclick = () => runPipelineCurrentScenario();
    $('#btnVerifyBundle').onclick = () => runOfflineVerifier();
  }

  async function selectScenario(scenId) {
    currentScenario = scenId;
    document.querySelectorAll('.zanin-scen-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.scen === scenId);
    });
    await runPipelineCurrentScenario();
  }

  async function runPipelineCurrentScenario() {
    try {
      const res = await api('/api/zanin/run-pipeline', {
        method: 'POST',
        body: JSON.stringify({ scenario_id: currentScenario })
      });
      if (res.status === 'PASS') {
        pipelineState = res.pipeline;
        bundleState = res.bundle;
        renderPipelineUI(res.pipeline, res.ledger_status, res.lsn);
        // Atualiza verificação offline
        await runOfflineVerifier();
      }
    } catch (err) {
      console.error('Erro ao executar pipeline do laboratório Zanin:', err);
    }
  }

  function renderPipelineUI(pipe, ledgerStatus, lsn) {
    const doc = pipe.document;
    const det = pipe.detection;
    const pol = pipe.policy_decision;
    const san = pipe.sanitization;

    // Metadados do documento
    $('#docFilename').textContent = `${doc.metadata.original_filename} (${doc.metadata.document_id})`;
    $('#lblOriginalSha256').textContent = doc.hashes.sha256_original_bytes.slice(0, 16) + '…';

    // Hashes da tabela
    $('#hashOriginalBytes').textContent = doc.hashes.sha256_original_bytes;
    $('#hashRenderedText').textContent = doc.hashes.rendered_text_hash;
    $('#hashRawExtracted').textContent = doc.hashes.raw_extracted_text_hash;
    $('#hashHiddenContent').textContent = doc.hashes.hidden_content_hash;
    $('#hashNormalizedText').textContent = doc.hashes.normalized_text_hash;
    $('#hashSanitizedText').textContent = san.sanitized_text_hash;

    // Diff
    $('#diffBefore').textContent = doc.raw_extracted_text;
    $('#diffAfter').textContent = san.sanitized_text || '(Documento inteiramente contido em quarentena)';

    // Status do Ledger
    const lBadge = $('#ledgerStatusBadge');
    if (ledgerStatus === 'HERACLITUSDB_REAL_COMMITTED') {
      lBadge.textContent = `HERACLITUSDB REAL (LSN ${lsn})`;
      lBadge.className = 'tag-status normal';
    } else {
      lBadge.textContent = `HARNESS LOCAL SINTÉTICO (LSN ${lsn})`;
      lBadge.className = 'tag-status';
    }

    // Upstream Hero Card
    const polTitle = $('#policyTitleLabel');
    const polDesc = $('#policyDescText');
    const polRule = $('#policyRuleCode');
    const upVal = $('#upstreamDeltaVal');
    const upBox = $('#upstreamScoreBox');
    const upEffect = $('#upstreamRealEffectLabel');

    upVal.textContent = pol.upstream_delta;
    polRule.textContent = pol.policy_rule;
    polDesc.textContent = pol.explanation;

    if (pol.decision === 'ALLOW') {
      polTitle.textContent = 'DECISÃO DO POLICY GATEWAY: ALLOW';
      polTitle.style.color = '#86efac';
      upBox.className = 'zanin-upstream-score executed';
      upVal.style.color = '#facc15';
      upEffect.textContent = 'AÇÃO JUDICIAL EXECUTADA';
      upEffect.style.color = '#facc15';
    } else {
      polTitle.textContent = `DECISÃO DO POLICY GATEWAY: ${pol.decision}`;
      polTitle.style.color = '#93c5fd';
      upBox.className = 'zanin-upstream-score deny';
      upVal.style.color = '#4ade80';
      upEffect.textContent = 'EFEITO REAL: NENHUM';
      upEffect.style.color = '#86efac';
    }

    const polHint = $('#policyHeraclitusHintText');
    if (polHint) {
      polHint.textContent = pol.heraclitus_role || 'O Heraclitus Policy Gateway garantiu fail-closed e upstream_delta=0.';
    }

    // Grafo do Incidente
    renderFlowGraph(pipe.incident_graph.nodes);

    // Findings
    renderFindings(det.findings);

    // Relatório ID
    $('#lblReportId').textContent = `REP-ZANIN-${doc.hashes.sha256_original_bytes.slice(0, 10)}`;

    // Atualiza viewport de acordo com o modo atual
    renderViewport();
  }

  function renderFlowGraph(nodes) {
    const host = $('#pipelineFlowGraph');
    if (!host || !nodes) return;

    host.innerHTML = nodes.map((node, i) => {
      let cls = 'zanin-flow-node';
      if (node.status === 'DENY' || node.status === 'QUARANTINED_PRE_LLM' || node.status === 'DETECTED') {
        cls += ' active-deny';
      } else if (node.status === 'ALLOW' || node.status === 'SANITIZED' || node.status === 'PASSTHROUGH') {
        cls += ' active-pass';
      } else {
        cls += ' active-neutral';
      }

      const arrow = i < nodes.length - 1 ? '<span class="zanin-flow-arrow">➔</span>' : '';
      return `
        <div class="${cls}">
          <span class="zanin-flow-node-title">${esc(node.label)}</span>
          <span class="zanin-flow-node-status">${esc(node.status)}</span>
        </div>
        ${arrow}
      `;
    }).join('');
  }

  function renderFindings(findings) {
    const host = $('#findingsList');
    const cnt = $('#findingsCount');
    cnt.textContent = findings.length;

    if (!findings.length) {
      host.innerHTML = `
        <div class="zanin-finding-item" style="border-left: 4px solid #22c55e;">
          <div class="zanin-finding-head">
            <span class="zanin-finding-badge" style="background: #dcfce7; color: #166534;">NENHUM ACHADO ADVERSARIAL</span>
            <span class="zanin-finding-rule">DOC-CLEAN-000</span>
          </div>
          <p class="zanin-finding-desc" style="margin: 0;">O documento não possui esteganografia, fontes microscópicas nem comandos imperativos de modelo.</p>
        </div>
      `;
      return;
    }

    host.innerHTML = findings.map(f => `
      <div class="zanin-finding-item sev-${esc(f.severidade)}">
        <div class="zanin-finding-head">
          <span class="zanin-finding-badge">${esc(f.categoria)} · ${esc(f.severidade)}</span>
          <span class="zanin-finding-rule">${esc(f.regra_disparada)} (${esc(f.posicao)})</span>
        </div>
        <div class="zanin-finding-desc">${esc(f.explicacao)}</div>
        <div class="zanin-finding-evidence">Evidência: ${esc(f.evidencia)}</div>
      </div>
    `).join('');
  }

  function setViewMode(mode) {
    currentMode = mode;
    document.querySelectorAll('.zanin-mode-btn').forEach(btn => btn.classList.remove('active'));
    if (mode === 'human') $('#btnModeHuman').classList.add('active');
    if (mode === 'structural') $('#btnModeStructural').classList.add('active');
    if (mode === 'forensic') $('#btnModeForensic').classList.add('active');
    if (mode === 'sanitized') $('#btnModeSanitized').classList.add('active');
    renderViewport();
  }

  function renderViewport() {
    const vp = $('#docViewport');
    if (!vp || !pipelineState) return;
    const doc = pipelineState.document;
    const san = pipelineState.sanitization;

    vp.className = `zanin-doc-viewport mode-${currentMode}`;

    if (currentMode === 'human') {
      // Visão Humana: apenas o que é legível a olho nu
      vp.textContent = doc.rendered_text;
    } else if (currentMode === 'structural') {
      // Visão Estrutural: todo o texto bruto extraído com marcações de stream
      vp.textContent = `[INÍCIO DO STREAM ESTRUTURAL PDF]\n${doc.raw_extracted_text}\n[FIM DO STREAM ESTRUTURAL]`;
    } else if (currentMode === 'forensic') {
      // Visão Forense: destaca em caixas vermelhas o conteúdo oculto e caracteres zero-width
      const visible = esc(doc.rendered_text);
      const hidden = esc(doc.hidden_content);
      vp.innerHTML = `
        <div>${visible}</div>
        ${hidden ? `
          <div class="forensic-hidden-box">
            <span class="forensic-hidden-badge">CAMADA OCULTA / ESTEGANOGRÁFICA DETECTADA:</span><br/>
            ${hidden}
          </div>
        ` : '<div style="color: #4ade80; margin-top: 10px;">✓ Nenhuma camada oculta ou invisível encontrada neste documento.</div>'}
      `;
    } else if (currentMode === 'sanitized') {
      // Visão Sanitizada: cópia purgada autorizada para a IA
      vp.textContent = san.sanitized_text || '(Documento inteiramente contido em quarentena pré-LLM)';
    }
  }

  function openWhyModal() {
    if (!pipelineState) return;
    const m = $('#modalWhyBlocked');
    const body = $('#modalWhyBody');
    const pol = pipelineState.policy_decision;
    const det = pipelineState.detection;

    body.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 10px;">
        <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
          <strong style="color: #0f172a; display: block; margin-bottom: 4px;">1. Decisão de Enforcement:</strong>
          <span>Veredito: <strong>${esc(pol.decision)}</strong></span><br/>
          <span>Código do Motivo: <code>${esc(pol.reason_code)}</code></span><br/>
          <span>Política Aplicada: <code>${esc(pol.policy_rule)}</code></span>
        </div>

        <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
          <strong style="color: #0f172a; display: block; margin-bottom: 4px;">2. Explicação da Barreira:</strong>
          <p style="margin: 0;">${esc(pol.explanation)}</p>
        </div>

        <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
          <strong style="color: #0f172a; display: block; margin-bottom: 4px;">3. Princípio Arquitetural de Segurança:</strong>
          <p style="margin: 0; color: #475569;">
            Mesmo que uma injeção de prompt consiga enganar o detector ou o modelo de IA,
            o texto do documento <strong>nunca adquire autoridade operacional</strong>. Qualquer mutação em processos
            exige credenciais formais de autoridade e aprovação humana (HITL). Portanto, o efeito upstream é rigorosamente zero.
          </p>
        </div>
      </div>
    `;
    m.style.display = 'flex';
  }

  function closeWhyModal() {
    $('#modalWhyBlocked').style.display = 'none';
  }

  async function runOfflineVerifier() {
    try {
      const res = await api('/api/zanin/verify-bundle', {
        method: 'POST',
        body: JSON.stringify({ bundle: bundleState })
      });
      verificationState = res;
      renderVerifierTable(res.checks);
    } catch (err) {
      console.error('Erro na verificação offline do bundle:', err);
    }
  }

  function renderVerifierTable(checks) {
    const tbody = $('#verifierTableBody');
    if (!tbody || !checks) return;

    tbody.innerHTML = checks.map(c => {
      let tagClass = 'pass';
      if (c.status === 'UNVERIFIED') tagClass = 'unverified';
      if (c.status === 'FAIL') tagClass = 'fail';

      return `
        <tr>
          <td><code>${esc(c.check)}</code></td>
          <td><span class="zanin-status-tag ${tagClass}">${esc(c.status)}</span></td>
          <td style="color: #334155; font-size: 12px;">${esc(c.detail)}</td>
        </tr>
      `;
    }).join('');
  }

  window.refreshDefesaZanin = async function() {
    if (!root.innerHTML || root.innerHTML.trim() === '') {
      renderSkeleton();
    }
    await runPipelineCurrentScenario();
  };

  // Render inicial
  renderSkeleton();
  runPipelineCurrentScenario();
})();
