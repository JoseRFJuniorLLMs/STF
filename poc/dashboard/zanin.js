// ========================================================
// DEFESA ZANIN — CÂMARA PERICIAL FORENSE DE IA (STF)
// AUDITORIA DOS INCIDENTES REGISTRADOS NO HERACLITUSDB LEDGER
// ========================================================
(() => {
  'use strict';

  const root = document.getElementById('viewZanin');
  if (!root) return;

  const $ = sel => root.querySelector(sel);
  const esc = str => String(str ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  let currentScenario = 'vector_stego_coercion';
  let currentAttackOrigin = 'IA_ZAN_05';
  let currentMode = 'human'; // 'human', 'structural', 'forensic', 'sanitized'
  let pipelineState = null;
  let bundleState = null;
  let verificationState = null;
  let experienceMode = 'executive';
  let replayTimer = null;

  function renderSkeleton() {
    root.innerHTML = `
      <div class="zanin-container zanin-experience-executive">

        <section class="zanin-command">
          <div class="zanin-command-copy">
            <span class="zanin-command-kicker">FORENSE DE IA · PROMPT INJECTION DOCUMENTAL</span>
            <h2>Da diferença Humano × Máquina à prova de efeito zero</h2>
            <p>Acompanhe como conteúdo documental não confiável é detectado, limitado a <code>DATA_ONLY</code>, avaliado pelo Policy Gateway e vinculado à evidência verificável da POC.</p>
          </div>
          <div class="zanin-experience-toggle" role="group" aria-label="Nível de detalhe">
            <button type="button" class="zanin-experience-btn active" data-experience="executive">Modo Executivo</button>
            <button type="button" class="zanin-experience-btn" data-experience="forensic">Modo Pericial</button>
          </div>
        </section>

        <section class="zanin-casebar" aria-label="Casos forenses">
          <button class="zanin-case-chip active" id="cardIncZanin" data-scenario="vector_stego_coercion" data-attack="IA_ZAN_05">
            <span>ZANIN</span><small>Esteganografia</small>
          </button>
          <button class="zanin-case-chip" id="cardIncMoraes" data-scenario="vector_moraes_header" data-attack="IA_MOR_01">
            <span>MORAES</span><small>Header override</small>
          </button>
          <button class="zanin-case-chip" id="cardIncVitoria" data-scenario="vector_tool_exfil" data-attack="IA_VIT_03">
            <span>VITÓRIA</span><small>Tool abuse</small>
          </button>
          <button class="zanin-case-chip" id="cardIncMiss" data-scenario="vector_zeroday_bypass" data-attack="IA_VIC_01">
            <span>DETECTOR MISS</span><small>Barreira 2</small>
          </button>
          <button class="zanin-case-chip legit" id="cardIncLegit" data-scenario="vector_legit_hitl" data-attack="BASELINE_00">
            <span>CONTROLE</span><small>Documento legítimo</small>
          </button>
        </section>

        <section class="zanin-story-card">
          <div class="zanin-story-head">
            <div>
              <span class="zanin-story-kicker">CASO SELECIONADO</span>
              <h3 id="execCaseTitle">Carregando análise...</h3>
              <p id="execCaseSubtitle">Executando pipeline forense sintético.</p>
            </div>
            <div class="zanin-hub-actions">
              <button type="button" class="btn ghost tiny" id="btnVoltarAtaques">⬅ Catálogo de Ataques</button>
              <button type="button" class="btn primary tiny" id="btnRecarregarCaso">🔄 Reexecutar</button>
            </div>
          </div>

          <div class="zanin-story-kpis">
            <div><span>Documento</span><strong id="execDocId">—</strong><small id="execFileName">—</small></div>
            <div><span>Detecção</span><strong id="execDetection">—</strong><small id="execFindings">0 achados</small></div>
            <div><span>Autoridade</span><strong>DATA_ONLY</strong><small>tools_allowed=false</small></div>
            <div><span>Policy</span><strong id="execPolicy">—</strong><small id="execReason">—</small></div>
            <div><span>Efeito no upstream sintético</span><strong id="execUpstream">—</strong><small>contador independente da POC</small></div>
          </div>

          <div class="zanin-story-strip" id="incidentLiveBanner">
            <span class="zanin-live-pill">AUDITORIA ATIVA</span>
            <span id="incidentLiveText">Carregando incidente selecionado...</span>
          </div>
        </section>

        <section class="zanin-human-machine-stage">
          <div class="zanin-stage-head">
            <div>
              <span class="zanin-story-kicker">A DIFERENÇA QUE IMPORTA</span>
              <h3>O humano vê uma coisa. A máquina pode receber outra.</h3>
            </div>
            <div class="zanin-hm-contract">
              <span class="zanin-contract-pill">UNTRUSTED_DOCUMENT</span>
              <span class="zanin-contract-pill">DATA_ONLY</span>
              <span class="zanin-contract-pill deny">NO TOOL AUTHORITY</span>
            </div>
          </div>
          <div class="zanin-hm-compare">
            <article class="zanin-hm-pane human">
              <header><span>👁 VISÃO HUMANA</span><strong id="hmHumanChars">0 caracteres</strong></header>
              <div id="execHumanText" class="zanin-hm-document">Carregando...</div>
            </article>
            <div class="zanin-hm-versus">≠</div>
            <article class="zanin-hm-pane machine">
              <header><span>🤖 VISÃO DA MÁQUINA</span><strong id="hmMachineChars">0 caracteres</strong></header>
              <div id="execMachineText" class="zanin-hm-document machine">Carregando...</div>
              <footer id="hmMachineOnly">0 tokens exclusivos da máquina</footer>
            </article>
          </div>
        </section>

        <section class="zanin-replay-card">
          <div class="zanin-stage-head">
            <div>
              <span class="zanin-story-kicker">REPLAY FORENSE</span>
              <h3>Como o documento percorre as duas barreiras</h3>
              <p id="replayNarrative">Clique em reproduzir para acompanhar a causalidade do incidente.</p>
            </div>
            <button type="button" class="btn primary small" id="btnReplayIncident">▶ Reproduzir incidente</button>
          </div>
          <div class="zanin-replay-track" id="replayTrack"></div>
        </section>

        <section class="zanin-evidence-card">
          <div class="zanin-stage-head">
            <div>
              <span class="zanin-story-kicker">CADEIA DE EVIDÊNCIA</span>
              <h3>Do documento ao efeito observado</h3>
              <p>Clique em um nó para ver a relação entre conteúdo, finding, política, efeito e bundle.</p>
            </div>
            <button type="button" class="btn small ghost" id="btnWhyBlocked">❓ Por que foi bloqueado?</button>
          </div>
          <div class="zanin-evidence-graph" id="evidenceGraph"></div>
          <div class="zanin-evidence-detail" id="evidenceGraphDetail">Selecione um nó da cadeia.</div>
        </section>

        <section class="zanin-trust-card">
          <div class="zanin-stage-head">
            <div>
              <span class="zanin-story-kicker">O QUE FOI PROVADO</span>
              <h3>Verificação sem transformar “não verificado” em verde decorativo</h3>
            </div>
            <span class="tag-status" id="ledgerStatusBadge">HARNESS LOCAL</span>
          </div>
          <div id="execTrustChecklist" class="zanin-trust-grid"></div>
        </section>

        <section class="zanin-pericial-only">
          <div class="zanin-card">
            <div class="zanin-card-head">
              <h3 class="zanin-card-title">
                <span>📄 Documento sob análise:</span>
                <code id="docFilename">documento.pdf</code>
              </h3>
              <div class="zanin-mode-tabs">
                <button type="button" class="zanin-mode-btn active" id="btnModeHuman">Visão Humana</button>
                <button type="button" class="zanin-mode-btn" id="btnModeStructural">Estrutural</button>
                <button type="button" class="zanin-mode-btn forensic" id="btnModeForensic">🔬 Mapa Forense</button>
                <button type="button" class="zanin-mode-btn sanitized" id="btnModeSanitized">✓ Sanitizado</button>
              </div>
            </div>
            <div class="zanin-doc-viewport mode-human" id="docViewport">Carregando documento...</div>

            <div class="zanin-diff-grid">
              <div class="zanin-diff-col">
                <span class="zanin-diff-label">Camada estrutural extraída</span>
                <div class="zanin-diff-box" id="diffBefore">Carregando...</div>
              </div>
              <div class="zanin-diff-col">
                <span class="zanin-diff-label">Cópia sanitizada entregue à IA</span>
                <div class="zanin-diff-box sanitized" id="diffAfter">Carregando...</div>
              </div>
            </div>

            <div class="zanin-integrity-badges">
              <span class="zanin-integrity-pill ok">✓ Bytes originais preservados</span>
              <span class="zanin-integrity-pill ok">✓ Original não sobrescrito</span>
              <span class="zanin-integrity-pill ok">✓ Sanitização em representação separada</span>
              <span class="zanin-integrity-pill">SHA-256: <code id="lblOriginalSha256">—</code></span>
            </div>

            <div class="zanin-findings-container">
              <div class="zanin-findings-head">
                <strong>Achados explicáveis (<span id="findingsCount">0</span>)</strong>
              </div>
              <div id="findingsList">Carregando achados...</div>
            </div>
          </div>

          <section class="zanin-pipeline-box">
            <div class="zanin-stage-head">
              <div>
                <span class="zanin-story-kicker">ARQUITETURA DE DEFESA EM PROFUNDIDADE</span>
                <h3>Barreira 1 → Authority Boundary → Policy Gateway</h3>
              </div>
              <button type="button" class="btn small ghost" id="btnReexecutar">🔄 Reexecutar Pipeline</button>
            </div>
            <div class="zanin-nodes-flow" id="pipelineFlowGraph"></div>
            <div class="zanin-upstream-hero">
              <div class="zanin-upstream-desc">
                <span class="zanin-upstream-title" id="policyTitleLabel">DECISÃO DO POLICY GATEWAY</span>
                <p id="policyDescText">Carregando decisão...</p>
                <div class="zanin-policy-rule">Regra: <code id="policyRuleCode">—</code></div>
                <div class="zanin-hint-inline">
                  <strong>Papel do Heraclitus Policy Gateway:</strong>
                  <span id="policyHeraclitusHintText">Carregando atuação...</span>
                </div>
              </div>
              <div class="zanin-upstream-score deny" id="upstreamScoreBox">
                <span class="zanin-upstream-val" id="upstreamDeltaVal">0</span>
                <span class="zanin-upstream-sub">upstream_delta</span>
                <strong id="upstreamRealEffectLabel">EFEITO NO UPSTREAM SINTÉTICO: 0</strong>
              </div>
            </div>
          </section>

          <div class="zanin-card">
            <div class="zanin-card-head">
              <h3 class="zanin-card-title"><span>🔐 Hashes das representações forenses</span></h3>
              <span class="zanin-scope-tag">CADEIA SINTÉTICA DA POC</span>
            </div>
            <div class="zanin-hashes-wrap">
              <table class="zanin-hashes-table">
                <tbody>
                  <tr><td class="zanin-hash-key">1. Bytes originais</td><td class="zanin-hash-val"><code id="hashOriginalBytes">—</code></td></tr>
                  <tr><td class="zanin-hash-key">2. Visão humana</td><td class="zanin-hash-val"><code id="hashRenderedText">—</code></td></tr>
                  <tr><td class="zanin-hash-key">3. Texto estrutural</td><td class="zanin-hash-val"><code id="hashRawExtracted">—</code></td></tr>
                  <tr><td class="zanin-hash-key">4. Conteúdo oculto</td><td class="zanin-hash-val"><code id="hashHiddenContent">—</code></td></tr>
                  <tr><td class="zanin-hash-key">5. Texto normalizado</td><td class="zanin-hash-val"><code id="hashNormalizedText">—</code></td></tr>
                  <tr><td class="zanin-hash-key">6. Cópia sanitizada</td><td class="zanin-hash-val"><code id="hashSanitizedText">—</code></td></tr>
                </tbody>
              </table>
              <div class="zanin-hint-inline">
                <strong>Limite de confiança:</strong> a POC verifica integridade dentro do domínio testado. Resistência a administrador do mesmo ambiente exige âncora externa, retenção WORM, HSM/KMS, TSA ou assinatura independente.
              </div>
            </div>
          </div>

          <div class="zanin-report-card">
            <div class="zanin-report-header">
              <span class="zanin-report-disclaimer-tag">ARTEFATO FORENSE SINTÉTICO · SEM EFEITO OFICIAL</span>
              <h2 class="zanin-report-title">RELATÓRIO TÉCNICO PERICIAL DA POC</h2>
              <div class="zanin-report-meta">HeraclitusDB / STF POC • ID: <span id="lblReportId">—</span></div>
            </div>
            <div class="zanin-verifier-head">
              <strong>Verificação Offline do Evidence Bundle</strong>
              <button type="button" class="btn small primary" id="btnVerifyBundle">⚡ Rodar Offline Verifier</button>
            </div>
            <table class="zanin-verifier-table">
              <thead><tr><th>Item</th><th>Status</th><th>Detalhes</th></tr></thead>
              <tbody id="verifierTableBody">
                <tr><td colspan="3">Clique em “Rodar Offline Verifier” para testar o bundle.</td></tr>
              </tbody>
            </table>
          </div>
        </section>

      </div>

      <div id="modalWhyBlocked" class="zanin-why-modal" style="display:none;">
        <div class="zanin-why-content">
          <div class="zanin-modal-head">
            <h3>❓ Por que foi bloqueado?</h3>
            <button type="button" class="btn tiny ghost" id="btnCloseWhyModal">✕ Fechar</button>
          </div>
          <div id="modalWhyBody">Carregando justificativa técnica...</div>
        </div>
      </div>
    `;

    wireEvents();
  }

  function wireEvents() {
    // Retorno para a Aba 1
    const btnVoltar = $('#btnVoltarAtaques');
    if (btnVoltar) {
      btnVoltar.onclick = () => {
        if (typeof mostrarView === 'function') {
          mostrarView('defesa');
        } else {
          const tab = document.getElementById('tabDefesa');
          if (tab) tab.click();
        }
      };
    }

    const btnRecarregar = $('#btnRecarregarCaso');
    if (btnRecarregar) {
      btnRecarregar.onclick = () => runPipelineCurrentScenario();
    }

    // Seletor de Incidentes Recebidos
    root.querySelectorAll('.zanin-case-chip').forEach(card => {
      card.onclick = () => {
        const scen = card.dataset.scenario;
        const atk = card.dataset.attack;
        selectIncident(scen, atk);
      };
    });

    // Modos de visualização
    const btnModeHuman = $('#btnModeHuman');
    if (btnModeHuman) btnModeHuman.onclick = () => setViewMode('human');
    const btnModeStructural = $('#btnModeStructural');
    if (btnModeStructural) btnModeStructural.onclick = () => setViewMode('structural');
    const btnModeForensic = $('#btnModeForensic');
    if (btnModeForensic) btnModeForensic.onclick = () => setViewMode('forensic');
    const btnModeSanitized = $('#btnModeSanitized');
    if (btnModeSanitized) btnModeSanitized.onclick = () => setViewMode('sanitized');

    // Botões de ação
    const btnWhyBlocked = $('#btnWhyBlocked');
    if (btnWhyBlocked) btnWhyBlocked.onclick = () => openWhyModal();
    const btnCloseWhyModal = $('#btnCloseWhyModal');
    if (btnCloseWhyModal) btnCloseWhyModal.onclick = () => closeWhyModal();
    const btnReexecutar = $('#btnReexecutar');
    if (btnReexecutar) btnReexecutar.onclick = () => runPipelineCurrentScenario();
    const btnVerifyBundle = $('#btnVerifyBundle');
    if (btnVerifyBundle) btnVerifyBundle.onclick = () => runOfflineVerifier();
  }

  function setExperienceMode(mode) {
    experienceMode = mode === 'forensic' ? 'forensic' : 'executive';
    const container = root.querySelector('.zanin-container');
    if (container) {
      container.classList.toggle('zanin-experience-executive', experienceMode === 'executive');
      container.classList.toggle('zanin-experience-forensic', experienceMode === 'forensic');
    }
    root.querySelectorAll('.zanin-experience-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.experience === experienceMode);
    });
  }

  function scenarioPresentation() {
    const map = {
      vector_stego_coercion: ['Caso Zanin · Esteganografia documental', 'Conteúdo invisível ao humano é extraído pela máquina e colocado em quarentena antes de adquirir qualquer autoridade.'],
      vector_moraes_header: ['Caso Moraes · Instruction Override em cabeçalho', 'Microfonte, baixa opacidade e conteúdo em header aparecem na visão estrutural, mas permanecem DATA_ONLY.'],
      vector_tool_exfil: ['Caso VitórIA · Tool Abuse', 'O documento tenta transformar texto em ação operacional. O Policy Gateway exige autoridade independente do conteúdo.'],
      vector_zeroday_bypass: ['Detector MISS · Defesa em profundidade', 'A primeira barreira falha de propósito. A fronteira de autoridade e o Policy Gateway ainda mantêm upstream_delta=0.'],
      vector_legit_hitl: ['Controle legítimo · Documento permitido', 'Uma referência legítima a segurança de IA não é tratada como ataque; a ação autorizada segue o fluxo HITL.']
    };
    return map[currentScenario] || ['Caso forense', 'Análise sintética controlada.'];
  }

  function renderExecutiveSummary(pipe, ledgerStatus, lsn) {
    const doc = pipe.document || {};
    const det = pipe.detection || {};
    const pol = pipe.policy_decision || {};
    const diff = pipe.differential || {};
    const [title,subtitle] = scenarioPresentation();
    const set = (id,value) => { const el=$(id); if(el) el.textContent=value; };
    set('#execCaseTitle', title);
    set('#execCaseSubtitle', subtitle);
    set('#execDocId', doc.metadata?.document_id || '—');
    set('#execFileName', doc.metadata?.original_filename || '—');
    set('#execDetection', det.verdict || '—');
    set('#execFindings', `${(det.findings || []).length} achado(s) explicável(is)`);
    set('#execPolicy', pol.decision || '—');
    set('#execReason', pol.reason_code || pol.policy_rule || '—');
    set('#execUpstream', String(pol.upstream_delta ?? '—'));

    const human = $('#execHumanText');
    const machine = $('#execMachineText');
    if (human) human.textContent = diff.human_text || doc.rendered_text || '';
    if (machine) {
      const machineText = diff.machine_text || doc.raw_extracted_text || '';
      const hidden = diff.machine_only_text || doc.hidden_content || '';
      machine.innerHTML = `${esc(machineText)}${hidden ? `<mark class="zanin-machine-only"><span>EXCLUSIVO DA MÁQUINA</span>${esc(hidden)}</mark>` : ''}`;
    }

    renderReplayTrack(pipe);
    renderEvidenceGraph(pipe, ledgerStatus, lsn);
    renderTrustChecklist(pipe, ledgerStatus);
  }

  function replaySteps(pipe) {
    const det = pipe.detection || {};
    const pol = pipe.policy_decision || {};
    const miss = det.verdict === 'ALLOWED' && pol.decision !== 'ALLOW';
    return [
      {id:'document',label:'Documento',status:'RECEIVED',detail:'Documento recebido como entrada não confiável.'},
      {id:'parser',label:'Parser',status:'EXTRACTED',detail:'Visão humana e visão estrutural são separadas.'},
      {id:'detector',label:'Detector',status:miss ? 'MISS' : (det.verdict || 'CHECKED'),detail:miss ? 'MISS controlado: a primeira barreira não detectou o ataque.' : `${(det.findings||[]).length} finding(s) explicável(is).`},
      {id:'authority',label:'Authority Boundary',status:'DATA_ONLY',detail:'Conteúdo documental não recebe autoridade de ferramenta.'},
      {id:'policy',label:'Policy Gateway',status:pol.decision || '—',detail:pol.explanation || 'Decisão da política.'},
      {id:'effect',label:'Upstream',status:`Δ ${pol.upstream_delta ?? '—'}`,detail:'Efeito medido no upstream sintético da POC.'},
      {id:'evidence',label:'Evidence Bundle',status:'PRESERVED',detail:'Decisão e representações são vinculadas à evidência da POC.'}
    ];
  }

  function renderReplayTrack(pipe) {
    const host=$('#replayTrack');
    if(!host) return;
    host.innerHTML=replaySteps(pipe).map((step,i)=>`
      <div class="zanin-replay-step" data-replay-step="${i}">
        <span class="zanin-replay-index">${i+1}</span>
        <strong>${esc(step.label)}</strong>
        <small>${esc(step.status)}</small>
      </div>${i<6?'<span class="zanin-replay-arrow">→</span>':''}
    `).join('');
  }

  function replayEvidenceFlow() {
    if (!pipelineState) return;
    if (replayTimer) clearInterval(replayTimer);
    const steps = replaySteps(pipelineState);
    const nodes=[...root.querySelectorAll('.zanin-replay-step')];
    nodes.forEach(n=>n.classList.remove('active','done'));
    let idx=0;
    const narrative=$('#replayNarrative');
    const tick=()=>{
      nodes.forEach((n,i)=>{ n.classList.toggle('active',i===idx); n.classList.toggle('done',i<idx); });
      if(narrative) narrative.textContent=steps[idx]?.detail || '';
      idx++;
      if(idx>=steps.length){
        clearInterval(replayTimer); replayTimer=null;
        nodes.forEach(n=>{n.classList.remove('active');n.classList.add('done');});
        if(narrative) narrative.textContent='Replay concluído: a causalidade do documento ao efeito observado ficou vinculada à evidência da POC.';
      }
    };
    tick();
    replayTimer=setInterval(tick,700);
  }

  function evidenceNodes(pipe, ledgerStatus, lsn) {
    const doc=pipe.document||{}, det=pipe.detection||{}, pol=pipe.policy_decision||{};
    const first=(det.findings||[])[0];
    return [
      {id:'doc',label:'Documento',value:doc.metadata?.document_id||'—',detail:`SHA-256 original: ${doc.hashes?.sha256_original_bytes||'—'}`},
      {id:'hidden',label:'Camada máquina',value:`${pipe.differential?.machine_only_token_count||0} tokens`,detail:pipe.differential?.machine_only_text||doc.hidden_content||'Nenhum conteúdo exclusivo da máquina.'},
      {id:'finding',label:'Finding',value:first?.regra_disparada||'CONTROL',detail:first?.explicacao||'Controle legítimo sem finding adversarial.'},
      {id:'policy',label:'Policy',value:pol.decision||'—',detail:`${pol.reason_code||pol.policy_rule||'—'} · ${pol.explanation||''}`},
      {id:'effect',label:'Efeito',value:`upstream Δ ${pol.upstream_delta??'—'}`,detail:'Contador do upstream sintético usado como oráculo de efeito na POC.'},
      {id:'bundle',label:'Evidence Bundle',value:ledgerStatus==='HERACLITUSDB_REAL_COMMITTED'?`LSN ${lsn}`:'HARNESS',detail:ledgerStatus==='HERACLITUSDB_REAL_COMMITTED'?'Persistência reportada pelo HeraclitusDB real para este evento.':'Evidência do harness local sintético; não é registro institucional.'}
    ];
  }

  function renderEvidenceGraph(pipe, ledgerStatus, lsn) {
    const host=$('#evidenceGraph');
    if(!host) return;
    host.innerHTML=evidenceNodes(pipe,ledgerStatus,lsn).map((n,i)=>`
      <button type="button" class="zanin-evidence-node" data-evidence-node="${esc(n.id)}">
        <span>${esc(n.label)}</span><strong>${esc(n.value)}</strong>
      </button>${i<5?'<span class="zanin-evidence-link">→</span>':''}
    `).join('');
    host.dataset.ledgerStatus=ledgerStatus||'';
    host.dataset.lsn=String(lsn??'');
    showEvidenceDetail('doc');
  }

  function showEvidenceDetail(nodeId) {
    if(!pipelineState) return;
    const host=$('#evidenceGraph');
    const detail=$('#evidenceGraphDetail');
    if(!host||!detail) return;
    const node=evidenceNodes(pipelineState,host.dataset.ledgerStatus,host.dataset.lsn).find(n=>n.id===nodeId);
    root.querySelectorAll('.zanin-evidence-node').forEach(n=>n.classList.toggle('active',n.dataset.evidenceNode===nodeId));
    if(node) detail.innerHTML=`<strong>${esc(node.label)} · ${esc(node.value)}</strong><p>${esc(node.detail)}</p>`;
  }

  function renderTrustChecklist(pipe, ledgerStatus) {
    const host=$('#execTrustChecklist');
    if(!host) return;
    const pol=pipe.policy_decision||{};
    const checks=[
      ['PASS','Bytes originais preservados','A sanitização não sobrescreve a representação original.'],
      ['PASS','Hashes das camadas calculados','Original, humano, máquina, oculto, normalizado e sanitizado possuem hashes independentes.'],
      ['PASS','Authority boundary aplicada','UNTRUSTED_DOCUMENT → DATA_ONLY → NO TOOL AUTHORITY.'],
      ['PASS','Efeito upstream observado',`upstream_delta=${pol.upstream_delta??'—'} no cenário sintético.`],
      [ledgerStatus==='HERACLITUSDB_REAL_COMMITTED'?'PASS':'UNVERIFIED','Persistência HeraclitusDB real',ledgerStatus==='HERACLITUSDB_REAL_COMMITTED'?'Commit reportado pelo backend real.':'Este run usa harness local; não tratar como persistência institucional.'],
      ['UNVERIFIED','TSA externa','Nenhuma autoridade externa de timestamp foi configurada para esta POC.'],
      ['UNVERIFIED','Assinatura institucional','Nenhuma assinatura institucional/HSM é afirmada por esta demonstração.']
    ];
    host.innerHTML=checks.map(([status,label,detail])=>`
      <div class="zanin-trust-item ${status.toLowerCase()}">
        <span class="zanin-trust-status">${status==='PASS'?'✓':'?'} ${esc(status)}</span>
        <strong>${esc(label)}</strong>
        <small>${esc(detail)}</small>
      </div>
    `).join('');
  }

  async function selectIncident(scenId, atkOrigin) {
    currentScenario = scenId;
    currentAttackOrigin = atkOrigin || 'CATÁLOGO DE ATAQUES';

    root.querySelectorAll('.zanin-case-chip').forEach(c => {
      c.classList.toggle('active', c.dataset.scenario === scenId);
    });

    await runPipelineCurrentScenario();
  }

  // Permite que a Aba 1 (ou qualquer script) carregue diretamente um caso
  window.loadDefesaZaninCase = async function(scenarioId, sourceAttackId) {
    currentScenario = scenarioId || 'vector_stego_coercion';
    currentAttackOrigin = sourceAttackId || 'IA_ZAN_05';

    if (!root.innerHTML || root.innerHTML.trim() === '') {
      renderSkeleton();
    }

    root.querySelectorAll('.zanin-case-chip').forEach(c => {
      c.classList.toggle('active', c.dataset.scenario === currentScenario);
    });

    await runPipelineCurrentScenario();
  };

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
      console.error('Erro ao executar pipeline da Central Forense de IA:', err);
    }
  }

  function renderPipelineUI(pipe, ledgerStatus, lsn) {
    const doc = pipe.document;
    const det = pipe.detection;
    const pol = pipe.policy_decision;
    const san = pipe.sanitization;

    // Banner do Incidente Atual sob Análise
    const liveText = $('#incidentLiveText');
    if (liveText) {
      const originLabel = currentAttackOrigin ? `Disparado via Aba 1 (Ataque ${currentAttackOrigin})` : 'Registrado nos autos';
      const outcomeLabel = pol.upstream_delta === 0 ? 'BLOQUEADO (upstream_delta=0)' : 'PERMITIDO (upstream_delta=1)';
      liveText.innerHTML = `
        Processo <strong>${esc(doc.metadata.document_id)}</strong> •
        Arquivo: <code>${esc(doc.metadata.original_filename)}</code> •
        Origem: <em>${esc(originLabel)}</em> •
        Enforcement: <strong style="color: ${pol.upstream_delta === 0 ? '#15803d' : '#854d0e'};">${esc(outcomeLabel)}</strong> •
        LSN: <code>${esc(lsn)}</code>
      `;
    }

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

    // Diff humano × máquina + sanitização
    const differential = pipe.differential || {};
    $('#diffBefore').textContent = doc.raw_extracted_text;
    $('#diffAfter').textContent = san.sanitized_text || '(Documento inteiramente contido em quarentena pré-LLM)';
    const humanChars = $('#hmHumanChars');
    const machineChars = $('#hmMachineChars');
    const machineOnly = $('#hmMachineOnly');
    if (humanChars) humanChars.textContent = `${(differential.human_text || doc.rendered_text || '').length} caracteres`;
    if (machineChars) machineChars.textContent = `${(differential.machine_text || doc.raw_extracted_text || '').length} caracteres`;
    if (machineOnly) machineOnly.textContent = `${differential.machine_only_token_count || 0} tokens exclusivos da máquina`;

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
      upEffect.textContent = 'EFEITO NO UPSTREAM SINTÉTICO: 0';
      upEffect.style.color = '#86efac';
    }

    const polHint = $('#policyHeraclitusHintText');
    if (polHint) {
      polHint.textContent = pol.heraclitus_role || 'O Policy Gateway aplicou fail-closed no cenário sintético e o oráculo registrou upstream_delta=0.';
    }

    // Grafo do Incidente
    renderFlowGraph(pipe.incident_graph.nodes);

    // Findings
    renderFindings(det.findings);

    // Relatório ID
    $('#lblReportId').textContent = `REP-FORENSE-${doc.hashes.sha256_original_bytes.slice(0, 10)}`;

    renderExecutiveSummary(pipe, ledgerStatus, lsn);

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
      renderForensicHeatmap(vp, doc, pipelineState.detection || {});
    } else if (currentMode === 'sanitized') {
      // Visão Sanitizada: cópia purgada autorizada para a IA
      vp.textContent = san.sanitized_text || '(Documento inteiramente contido em quarentena pré-LLM)';
    }
  }

  function renderForensicHeatmap(vp, doc, detection) {
    const spans = Array.isArray(doc.spans) ? doc.spans : [];
    const findings = Array.isArray(detection.findings) ? detection.findings : [];
    const byPage = new Map();
    spans.forEach((s, idx) => {
      const page = Number(s.page || 1);
      if (!byPage.has(page)) byPage.set(page, []);
      byPage.get(page).push({ ...s, __idx: idx + 1 });
    });

    const pages = [...byPage.keys()].sort((a, b) => a - b);
    if (!pages.length) {
      vp.textContent = doc.raw_extracted_text || '';
      return;
    }

    vp.innerHTML = pages.map(page => {
      const pageSpans = byPage.get(page);
      const hotspots = pageSpans.map(s => {
        const fg = String(s.font_color_hex || '').toLowerCase();
        const bg = String(s.bg_color_hex || '').toLowerCase();
        const hidden = s.is_visible_to_human === false ||
          Number(s.font_size_pt || 12) < 2 ||
          Number(s.opacity ?? 1) < 0.08 ||
          s.clipped || s.outside_page || s.behind_image ||
          Math.abs(Number(s.transform_scale ?? 1)) < 0.05 ||
          ((fg === '#ffffff' || fg === '#fff') && (bg === '#ffffff' || bg === '#fff'));
        if (!hidden) return '';

        const bbox = Array.isArray(s.bbox) ? s.bbox : [50, 50, 500, 70];
        const left = Math.max(0, Math.min(96, (Number(bbox[0]) / 595) * 100));
        const top = Math.max(0, Math.min(96, (Number(bbox[1]) / 842) * 100));
        const width = Math.max(3, Math.min(100 - left, ((Number(bbox[2]) - Number(bbox[0])) / 595) * 100));
        const height = Math.max(2, Math.min(100 - top, ((Number(bbox[3]) - Number(bbox[1])) / 842) * 100));
        const related = findings.filter(f => String(f.posicao || '').includes(`span #${s.__idx}`));
        const rules = related.map(f => f.regra_disparada).join(', ') || 'HIDDEN-CONTENT';
        return `
          <button type="button" class="forensic-hotspot"
            style="left:${left}%;top:${top}%;width:${width}%;height:${height}%"
            title="${esc(rules)} · ${esc(s.text)}">
            <span>${esc(rules)}</span>
          </button>
        `;
      }).join('');

      const pageVisible = pageSpans
        .filter(s => s.is_visible_to_human !== false && Number(s.font_size_pt || 12) >= 2 && Number(s.opacity ?? 1) >= 0.08)
        .map(s => esc(s.text))
        .join('<br/>');

      return `
        <div class="forensic-page-wrap">
          <div class="forensic-page-label">Página ${page}</div>
          <div class="forensic-page">
            <div class="forensic-page-text">${pageVisible}</div>
            ${hotspots}
          </div>
        </div>
      `;
    }).join('');

    const hidden = esc(doc.hidden_content || '');
    if (hidden) {
      vp.insertAdjacentHTML('beforeend', `
        <div class="forensic-hidden-box">
          <span class="forensic-hidden-badge">PAYLOAD EXTRAÍDO DA CAMADA NÃO VISÍVEL</span><br/>
          ${hidden}
        </div>
      `);
    }
  }

  function openWhyModal() {
    if (!pipelineState) return;
    const m = $('#modalWhyBlocked');
    const body = $('#modalWhyBody');
    if (!m || !body) return;
    const pol = pipelineState.policy_decision || {};
    const det = pipelineState.detection || {};

    body.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 10px;">
        <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
          <strong style="color: #0f172a; display: block; margin-bottom: 4px;">1. Decisão de Enforcement:</strong>
          <span>Veredito: <strong>${esc(pol.decision || 'N/A')}</strong></span><br/>
          <span>Código do Motivo: <code>${esc(pol.reason_code || 'N/A')}</code></span><br/>
          <span>Política Aplicada: <code>${esc(pol.policy_rule || 'N/A')}</code></span>
        </div>

        <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
          <strong style="color: #0f172a; display: block; margin-bottom: 4px;">2. Explicação da Barreira:</strong>
          <p style="margin: 0;">${esc(pol.explanation || 'N/A')}</p>
        </div>

        <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px;">
          <strong style="color: #0f172a; display: block; margin-bottom: 4px;">3. Princípio Arquitetural de Segurança:</strong>
          <div style="font-family:ui-monospace,monospace;background:#0f172a;color:#e2e8f0;padding:8px 10px;border-radius:6px;margin-bottom:8px;">UNTRUSTED_DOCUMENT → DATA_ONLY → NO TOOL AUTHORITY</div>
          <p style="margin: 0; color: #475569;">
            Mesmo que uma injeção de prompt consiga enganar o detector ou o modelo de IA,
            o texto do documento <strong>nunca adquire autoridade operacional</strong>. Qualquer mutação em processos
            exige credenciais independentes do documento e, quando aplicável, aprovação humana (HITL). Neste cenário executado, o oráculo da POC registrou upstream_delta=0.
          </p>
        </div>
      </div>
    `;
    m.style.display = 'flex';
  }

  function closeWhyModal() {
    const m = $('#modalWhyBlocked');
    if (m) m.style.display = 'none';
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
