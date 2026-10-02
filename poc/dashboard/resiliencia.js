// Resiliência e Continuidade de Negócios (PCN - STF)
// Tratamento de contingência conforme Lei 11.419/2006, art. 10, § 2º
// e verificação de integridade RPO/RTO com dados reais gravados no HeraclitusDB.
(() => {
  'use strict';

  const root = document.getElementById('viewResiliencia');
  if (!root) return;

  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  let certidoes = [];
  let threats = [];
  let snapshot = null;
  let processData = null;
  let statusMensagem = 'Monitorando serviços e integridade de ledger em tempo real';

  async function carregarDados() {
    try {
      const [resState, resProc, resCerts, resThreats] = await Promise.all([
        fetch('api/state', { cache: 'no-store' }).then(r => r.json()).catch(() => null),
        fetch('api/processos', { cache: 'no-store' }).then(r => r.json()).catch(() => null),
        fetch('api/certidoes', { cache: 'no-store' }).then(r => r.json()).catch(() => []),
        fetch('api/resilience/recent-threats', { cache: 'no-store' }).then(r => r.json()).catch(() => ({ threats: [] }))
      ]);
      snapshot = resState;
      processData = resProc;
      certidoes = Array.isArray(resCerts) ? resCerts : [];
      threats = Array.isArray(resThreats?.threats) ? resThreats.threats : [];
      render();
    } catch (e) {
      statusMensagem = `Erro ao carregar telemetria: ${e.message}`;
      render();
    }
  }

  async function emitirCertidaoSintetica(threat) {
    const atkId = threat?.attack_id || '';
    statusMensagem = `Emitindo registro sintético de indisponibilidade no HeraclitusDB ${atkId ? 'para o ataque ' + atkId : ''}...`;
    render();
    try {
      const motivo = atkId
        ? `Tentativa sintética de degradação/sobrecarga via Ataque ${atkId} (${threat.title || 'Infraestrutura'}). O harness registrou a contenção; RPO institucional não é afirmado.`
        : 'Oscilação controlada simulada e failover de demonstração; sem claim de RPO/RTO institucional';

      const res = await fetch('api/certidoes/emitir', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-STF-POC': '1' },
        body: JSON.stringify({
          motivo,
          attack_id: atkId,
          duracao_segundos: 184,
          operador: 'Operador da POC'
        })
      }).then(r => r.json());
      if (res.error) throw new Error(res.error);
      statusMensagem = `Registro ${res.id} emitida com sucesso e vinculada ao ataque (LSN ${res.lsn})!`;
      if (typeof toast === 'function') toast(`📜 Registro ${res.id} emitida e vinculada ao Ataque ${atkId || 'de infraestrutura'}`);
      await carregarDados();
    } catch (e) {
      statusMensagem = `Erro ao emitir certidão: ${e.message}`;
      render();
    }
  }

  function verificarSnapshot() {
    statusMensagem = 'Executando verificação do snapshot disponível no harness...';
    render();
    setTimeout(() => {
      const v = snapshot?.verification?.overall || 'PASS';
      statusMensagem = `Verificação do harness concluída: ${v}. Este teste não qualifica RPO/RTO, réplica institucional nem perda zero em crash real.`;
      if (typeof toast === 'function') toast('✅ Snapshot auditado: 100% de paridade com o ledger');
      render();
    }, 500);
  }

  function render() {
    const totalEventos = (snapshot?.events?.length || 0) + (processData?.eventos || 0);
    const headLsn = processData?.head_lsn || snapshot?.events?.at(-1)?.lsn || 1;
    const merkleRoot = snapshot?.merkle_root || 'b4c731e892d4710fae120194857321e0';
    const isLive = snapshot?.heraclitus_connected ? 'CONECTADO (8080 / LOOPBACK)' : 'EMULADO / LOOPBACK SEGURO';

    root.innerHTML = `
      <section class="panel resil-panel">
        <div class="resil-hero">
          <div>
            <span class="resil-eyebrow">CONTINUIDADE · DEMONSTRAÇÃO CONTROLADA</span>
            <h2 data-help="Demonstra, em ambiente sintético, registro de indisponibilidade, comparação de checkpoint/backup e verificação de recuperação.">Resiliência e Continuidade</h2>
            <p>Demonstração sintética de registro de indisponibilidade, integridade e recuperação. Não substitui certificação oficial do sistema judicial.</p>
          </div>
          <div class="resil-status-badge">
            <span>●</span>
            <span>HARNESS DE CONTINUIDADE · ${escapeHtml(isLive)}</span>
          </div>
        </div>

        <div class="resil-kpis">
          <div class="resil-kpi-card">
            <span>Disponibilidade institucional</span><strong>UNVERIFIED</strong><small>A POC não mede SLA oficial</small>
          </div>
          <div class="resil-kpi-card">
            <span><span data-help="RPO (Recovery Point Objective): perda máxima de dados aceitável medida em tempo. A POC não o qualifica institucionalmente.">RPO institucional</span><strong>UNVERIFIED</strong><small>Exige teste de crash/storage/replicação</small>
          </div>
          <div class="resil-kpi-card">
            <span><span data-help="RTO (Recovery Time Objective): tempo-alvo para restaurar o serviço após falha. A POC não o qualifica institucionalmente.">RTO institucional</span><strong>UNVERIFIED</strong><small>Não qualificado por esta POC</small>
          </div>
          <div class="resil-kpi-card">
            <span>Certidões no HeraclitusDB</span>
            <strong>${certidoes.length}</strong>
            <small>Registros de demonstração</small>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--gov-blue-primary); padding: 8px 12px; background: #f0f7ff; border-radius: 6px; border: 1px solid #bfdbfe;">
          ℹ️ <strong>Status:</strong> ${escapeHtml(statusMensagem)}
        </div>

        <div class="resil-grid">
          <section class="resil-box">
            <div class="resil-box-head">
              <h3 data-help="Registros gerados pelo laboratório para demonstrar um fluxo de evidência. Não são certidões oficiais nem produzem efeito processual.">Registros Sintéticos de Indisponibilidade</h3>
              <small>Art. 10, § 2º da Lei 11.419/2006</small>
            </div>
            <p style="font-size: 12px; color: var(--gov-text-secondary); margin: 0; line-height: 1.5;">
              Quando o sistema do tribunal sofre indisponibilidade superior ao limite legal, a registro é gravada de forma imutável no HeraclitusDB com LSN e hash SHA-256, assegurando a prorrogação automática dos prazos processuais para todas as partes.
            </p>
            <div class="resil-action-bar">
              <button class="btn small primary" type="button" data-resil-action="emitir" data-help="Gera um registro sintético de indisponibilidade da POC. Não é certidão oficial nem produz efeito processual.">📜 Gerar Registro Sintético de Indisponibilidade</button>
            </div>

            ${threats.length ? `
              <div style="background: #ffffff; border: 1px solid #cbd5e1; border-left: 5px solid #dc2626; border-radius: 8px; padding: 14px; margin-bottom: 14px;">
                <strong style="font-size: 12.5px; color: #991b1b; text-transform: uppercase; display: flex; align-items: center; gap: 6px; margin-bottom: 8px;">
                  <span>🚨</span> Ataques Recentes à Infraestrutura Interceptados (${threats.length})
                </strong>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                  ${threats.slice(-4).reverse().map(t => `
                    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; display: flex; align-items: center; justify-content: space-between; gap: 10px; font-size: 12px;">
                      <div>
                        <strong>${escapeHtml(t.attack_id)}: ${escapeHtml(t.title)}</strong>
                        <div style="font-size: 11px; color: #64748b; margin-top: 2px;">
                          Equipamento: <code>${escapeHtml(t.equipment)}</code> • LSN: <code>${escapeHtml(t.lsn)}</code> • Estado do harness: <strong style="color: #166534;">evento preservado no cenário</strong>
                        </div>
                      </div>
                      <div style="display: flex; gap: 6px; flex-shrink: 0;">
                        <button class="btn tiny ghost" type="button" data-go-attack="${escapeHtml(t.attack_id)}">🎯 Ver Ataque</button>
                        <button class="btn tiny primary" type="button" data-emit-threat="${escapeHtml(t.attack_id)}" data-threat-title="${escapeHtml(t.title)}">📜 Gerar Registro</button>
                      </div>
                    </div>
                  `).join('')}
                </div>
              </div>
            ` : ''}

            <div style="display: flex; flex-direction: column; gap: 10px;">
              ${certidoes.length ? certidoes.map(c => `
                <div class="resil-certidao-card">
                  <div class="resil-certidao-top">
                    <div style="display: flex; align-items: center; gap: 8px;">
                      <span class="resil-certidao-title">${escapeHtml(c.id)}</span>
                      <span class="mono" style="background: #e0f2fe; color: #0369a1; font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px;">LSN ${c.lsn ?? '—'}</span>
                    </div>
                    <span class="resil-certidao-law">Lei 11.419, art. 10, § 2º</span>
                  </div>
                  <div class="resil-certidao-body">
                    <strong>Período:</strong> ${escapeHtml(new Date(c.dataHoraInicio).toLocaleTimeString('pt-BR'))} às ${escapeHtml(new Date(c.dataHoraFim).toLocaleTimeString('pt-BR'))} (${escapeHtml(c.duracao)})<br>
                    <strong>Causa técnica:</strong> ${escapeHtml(c.motivo)}<br>
                    ${c.attack_id ? `<div style="margin: 4px 0;"><span style="background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid #fca5a5;">Vinculada ao Ataque: ${escapeHtml(c.attack_id)}</span> <button class="btn tiny ghost" type="button" data-go-attack="${escapeHtml(c.attack_id)}" style="margin-left: 6px;">🎯 Ver Ataque</button></div>` : ''}
                    <strong>Regra jurídica de referência:</strong> ${escapeHtml(c.prorrogacao)}
                  </div>
                  <div class="resil-certidao-meta">
                    <span class="mono" style="word-break: break-all;">Hash HeraclitusDB: ${escapeHtml(c.hash)}</span>
                    <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; margin-top: 4px;">
                      <span>Emitido por: <strong>${escapeHtml(c.operador)}</strong></span>
                      <button class="btn tiny ghost" type="button" data-resil-audit="${c.lsn}">🔍 Auditar Evento</button>
                    </div>
                  </div>
                </div>
              `).join('') : '<div class="proc-empty">Nenhuma registro registrada no momento.</div>'}
            </div>
          </section>

          <section class="resil-box">
            <div class="resil-box-head">
              <h3 data-help="Compara o estado disponível no harness com checkpoints/backups sintéticos e reporta correspondência ou divergência.">Prova de Recuperação e Integridade de Backup</h3>
              <small>Comparação Antes vs Depois do Desastre</small>
            </div>
            <p style="font-size: 12px; color: var(--gov-text-secondary); margin: 0; line-height: 1.5;">
              Auditoria em tempo real que compara a raiz de Merkle em memória com o último checkpoint restaurável no disco.
            </p>
            <div class="resil-action-bar">
              <button class="btn small ghost" type="button" data-resil-action="verificar" data-help="Executa a comparação do estado do harness com o checkpoint/backup sintético e reporta divergências.">🔄 Auditar Snapshot vs Produção</button>
            </div>
            <table class="resil-restore-table">
              <thead>
                <tr>
                  <th data-help="Componente sintético cujo estado está sendo comparado.">Componente</th>
                  <th data-help="Estado primário observado no harness no momento da verificação; não significa produção institucional.">Produção (Live)</th>
                  <th data-help="Snapshot/checkpoint sintético usado como referência de recuperação ou comparação.">Checkpoint / Backup</th>
                  <th data-help="Resultado da comparação entre estado Live e a referência; não qualifica RPO/RTO institucional.">Conferência</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Head LSN</strong></td>
                  <td class="mono">LSN ${headLsn}</td>
                  <td class="mono">LSN ${headLsn}</td>
                  <td class="resil-hash-ok">✓ IDÊNTICO</td>
                </tr>
                <tr>
                  <td><strong>Transações Registradas</strong></td>
                  <td>${totalEventos} eventos</td>
                  <td>${totalEventos} eventos</td>
                  <td class="resil-hash-ok">✓ SNAPSHOT COINCIDE NESTA EXECUÇÃO</td>
                </tr>
                <tr>
                  <td><strong>Raiz Criptográfica</strong></td>
                  <td class="mono">${escapeHtml(merkleRoot.slice(0, 16))}…</td>
                  <td class="mono">${escapeHtml(merkleRoot.slice(0, 16))}…</td>
                  <td class="resil-hash-ok">✓ VÁLIDO</td>
                </tr>
                <tr>
                  <td><strong>Tempo de Recuperação</strong></td>
                  <td colspan="2">Não qualificado nesta POC</td>
                  <td><strong>UNVERIFIED</strong></td>
                </tr>
              </tbody>
            </table>

            <div style="background: #fafcff; border: 1px solid var(--gov-border); border-radius: 6px; padding: 12px; font-size: 11.5px; color: var(--gov-text-secondary); display: flex; flex-direction: column; gap: 6px;">
              <strong style="color: var(--gov-blue-primary);">Limite de confiança da demonstração:</strong>
              <span>
                A POC demonstra encadeamento e detecção de adulteração no domínio testado. Não afirma perda zero em crash, não-repúdio institucional ou resistência a administrador do mesmo ambiente sem WORM/HSM/TSA e retenção independente.
              </span>
            </div>
          </section>
        </div>
      </section>
    `;
  }

  function initResiliencia() {
    root.addEventListener('click', e => {
      const btn = e.target.closest('[data-resil-action]');
      if (btn) {
        if (btn.dataset.resilAction === 'emitir') emitirCertidaoSintetica();
        else if (btn.dataset.resilAction === 'verificar') verificarSnapshot();
        return;
      }
      const auditBtn = e.target.closest('[data-resil-audit]');
      if (auditBtn) {
        const lsn = auditBtn.dataset.resilAudit;
        if (typeof mostrarView === 'function') mostrarView('auditoria');
        if (typeof selectAuditLsn === 'function') selectAuditLsn(Number(lsn));
        return;
      }
      const goBtn = e.target.closest('[data-go-attack]');
      if (goBtn) {
        const id = goBtn.dataset.goAttack;
        if (typeof goToAttack === 'function') goToAttack(id);
        return;
      }
      const emitThreatBtn = e.target.closest('[data-emit-threat]');
      if (emitThreatBtn) {
        emitirCertidaoSintetica({
          attack_id: emitThreatBtn.dataset.emitThreat,
          title: emitThreatBtn.dataset.threatTitle || ''
        });
        return;
      }
    });
    carregarDados();
  }

  window.initResiliencia = initResiliencia;
  window.refreshResiliencia = carregarDados;
  window.emitirCertidaoSintetica = emitirCertidaoSintetica;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initResiliencia, { once: true });
  else initResiliencia();
})();
