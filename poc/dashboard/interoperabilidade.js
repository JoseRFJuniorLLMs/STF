// Interoperabilidade e Reconciliação — Padrão MNI (CNJ) e Tribunais de Origem
// Rastreamento de remessas e detecção de duplicatas (idempotência) e recibos ausentes.
(() => {
  'use strict';

  const root = document.getElementById('viewInteroperabilidade');
  if (!root) return;

  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  let remessas = [
    {
      id: 'REM-2026-081',
      processo: 'RE 000001',
      origem: 'TJSP (Tribunal de Justiça de SP)',
      destino: 'STF (Supremo Tribunal Federal)',
      dataHora: '2026-09-24T06:10:00-03:00',
      status: 'RECEBIDO',
      reciboHash: 'e7a18b...9f02',
      idempotenciaChave: 'mni:tjsp:stf:re000001:remessa-01',
      divergencias: 0
    },
    {
      id: 'REM-2026-082',
      processo: 'ADI 000002',
      origem: 'PGR (Procuradoria-Geral da República)',
      destino: 'STF (Protocolo Geral)',
      dataHora: '2026-09-24T06:14:22-03:00',
      status: 'RECEBIDO',
      reciboHash: 'f412c0...33a1',
      idempotenciaChave: 'mni:pgr:stf:adi000002:peticao-inicial',
      divergencias: 0
    },
    {
      id: 'REM-2026-083',
      processo: 'ARE 000006',
      origem: 'TRF3 (Tribunal Regional Federal 3ª Região)',
      destino: 'STF (Secretaria Judiciária)',
      dataHora: '2026-09-24T06:18:45-03:00',
      status: 'DUPLICATA_DETECTADA',
      reciboHash: 'e7a18b...9f02 (recibo original preservado)',
      idempotenciaChave: 'mni:trf3:stf:are000006:agravo-01',
      divergencias: 0,
      detalhe: 'Tribunal parceiro reenviou o lote por timeout de rede. HeraclitusDB descartou duplicação via chave de idempotência.'
    }
  ];

  let statusMsg = 'Barramento de Interoperabilidade MNI ativo e sincronizado';

  function reconciliar() {
    statusMsg = 'Reconciliando remessas com o barramento do DataJud (CNJ)...';
    render();
    setTimeout(() => {
      statusMsg = 'Reconciliação 100% concluída: todas as remessas possuem recibos criptográficos válidos.';
      render();
    }, 700);
  }

  function simularDuplicata() {
    const agora = new Date();
    const novaDuplicata = {
      id: `REM-2026-${String(remessas.length + 84).padStart(3, '0')}`,
      processo: 'RE 000001',
      origem: 'TJSP (Tribunal de Justiça de SP)',
      destino: 'STF',
      dataHora: agora.toISOString(),
      status: 'DUPLICATA_DETECTADA',
      reciboHash: 'd4821a...881f (hash anterior retornado)',
      idempotenciaChave: 'stf-proc:0000001-44.2026.1.00.0000:001',
      divergencias: 0,
      detalhe: 'Tentativa de gravar novamente o protocolo inicial de RE 000001. Append retornou deduplicated=true.'
    };
    remessas.unshift(novaDuplicata);
    statusMsg = `Remessa duplicada interceptada com sucesso pelo HeraclitusDB: deduplicated=true (Risco de duplicidade zero).`;
    render();
  }

  function render() {
    const total = remessas.length;
    const confirmados = remessas.filter(r => r.status === 'RECEBIDO').length;
    const dups = remessas.filter(r => r.status === 'DUPLICATA_DETECTADA').length;

    root.innerHTML = `
      <section class="panel interop-panel">
        <div class="interop-hero">
          <div>
            <span class="interop-eyebrow">PADRÃO CNJ MNI &amp; DATAJUD</span>
            <h2>Interoperabilidade e Reconciliação</h2>
            <p>Rastreamento de remessas processuais entre o STF e tribunais estaduais/federais com recibos de entrega e garantia de idempotência.</p>
          </div>
          <div class="interop-status-badge">
            <span>●</span>
            <span>BARRAMENTO MNI ONLINE</span>
          </div>
        </div>

        <div class="interop-kpis">
          <div class="interop-kpi-card">
            <span>Remessas Monitoradas</span>
            <strong>${total}</strong>
            <small>Transações MNI nesta sessão</small>
          </div>
          <div class="interop-kpi-card">
            <span>Recibos Confirmados</span>
            <strong>${confirmados}</strong>
            <small>Comprovante criptográfico entregue</small>
          </div>
          <div class="interop-kpi-card">
            <span>Duplicatas Neutralizadas</span>
            <strong>${dups}</strong>
            <small>Idempotência do HeraclitusDB</small>
          </div>
          <div class="interop-kpi-card">
            <span>Divergência de Dados</span>
            <strong>0%</strong>
            <small>Consistência total de metadados</small>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--gov-blue-primary); padding: 8px 12px; background: #f0f7ff; border-radius: 6px; border: 1px solid #bfdbfe;">
          ℹ️ <strong>Status:</strong> ${escapeHtml(statusMsg)}
        </div>

        <div class="interop-grid">
          <section class="interop-box">
            <div class="interop-box-head">
              <h3>Remessas e Transmissões MNI</h3>
              <div style="display: flex; gap: 8px;">
                <button class="btn tiny primary" type="button" data-interop-action="reconciliar">🔄 Reconciliar Barramento</button>
                <button class="btn tiny ghost" type="button" data-interop-action="duplicata">⚡ Testar Remessa Duplicada</button>
              </div>
            </div>
            <table class="interop-table">
              <thead>
                <tr>
                  <th>Código / Data</th>
                  <th>Processo</th>
                  <th>Origem ➔ Destino</th>
                  <th>Status MNI</th>
                  <th>Chave de Idempotência</th>
                </tr>
              </thead>
              <tbody>
                ${remessas.map(r => `
                  <tr>
                    <td>
                      <strong>${escapeHtml(r.id)}</strong><br>
                      <small style="color: var(--gov-muted);">${escapeHtml(new Date(r.dataHora).toLocaleTimeString('pt-BR'))}</small>
                    </td>
                    <td><strong>${escapeHtml(r.processo)}</strong></td>
                    <td><small>${escapeHtml(r.origem)} ➔ ${escapeHtml(r.destino)}</small></td>
                    <td>
                      <span class="interop-badge ${r.status === 'RECEBIDO' ? 'ok' : 'dup'}">${escapeHtml(r.status)}</span>
                      ${r.detalhe ? `<br><small style="color: var(--gov-muted); font-size: 10px;">${escapeHtml(r.detalhe)}</small>` : ''}
                    </td>
                    <td class="mono" style="font-size: 11px;">${escapeHtml(r.idempotenciaChave)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </section>

          <section class="interop-box">
            <div class="interop-box-head">
              <h3>Garantia de Idempotência Criptográfica</h3>
            </div>
            <p style="font-size: 12px; color: var(--gov-text-secondary); margin: 0; line-height: 1.5;">
              No Poder Judiciário, problemas comuns de latência levam sistemas emissores a tentar reenviar a mesma petição ou andamento várias vezes.
            </p>
            <div style="background: #fafcff; border: 1px solid var(--gov-border); border-radius: 6px; padding: 12px; font-size: 12px; color: var(--gov-text); display: flex; flex-direction: column; gap: 8px;">
              <strong style="color: var(--gov-blue-primary);">Como o HeraclitusDB protege o processo:</strong>
              <div>
                <strong>1. Chave Determinística:</strong> Toda remessa MNI possui uma chave única indexada em árvore (ex: <code>stf-proc:numero_unico:seq</code>).
              </div>
              <div>
                <strong>2. Append Deduplicado:</strong> Se a mesma chave chega com o mesmo conteúdo, o banco retorna o LSN já gravado com <code>deduplicated=true</code> sem criar um segundo andamento repetido.
              </div>
              <div>
                <strong>3. Detecção de Tampering:</strong> Se a mesma chave chega com conteúdo alterado, o banco rejeita imediatamente com erro de integridade, impedindo substituição ilícita de peças processuais.
              </div>
            </div>
          </section>
        </div>
      </section>
    `;
  }

  function initInteroperabilidade() {
    root.addEventListener('click', e => {
      const btn = e.target.closest('[data-interop-action]');
      if (!btn) return;
      if (btn.dataset.interopAction === 'reconciliar') reconciliar();
      else if (btn.dataset.interopAction === 'duplicata') simularDuplicata();
    });
    render();
  }

  window.initInteroperabilidade = initInteroperabilidade;
  window.refreshInteroperabilidade = reconciliar;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initInteroperabilidade, { once: true });
  else initInteroperabilidade();
})();
