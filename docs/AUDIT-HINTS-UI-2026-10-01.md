# Auditoria de Hints, Tooltips e Explicabilidade da UI

Data: 01/10/2026
Baseline auditado: ac1ebf2db9a319d51b2a51e5123300ec7b069405
Escopo: todas as superfícies em poc/dashboard/.

## Resumo executivo

Não, ainda não está tudo com hint.

Varredura heurística dos templates HTML/JS:
- 97 botões; 34 possuem title, aria-label ou aria-describedby diretamente: 35%.
- 31 cabeçalhos de tabela; 9 possuem hint explícito: 29%.
- 40 títulos H2/H3; 5 possuem subtítulo/hint próximo pelo critério automatizado: 13%.
- 0 ocorrências de aria-describedby no dashboard.
- tooltips gráficos são acionados principalmente por mousemove.
- nós do grafo principal usam onmouseenter/onmouseleave sem caminho equivalente por foco.

Esses percentuais não significam que todo botão precise de tooltip. A lacuna real está nos termos e controles cujo significado não é óbvio.

## Matriz por aba

| Aba | Situação | Lacunas principais |
| --- | --- | --- |
| Defesa cibernética | Parcialmente boa | badges globais, contadores e nós do grafo |
| Acompanhamento processual | Boa, incompleta | AS OF LSN, HITL e estados de fallback |
| Log Visual HeraclitusDB | Boa, incompleta | cadeia/LSN e filtros sem explicação uniforme |
| Forense de IA | Fraca em hints | DATA_ONLY, UNTRUSTED_DOCUMENT, NO TOOL AUTHORITY, TSA/HSM/WORM e Policy Gateway |
| Incidente 360º | Fraca em hints | LSN, upstream, reason codes, correlação e tabela de componentes |
| Auditoria e Evidências | Parcial | LSN, Merkle, manifesto, package root, semântica e proveniência |
| Resiliência e Continuidade | Fraca em hints | Live, checkpoint, conferência e RPO/RTO |
| Interoperabilidade e Reconciliação | Fraca em hints | MNI, idempotência, reconciliação e status MNI |

## Achados prioritários

### HINT-01 — badges globais sem explicação
RISCO, INCIDENTE, UPSTREAM e HERACLITUS aparecem no topo sem ajuda contextual. UPSTREAM é o mais ambíguo.

### HINT-02 — Forense de IA
Termos críticos sem ajuda de proximidade consistente: UNTRUSTED_DOCUMENT, DATA_ONLY, NO TOOL AUTHORITY, Policy Gateway, Evidence Bundle, upstream_delta, detector MISS, TSA, HSM/KMS, WORM e Authority Boundary.

Dos 20 botões renderizados nessa aba, apenas 1 possui title diretamente. Nem todos precisam, mas Modo Executivo, Modo Pericial, Mapa Forense, Replay e os casos deveriam explicar seu efeito antes do clique.

### HINT-03 — Incidente 360º
A tabela de componentes tem cabeçalhos sem hint: Componente, Tent., Def., Bloq. e Alvo. LSN, upstream, reason_code e correlação também aparecem sem glossário contextual.

### HINT-04 — Auditoria e Evidências
Conceitos sem explicação localizada consistente: LSN, AS OF LSN, cadeia, Merkle, manifesto, raiz do pacote, semântica, proveniência, hash anterior e efeitos upstream.

### HINT-05 — Interoperabilidade
Os cinco cabeçalhos da tabela não possuem hint: Código/Data, Processo, Origem-Destino, Status MNI e Chave de Idempotência. MNI e idempotência são prioritários.

### HINT-06 — Resiliência
Os quatro cabeçalhos Componente, Produção (Live), Checkpoint/Backup e Conferência não possuem hint. RPO/RTO estão corretamente como UNVERIFIED, mas ainda precisam de definição.

### HINT-07 — Processos
A tabela Log HeraclitusDB é uma das melhores áreas: seus sete cabeçalhos técnicos possuem explicação. Ainda faltam ajuda consistente para AS OF LSN, HITL e fallback volátil.

### HINT-08 — Defesa cibernética
A tabela principal do Ledger possui bons hints. A tabela Contadores por equipamento não explica Equipamento/Sistema, Tent., Bloq. e Status. Também falta explicar melhor a diferença entre infraestrutura simulada, Agent-Atack, campanha roteirizada e ataque massivo.

### HINT-09 — tooltips de gráfico são mouse-first
Os data-tip abrem por mousemove. Não há fluxo equivalente por focusin/focusout ou touch.

### HINT-10 — nós do grafo principal são hover-only
Os nós SVG usam onmouseenter/onmouseleave/onclick, sem tabindex=0, role=button e nome acessível equivalente.

### HINT-11 — title não basta
title é útil como reforço, mas não deve ser o único mecanismo. Não há aria-describedby no dashboard inteiro.

## Prioridade de correção

P0:
1. UPSTREAM/upstream_delta.
2. DATA_ONLY/NO TOOL AUTHORITY.
3. MEMORY_FALLBACK/VOLATILE.
4. LSN e AS OF LSN.
5. MNI.
6. RPO/RTO.
7. VERIFIED versus UNVERIFIED.
8. Evidence Bundle, Merkle e raiz do pacote.

P1:
- adicionar hint aos cabeçalhos técnicos das abas Incidente, Resiliência, Interoperabilidade, Contadores por equipamento e Offline Verifier;
- tornar tooltips acessíveis por teclado e touch;
- tornar nós SVG focáveis e nomeados.

P2:
- adicionar ajuda curta às abas principais e aos modos Executivo/Pericial;
- criar glossário global ou glossário por área.

## Gate recomendado

1. Todo cabeçalho técnico de tabela deve ter data-help, aria-describedby, title ou componente help-tip.
2. Termos críticos definidos em lista devem ter explicação na mesma view.
3. data-tip interativo deve ser alcançável por teclado.
4. Nós SVG clicáveis devem ter tabindex=0, role=button e nome acessível.
5. aria-describedby deve existir e apontar para IDs válidos.
6. CI deve falhar se uma nova coluna técnica for adicionada sem hint.

## Conclusão

A cobertura é parcial, não completa. O Ledger e o Log Processual estão bem explicados; as abas mais novas evoluíram mais rápido em funcionalidade do que em explicabilidade.

A meta correta não é colocar tooltip em cada botão. É garantir que todo conceito não óbvio seja explicável no ponto de uso por mouse, teclado e touch.
