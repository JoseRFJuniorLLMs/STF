# Remediação — Auditoria de Hints, Tooltips e Explicabilidade

Data: 01/10/2026
Branch de remediação: fix/ui-hints-accessibility
Baseline da auditoria: ac1ebf2db9a319d51b2a51e5123300ec7b069405

## Resultado

Todos os 11 achados da auditoria de hints foram tratados no código.

### HINT-01 — badges globais
RESOLVIDO: RISCO, INCIDENTE, UPSTREAM e HERACLITUS agora possuem data-help contextual.

### HINT-02 — Forense de IA
RESOLVIDO: modos Executivo/Pericial, cinco casos, UNTRUSTED_DOCUMENT, DATA_ONLY, NO TOOL AUTHORITY, replay, Policy Gateway, Evidence Bundle, TSA, HSM/KMS e WORM receberam explicações contextuais.

### HINT-03 — Incidente 360º
RESOLVIDO: correlação, LSN, upstream_delta, decisões e os cinco cabeçalhos da tabela de componentes possuem ajuda contextual.

### HINT-04 — Auditoria e Evidências
RESOLVIDO: LSN/AS OF, proveniência, cadeia, Merkle, manifesto, raiz do pacote e semântica possuem explicação no ponto de uso.

### HINT-05 — Interoperabilidade
RESOLVIDO: MNI, reconciliação, teste de duplicata, idempotência e os cinco cabeçalhos técnicos possuem ajuda.

### HINT-06 — Resiliência
RESOLVIDO: Live, Checkpoint/Backup, Conferência, RPO, RTO, registro sintético e verificação de recuperação possuem ajuda.

### HINT-07 — Acompanhamento processual
RESOLVIDO: AS OF LSN, HITL, MEMORY_FALLBACK/VOLATILE e cabeçalhos gerados pelas tabelas possuem explicações.

### HINT-08 — Defesa cibernética
RESOLVIDO: badges globais, cabeçalho Ataques, foco Upstream e os quatro cabeçalhos do contador por equipamento possuem ajuda.

### HINT-09 — tooltips de gráficos mouse-only
RESOLVIDO: pontos data-tip agora recebem aria-label e roving tabindex. Setas navegam entre pontos; foco abre tooltip; touch usa pointerup.

### HINT-10 — nós do grafo hover-only
RESOLVIDO: nós SVG clicáveis possuem role=button, tabindex=0, aria-label, onfocus/onblur e Enter/Espaço equivalentes ao clique.

### HINT-11 — title como único mecanismo
RESOLVIDO: data-help é a fonte declarativa; o motor cria descrições estáticas e aria-describedby em runtime. O mesmo conteúdo é apresentado por hover, foco e tap, com Escape para fechar.

## Métricas depois da remediação

- 31/31 cabeçalhos de tabela com hint explícito: 100%.
- 8/8 abas principais com data-help.
- 92 pontos data-help declarados nas views auditadas.
- 26/40 títulos H2/H3 com explicação próxima/direta segundo a heurística usada na auditoria.
- 57/97 botões com hint direto segundo a mesma heurística. Os demais são majoritariamente ações autoexplicativas e não foram artificialmente poluídos com tooltip.
- aria-describedby passou a ser criado pelo motor contextual para cada alvo data-help.
- gráficos e grafo principal possuem equivalentes por teclado.

## Gates adicionados

O CI agora falha se:
- um cabeçalho técnico de tabela surgir sem data-help/title/aria-describedby;
- conceitos P0 desaparecerem das views explicadas;
- o motor contextual perder mouse, teclado, touch, Escape ou aria-describedby;
- nós do grafo perderem o equivalente de teclado;
- as abas principais perderem data-help;
- a cobertura contextual mínima regredir;
- os tooltips dos gráficos perderem roving tabindex/teclas de direção/touch.

## Princípio adotado

Nem todo botão precisa de tooltip. Todo conceito não óbvio precisa ser explicável no ponto de uso, com a mesma informação disponível por mouse, teclado e touch.
