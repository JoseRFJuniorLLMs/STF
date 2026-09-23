# SPEC-0004 — Integridade, Merkle e Detecção de Adulteração

**Status:** Proposed  
**Classe:** Integrity / Tamper Evidence  
**Prioridade:** P0  
**Dependências:** SPEC-0003

## 1. Objetivo

Provar que alterações posteriores na história preservada são detectáveis.

A POC deve cobrir quatro classes:

1. modificação;
2. exclusão;
3. inserção retroativa indevida;
4. reordenação.

## 2. Estado saudável

Após ingestão do cenário base, registrar:

- intervalo de LSN;
- HLC quando disponível;
- digest dos objetos;
- raiz Merkle;
- identidade do build;
- timestamp local alegado;
- event count.

## 3. Teste de modificação

Procedimento:

1. ingerir dataset;
2. fechar/checkpoint do estado necessário;
3. registrar raiz esperada;
4. modificar bytes de um evento ou representação persistida por mecanismo controlado de sabotagem;
5. executar verificador;
6. exigir DETECTED.

Saída mínima:

```text
TEST                  TAMPER-MODIFY
EXPECTED              DETECTED
OBSERVED              DETECTED
AFFECTED_RANGE        ...
EXPECTED_ROOT         ...
OBSERVED_ROOT         ...
RESULT                PASS
```

## 4. Teste de exclusão

Excluir um registro ou objeto do conjunto exportado.

O sistema não pode simplesmente validar os objetos restantes e concluir integridade.

Deve detectar:

- count inconsistente;
- quebra de encadeamento/prova;
- manifesto divergente;
- digest faltante.

## 5. Teste de reordenação

Trocar a posição de dois eventos preservando individualmente seus conteúdos.

Resultado exigido: DETECTED.

Isso prova que a integridade cobre história/ordem e não apenas hash isolado de objeto.

## 6. Teste de inserção

Adicionar evento não pertencente ao intervalo original e tentar apresentá-lo como histórico.

Resultado exigido: DETECTED ou FAIL, conforme camada em que a fraude for descoberta.

## 7. Prova de sabotagem

É obrigatório demonstrar que o teste negativo realmente testa algo.

Pelo menos uma mutação controlada no código/teste deve provar que, se a checagem crítica for removida, o cenário negativo falha.

Exemplo:

```text
sabotagem: ignorar comparação da Merkle root
efeito esperado: teste TAMPER-MODIFY fica vermelho
```

A sabotagem não permanece na branch final.

## 8. Limites

A POC prova detecção dentro do modelo testado. Não deve afirmar resistência absoluta contra administrador com controle total simultâneo de código, kernel, disco e cadeia de distribuição.

Esse problema exige fronteiras externas adicionais, como WORM, HSM, atestação ou retenção independente, fora do escopo P0.
