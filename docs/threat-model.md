# Modelo de ameaças

**Ativos** Autorização vigente, credenciais de programa, observações redigidas, identidade do revisor, trilha de auditoria e disponibilidade do FX-6300. Entradas externas, artefatos analíticos, callbacks e respostas de modelos cruzam fronteiras de confiança.

| Ameaça | Controle | Prova |
|---|---|---|
| Instrução injetada em HTML/JS ou em resposta de modelo | Conteúdo tratado como dado, schema fechado, referências internas validadas e IA isolada de ferramentas | M0 rejeita campos extras; teste futuro deve enviar fixture com instruções e verificar somente classificação |
| Escape via wildcard, IDNA, URL ambígua, redirect ou IPv4-mapped IPv6 | Correspondência canônica, exclusões, bloqueio de sintaxe ambígua e hop independente | Testes unitários e propriedades de `scope-engine` |
| DNS rebinding ou atribuição incorreta a cloud/CDN | Atribuição não concede escopo; qualquer integração futura deve verificar destino no ponto de uso | Contrato de segurança; M0 usa somente arquivos locais |
| Snapshot antigo ou política alterada | Janela de validade, ponteiro ativo, escopo de job imutável e revalidação | Testes de engine e migrations |
| Vazamento de API keys ou dados de observação | HMAC local por programa, nenhum payload bruto em log, allowlist de campos antes de transmissão | Teste HMAC e saída do Shadow Mode |
| Replay, callback adulterado ou expirado no Telegram | Assinatura interna, chat/revisor permitidos, TTL, nonce, hash, snapshot e CAS | DTO e constraints em M0; teste de concorrência e identidade fica em M5 |
| APK ou conta de controle comprometida | Grants por postura, porta única, autenticação independente, revogação de chave/dispositivo | Ensaio com conexões permitidas e proibidas antes de ativar o controle |
| Pressão de RAM, stdout infinito ou hang no FX-6300 | Fila limitada, limites de bytes/tempo, `MemoryMax=3G` e concorrência pesada de um | Contratos e unidade offline; testes de processo usam fixtures locais inofensivas |
| Perda do SSD, adulteração de banco ou WAL excessivo | Permissões locais, trilha append-only, verificação e exercícios de backup | Migrations cobrem mutações e WAL real; runbook cobre restauração |
| Supressão de novidade por false merge | Associação reversível e versão de algoritmo | Caso rotulado com reversão prevista em M3 |

O risco residual inclui comprometimento de administrador, política manual mal revisada, dados mal classificados e perda simultânea do host e do backup. Preserve registros redigidos para investigação e confirme mudanças de autoridade com revisão humana.
