# Desenvolvimento em dupla com Codex e Antigravity

1. O operador abre uma Issue com objetivo verificável, arquivos afetados, entradas representativas, comportamento de falha e critérios de aceite. Se a Issue atravessar duas fronteiras de confiança, divida-a em dois contratos verificáveis.
2. No Google Antigravity IDE, converta a Issue em casos de aceitação e destaque as dúvidas sobre dados, escopo e recursos. Antes do código, escreva ou revise o ADR se a tarefa mudar autoridade, limites de recursos, formato persistido, protocolo ou topologia. Para ajustes internos, registre a decisão na Issue.
3. No Codex, implemente uma fatia pequena em uma branch de trabalho. Use fixtures sintéticas e execute as verificações de `AGENTS.md`. Para trabalho simultâneo, use branches ou worktrees separados e defina qual agente edita cada caminho na Issue.
4. Inverta os papéis na revisão. O outro agente lê o diff e procura mudança implícita de autorização, inversão de precedência, construção de alvo a partir de texto de modelo, conteúdo sensível em sinks, quebra de rastreabilidade e efeitos de reexecução. A pessoa operadora decide discrepâncias e revisa o diff final.
5. Anexe ao PR a reprodução local, resultados de verificação, invariantes afetadas e migrações. Para mudanças de política, inclua uma regressão contra entrada ambígua ou não autorizada. Para mudanças de deploy, registre as arquiteturas verificadas.

Toda Issue deve indicar uma entrada de fixture, um resultado esperado e a forma de reproduzi-lo. Se falhar uma barreira de escopo, auditoria ou evidência, o critério de aceite local é que o sistema permaneça bloqueado e apresente um diagnóstico redigido.
