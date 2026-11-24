# ADR 0004 · ModelBroker por contrato

**Status** Aceita

A interface recebe identificadores internos e entrada redigida. Perfis escolhem OpenAI, Gemini ou um endpoint OpenAI-compatible, incluindo OpenRouter. Modelos, credenciais, endpoint, prompt, schema e orçamento ficam em configuração. Cada adaptador precisa de fixtures de compatibilidade e testes de falha em saída parcial ou fora do schema. O contrato atual é offline.

Primeiro tente análise determinística. Em misses de cache, considere lote rápido com saída estruturada e, sob orçamento, uma etapa avançada para novidade ou correlação. Gere chave content-addressed no namespace do programa usando conteúdo redigido e versões de schema, prompt, redação e perfil. Reserve orçamento atomicamente, contabilize uso real e libere a reserva ao finalizar. Em falha de schema, inspeção ou budget, mantenha o item em revisão. Redação e isolamento precedem qualquer integração. Logs recebem agregados sem conteúdo.

Nenhum adaptador fornece ferramentas ou credenciais de execução ao modelo. Provedores diferentes não aumentam a independência de uma evidência com a mesma origem.
