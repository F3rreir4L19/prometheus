# Roadmap

| Marco | Entrega | Aceite local ou de homologação |
|---|---|---|
| M0 Fundação e Shadow Mode | Workspace, documentação, compiler de política, WAL, fixtures e automação GitHub | CI passa. Property tests, migrations e demo provam decisões sem atividade de rede do worker. |
| M1 Ingestão passiva e delta | Importação manual transacional, descoberta `bounty-targets-data` por arquivo, delta local e saúde somente leitura | Fixtures diferenciam novo, alterado, ausente e parcial. Nenhum feed promove escopo. |
| M2 Políticas oficiais | Adaptadores oficiais HackerOne, Bugcrowd e Intigriti para importação de políticas, preservando limites e proveniência; revisão de semântica DNS/HTTP a partir de fixtures | Um fixture por plataforma para inclusão, exclusão, lacuna e expiração. Conta sem acesso mantém o fluxo manual. Redirect e vínculo a snapshot passam nos testes. |
| M3 Inteligência web offline | Inventário de endpoints/JS de arquivos, forma de rota, hash BLAKE3, DOM, SimHash e clusters reversíveis | Corpus rotulado publica falsos merges/splits e demonstra reversão sem apagar observação. |
| M4 Triagem por IA | Redação, schema, cache, budgets e adaptadores OpenAI, Gemini e OpenRouter | Fixtures rejeitam payload adversário, budget excedido não reserva nova chamada e hit de cache evita consumo. |
| M5 Revisão humana | Controle autenticado, Telegram long polling, watchdog, aprovações de revisão e expiração | Replay, chat errado, expiração, hash divergente e snapshot obsoleto falham. Duas confirmações concorrentes consomem uma vez. |
| M6 Escala e recuperação | Ensaios de falha, restauração e avaliação de migração PostgreSQL conforme ADR 0002 | Ensaio alcança RPO ≤ 24h e RTO ≤ 30min, sem perda de vínculo histórico. |
| M7 Sistema Completo | Correlação de evidência, relatório assistido, dashboard de métricas e calibração da análise | Cada afirmação relevante aponta para evidência; revisão humana obrigatória e zero submissão automática. |

M0 fornece apenas a fundação offline. Os marcos descrevem entregas de defesa, análise e revisão. A ativação de acesso ao ambiente externo exige autorização humana e revisão separada dos limites operacionais.
