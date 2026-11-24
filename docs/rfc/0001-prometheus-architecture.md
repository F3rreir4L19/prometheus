# RFC 0001 · Arquitetura do Prometheus

**Status** Aceita para a fundação M0.  
**Entrada** [RFC de pesquisa](../research/2026-11-24-deep-research-rfc.md), com precedência das decisões do bootstrap sobre a decomposição sugerida na pesquisa.

O Prometheus registra mudanças de superfície autorizada e organiza evidências para triagem humana. A unidade de autorização é um snapshot por programa. A unidade de prova é uma observação temporal com proveniência. O sistema deriva candidatos e relatórios dessas evidências, mantendo a decisão final com a pessoa operadora.

## Nós e fronteiras

```text
i7 Ultra / 32 GB (WSL2 ou Debian em Hyper-V)
    ├── Codex + Antigravity, CI e fixtures
    ├── release GNU x86-64 baseline ───► FX-6300 / Debian Minimal
    └── release ARM64 musl estático ────► Redmi Note 10 / Termux

FX-6300 / Data Plane                     Redmi Note 10 / Control Plane
worker + SSD local + SQLite WAL          controle + watchdog com bateria
    política e trilha de auditoria ◄────── revisão humana (API autenticada)
    heartbeat com versão e sequência ─────► watchdog / dashboard
                       Tailscale: única porta da control-api
```

Em M0, o worker lê arquivos e imprime JSON Lines. O controle expõe uma rota Axum para testes em processo. A API remota, o long polling e o watchdog são componentes planejados. O telefone acessará apenas a porta da API de controle no worker, de acordo com identidade e postura do dispositivo, sem SSH, banco ou disparo de varredura.

## Componentes

| Componente | Limite |
|---|---|
| Domain | IDs, estados e entidades; tipos sem dependência de rede |
| Scope Engine | Política determinística e compilação de snapshots |
| Storage | Migrations SQLx, persistência histórica, referência ativa e auditoria |
| Runner | Contrato local de replay, limites de processo e fila |
| Intel | Canonicalização analítica, fingerprints, redação, cache e triagem |
| Control Protocol | Payloads versionados de heartbeat e revisão |
| Telemetry | Métricas agregadas e eventos com campos permitidos |

## Autoridade e verificação

O operador revisa o documento manual versionado YAML/JSON antes de promover o snapshot. APIs oficiais de HackerOne, Bugcrowd e Intigriti entram em M2 como fontes nativas vinculadas à conta e ao programa, com fixture de regressão e revisão de semântica. `bounty-targets-data` serve para descoberta. DNS, ASN, cloud/CDN, archives e LLM podem sugerir relações, sem conceder autorização. Ausência de política clara, regra inválida, versão obsoleta ou ação sem permissão mantém a operação bloqueada.

Quatro pontos exigem confirmação do escopo vigente, da ação e do destino: criação, expansão, barreira pré-subprocesso e barreira pré-ação sensível. Qualquer eventual componente que realize acesso ativo pertence a uma fronteira determinística, isolada e operada por humanos. O M0 não implementa executor, integração com scanners ou ações sensíveis. Objetivo de segurança em cada fronteira é reconstruir o destino por ID interno e aplicar a política ao destino final. Redirecionamentos exigem checagem separada por hop. Mudanças de DNS exigem nova verificação no ponto de uso.

Semântica v1:

- Domínio exato considera host normalizado por IDNA. Wildcard aceita descendentes em limite de label e exclui o apex. Hosts de URLs também são avaliados.
- Prefixo URL exige igualdade de esquema, host e porta normalizados, com limite de segmento. A query é ignorada no matching de prefixo e excluída do log. Caminhos com escapes, dot segments, barras duplicadas ou sintaxe ambígua ficam em `UNKNOWN`, inclusive antes da normalização WHATWG. Autorização de host ou CIDR em uma simulação nunca substitui a verificação de uma URL concreta.
- IPv4-mapped IPv6 converge para IPv4. CIDR precisa estar alinhado. Um intervalo só recebe `ALLOW` se uma regra permitir o intervalo inteiro. Qualquer sobreposição com exclusão custa `DENY`. Super-redes IPv6 que abrangem o espaço mapped ficam em `UNKNOWN`.
- `DENY > ALLOW`. Sem match, com malformação ou snapshot fora de `[valid_from, expires_at)`, o resultado é `UNKNOWN`. A engine recebe o snapshot ativo e o identificador que o job carrega. O Shadow Mode usa o arquivo indicado como snapshot ativo da simulação.
- O relatório por linha inclui digest BLAKE3 da política, ID do snapshot, ação, tempo, linha, hop, motivo e regra quando houver. O processamento da cadeia para no primeiro hop bloqueado. Alvos brutos ficam no arquivo de entrada.

## Entidades e delta

```text
Program ──┬── ScopeSnapshot ── ScopeRule
          ├── ProgramScopeHead ── ScopeSnapshot
          ├── Asset ──┬── Observation ── ScopeSnapshot
          │           ├── AssetRelation ── Observation
          │           └── Endpoint
          └── LlmCall
ScopeSnapshot ── AuditEvent ── Job ── ToolRun
Asset ── CandidateFinding ── Evidence ── Observation
CandidateFinding ── Review ── Approval ── ScopeSnapshot
CandidateFinding ── ReportDraft ── ReportEvidence
DedupCluster ── DedupMembership ── Observation
```

O [schema](../../crates/storage/migrations/0001_init.sql) guarda identidade estável por programa, observações imutáveis por tempo e os registros posteriores de interpretação. Promova snapshots em uma transação após gravar as regras. Publicar sela o conjunto de regras. O ponteiro ativo é mutável, e sua ausência ou expiração implica bloqueio. A trilha append-only é protegida por triggers no banco da aplicação. A integridade diante de um administrador com acesso ao arquivo depende de controles operacionais e backups.

O delta compara observações por identidade, coletor e janela. Distingue presença nova, alteração, ausência confirmada e coleta incompleta. A ausência em input parcial não confirma remoção. Preserve a observação original ao agrupar:

1. Canonicalize URLs conservadoramente. Derive uma forma analítica com `{int}`, `{uuid}`, `{hex}`, `{hash}`, `{date}`, `{slug}`, `{opaque}` somente com evidência suficiente. Preserve `v1`, `v2`, anos e segmentos semanticamente distintos. Formas analíticas jamais autorizam destino.
2. Use BLAKE3 para igualdade exata de conteúdo redigido. Identifique o perfil de redação e a versão.
3. Calcule fingerprint estrutural de DOM em conteúdo estático, ignorando nonces e timestamps sob regra versionada.
4. Compare SimHash 64 bits ou MinHash em cohorts. Mantenha `algorithm_version` e histórico de associação e exclusão. Meça falsos merges e falsos splits contra um corpus rotulado. Mantenha a triagem disponível em nível de observação.

## IA e evidência

`ScopeGuardian`, `ReconPlanner`, `AssetEnricher`, `DeltaAnalyst`, `EvidenceReviewer` e `ReportComposer` são papéis lógicos de análise. Sugestões são dados não confiáveis. Cada schema é fechado a campos inesperados e só referencia entidades internas. Valide schema, limites e existência de cada ID no programa, além do vínculo à evidência. Conteúdo HTML/JS não pode fornecer instruções ao orquestrador ou alterar política.

Cascata planejada: Nível 0 em Rust para regras e delta, Nível 1 para modelo rápido com lotes e saída estruturada, Nível 2 para alta novidade, correlação e trechos filtrados de JS. Configure modelo, credencial, limite de tokens, requests e custo diário por programa. Consulte cache local content-addressed com origem redigida e versões de prompt, schema, redação e perfil antes de reservar budget. Registre custos em microunidades de moeda. Redija localmente antes de persistir ou enviar conteúdo para qualquer modelo, Telegram ou logs. O M0 mascara o campo inteiro com HMAC-SHA256 e oferece apenas contratos e schema.

`Observed → Candidate → EvidenceComplete → HumanReviewRequired → ApprovedForValidation → HumanValidated → ReportReady → HumanApprovedForSubmission`

Evidência independente exige fontes distintas. Duas respostas de modelos não contam como duas fontes. A aprovação humana autoriza somente a revisão que identifica. O draft inclui ligações entre afirmações e `evidence_id`. A pessoa operadora faz qualquer submissão.

## Controle e contenções

Eventos do plano de controle incluem versão, identificador de chave, assinatura e sequência quando aplicável. O Telegram em long polling terá um ID opaco por callback. A validação exige assinatura no canal interno, `reviewer_allowlist`, `chat_id`, TTL, nonce, `operation_hash` e `scope_snapshot_id`. A transição `PENDING → CONSUMED` será atômica no Data Plane e sujeita à política vigente. Um heartbeat antigo indica degradação, sem ampliar autoridade.

| Falha | Contenção esperada |
|---|---|
| Documento inválido ou revisão antiga | Abortar importação ou retornar UNKNOWN |
| Redirect externo, DNS rebinding ou CDN de terceiros | Nova checagem do destino; manter bloqueado na falta de autorização |
| Entrada hostil ou truncada | Limite de ingestão, schema fechado e diagnóstico redigido |
| Processo travado ou saída excessiva | Orçamentos isolados de bytes e tempo, fila limitada, encerramento e recolha |
| Saturação de CPU ou memória | No máximo um processo pesado; `MemoryMax=3G` no FX-6300 |
| Binário externo ou conjunto de templates alterado | Revisão de versão, SHA-256 e classe antes de qualquer admissão; validação ativa de segredos proibida |
| Pressão de taxa | Limites compostos global → programa → classe → host/IP → ferramenta e backoff em 429, 503 ou aumento de latência, como requisitos de segurança |
| Modelo injeta ferramenta ou vaza dado | Validação de schema, IDs e redação; isolamento de credenciais e ferramentas |
| Esgotamento de quota | Cache e nível determinístico; enviar para revisão diante de limitação |
| Falso merge | Reabrir associação preservando observações e versão |
| Replay, tempo expirado ou mudança de escopo | Bloquear confirmação; registro atômico de consumo |
| Queda durante operação | Reconciliação explícita do estado em dúvida |
| WAL cresce ou disco fica cheio | Medir duração de leitores e WAL; pausar ingestão e recuperar a cópia verificada |

Em qualquer proposta de subprocesso, a interface usará `tokio::process::Command` com argv fixado por código, `kill_on_drop(true)`, orçamento de parede/inatividade, máximos de stdout/stderr e fila `mpsc` limitada. `governor` é a opção prevista para contabilização hierárquica de taxa. O M0 inclui somente os contratos locais de limite e replay.
