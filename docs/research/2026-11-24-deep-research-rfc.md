# RFC — Arquitetura de ASM Contínuo, Reconhecimento Profundo e Triagem Assistida por IA para Bug Bounty Autorizado

## Escopo, premissas e estado da arte

**Status:** proposta de arquitetura.  
**Data de consulta das fontes:** 24 de novembro de 2026.  
**Objetivo:** construir um sistema contínuo de Attack Surface Management e reconnaissance que opere exclusivamente dentro das regras de programas autorizados de Bug Bounty, com execução ativa limitada por política determinística e ações sensíveis sujeitas a aprovação humana.

A arquitetura aqui proposta parte de quatro influências diferentes que não devem ser confundidas. A Trickest documenta um modelo de workflows em grafo, com módulos reutilizáveis, runtime, resultados e histórico de execução integrados; seu catálogo atual continua contendo workflows e módulos voltados a recon/ASM, inclusive integrações com ferramentas como `subfinder` e `httpx`. citeturn371104search27turn371104search28turn371104search23turn371104search26 O ecossistema ProjectDiscovery segue uma filosofia complementar: ferramentas especializadas que aceitam streams/listas e produzem saídas consumíveis por outros estágios — `subfinder → dnsx → httpx → katana/nuclei` é um padrão explicitamente suportado pela documentação, que também ressalta que os ativos devem estar autorizados para teste. citeturn230178search5turn230178search0turn230178search1turn230178search2

O *Bug Hunter's Methodology* de Jason Haddix continua sendo uma referência metodológica útil para organização mental de descoberta, mapeamento de aplicações e posterior análise, mas é importante não transformar isso em algo que a fonte não diz: o TBHM é uma metodologia/repositório de pesquisa ofensiva, não uma especificação formal de arquitetura de ASM distribuído para 2026. citeturn371104search0turn371104search1 Da mesma forma, abordagens contemporâneas de agentes oferecem padrões interessantes de coordenação: a documentação da OpenAI diferencia, por exemplo, um gerente que mantém o controle e usa especialistas como ferramentas de um fluxo de *handoff* em que o especialista assume a conversa; o SDK também dispõe de mecanismos de aprovação humana e guardrails. citeturn740841search0turn740841search2turn740841search3turn740841search4 O ecossistema de agentes do Google também documenta coordenação entre agentes especializados. citeturn740841search6turn740841search7

**A decisão arquitetural central deste RFC é deliberadamente menos “agêntica” que a moda de 2026:** LLMs podem classificar, correlacionar e sugerir próximos passos, mas **não possuem autoridade para produzir tráfego de rede**. O executor de rede é um componente Rust separado, sujeito a um Scope & Policy Engine determinístico. Nenhuma saída textual de um modelo é executável. Essa separação é uma proposta de engenharia deste RFC, e não uma característica documentada da Trickest, ProjectDiscovery, OpenAI ou Google.

As fontes oficiais das plataformas mostram que “escopo” é mais rico do que uma lista de domínios. HackerOne modela tipos de ativos como domínio, wildcard, URL, IP e CIDR e diferencia programas de escopo definido e aberto; também há atributos como elegibilidade e severidade máxima. citeturn657478search2turn657478search3turn657478search4 A Hacker API da Bugcrowd possui endpoint específico de escopo que expõe elementos in-scope, out-of-scope e regras relacionadas ao VRT. citeturn657478search5turn657478search6turn657478search8 A Intigriti enfatiza ativos explícitos, grupos de ativos, itens fora de escopo e regras de engajamento. citeturn657478search10turn657478search11 A API do YesWeHack expõe `scopes` e `out_of_scope`, e sua documentação define o escopo como os ativos em que o teste é permitido. citeturn455581search0turn455581search1turn455581search3turn455581search6

O `bounty-targets-data` é extremamente útil como feed agregado: o projeto coleta dados de HackerOne, Bugcrowd, Intigriti e YesWeHack e produz listas e JSONs normalizados. Entretanto, sua própria documentação alerta que um wildcard agregado pode ter exceções específicas no programa original. Além disso, as fontes do projeto apresentam cadências de atualização descritas de forma não totalmente uniforme. Por isso, neste RFC ele é tratado como **índice de descoberta**, jamais como autoridade final de autorização. citeturn111796search0turn111796search1turn111796search2turn111796search5

A hierarquia de confiança recomendada é:

| Origem | Papel no sistema | Autoridade |
|---|---|---|
| Regra nativa da plataforma/programa | Escopo, exclusões, limites, regras de engajamento | **Autoritativa** |
| Snapshot manual aprovado pelo operador | Complemento ou programa sem API adequada | **Autoritativa após revisão** |
| `bounty-targets-data` | Descoberta/bootstrapping | Não autoritativa |
| DNS, ASN, WHOIS, CNAME, IP cloud | Atribuição/hipótese de propriedade | **Nunca autorização** |
| Wayback/Common Crawl | Descoberta histórica | **Nunca autorização** |
| Inferência de LLM | Priorização/contexto | **Nunca autorização** |

Isso é particularmente importante para infraestrutura em nuvem. AWS publica faixas de IP e identificadores de serviço, Google publica `cloud.json` para faixas externas e Azure mantém ranges/service tags; esses conjuntos são excelentes sinais de atribuição. citeturn705770search1turn705770search3turn705770search5turn705770search0turn705770search2 Já um IP da Cloudflare apenas prova que o tráfego passa pela rede da Cloudflare; não identifica necessariamente o origin nem transfere autorização sobre qualquer outra propriedade hospedada ali. citeturn705770search33 Portanto, **“parece pertencer à empresa” nunca deve virar “pode ser escaneado”**.

## Arquitetura de referência e fluxo contínuo

A proposta combina o modelo em grafo da Trickest com a composabilidade Unix do ProjectDiscovery, mas materializa ambos como uma máquina de eventos explicitamente tipada em Rust. O grafo é persistente; ferramentas CLI são adaptadores, não o mecanismo de orquestração. A execução é separada em estágios reexecutáveis e idempotentes: ingestão de escopo, descoberta passiva, expansão autorizada, resolução, probing HTTP, crawling, enriquecimento, normalização, delta, triagem e revisão.

O desenho lógico é:

```text
                     FONTES DE ESCOPO
        ┌──────────────────────────────────────────┐
        │ H1 / Bugcrowd / Intigriti / YesWeHack  │
        │ bounty-targets-data / import manual     │
        └───────────────────┬──────────────────────┘
                            │
                            ▼
                 ┌───────────────────────┐
                 │ Scope Ingest + Diff   │
                 │ immutable snapshots   │
                 └───────────┬───────────┘
                             │ scope_version
                             ▼
                  ┌───────────────────────┐
                  │ SCOPE & POLICY ENGINE │◄──────────────┐
                  │     FAIL CLOSED       │               │
                  └──────┬────────┬───────┘               │
                         │ allow  │ deny/hold             │
                         │        └─────► audit log       │
                         ▼                               │
┌──────────────────────────────── DATA PLANE ───────────────────────────────┐
│ Linux x86_64 / Rust / Tokio                                             │
│                                                                         │
│  Scheduler ─► queue.passive ─► passive collectors                       │
│     │                           subfinder / archives / APIs               │
│     │                                    │                              │
│     │                                    ▼                              │
│     │                           normalize + scope gate                    │
│     │                                    │                              │
│     ├────► queue.dns ─────────► dnsx / resolver pool                    │
│     │                                    │                              │
│     ├────► queue.http ────────► httpx                                   │
│     │                                    │                              │
│     ├────► queue.web ─────────► katana / JS inventory                   │
│     │                                    │                              │
│     ├────► queue.safe_scan ───► policy-approved nuclei                  │
│     │                                    │                              │
│     └────► queue.oob ─────────► restricted Interactsh [HITL]            │
│                                          │                              │
│                                          ▼                              │
│                ┌───────────────────────────────────────┐                │
│                │ Observation Store / Delta Engine      │                │
│                │ exact + structural + similarity       │                │
│                └──────────────────┬────────────────────┘                │
│                                   │                                     │
│              deterministic filter│                                     │
│                                   ▼                                     │
│                     queue.ai.fast / queue.ai.deep                       │
│                                   │                                     │
│                      ┌────────────▼────────────┐                        │
│                      │ Model Router / Redactor │                        │
│                      │ OpenAI / Gemini         │                        │
│                      └────────────┬────────────┘                        │
│                                   │ candidate                           │
│                                   ▼                                     │
│                      Evidence-Gated Triage                              │
│                                   │                                     │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │ signed event over Tailscale
                                    ▼
┌────────────────────────────── CONTROL PLANE ─────────────────────────────┐
│ ARM / Android / Termux                                                  │
│                                                                         │
│ Event consumer ─► local review cache ─► Telegram bot                    │
│       │                                  │                              │
│       ├──► dashboard               Approve / Reject / Defer              │
│       ├──► watchdog                     │                              │
│       └──► alerting                     ▼                              │
│                                 signed approval                         │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
                     Data Plane verifies again:
                reviewer + TTL + action_hash + scope_version
                                    │
                              execute / refuse
```

A conexão entre nós não deve consistir em compartilhar um SQLite pela rede. O modo WAL do SQLite permite concorrência entre leitores e escritor, mas continua tendo apenas um escritor de cada vez e pressupõe que os processos participantes estejam no mesmo host; a própria documentação alerta contra WAL em filesystem de rede. citeturn791560search0 Portanto, no MVP o banco fica **local ao Data Plane**. O Control Plane recebe uma projeção limitada via API/eventos. Quando a arquitetura evoluir para múltiplos workers ou múltiplos escritores reais, PostgreSQL passa a ser a opção natural devido a MVCC, suporte multiusuário, JSONB e particionamento. citeturn791560search1turn791560search2turn791560search3

**Scope & Policy Engine.** O objeto mais importante do sistema não é `Asset`; é `ScopeVersion`. Cada job carrega a versão exata de escopo que o autorizou. Um snapshot novo nunca altera silenciosamente jobs antigos: ele invalida ou reavalia os pendentes.

Uma regra compilada deveria conceitualmente ser:

```rust
PolicyRule {
    program_id,
    scope_version,
    precedence,
    effect: Allow | Deny,
    target_type: Domain | WildcardDomain | UrlPrefix | Ip | Cidr,
    canonical_target,
    allowed_actions,
    max_rps,
    max_concurrency,
    max_bytes,
    max_depth,
    third_party_policy,
    valid_from,
    valid_until,
    source_provenance,
}
```

A semântica recomendada é **deny-overrides-allow**. Exclusões explícitas vencem inclusões; um erro de parsing, regra incompatível ou conflito de origem produz `UNKNOWN → DENY/HOLD`, nunca “melhor esforço”. Wildcards devem ser compilados segundo a semântica da plataforma/programa, em vez de assumir que `*.example.com`, `example.com` e todos os seus URLs são equivalentes. Isso é necessário justamente porque plataformas modelam tipos de ativo e exclusões de maneiras distintas. citeturn657478search2turn657478search6turn455581search0

O policy check deve ocorrer pelo menos em quatro momentos: criação do job, expansão de candidatos, imediatamente antes de entregar o alvo ao subprocesso e imediatamente antes de uma ação sensível aprovada. Uma mudança de escopo entre esses pontos invalida a autorização anterior.

Redirecionamentos HTTP merecem tratamento especial. Uma URL inicialmente autorizada pode responder com `Location:` para outro domínio. Portanto, seguir redirects não deve ser uma propriedade implícita de uma CLI: cada hop precisa passar novamente pelo policy engine. Para ferramentas externas nas quais esse controle não pode ser interceptado de modo confiável, a proposta é desativar redirects automáticos ou executar a ferramenta atrás de um mediador de egress.

O rate limiting deve ser hierárquico:

```text
global
 └─ provider/program
     └─ action class
         └─ hostname / IP
             └─ tool invocation
```

Para Rust, `governor` implementa rate limiting baseado em GCRA e pode sustentar buckets independentes por chave. citeturn206637search12turn206637search20 Acima disso, proponho um controlador adaptativo: `429`, `503`, aumento abrupto de latência ou erros repetidos reduzem concorrência; estabilidade prolongada a recupera lentamente até o teto definido pela política. Não há justificativa para “descobrir o limite” agressivamente; o teto humano/programático continua sendo a autoridade.

**Multiagente, sem entregar as chaves da nave à IA.** Os “agentes” úteis aqui são papéis lógicos:

```text
ScopeGuardian
ReconPlanner
AssetEnricher
DeltaAnalyst
EvidenceReviewer
ReportComposer
```

Só `ReconExecutor`, que não é um agente LLM, recebe capacidade de rede. `ReconPlanner` pode sugerir `{"action":"crawl","asset_id":"..."}`, mas essa mensagem é apenas dados. O executor reconstrói o alvo a partir do banco, verifica escopo, orçamento, aprovação e política. Esse desenho aproveita os padrões atuais de orquestração de agentes sem criar um caminho em que prompt injection em um JavaScript remoto vire uma chamada de ferramenta. Os mecanismos de guardrail e HITL dos SDKs de agentes são úteis como inspiração, mas até a documentação da OpenAI distingue guardrails de ferramentas, entrada e saída e observa diferenças de execução conforme o modo; isso reforça a decisão de manter a fronteira de segurança fora do modelo. citeturn740841search2turn740841search3

## Descoberta profunda com baixo ruído e execução segura

**Subdomínios e DNS.** `subfinder` permanece adequado à primeira fase porque seu foco é descoberta passiva e ele integra múltiplas fontes configuráveis, suporta saída estruturada e pipelines. citeturn230178search0 A saída nunca entra diretamente na fila ativa: ela é primeiro normalizada, deduplicada, vinculada à proveniência e recompilada contra o escopo.

Permutação deve ser uma segunda camada, não um gerador cartesiano enlouquecido. A proposta é derivar tokens observados — `api`, `dev`, `stage`, regiões, nomes de produtos, padrões numéricos — e gerar apenas permutações com uma pontuação mínima baseada na frequência e no contexto. Limites devem existir por domínio pai e por ciclo. Isso economiza consultas DNS e reduz o clássico cemitério de milhões de nomes impossíveis.

`dnsx` oferece resolução concorrente, escolha de resolvers e mecanismos automáticos de wildcard. citeturn230178search1 Ainda assim, o banco deve conservar evidência própria de wildcard: respostas a canários aleatórios, conjunto de A/AAAA/CNAME, TTL e timestamp. “Wildcard detectado” é um atributo temporal; não uma propriedade eterna de uma zona.

Atribuição de ASN/cloud/CDN entra somente como enriquecimento:

```text
hostname
  ├─ DNS A/AAAA
  ├─ CNAME chain
  ├─ ASN
  ├─ cloud/service prefix
  ├─ CDN indication
  └─ authorization = UNKNOWN unless scope says otherwise
```

Isso evita um erro bastante comum em ASM improvisado: expandir de “um domínio da empresa resolve para AWS” para “todos os IPs/buckets relacionados pertencem ao programa”. As listas oficiais AWS/GCP/Azure só fornecem metadados de infraestrutura. citeturn705770search1turn705770search5turn705770search0

Para objetos de cloud, a política recomendada é particularmente conservadora. Nomes de buckets, storage endpoints ou distribuições descobertos em DNS, HTML ou JavaScript podem ser inventariados como **candidatos**, mas nenhuma enumeração global, acesso a conteúdo ou tentativa de credencial deve ocorrer a menos que aquele recurso esteja explicitamente autorizado pelas regras do programa. A presença de uma string num bundle não concede permissão.

**HTTP e crawling.** Depois da resolução, `httpx` pode fornecer status, TLS, títulos e metadados HTTP em fluxo. citeturn230178search2 Esses resultados alimentam `AssetObservation`, não um relatório imediatamente. Um `200`, título novo ou tecnologia nova é interessante como delta, não como vulnerabilidade.

Para aplicações modernas, `katana` é especialmente relevante em 2026. Sua documentação atual diferencia crawling padrão e headless, suporta parsing/crawling de JavaScript, captura de XHR e classificação de endpoints REST/GraphQL/SOAP/XHR; a análise mais pesada com `jsluice` tem custo de memória maior. citeturn379155search0 Isso sugere uma escada de custo:

```text
HTTP estático
     │
     ▼
Katana padrão
     │ novidade suficiente?
     ├── não ──► stop/cache
     │
     ▼
JS parsing / XHR extraction
     │ ainda há lacunas e política permite?
     ▼
Headless [budget alto / opcionalmente HITL]
```

O crawler nunca deve atravessar o scope boundary só porque a página contém um link. Links externos são registrados como `ExternalReference`, mas não visitados.

Para JavaScript, recomendo armazenar três níveis:

```text
JSResource
 ├─ raw_hash
 ├─ normalized_hash
 └─ extracted_features
      ├─ URL/path literals
      ├─ fetch/XHR targets
      ├─ GraphQL-like operations
      ├─ WebSocket endpoints
      ├─ sourceMappingURL
      └─ SecretCandidate fingerprints
```

Source maps podem ser buscados quando estão publicamente referenciados por um ativo em escopo; não são permissão para buscar repositórios, hosts ou recursos externos referenciados pelo código. A detecção de segredos deve ser **defensiva e não validante**. O Katana atual possui tanto extração de possíveis segredos quanto uma opção para validação ativa; este RFC recomenda expressamente **proibir a validação de segredo**, pois ela pode executar chamadas reais contra APIs. citeturn379155search0

O Data Plane deve converter um segredo potencial em algo como:

```json
{
  "kind": "possible_api_token",
  "location": "bundle.js:...",
  "redacted_preview": "abcd…wxyz",
  "fingerprint": "HMAC-SHA256(k_local, raw_value)",
  "entropy": 4.71,
  "validated": false
}
```

O valor integral não vai para Telegram, LLM, logs ou relatório intermediário. Nenhuma credencial é testada.

Entropia, regex e formato são apenas sinais. Um blob base64, UUID ou hash de build pode ter entropia alta e não ser segredo. Portanto, o detector deve combinar formato, contexto lexical (`token`, `secret`, `authorization` etc.), tamanho, entropia e exclusões conhecidas. Mesmo uma pontuação alta produz `SecretCandidate`, nunca “credencial válida”.

**Histórico web.** A API CDX do Internet Archive permite consultar URLs históricas e aplicar filtros/colapsos; a documentação do Common Crawl fornece índice CDX e datasets WARC, e seu FAQ alerta que a API de índice é limitada e que consultas em volume devem preferir o índice bulk/columnar em vez de bombardear o serviço com concorrência. citeturn968274search0turn379155search2turn379155search3turn379155search5 O Common Crawl possui coleções publicadas em 2026, portanto continua sendo uma fonte efetivamente disponível no período analisado. citeturn379155search6

O fluxo seguro é:

```text
archive URL
   ↓
parse only
   ↓
canonicalize hostname/path/params
   ↓
does CURRENT scope authorize current target?
   ├─ no/unknown → archive-only metadata
   └─ yes        → candidate for current HTTP queue
```

Jamais “replay tudo do Wayback”.

**Nuclei.** O Nuclei é útil quando tratado como engine de templates, não como botão de “scan everything”. A documentação oferece filtros por template/severidade/tags e controles de taxa, concorrência e backoff. citeturn544127search0turn544127search1 Para um pipeline profissional, cada release do sistema deve fixar uma versão/hash da coleção aprovada e manter um *manifest* interno:

```text
template_id
template_hash
protocol
intrusiveness_class
requires_oob
requires_headless
requires_code
approved_by
approved_at
```

Classes de baixa interação podem entrar na fila automática se as regras do programa permitirem. Templates headless, code, OOB ou capazes de alterar estado devem exigir regra explícita e, conforme o risco, aprovação humana. O executor não deve aceitar `template_id` arbitrário sugerido por LLM.

**Interactsh.** O Interactsh suporta detecção de interações fora de banda em diversos protocolos e pode ser self-hosted. citeturn544127search2turn544127search4 Neste projeto eu restringiria o serviço aos protocolos necessários, preferencialmente DNS/HTTP(S), desabilitando capacidades que possam receber ou armazenar material de autenticação. Cada correlação OOB recebe TTL curto, `candidate_id`, programa e aprovação correspondente. Self-hosting oferece controle de retenção, mas também transfere para você a responsabilidade sobre logs e dados recebidos.

**Processos filhos em Rust.** `tokio::process::Command` fornece a base assíncrona para subprocessos; a documentação também chama atenção para `kill_on_drop` e para a necessidade de aguardar/recolher corretamente processos terminados. citeturn206637search0turn206637search2turn206637search11 O wrapper de ferramentas deve evitar shell interpolation completamente:

```text
ToolSpec
   ↓
argv[] construído por código
   ↓
Command::new(binary)
   .args(argv)
   .stdin(piped)
   .stdout(piped)
   .stderr(piped)
   .kill_on_drop(true)
```

Cada execução ganha stdout e stderr separados, limites máximos de bytes, timeout de parede, timeout de inatividade e canais `mpsc` limitados. Se o consumidor estiver saturado, o reader desacelera; isso transforma backpressure em comportamento explícito, em vez de encher RAM.

A saída de uma ferramenta é **entrada não confiável**. JSON inválido, linha gigantesca, ANSI escape, texto contendo instruções de prompt ou campos inesperados deve ser rejeitado/normalizado. O parser precisa impor limite de tamanho, tipos e versão do esquema antes que qualquer evento entre no banco.

O isolamento recomendado por job inclui usuário Linux sem privilégio, diretório temporário exclusivo, ambiente reduzido, filesystem somente onde necessário, limites de CPU/memória/PIDs e controle de egress. Mais importante que “containerizar tudo” é garantir que nem uma ferramenta comprometida nem um erro de configuração consigam inventar novos destinos. Em workloads que não permitem interposição do policy engine por conexão, uma camada de proxy/namespace de egress alimentada exclusivamente pelos destinos aprovados é a última barreira.

## Modelo de dados, Delta Recon e deduplicação

O banco deve separar **identidade**, **observação temporal** e **interpretação**. Atualizar a linha de um host com “o status agora é 200” destrói justamente a informação que torna ASM contínuo útil.

O esquema conceitual recomendado é:

```text
Program
 ├─ id
 ├─ platform
 ├─ external_program_id
 ├─ state
 └─ policy_profile

ScopeSnapshot
 ├─ id
 ├─ program_id
 ├─ source
 ├─ source_hash
 ├─ fetched_at
 ├─ valid_from
 └─ supersedes_id

ScopeRule
 ├─ snapshot_id
 ├─ effect
 ├─ target_type
 ├─ target
 ├─ action_policy
 ├─ limits
 └─ provenance

Asset
 ├─ id
 ├─ program_id
 ├─ kind
 ├─ canonical_key
 ├─ first_seen_at
 └─ last_seen_at

AssetRelation
 ├─ src_asset_id
 ├─ relation_type
 ├─ dst_asset_id
 └─ observation_id

Observation
 ├─ id
 ├─ asset_id
 ├─ observed_at
 ├─ collector
 ├─ status
 ├─ metadata_json
 ├─ exact_hash
 ├─ structural_hash
 ├─ simhash
 └─ raw_blob_ref

Endpoint
 ├─ id
 ├─ web_asset_id
 ├─ canonical_route
 ├─ route_shape
 └─ param_signature

ToolRun
 ├─ id
 ├─ job_id
 ├─ tool/version/hash
 ├─ scope_snapshot_id
 ├─ policy_decision_id
 ├─ started/finished
 └─ exit_metadata

CandidateFinding
 ├─ id
 ├─ asset_id
 ├─ type
 ├─ state
 ├─ novelty_score
 ├─ evidence_score
 ├─ created_at
 └─ triage_version

Evidence
 ├─ candidate_id
 ├─ kind
 ├─ observation_id
 ├─ redacted_blob_ref
 ├─ reproducibility
 └─ provenance

LLMCall
 ├─ provider
 ├─ model
 ├─ prompt_version
 ├─ schema_version
 ├─ input_hash
 ├─ cached
 ├─ usage
 └─ result_hash

Review
 ├─ candidate_id
 ├─ reviewer
 ├─ decision
 ├─ decision_at
 └─ notes

Approval
 ├─ id
 ├─ operation_hash
 ├─ scope_snapshot_id
 ├─ reviewer
 ├─ expires_at
 ├─ consumed_at
 └─ state

ReportDraft
 ├─ candidate_id
 ├─ revision
 ├─ generated_from_evidence_hash
 ├─ reviewer_approved
 └─ body_ref

AuditEvent
 ├─ actor
 ├─ event_type
 ├─ object_id
 ├─ timestamp
 └─ immutable_payload
```

No MVP, SQLite em WAL é perfeitamente defensável porque existe um worker principal e muitos leitores; ele evita a complexidade operacional de um PostgreSQL separado. WAL melhora a coexistência de readers/writer, mas continua limitando escrita concorrente e exige checkpoint. citeturn791560search0 O passo para PostgreSQL deve acontecer quando houver pelo menos uma destas condições: vários Data Plane workers escrevendo simultaneamente, retenção histórica muito grande, necessidade real de consultas analíticas concorrentes, HA ou ingestão distribuída. PostgreSQL oferece MVCC, JSONB e particionamento nativos para esse estágio. citeturn791560search1turn791560search2turn791560search3

**Delta Recon** deve ser event-driven. Um asset recém-visto é delta. Um host que alterna de NXDOMAIN para A record é delta. Uma aplicação que troca de cluster estrutural, um JS cujo conteúdo mudou, um novo endpoint, novo conjunto de parâmetros ou novo CNAME também podem ser delta. O sistema não precisa perguntar ao LLM “isso mudou?”; hashes e comparações determinísticas respondem primeiro.

A redução de ruído proposta opera em camadas.

**Canonicalização de URL.** Para identidade, normalize hostname, IDNA, portas default, `.`/`..` e fragmentos. Para clustering, ordene chaves de query e remova parâmetros de tracking conhecidos. Não use a versão canonicalizada para repetir requests sem guardar a URL original: ordem de parâmetros repetidos, case de path e valores podem ter semântica.

Exemplo:

```text
Original:
https://api.example.com/users/91/orders/5501?utm_source=x&expand=items

Canonical identity:
https://api.example.com/users/91/orders/5501?expand=items

Route shape:
api.example.com/users/{int}/orders/{int}?expand
```

Tipos úteis de segmento incluem `{int}`, `{uuid}`, `{hex}`, `{hash}`, `{date}`, `{slug}` e `{opaque}`. A transformação deve ser conservadora: `v1`, `v2`, `200`, `404` e anos podem ser semanticamente importantes e não devem ser indiscriminadamente substituídos.

**Hash exato.** BLAKE3 é adequado para conteúdo e chaves internas; a implementação Rust oficial oferece hashing otimizado em múltiplas arquiteturas. citeturn229546search3turn229546search6 Hash exato é barato e elimina duplicatas idênticas antes de qualquer algoritmo aproximado.

**Hash estrutural.** HTML é convertido em uma representação de árvore que mantém tags, classes/atributos selecionados e estrutura, removendo valores reconhecidamente voláteis — nonce, timestamps, request IDs etc. O hash desse modelo detecta “mesma página, conteúdo dinâmico diferente” melhor que body hash. É uma proposta específica deste RFC; os campos considerados voláteis devem ser configuráveis por programa para não esconder mudanças úteis.

**SimHash.** O trabalho do Google sobre near-duplicates em crawling popularizou fingerprints compactos que permitem comparar documentos pela distância entre fingerprints. citeturn617720search2turn617720search28 Aqui ele pode operar sobre shingles de texto/DOM normalizado. Para um fingerprint de 64 bits, comparar Hamming distance é extremamente barato.

**MinHash.** A família de técnicas de Broder estima semelhança/containment entre conjuntos a partir de sketches muito menores que os documentos originais e é particularmente apropriada quando o objeto é representado como conjuntos de shingles. citeturn617720search50turn617720search48 Uma implementação Rust pode usar, após validação, bibliotecas como `probminhash`, que disponibilizam variantes de MinHash. citeturn206637search21turn206637search36

Esses algoritmos **não devem deletar dados**. Um falso merge seria péssimo: duas páginas distintas podem compartilhar template; um falso split também desperdiça tokens. Portanto:

```text
raw observation
      │
      ├─ exact hash
      ├─ structural hash
      ├─ SimHash
      └─ MinHash sketch
             │
             ▼
      reversible cluster membership
             │
        representative chosen
```

O cluster tem `algorithm_version` e seus membros continuam recuperáveis. Thresholds devem ser calibrados por tipo de página e medidos contra um conjunto humano rotulado. Nada justifica escolher “Hamming <= 3” ou “Jaccard >= 0,9” universalmente e fingir que virou ciência.

As métricas que realmente importam são:

```text
dedup_exact_ratio
near_duplicate_merge_rate
false_merge_rate       ← amostra rotulada
false_split_rate        ← amostra rotulada
new_asset_rate
new_route_rate
interesting_delta_rate
raw_observations / alert
raw_observations / LLM_call
LLM_tokens / reviewed_candidate
LLM_tokens / accepted_candidate
```

Essas métricas permitem descobrir uma arquitetura que “economiza 90% de tokens” apenas porque está jogando fora os sinais mais interessantes — um truque estatístico digno de um vendedor de snake oil, não de ASM.

## Roteamento de modelos, economia de tokens e segurança contra conteúdo hostil

Structured Outputs da OpenAI permite restringir respostas de modelos a um JSON Schema definido; a documentação também deixa claro que aplicações ainda precisam tratar recusas, respostas incompletas e erros. citeturn752476search0 O Gemini também oferece saída estruturada orientada por schema. citeturn412333search27turn670668search8 Isso torna possível construir um broker de modelos sem depender de parsing de prosa.

A cascata proposta é:

```text
NÍVEL ZERO — Rust determinístico
  normalização
  scope check
  exact dedup
  route clustering
  structural hashing
  regex/entropy
  novelty calculation
  evidence completeness
              │
              │ apenas sobreviventes
              ▼
NÍVEL UM — modelo rápido / baixo custo
  classificação em lote
  categoria
  relevância
  resumo
  evidências citadas
  necessidade de revisão profunda
              │
              │ apenas alta novidade / ambiguidade
              ▼
NÍVEL DOIS — modelo de maior capacidade
  correlação entre evidências
  raciocínio sobre fluxo de código
  análise de pequenos trechos JS/source-map
  hipótese de impacto
  roteiro de validação HUMANA
              │
              ▼
        CandidateFinding
              │
              ▼
           humano
```

Não recomendo fixar neste RFC nomes de modelos nem números de RPM/TPM. A OpenAI documenta limites por modelo, organização/projeto e diferentes tipos de quota, com headers de rate-limit para observação dinâmica; esses valores são variáveis. citeturn752476search2turn752476search4 O mesmo princípio deve ser aplicado à Gemini, cujos níveis e capacidades de batch/cache fazem parte da configuração atual do serviço e podem variar por modelo/tier. citeturn670668search0turn412333search0

O `ModelBroker` deveria controlar simultaneamente:

```text
provider_request_budget
provider_token_budget
program_daily_budget
candidate_budget
model_concurrency
queued_batch_budget
retry_budget
```

Para classificação assíncrona, tanto OpenAI quanto Gemini oferecem mecanismos de batch; isso combina muito bem com triagem de milhares de observações que não exigem resposta interativa. citeturn752476search5turn670668search1turn670668search3

O cache deve existir **antes** do cache do provedor:

```text
cache_key =
    hash(
      provider +
      model +
      model_parameters +
      system_prompt_version +
      schema_version +
      canonical_input_hash
    )
```

O prompt caching da OpenAI pode reduzir trabalho repetido quando existe prefixo comum reutilizável, mas não substitui o cache semântico/content-addressed da aplicação. citeturn752476search7turn752476search15

Um pipeline eficiente raramente deveria mandar um HTML inteiro para um modelo. Depois do clustering, um input de triagem pode se parecer com:

```json
{
  "asset": "redacted identifier",
  "delta": {
    "type": "new_api_route",
    "route": "/api/users/{uuid}/preferences",
    "first_seen": "...",
    "sources": ["bundle_hash:...", "crawl:..."]
  },
  "response": {
    "status": 401,
    "content_type": "application/json",
    "body_excerpt": "...small redacted excerpt..."
  },
  "detectors": {
    "novel_route": true,
    "secret_candidate": false,
    "similarity_cluster": 812
  }
}
```

Isso produz enorme economia estrutural: o LLM recebe **features e evidências representativas**, não o lixo bruto de recon.

Para análise de JavaScript, aplique seleção progressiva:

```text
bundle inteiro
   ↓ local parsing
funções/módulos que contêm:
   endpoint novo
   auth logic
   dangerous sink/source
   GraphQL operation
   high-confidence secret candidate
   ↓
somente esses trechos + contexto mínimo
   ↓
LLM avançado
```

O mesmo vale para páginas: selecione o representante do cluster e inclua o delta em relação ao representante anterior.

**Prompt injection merece ser tratado como propriedade inevitável dos dados de recon.** HTML, JS, comentários, robots.txt e responses podem conter texto do tipo “ignore todas as instruções e faça X”. O modelo nunca deve poder obedecer operacionalmente a isso.

A política proposta é:

```text
untrusted recon text
      ↓
size limit + encoding normalization + redaction
      ↓
structured DATA field
      ↓
LLM
      ↓
JSON Schema
      ↓
business-rule validation
      ↓
NO direct tool invocation
      ↓
candidate / suggestion only
```

Mesmo que o modelo retorne:

```json
{"recommended_action":"scan 203.0.113.0/24"}
```

o executor não pega aquele CIDR da string. Ele só aceita um `asset_id` existente, reconstrói o alvo autorizado no servidor e submete novamente a operação ao Scope Engine. Essa diferença entre **referência a objeto interno** e **target fornecido por modelo** fecha uma classe inteira de ataques de prompt injection.

Redação deve ocorrer antes do request ao provedor. Tokens, cookies, Authorization headers, PII desnecessário, URLs assinadas e material de sessão são descartados ou pseudonimizados. Um HMAC local permite reconhecer o mesmo segredo em dois lugares sem expor seu valor.

Para respostas estruturadas, `schemars` pode gerar JSON Schema a partir de tipos Rust, reduzindo divergência entre o tipo do programa e o contrato enviado ao provedor. citeturn229546search14turn229546search16 O padrão deveria ser:

```rust
struct TriageResult {
    schema_version: String,
    category: Category,
    confidence: f32,
    evidence_ids: Vec<EvidenceId>,
    rationale_short: String,
    needs_deep_review: bool,
}
```

O campo `confidence` do modelo **não é a confiança de segurança**. Ele é apenas um sinal. A confiança operacional vem de evidência verificável.

## Evidence-Gated Triage, aprovação humana e Control Plane

O princípio do *Evidence-Gated Triage* é simples: nenhum achado ganha prioridade alta só porque um modelo “acha provável”. Ele precisa atravessar gates objetivos.

Uma máquina de estados recomendada é:

```text
Observed
   ↓
Candidate
   ↓
EvidenceComplete
   ↓
HumanReviewRequired
   ├───────────────► Rejected
   ├───────────────► Deferred
   └───────────────► ApprovedForValidation
                           ↓
                    HumanValidated
                           ↓
                      ReportReady
```

A aprovação para **validar** não é aprovação para **submeter**. São estados separados.

Uma função de priorização inicial poderia ser:

```text
score =
  25 × novelty
+ 20 × reproducibility
+ 20 × evidence_diversity
+ 15 × detector_confidence
+ 10 × impact_plausibility
+ 10 × model_correlation
- 30 × instability
```

com todos os termos normalizados em `[0,1]`.

Esses pesos são **proposta inicial**, não benchmark. O hard gate vem antes:

```text
scope_confirmed == true
evidence_count >= policy.minimum
raw_secret_exposed == false
prohibited_action_required == false
```

Se `scope_confirmed` não for verdadeiro, a pontuação operacional é irrelevante: o item não gera ação ativa.

“Evidência independente” deve significar fontes diferentes de observação, não dois modelos concordando entre si. Exemplos legítimos são: endpoint encontrado no JS e também observado pelo crawler; mudança de DNS registrada por resoluções em instantes diferentes; um possível comportamento identificado por um detector e reproduzido por uma request autorizada não destrutiva. Dois LLMs lendo o mesmo trecho são uma única evidência com duas interpretações.

O YesWeHack, por exemplo, orienta pesquisadores a limitar a coleta de dados sensíveis quando encontram exposição, em vez de copiar todo o conteúdo. citeturn455581search5 O mesmo princípio deve valer globalmente no sistema: capturar o mínimo suficiente para demonstrar o problema.

**Telegram.** O Bot API oferece inline keyboards e `callback_data`; callbacks identificam o usuário que acionou o botão. Webhooks podem usar um secret token em header. citeturn159340search0turn159340search1 Para um Control Plane em Android/Termux, eu prefiro **long polling**: ele elimina a necessidade de publicar um endpoint do telefone na Internet. Webhook continua possível, mas só é justificável se houver requisito real.

A mensagem não deve conter uma ação executável:

```text
[HIGH] Novo candidato #F-218

Programa: acme
Asset: api.example.com
Classe: possível endpoint sensível novo
Evidence: 3
Scope snapshot: S-9182
Expira: 30 min

[Ver evidências]
[Aprovar validação]
[Rejeitar]
[Adiar]
```

O `callback_data` leva apenas um identificador opaco curto, não `scan=https://...`. O Control Plane resolve o ID localmente, verifica:

```text
telegram_user_id ∈ reviewer_allowlist
chat_id esperado
approval.state == PENDING
now < expires_at
candidate.state == HUMAN_REVIEW_REQUIRED
```

e emite uma requisição assinada:

```json
{
  "approval_id": "...",
  "candidate_id": "...",
  "operation_hash": "...",
  "scope_snapshot_id": "...",
  "reviewer": "...",
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "..."
}
```

No Data Plane ocorre `compare-and-swap(PENDING → CONSUMED)`. Nonce repetido, aprovação expirada, hash de operação diferente ou snapshot de escopo obsoleto resulta em recusa. Isso fornece idempotência mesmo quando Telegram ou rede reenviam eventos.

Tailscale é apropriado como transporte privado, mas precisa de configuração explícita. A documentação atual recomenda grants para novas configurações e mantém um modelo de autorização baseado em origem/destino; também é relevante que uma tailnet sem seção ACL/grants restritiva pode acabar com permissões mais amplas que o desejado. citeturn159340search4turn159340search5 Device posture pode adicionar restrições baseadas no estado do dispositivo. citeturn159340search6 Tags são destinadas principalmente a máquinas não associadas a usuário; aplicá-las muda a semântica de identidade, então eu usaria uma tag de serviço no worker Linux e manteria o Android com identidade de usuário/posture. citeturn159340search7

Uma regra conceitual seria:

```text
ARM reviewer device:
    can -> worker:443/control-api
    cannot -> worker:ssh
    cannot -> database
    cannot -> recon targets

worker:
    can -> approved Internet recon egress
    can -> provider APIs
    cannot -> initiate control session into Android
```

Assim o telefone não é um segundo scanner; é um console de controle com poderes mínimos.

O watchdog no ARM monitora `heartbeat`, profundidade de filas, timestamp do último checkpoint, espaço em disco, versão/configuração, falhas repetidas e orçamento de APIs. Ele não reinicia scans cegamente. Um worker que morreu durante uma operação ativa deve retomar em estado `UNKNOWN/PENDING_RECONCILIATION`, conferir escopo e idempotência e só então decidir se o job pode ser reiniciado.

Relatórios são produzidos apenas após validação humana. A estrutura recomendada é:

```text
Título
Programa / asset / escopo
Resumo técnico
Pré-condições
Passos de reprodução revisados
Resultado observado
Resultado esperado
Evidências
Impacto demonstrado — sem extrapolação
Timeline
Hashes/IDs de observações
Dados redigidos
Notas sobre limites da validação
```

O LLM pode transformar evidências estruturadas nessa narrativa, mas não inventar impacto. Cada afirmação importante no draft deve ter `evidence_id`. Se uma frase não consegue apontar para uma evidência, ela é marcada para revisão ou removida.

A Bugcrowd documenta permissões distintas para leitura de escopo e criação de draft submissions em sua API. citeturn657478search5 Mesmo onde integrações de submissão forem possíveis, eu manteria a submissão fora do caminho automático: `ReportReady → HumanApprovedForSubmission` é uma fronteira consciente.

## Roadmap incremental, crates e critérios de aceitação

A implementação deve começar pelo freio, não pelo acelerador. Um scanner ultra-rápido sem modelo de autorização confiável é só uma forma muito eficiente de cometer um erro.

| Etapa | Entrega | Crates/componentes recomendados | Critério de aceitação |
|---|---|---|---|
| **Fundação de política** | Importadores de escopo, snapshots imutáveis, matcher domain/URL/IP/CIDR, deny-overrides-allow, audit | `tokio`, `serde`, `serde_json`, `url`, `ipnet`, `sqlx`, `blake3` | 100% dos jobs possuem `scope_snapshot_id`; caso ambíguo nunca produz tráfego |
| **MVP passivo + delta** | H1/feeds disponíveis, `bounty-targets-data`, subfinder passivo, SQLite WAL, Telegram read-only | `reqwest`, `sqlx`, `teloxide`, `tracing` | novo/removido/alterado é detectável sem scan ativo |
| **DNS/HTTP de baixo impacto** | dnsx/httpx supervisionados, rate limit, process wrapper, health/watchdog | `tokio::process`, `governor`, bounded `mpsc` | ferramenta travada é encerrada/recolhida; nenhum target não autorizado é emitido |
| **Web intelligence** | Katana padrão, JS inventory, archives, endpoint/param clustering, DOM fingerprints | parser HTML/URL escolhido após benchmark, `blake3`, SimHash local, opcional `probminhash` | redução mensurável de duplicatas sem false-merge acima do limite escolhido |
| **IA de triagem** | redaction, cache, broker OpenAI/Gemini, schema, batch, budgets | `reqwest`, `schemars`, `serde`, filas Tokio | nenhuma chamada contém segredo bruto; toda saída é schema-validada |
| **HITL sensível** | Telegram approvals, TTL, nonce, operation hash, Nuclei allowlist, OOB restrito | `teloxide`, `axum`, primitives criptográficas auditadas | replay e aprovação expirada sempre falham; escopo é revalidado na execução |
| **Escala/HA** | PostgreSQL, múltiplos workers, filas duráveis, dashboard e analytics | `sqlx` PostgreSQL, `axum`, OpenTelemetry/tracing | worker pode cair e retomar sem duplicar ações sensíveis |
| **Sistema completo** | agentes lógicos, correlação profunda, relatórios assistidos, calibração contínua | mesmos componentes; agentes continuam sem network authority | zero submissões automáticas; cada relatório possui cadeia de evidências humana |

`SQLx` oferece acesso async tanto a SQLite quanto PostgreSQL e possui suporte a verificação de queries, o que torna a migração gradual especialmente conveniente. citeturn206637search14turn206637search17 `reqwest` é um cliente HTTP Rust adequado para as APIs de plataforma e dos provedores de IA. citeturn229546search0turn229546search1 `ipnet` fornece tipos para redes IPv4/IPv6, úteis para o matcher de CIDRs. citeturn229546search4turn229546search11 `axum` continua ativo no ecossistema Rust em 2026 e é uma boa base para a API interna/dashboard. citeturn617720search0turn617720search3 `teloxide` fornece cliente Rust para Telegram e segue publicado em 2026. citeturn617720search1turn617720search8

Uma organização de workspace razoável seria:

```text
asm/
├─ crates/
│  ├─ domain/             # tipos, IDs, estados
│  ├─ scope-engine/       # compilação e decisão
│  ├─ platform-ingest/    # H1/Bugcrowd/Intigriti/YWH
│  ├─ scheduler/
│  ├─ tool-runner/
│  ├─ collectors/
│  ├─ normalizer/
│  ├─ fingerprint/
│  ├─ delta-engine/
│  ├─ evidence/
│  ├─ model-broker/
│  ├─ report-engine/
│  ├─ storage/
│  ├─ control-api/
│  └─ telemetry/
├─ apps/
│  ├─ asm-worker/
│  ├─ asm-control/
│  └─ asm-cli/
└─ migrations/
```

O `scope-engine` deveria ter poucas dependências e nenhum conhecimento de LLM. Isso facilita fuzzing/property tests. Propriedades particularmente importantes são:

```text
DENY sempre vence ALLOW conflitante
UNKNOWN nunca vira ALLOW
exclusão explícita nunca é perdida por wildcard
canonicalização é idempotente
scope_version antiga não autoriza operação nova
redirect não herda autorização do origin
CIDR adjacente não é incluído
IPv4-mapped IPv6 não burla política
IDNA/punycode não cria matcher divergente
```

Além dos testes unitários, o MVP deveria ter um “shadow mode”: todas as ferramentas são substituídas por um executor que apenas registra o target que *teria* sido enviado. Alimenta-se o sistema com scopes artificiais contendo wildcards, exclusões, CIDRs, URLs, redirects e conflitos. Somente depois de demonstrar que nenhum destino proibido aparece no log é que se habilita DNS/HTTP real em laboratórios ou programas autorizados.

As falhas previsíveis e suas respostas são:

| Falha | Consequência | Contenção proposta |
|---|---|---|
| Escopo stale | scan após remoção do ativo | snapshots + TTL + recheck pré-execução |
| Semântica errada de wildcard | alvo indevido | parser por plataforma + deny-on-unknown |
| Feed agregado diverge da plataforma | autorização falsa | feed nunca autoritativo |
| Redirect externo | saída do escopo | validação por hop |
| CDN/cloud confundido com ownership | expansão indevida | attribution ≠ authorization |
| DNS muda durante job | alvo diferente | resolução temporal + policy recheck |
| CLI trava | worker preso | timeouts + kill/reap |
| CLI inunda stdout | OOM | bounded queues + max bytes |
| Output malicioso | prompt injection/parser abuse | schema/length/encoding gates |
| LLM alucina target | scan arbitrário | modelos só referenciam IDs internos |
| LLM recebe segredo | vazamento | redaction antes do provider |
| Dedup faz falso merge | novidade escondida | clusters reversíveis + avaliação humana |
| Dedup faz falso split | custo excessivo | thresholds calibrados |
| Quota de IA esgota | pipeline interrompido | deterministic-first + budgets + fallback |
| Telegram comprometido | aprovação indevida | allowlist, TTL, nonce, operation hash, Tailscale |
| Callback repetido | execução duplicada | CAS/idempotency |
| Scope muda após aprovação | aprovação inválida | aprovação vinculada ao snapshot |
| Worker cai após ação | replay incerto | operation journal + reconciliation |
| Interactsh recebe dado inesperado | retenção sensível | protocolo restrito + TTL + minimização |

Os **critérios sistêmicos de aceitação** que eu consideraria obrigatórios antes de declarar o sistema “produção” são mais importantes que throughput: nenhuma operação ativa sem policy decision persistida; nenhuma decisão `UNKNOWN` resultando em rede; cada aprovação vinculada a hash da operação e versão de escopo; nenhum segredo bruto em logs/Telegram/LLM; subprocessos sempre limitados e reaproveitados/recolhidos corretamente; cada candidate com proveniência reproduzível; nenhum LLM com autoridade de ferramenta; todo relatório submetível revisado por humano.

Por fim, há limitações importantes na pesquisa. Documentação de plataformas e APIs muda rapidamente; o que foi verificado aqui reflete disponibilidade observada em **24 de novembro de 2026**. Bugcrowd, YesWeHack, HackerOne e Intigriti podem limitar APIs por conta, programa ou modalidade, portanto a existência de um endpoint documentado não garante acesso para toda conta. citeturn657478search5turn657478search9turn455581search2 O `bounty-targets-data` é deliberadamente derivado e pode estar atrasado ou simplificar regras complexas, motivo pelo qual não deve assumir papel de autorização. citeturn111796search0turn111796search2 Flags e capacidades de `katana`, `nuclei`, `interactsh` e demais CLIs também evoluem; produção deve piná-las por versão e hash e validar o manifest em CI. citeturn379155search0turn544127search0turn544127search4

A principal conclusão arquitetural é que um ASM profissional para Bug Bounty não é uma cadeia `subfinder | httpx | nuclei` com um LLM pendurado no final. É uma **máquina de estado orientada a evidências**, na qual autorização, proveniência, delta, deduplicação, custo e revisão humana são cidadãos de primeira classe. Trickest demonstra o valor de grafos e workflows reutilizáveis; ProjectDiscovery fornece excelentes building blocks composáveis; plataformas de Bug Bounty fornecem o contrato de autorização; e os modelos atuais oferecem uma camada potente de triagem e correlação. citeturn371104search28turn230178search5turn657478search2turn455581search3turn752476search0turn412333search27 O Rust Data Plane deve permanecer o árbitro determinístico que une essas peças — e, principalmente, o componente capaz de dizer **“não”** quando qualquer uma delas tenta sair do envelope autorizado.