# Prometheus

Leia a [RFC](docs/rfc/0001-prometheus-architecture.md), o [modelo de ameaças](docs/threat-model.md) e o [fluxo em dupla](docs/ai-workflow.md) ao alterar um limite de confiança. M0 opera com arquivos locais e fixtures sintéticas.

## Mapa do workspace

| Caminho | Responsabilidade |
|---|---|
| `crates/domain` | IDs, classes de ação, decisões, entidades e estados |
| `crates/scope-engine` | Importação revisada, compilação, canonicalização e decisão |
| `crates/storage` | SQLite WAL local, proveniência e trilha de auditoria |
| `crates/runner` | Contratos de replay e limites de recursos |
| `crates/intel` | Redação, deduplicação e contratos de triagem por modelo |
| `crates/control-protocol` | Envelopes versionados, heartbeat e revisão humana |
| `crates/telemetry` | Eventos estruturados com campos permitidos e métricas agregadas |
| `apps/prometheus-worker` | CLI de Shadow Mode no FX-6300 |
| `apps/prometheus-control` | Rota local de saúde e base do controle no Redmi Note 10 |

## Invariantes

- Modelos produzem dados não confiáveis sob JSON Schema. Aceite somente IDs internos autorizados e valide associação ao programa. Isole os papéis de IA de subprocessos, credenciais de execução e autoridade de rede.
- Vincule cada job e observação a um snapshot imutável. Aceite somente fontes autoritativas revisadas. `bounty-targets-data`, DNS, ASN, cloud/CDN, archives e LLM servem apenas como descoberta. `DENY` vence `ALLOW`, e `UNKNOWN` mantém o bloqueio. Revalide escopo e ação na criação do job, expansão, barreira pré-subprocesso e barreira pré-ação sensível. Valide cada hop de redirect independentemente. Em M0, toda decisão é de simulação.
- Mantenha limites independentes para bytes, tempo de parede, inatividade, concorrência e filas. Qualquer revisão de integração externa exige versão e SHA-256 pinados, classe de intrusividade, ausência de validação ativa de segredos, e limite de um processo pesado sob `MemoryMax`. Use argv tipado e zero interpolação de shell.
- Preserve observações e auditoria. Guarde SQLite WAL em SSD local. Identidade, observação e interpretação são entidades distintas. Deduplicação mantém associações reversíveis e `algorithm_version`.
- Redija conteúdo localmente antes de persistir ou enviar a LLM, Telegram ou logs. Zero segredos em logs, fixtures ou relatórios. Configure modelos e budgets por programa e use cache content-addressed antes de qualquer provedor.
- Exija evidências de fontes independentes e revisão humana para afirmações e submissão. Toda confirmação exige identidade do revisor, chat, TTL, nonce, hash da operação, snapshot vigente e consumo atômico. Restrinja Tailscale à API de controle, sem SSH ou banco.
- Mire `target-cpu=x86-64` no FX-6300. No Note 10 use `aarch64-unknown-linux-musl` com CRT estático e rustls quando houver TLS.

## Rust e aceite

Use `thiserror` em bibliotecas e `anyhow` nas bordas. Proibido `unwrap()` e `expect()` em produção. Preserve entradas legadas, tipagem e falhas explícitas. Prefira fixtures locais e testes determinísticos.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p prometheus-worker -- shadow-mode --scope examples/lab-scope.yaml --targets examples/shadow-targets.txt --action http
cargo build --release --target x86_64-unknown-linux-gnu -p prometheus-worker
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl -p prometheus-control
```

Antes de qualquer commit ou PR:

- [ ] Revise o diff, a Issue e os ADRs aplicáveis. Verifique ausência de segredos e dados reais.
- [ ] Rode formato, Clippy, testes e Shadow Mode. Registre resultados e lacunas.
- [ ] Prove exclusão em wildcard, CIDR adjacente, mapped IPv6, IDNA, idempotência, ação divergente, snapshot obsoleto e redirect independente quando a política mudar.
- [ ] Verifique isolamento de IA, proveniência, auditoria, redação e revisão humana conforme o impacto.
- [ ] Quando afetar build ou deploy, rode os builds de destino e registre a inspeção ELF e os testes físicos disponíveis.
