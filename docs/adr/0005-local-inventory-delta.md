# ADR 0005 · Inventário local e delta

**Status** Aceita para a implementação local do M1

O operador fornece um documento de escopo versionado e revisado. O mesmo `ScopeEngine` que compila e valida o documento disponibiliza os dados da revisão e o digest da fonte à camada de persistência. O SQLite publica a revisão e sela suas regras na mesma transação. Uma revisão nova precisa apontar para o head anterior do programa. O head anterior permanece no histórico.

O worker canonicaliza nomes de domínio, aplica `Action::Passive` e mantém somente os candidatos permitidos. O SQLite confirma a revisão vigente e a decisão em sua transação de escrita. Publicação e ingestão consultam o relógio depois de obter o lock de escrita e imediatamente antes do commit. Cada execução tem identidade para reprocessamento idempotente. Um lote parcial pode registrar presença. Um inventário completo pode confirmar ausência para ativos com presença anterior no mesmo coletor que ainda sejam permitidos pela revisão vigente. Cada lote admite até 10 mil domínios e 20 mil deltas. Índices de terceiros servem para descoberta local.

O controle recebe eventos agregados e assinados em uma rota separada da saúde local. A versão, o identificador de chave e o payload compõem a entrada do HMAC-SHA256. O receptor associa a chave a um worker, valida a janela de tempo e verifica a sequência de heartbeats e a de cada resumo. O relógio de disponibilidade acompanha heartbeats. O resumo inclui um ID interno de execução, com deduplicação em memória por uma hora. O watchdog usa uma fila e um fluxo de entrega independentes dos resumos. As filas de notificações são voláteis. A rota de eventos e o transporte de alertas expõem somente dados operacionais agregados.

## Ensaio local

```sh
cargo run -p prometheus-worker -- passive-sync \
  --scope examples/lab-passive-scope.yaml --fixture examples/passive-domains.txt --dry-run

workdir=$(mktemp -d)
observed_at=$(date +%s)
cargo run -p prometheus-worker -- publish-scope \
  --scope examples/lab-passive-scope.yaml --db "$workdir/inventory.sqlite"
cargo run -p prometheus-worker -- passive-sync \
  --scope examples/lab-passive-scope.yaml --fixture examples/passive-domains.txt \
  --db "$workdir/inventory.sqlite" --run-key lab-capture-1 --observed-at "$observed_at" --complete
```

O mesmo comando de ingestão com o mesmo `observed_at`, `run-key` e inventário retorna o lote já registrado. Uma captura nova precisa de outro `run-key` e um `observed_at` maior.

## Coleta passiva supervisionada

`passive-sync` aceita `--source fixture`, `--source crtsh`, `--source subfinder` e `--source all`. A fonte padrão é `fixture` e `--dry-run` mantém a simulação local. `all` executa `crtsh` e `subfinder` e inclui a fixture quando `--inventory` e seu `--observed-at` são fornecidos. Cada fonte gera uma linha JSON. O worker persiste cada fonte em sua própria transação e continua com as demais quando uma delas falha.

O operador publica a revisão que declara `passive_live` e autoriza cada domínio de consulta com uma regra exata para `passive`. O comando admite até 32 domínios de consulta por fonte. Wildcards podem autorizar candidatos de um resultado. As quotas inteiras por minuto têm burst de uma admissão por camada. A taxa efetiva aplica o menor limite entre o teto global de 60 por minuto e as quotas do programa, da ação, do host e do provedor. Use um único SQLite WAL no SSD local do nó para preservar admissões e recuos entre invocações. As cotas usam o relógio monotônico desde o boot. Após reiniciar o nó, admissões anteriores podem impor uma espera de até 120 segundos. O worker mantém um `flock` exclusivo nesse arquivo durante o comando live.

O worker grava cada despacho em `tool_runs` antes da consulta ou do subprocesso. A trilha registra o desfecho mesmo se o snapshot for revogado durante a execução. Toda ingestão live é parcial e registra apenas presença. A revisão vigente é revalidada na admissão, na escrita e antes do envio do resumo. O banco guarda contagens agregadas de rejeições `DENY` e `UNKNOWN`. A rotina encerra a fonte após três falhas consecutivas e registra o lote parcial e sua contagem de falhas quando a revisão continua vigente. O mesmo `--run-key` recupera a execução registrada daquela fonte sem repetir a coleta. Use uma chave nova e um `observed_at` posterior para capturar novamente. A marca temporal live padrão é o início da execução da fonte.

Use [o manifest de exemplo](../../examples/tools-manifest.yaml) para pinagem. Informe o caminho absoluto e o SHA-256 do ELF revisado da versão `2.17.0-prometheus-passive.1`. Siga [as instruções de build do subfinder](../../tools/subfinder/README.md). O [patch de egress](../../tools/subfinder/2.17.0-prometheus-passive.1.patch) restringe o subfinder a HTTPS com TLS validado e uma consulta pública ao provedor HackerTarget por invocação, com redirects e credenciais desabilitados. Em produção, execute o worker em uma unidade systemd com `MemoryMax=3G` e `KillMode=control-group` e mantenha o SQLite no SSD do FX-6300. `crtsh` consulta o endpoint HTTPS fixo de Certificate Transparency com TLS validado. `--crtsh-loopback-origin` aceita uma origem HTTP numérica de loopback para escopos sintéticos `.test`. O mock tem identidade própria no banco e seus resumos só podem seguir para controle local.

Publique uma revisão live verificada com `publish-scope`. A amostra [lab-passive-live-scope.yaml](../../examples/lab-passive-live-scope.yaml) usa domínios sintéticos. O teste `passive_live` do worker publica a amostra, consulta um servidor Axum de loopback, executa um stub ELF pinado e verifica a auditoria e os resumos assinados.

```sh
cargo test -p prometheus-worker --test passive_live
```

## Controle

Configure `PROMETHEUS_WORKER_ID`, `PROMETHEUS_CONTROL_KEY_ID` e `PROMETHEUS_CONTROL_KEY` nos dois nós. A origem do controle é HTTPS ou HTTP com endereço numérico de loopback para ensaio local. `prometheus-control serve` escuta em `127.0.0.1:8765` por padrão. Para acesso entre nós, publique somente a rota de controle por um proxy HTTPS restrito à tailnet. Sincronize os relógios dos nós. O TTL do receptor deve exceder o intervalo de `prometheus-worker heartbeat`.

Para Telegram, configure `PROMETHEUS_TELEGRAM_TOKEN` e `PROMETHEUS_TELEGRAM_CHAT_ID` no controle. O chat recebe contagens e alertas de disponibilidade. O polling descarta o conteúdo recebido e não executa comandos. Na ausência dessas duas variáveis, os avisos são registrados localmente.

O build do controle para `aarch64-unknown-linux-musl` precisa de um compilador C que gere objetos AArch64 para a dependência criptográfica de rustls. Em um host x86-64 com Clang e o target Rust instalado:

```sh
CC_aarch64_unknown_linux_musl=clang \
  cargo build --release --target aarch64-unknown-linux-musl -p prometheus-control
```
