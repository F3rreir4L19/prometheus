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

## Controle

Configure `PROMETHEUS_WORKER_ID`, `PROMETHEUS_CONTROL_KEY_ID` e `PROMETHEUS_CONTROL_KEY` nos dois nós. A origem do controle é HTTPS ou HTTP com endereço numérico de loopback para ensaio local. `prometheus-control serve` escuta em `127.0.0.1:8765` por padrão. Para acesso entre nós, publique somente a rota de controle por um proxy HTTPS restrito à tailnet. Sincronize os relógios dos nós. O TTL do receptor deve exceder o intervalo de `prometheus-worker heartbeat`.

Para Telegram, configure `PROMETHEUS_TELEGRAM_TOKEN` e `PROMETHEUS_TELEGRAM_CHAT_ID` no controle. O chat recebe contagens e alertas de disponibilidade. O polling descarta o conteúdo recebido e não executa comandos. Na ausência dessas duas variáveis, os avisos são registrados localmente.

O build do controle para `aarch64-unknown-linux-musl` precisa de um compilador C que gere objetos AArch64 para a dependência criptográfica de rustls. Em um host x86-64 com Clang e o target Rust instalado:

```sh
CC_aarch64_unknown_linux_musl=clang \
  cargo build --release --target aarch64-unknown-linux-musl -p prometheus-control
```
