# FX-6300 com Debian Server Minimal

## Host e build

Use SSD local com espaço para banco, WAL e exportações. Em Debian Minimal, instale `sqlite3`, `ca-certificates` e `binutils` pelos repositórios da distribuição. Use a mesma versão de Debian na Build Factory ou versão compatível para manter os requisitos da glibc. Compile e inspecione o binário no host de build.

```sh
make build-fx6300
readelf -h target/x86_64-unknown-linux-gnu/release/prometheus-worker
sha256sum target/x86_64-unknown-linux-gnu/release/prometheus-worker
```

Transfira binário, digest e fixtures por canal administrativo ou mídia local. Compare o digest no Debian. Use `target-cpu=x86-64` e verifique execução física no FX-6300 antes de liberar.

```sh
sudo useradd --system --user-group --home-dir /var/lib/prometheus-worker \
  --shell /usr/sbin/nologin prometheus
sudo install -d -o root -g prometheus -m 0750 /etc/prometheus-worker
sudo install -o root -g root -m 0755 prometheus-worker /usr/local/bin/prometheus-worker
sudo install -o root -g prometheus -m 0640 lab-scope.yaml shadow-targets.txt /etc/prometheus-worker/
```

## Unidade offline M0

Grave em `/etc/systemd/system/prometheus-shadow.service`.

```ini
[Unit]
Description=Prometheus shadow scope audit

[Service]
Type=oneshot
User=prometheus
Group=prometheus
StateDirectory=prometheus-worker
StateDirectoryMode=0700
UMask=0077
ExecStart=/usr/local/bin/prometheus-worker shadow-mode --scope /etc/prometheus-worker/lab-scope.yaml --targets /etc/prometheus-worker/shadow-targets.txt --action http
MemoryMax=3G
TasksMax=32
TimeoutStartSec=30s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
```

```sh
sudo systemd-analyze verify /etc/systemd/system/prometheus-shadow.service
sudo systemctl daemon-reload
sudo systemctl start prometheus-shadow.service
sudo journalctl -u prometheus-shadow.service -n 30 --no-pager
```

O Shadow Mode usa somente o binário do workspace e as fixtures. Instale futuras dependências externas apenas após revisão do manifesto com origem, versão, SHA-256, arquitetura e classe de intrusividade. A unidade M0 impede acesso IP.

## Backup e recuperação de SQLite WAL

Quando houver banco persistente, use `/var/lib/prometheus-worker/prometheus.sqlite` em filesystem local. O Shadow Mode M0 registra em stdout. Para o banco da aplicação, agende backup diário por timer administrativo usando o comando online `.backup`. O exemplo é executado em shell root com o banco existente.

```sh
set -eu
umask 077
install -d -o root -g root -m 0700 /var/backups/prometheus-worker
backup=$(mktemp /var/backups/prometheus-worker/snapshot-XXXXXXXX.sqlite)
trap 'rm -f -- "$backup"' EXIT
sqlite3 -batch -bail -readonly /var/lib/prometheus-worker/prometheus.sqlite \
  ".timeout 5000" ".backup '$backup'"
test "$(sqlite3 -batch -bail -readonly "$backup" 'PRAGMA integrity_check;')" = ok
test -z "$(sqlite3 -batch -bail -readonly "$backup" 'PRAGMA foreign_key_check;')"
trap - EXIT
printf '%s\n' "$backup"
```

Proteja a cópia com criptografia e retenção conforme a política do operador. Faça um exercício restaurando em caminho separado, com conferência de integridade, migrações e amostra de auditoria. Na recuperação real, pause todos os acessos de escrita, preserve o conjunto original de banco e sidecars em quarentena, e restaure a cópia verificada antes de reabrir. Monitore idade do backup, tamanho do WAL e disponibilidade de disco. [SQLite Online Backup API](https://sqlite.org/backup.html)
