# Redmi Note 10 com Termux

1. Instale Termux e Termux:Boot do F-Droid, ambos da mesma origem de assinatura. Abra cada app uma vez. Em MIUI ou HyperOS, permita inicialização automática quando disponível e retire o Termux da otimização de bateria quando o telefone oferecer essa opção. Os nomes dos menus variam por firmware. [Termux:Boot](https://github.com/termux/termux-boot)
2. Instale Tailscale Android, registre o telefone na tailnet e confira identidade e postura no console. Antes de ativar uma API no worker, restrinja o Grant ao usuário autenticado com postura do telefone, destino `tag:prometheus-worker` e porta `tcp:8443` reservada ao controle. Teste que TCP 22 e portas de dados permanecem inacessíveis ao telefone. Grants são cumulativos, então revise regras mais amplas que atinjam o mesmo worker. Mantenha autenticação própria na API. [Tailscale Grants](https://tailscale.com/docs/features/access-control/grants)
3. Na Build Factory, compile e inspecione o executável.

No arquivo de política da tailnet, configure `posture:prometheus-note10` com um atributo de inventário exclusivo do telefone e disponibilize `tag:prometheus-worker` apenas a administradores. Adicione esta entrada a `grants` após substituir o e-mail pelo usuário cadastrado. Valide o dispositivo correto, outro Android da mesma conta e uma conta distinta antes de publicar a política.

```json
{
  "src": ["operador@example.com"],
  "srcPosture": ["posture:prometheus-note10"],
  "dst": ["tag:prometheus-worker"],
  "ip": ["tcp:8443"]
}
```

```sh
make build-note10
artifact=target/aarch64-unknown-linux-musl/release/prometheus-control
file "$artifact"
readelf -h "$artifact"
readelf -l "$artifact"
readelf -d "$artifact"
sha256sum "$artifact"
```

Confirme AArch64, ausência de `INTERP` e de entradas `NEEDED`. Integrações TLS futuras devem usar rustls. Transfira por USB para Downloads do Android e compare o digest com o publicado pela Build Factory. Em Termux:

```sh
termux-setup-storage
sha256sum "$HOME/storage/downloads/prometheus-control"
install -d -m 0700 "$HOME/bin"
install -m 0700 "$HOME/storage/downloads/prometheus-control" "$HOME/bin/prometheus-control"
"$HOME/bin/prometheus-control"
```

Em M0, o processo imprime `prometheus-control: offline bootstrap` e sai; `/healthz` é exercitado como rota Axum em memória. Para ensaiar Termux:Boot em M0, coloque o script abaixo em `~/.termux/boot/10-prometheus`, dê permissão de execução e reinicie o telefone. O wake lock é liberado ao fim do smoke test.

```sh
#!/data/data/com.termux/files/usr/bin/sh
set -eu
umask 077
termux-wake-lock
trap 'termux-wake-unlock' EXIT
"$HOME/bin/prometheus-control" > "$HOME/prometheus-boot.log" 2>&1
```

Confirme a saída no arquivo e teste uma segunda reinicialização com a tela bloqueada. O teste de long polling, watchdog e heartbeat fica para o marco M5. Credenciais dessa etapa devem ficar no armazenamento privado do Termux, com permissão restrita ao usuário do app.
