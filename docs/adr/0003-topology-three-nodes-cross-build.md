# ADR 0003 · Topologia e builds de destino

**Status** Aceita

- i7 Ultra com 32 GB é a Build Factory, em WSL2 ou VM Hyper-V Debian Minimal. É o nó para CI, property tests, releases e benchmarks analíticos.
- FX-6300 Debian Minimal com 4–8 GB e SSD é o Data Plane. Compile GNU x86_64 com `-C target-cpu=x86-64` e libc compatível com o Debian de destino. Proíba `target-cpu=native` para o artefato de release. Aplique `MemoryMax=3G`, proteção systemd e limite de um processo pesado se houver integração aprovada.
- Redmi Note 10 sem root em Termux é o Control Plane e watchdog com bateria própria. Use CRT estático ARM64 musl e rustls para TLS nas integrações futuras. Inspecione ELF e faça smoke test físico.

Tailscale Grants restringe o usuário com postura do Redmi à porta da API de controle no worker. Evite regras mais amplas que também concedam acesso ao mesmo destino. A API terá autenticação independente. SSH, banco e disparo de varredura ficam fora da interface do telefone.
