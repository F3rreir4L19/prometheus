## Alteração

Issue, comportamento, arquivos relevantes e ADRs.

## Verificação local

Comandos, resultados, fixtures e alvos de build exercitados.

## Invariantes

- [ ] Revisei snapshot e ação, DENY/UNKNOWN, exclusões, IP/IDNA e redirects nas barreiras afetadas.
- [ ] A IA permanece isolada de ferramentas e autoridade de rede; entradas/saídas usam schema fechado e IDs internos.
- [ ] Logs, armazenamento e integrações recebem dados redigidos. Fixtures não contêm credenciais.
- [ ] Operações locais respeitam limites de bytes, tempo, fila e concorrência; nenhum comando é interpolado.
- [ ] Auditoria e observações são imutáveis; agrupamentos são reversíveis.
- [ ] Evidências, revisão humana, TTL, nonce, CAS e ausência de submissão automática foram revisados.
- [ ] Revisei os builds baseline x86-64 e ARM64 musl e a restrição do Control Plane conforme impacto.
- [ ] Formato, Clippy, testes e Shadow Mode passam.
