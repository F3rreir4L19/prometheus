# ADR 0001 · Fronteira determinística de escopo

**Status** Aceita

O texto produzido por um modelo pode vir de HTML, JS ou evidência adversária. Mantemos o Scope Engine independente de rede e IA. Modelos podem classificar evidências e referenciar IDs internos em schema fechado. Nenhuma saída de modelo autoriza rede, subprocesso ou submissão. Verifique IDs contra o programa e o snapshot.

O snapshot manual revisado é autoritativo em M0. Fontes nativas poderão ser aceitas após verificação; feeds e inferências são descoberta. Use `DENY > ALLOW` e bloqueie `UNKNOWN`. Preserve o ID do snapshot em jobs e observações, com revalidação na criação, expansão, pré-subprocesso e pré-ação sensível. Redirecionamentos passam pela política a cada hop. A validade termina no instante de expiração.

M0 testa regras exatas, wildcard e exclusões, prefixos URL, CIDR/IP, IDNA, IPv4-mapped IPv6, imutabilidade e revisão obsoleta. O Shadow Mode fornece trilha local. Uma aprovação humana nunca amplia o escopo.
