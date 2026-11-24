# ADR 0002 · SQLite WAL local e caminho para PostgreSQL

**Status** Aceita

Use SQLite em SSD local do FX-6300, `sqlx`, foreign keys e até quatro conexões. Use WAL e `synchronous=FULL` no banco persistente com cinco segundos de `busy_timeout`. Execute migrations e a maioria dos testes em SQLite in-memory com uma conexão e cubra WAL em arquivo temporário. Mantenha transações de escrita curtas e faça backup com a API online do SQLite. Preserve identidade, observação e interpretação separadas. Triggers protegem auditoria e observações contra mutação pela aplicação.

Abra um ADR de migração quando existir pelo menos uma condição sustentada:

- Segundo writer em outro host necessário para cumprir o objetivo de disponibilidade.
- Mais de 1% das escritas encerradas com `SQLITE_BUSY` em sete dias após corrigir transações longas.
- Backup/restauração medidos excedem RPO de 24 horas ou RTO de 30 minutos em dois exercícios consecutivos.

Crie migrations próprias para PostgreSQL. Mapeie inteiros de tempo, JSON, BLOB/bytea e triggers explicitamente, mantendo as interfaces de repositório. Ensaie exportação/importação com contagem, chaves, digests e trilha. Corte com writers pausados e mantenha cópia SQLite verificada para rollback.
