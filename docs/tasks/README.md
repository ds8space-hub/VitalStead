# Бэклог

## Эпики

| Эпик | Название | Приоритет | Статус |
|---|---|---|---|
| [EPIC-01](EPIC-01-core-migration.md) | Перенос ядра из родительского проекта | P0 | ✅ выполнен (T-102/T-103 открыты) |
| [EPIC-02](EPIC-02-mcp-server.md) | Каркас MCP-сервера | P0 | ✅ выполнен (T-201/T-202/T-203/T-410) |
| [EPIC-03](EPIC-03-oauth.md) | OAuth end-to-end (loopback callback) | P0 | ✅ выполнен (T-301…T-306) |
| [EPIC-04](EPIC-04-providers.md) | Провайдеры: WHOOP (MVP), Oura (post-MVP) | P0/P1 | ✅ выполнен для MVP (T-401/T-403/T-407; T-402/Oura — post-MVP, D-017) |
| [EPIC-05](EPIC-05-garmin-import.md) | Garmin: ручной ZIP-импорт | P1 | ⬜ post-MVP (D-018) |
| [EPIC-06](EPIC-06-sync-tools.md) | Sync engine + tool surface | P0 | ✅ выполнен (T-601…T-606, T-411) |
| [EPIC-07](EPIC-07-plugin-packaging.md) | Плагин, skill, дистрибуция | P0/P1 | ⚠️ T-701…T-704 сделаны (частично — ручная проверка на чистой машине не проведена); T-705 (post-MVP) ждёт действий пользователя |
| [EPIC-08](EPIC-08-security.md) | Security: threat model, логи, privacy | P0 | ✅ выполнен полностью (T-801…T-804) |

Порядок выполнения — `../roadmap.md`. Нумерация задач: `T-<эпик><порядковый>`
(EPIC-02 → T-201…). Ссылки вида «родительский T-xxx» указывают на задачи
`../Control your data/docs/mvp-plan/tasks/`.

## Definition of Ready

Задача готова к работе, когда: сформулирована одна измеримая цель; перечислены
критерии приёмки; указаны контракт/решение-источник (D-0xx или файл architecture.md);
зависимости от других задач разрешены.

## Definition of Done

Задача завершена, когда: все критерии приёмки выполнены; `cargo test` зелёный;
новый код не нарушает правила логирования (CLAUDE.md → Security rules); затронутые
доки (decisions/architecture/roadmap) обновлены в том же изменении; для задач с
внешними эффектами (OAuth, файлы) есть тест или воспроизводимая ручная проверка,
описанная в задаче.
