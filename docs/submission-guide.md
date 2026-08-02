# Подача Vitalstead в директорию Anthropic — пошаговый гайд

Статус: рабочий чеклист к `docs/tasks/EPIC-07-plugin-packaging.md` T-705
(«Подача в публичную директорию», P2, post-MVP, пока ⛔ не подана). Собран по
актуальному (на 2026-07-16) публичному процессу Anthropic — Anthropic может
менять форму/требования, перепроверяй ссылки перед подачей.

T-705 уже фиксирует главное ограничение: **агент не может подать заявку сам**
— нужны реальный контакт поддержки пользователя и реальные тестовые
credentials (WHOOP developer app), это должен сделать владелец проекта лично.
Этот документ — что именно нужно сделать и в каком порядке.

## 0. Два разных канала — какой выбираем

У Anthropic два независимых процесса подачи, и у этого репозитория есть
артефакты под оба:

| Канал | Что подаётся | Соответствует |
|---|---|---|
| **Desktop Extensions (MCPB)** — one-click установка в Claude Desktop | `mcpb/vitalstead.mcpb` | T-704, roadmap M7 |
| **Claude Plugin marketplace** — плагин для Cowork/Claude Code (skill+commands+.mcp.json) | `plugin/` (сейчас через personal marketplace, `.claude-plugin/marketplace.json`) | T-703, roadmap M6 |

T-705 в своих критериях приёмки явно называет «форма для desktop extensions»
— то есть план проекта уже выбрал **MCPB-канал как основной**. Ниже гайд
в первую очередь про него; plugin-marketplace описан в конце как
опциональный параллельный канал (D-016 упоминает оба — «Partners / desktop
extensions»).

Источники (проверено веб-поиском 2026-07-16):

- Desktop Extensions / Connectors submission: https://claude.com/docs/connectors/building/submission
- Building Desktop Extensions with MCPB: https://support.claude.com/en/articles/12922929-building-desktop-extensions-with-mcpb
- Anthropic Software Directory Policy: https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy
- Plugin marketplace submission: https://claude.com/docs/plugins/submit (формы: `claude.ai/settings/plugins/submit`, `platform.claude.com/plugins/submit`)
- Эскалации по ревью: mcp-review@anthropic.com

## 1. Что уже готово в репозитории

- `mcpb/vitalstead.mcpb` — собранный universal-бинарь (arm64 + x86_64),
  манифест валиден (`mcpb pack` прошёл без ошибок при переименовании D-020).
- `docs/privacy.md` — privacy policy на английском (D-012), написана по
  фактическому поведению tools, не по намерениям (T-705 частично выполнено
  2026-07-16, см. EPIC-07).
- Security: EPIC-08 закрыт (threat model, аудит логирования, privacy policy,
  CSV formula injection guard) — типичный пункт ревью Anthropic по
  безопасности закрыт заранее.
- `plugin/README.md` — objections/troubleshooting, известные ограничения
  закрытого MVP (single arch, fixed OAuth port).

## 2. Что должен сделать пользователь ДО подачи (агент не может)

Это ровно то, что T-705 называет «вне полномочий агента»:

1. **Аккаунт для подачи.** Console (`platform.claude.com`) с ролью Developer/
   Admin/Owner, либо claude.ai Team/Enterprise организация с правами
   directory management. Если ты individual author — регистрируешься в
   Console напрямую.
2. **Реальный контакт поддержки** (email/организация) — попадёт в публичную
   карточку в директории и будет виден ревьюерам/пользователям.
3. **Тестовые credentials для ревьюеров**:
   - реальный WHOOP developer app (client_id/secret) — по D-006 (BYO OAuth),
     сервер не собирает пароли WHOOP (D-005), но ревьюеру нужен рабочий
     client_id/secret, чтобы пройти connect_provider;
   - тестовый WHOOP-аккаунт, **предзаполненный данными** (сон/recovery/
     workout) — Anthropic явно требует не пустой аккаунт, ревьюер должен
     увидеть реальный результат sync_now/query_data, а не «no_connections».
4. **Иконка** — в репозитории её пока нет (`find . -iname "*icon*"` — пусто).
   Точный размер/формат смотри в самой форме подачи на момент заполнения
   (у Anthropic это менялось между релизами).
5. **Публичный URL для privacy policy.** Anthropic должен получить ссылку,
   не файл в приватном репо. Варианты:
   - сделать репозиторий публичным и ссылаться на
     `raw.githubusercontent.com/.../docs/privacy.md` (или `.../blob/...`
     для читаемого рендера);
   - GitHub Pages из этого же репо;
   - захостить `docs/privacy.md` как статичную страницу где угодно ещё.
   Ничего из этого агент сам не выбирает — это решение о публичности
   репозитория (см. пункт 3 ниже), полностью на пользователе.
6. **≥3 рабочих примера промптов**, явно называющих предметную область
   (WHOOP/health data), которые действительно вызывают tools. Черновик
   (можно брать как есть или адаптировать):
   - *"Connect my WHOOP account and set my data folder to ~/HealthData."*
   - *"Sync my WHOOP data now and tell me how many nights of sleep got saved."*
   - *"What's my average recovery score over the last week from my WHOOP data?"*

## 3. Решение, которое блокирует всё остальное: делать ли репозиторий публичным

- Plugin-marketplace канал (раздел 5) **требует** публичный GitHub-репозиторий
  или zip — «closed-source plugins are not accepted» (подтверждено
  веб-поиском).
- Для MCPB/Desktop Extensions канала прямого требования «репозиторий должен
  быть публичным» в источниках не нашлось — заявка идёт через загрузку
  собранного `.mcpb` + ссылки (документация, privacy policy), не через код.
  Но privacy policy всё равно должна быть на публичном URL (пункт 2.5) —
  то есть даже без публикации всего репозитория придётся опубликовать хотя
  бы `docs/privacy.md` где-то.
- В репозитории уже есть прагматичное решение на этот счёт (EPIC-07,
  T-703-примечание): marketplace-репозиторий — это ЭТОТ ЖЕ репозиторий, то
  есть тестеры personal marketplace и так видят весь исходный код ядра, а не
  только упакованный плагин. Публикация вовне — следующий шаг того же выбора,
  не новое решение с нуля.

Это продуктовое решение пользователя — публичность репозитория. Когда решишь,
это нумерованная запись в `docs/decisions.md` (D-021), т.к. меняет модель
распространения (D-016).

## 4. Шаги подачи — Desktop Extensions (MCPB), основной канал

1. Определиться с публичным URL privacy policy (раздел 2.5) — без него форма
   не пройдёт («Missing or incomplete privacy policies result in immediate
   rejection», по данным ревью-гайдов).
2. Добавить в `mcpb/manifest.json` поле `privacy_policies` (массив объектов
   `{"url": "..."}`) — минимум ссылка на privacy policy самого Vitalstead;
   т.к. данные уходят в WHOOP API, стоит добавить и ссылку на privacy policy
   WHOOP. Это правка манифеста делается ПОСЛЕ того, как появится реальный
   публичный URL из пункта 1 — вставлять фиктивный сейчас смысла нет.
3. Пересобрать бандл: `mcpb pack mcpb mcpb/vitalstead.mcpb` (как уже сделано
   при переименовании — команда идемпотентна).
4. Добавить раздел "Privacy Policy" в `plugin/README.md` (или отдельный
   README для канала MCPB) со ссылкой на тот же публичный URL.
5. Открыть https://claude.com/docs/connectors/building/submission, найти
   форму для desktop extensions (MCPB), залогиниться нужным аккаунтом
   (раздел 2.1).
6. Заполнить форму: описание, иконка, ссылка на документацию (README),
   ссылка на privacy policy, контакт поддержки, тестовые credentials
   (раздел 2.3), ≥3 примера промптов (раздел 2.6), приложить/указать
   `vitalstead.mcpb`.
7. Отправить. Статус и фидбек ревьюеров — в submissions dashboard
   (см. support-статью выше). Эскалации — mcp-review@anthropic.com.
8. Фидбек ревью → завести задачи (в `13-issue-tracker.md`, если работаешь
   через agent-team процесс, либо прямо в T-705).

## 5. Альтернативный/дополнительный канал — Claude Plugin marketplace

Если параллельно (или вместо MCPB) хочешь плагин в общей директории
Cowork/Claude Code:

1. Репозиторий обязан быть публичным (раздел 3) — GitHub-ссылка или zip.
2. Прогнать локальную валидацию: `claude plugin validate` (если утилита
   доступна) — ревью гоняет ту же проверку.
3. Убедиться, что `plugin/README.md` подробно объясняет установку и
   использование каждого компонента (skill/commands) — сейчас он это уже
   делает для closed-MVP канала, для публичного стоит перечитать на предмет
   ссылок на «personal marketplace»/«closed MVP», которые к этому моменту
   устареют.
4. Подать через `claude.ai/settings/plugins/submit` (нужна Team/Enterprise
   организация с directory management) или `platform.claude.com/plugins/submit`
   (Console, роль Developer/Admin/Owner).
5. Автоматическое ревью занимает «несколько дней» по данным support-статей;
   badge «Anthropic Verified» — отдельная, необязательная стадия.
6. После публикации обновления подхватываются автоматически из GitHub —
   повторно форму заполнять не нужно.

## 6. После подачи

- Обновить `docs/tasks/EPIC-07-plugin-packaging.md` T-705: дата подачи,
  какой канал, статус ревью.
- Definition of Done проекта: любое продуктовое решение (публичность
  репозитория, выбор канала) — каскад в `docs/decisions.md` в том же
  изменении, где оно фактически принято.
